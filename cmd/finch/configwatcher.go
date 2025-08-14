package main

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	cblog "github.com/charmbracelet/log"

	"github.com/0x4D31/finch/internal/admin"
	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/proxy"
	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/internal/sse"
	"github.com/0x4D31/finch/internal/watch"
	galah "github.com/0x4d31/galah/galah"
)

func canonicalPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if rp, err := filepath.EvalSymlinks(abs); err == nil {
		abs = rp
	}
	return abs
}

// watchConfig watches the provided config file for changes and reloads
// rule engines and Suricata sets via the given Loader when updates occur.
func watchConfig(ctx context.Context, path string, rt *runtimeState, svc **galah.Service, initCfg *config.GalahConfig, sseSrv **sse.Server, hub *sse.Hub, adminSrv **admin.Server) error {
	initCfgFile, err := config.Load(path)
	if err != nil {
		return err
	}
	prevGalah := initCfg
	prevRules := make(map[string]string)
	prevDefault := ""
	for _, l := range initCfgFile.Listeners {
		rf := l.RuleFile
		if rf == "" && initCfgFile.Defaults != nil {
			rf = initCfgFile.Defaults.RuleFile
		}
		if rf != "" {
			prevRules[l.ID] = canonicalPath(rf)
		}
	}
	if initCfgFile.Defaults != nil {
		prevDefault = initCfgFile.Defaults.RuleFile
	}
	prevSuri := ""
	if initCfgFile.Suricata != nil && initCfgFile.Suricata.Enabled && initCfgFile.Suricata.RulesDir != "" {
		prevSuri = canonicalPath(initCfgFile.Suricata.RulesDir)
	}
	prevSSE := initCfgFile.SSE
	prevAdmin := initCfgFile.Admin

	errCh, err := watch.Watch(ctx, path, func() error {
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		var defaultEng *rules.Engine
		if cfg.Defaults != nil && cfg.Defaults.RuleFile != "" {
			var err error
			defaultEng, err = rt.loader.LoadEngine(cfg.Defaults.RuleFile)
			if err != nil {
				return err
			}
			if cfg.Defaults.RuleFile != prevDefault {
				for _, srv := range rt.servers {
					srv.SetGlobalEngine(defaultEng)
				}
				if prevDefault != "" {
					rt.loader.RemoveWatch(prevDefault)
				}
				prevDefault = cfg.Defaults.RuleFile
			}
		} else if prevDefault != "" {
			for _, srv := range rt.servers {
				srv.SetGlobalEngine(nil)
			}
			rt.loader.RemoveWatch(prevDefault)
			prevDefault = ""
		}
		if cfg.Suricata != nil && cfg.Suricata.Enabled && cfg.Suricata.RulesDir != "" {
			ptr, err := rt.loader.LoadSuricata(cfg.Suricata.RulesDir)
			if err != nil {
				return err
			}
			newDir := canonicalPath(cfg.Suricata.RulesDir)
			if prevSuri != "" && prevSuri != newDir {
				rt.loader.UnloadSuricata(prevSuri)
			}
			if newDir != prevSuri {
				for _, srv := range rt.servers {
					srv.SetSuricataSet(ptr)
				}
				prevSuri = newDir
			}
		} else if prevSuri != "" {
			rt.loader.UnloadSuricata(prevSuri)
			for _, srv := range rt.servers {
				srv.SetSuricataSet(nil)
			}
			prevSuri = ""
		}
		rt.globalEng = defaultEng
		rt.suriSet = nil
		if cfg.Suricata != nil && cfg.Suricata.Enabled && cfg.Suricata.RulesDir != "" {
			ptr, _ := rt.loader.LoadSuricata(cfg.Suricata.RulesDir)
			rt.suriSet = ptr
		}

		currentIDs := make(map[string]config.ListenerConfig)
		for _, l := range cfg.Listeners {
			currentIDs[l.ID] = l
		}

		for id, l := range currentIDs {
			rf := l.RuleFile
			if rf == "" && cfg.Defaults != nil {
				rf = cfg.Defaults.RuleFile
			}
			if rf != "" {
				var eng *rules.Engine
				if cfg.Defaults != nil && rf == cfg.Defaults.RuleFile && defaultEng != nil {
					eng = defaultEng
				} else {
					var err error
					eng, err = rt.loader.LoadEngine(rf)
					if err != nil {
						return err
					}
				}
				cp := canonicalPath(rf)
				if prevRules[id] != cp {
					if prevRules[id] != "" {
						rt.loader.RemoveWatch(prevRules[id])
					}
					if srv, ok := rt.servers[id]; ok {
						srv.SetLocalEngine(eng)
					}
					prevRules[id] = cp
				}
			} else if prevRules[id] != "" {
				if srv, ok := rt.servers[id]; ok {
					srv.SetLocalEngine(nil)
				}
				rt.loader.RemoveWatch(prevRules[id])
				delete(prevRules, id)
			}

			if srv, ok := rt.servers[id]; ok {
				accessLog := l.AccessLog
				if accessLog == "" && cfg.Defaults != nil {
					accessLog = cfg.Defaults.AccessLog
				}
				certFile, keyFile := "", ""
				if l.TLS != nil {
					certFile = l.TLS.Cert
					keyFile = l.TLS.Key
				}
				caFile := l.UpstreamCAFile
				skipVerify := l.UpstreamSkipTLSVerify
				if caFile == "" && cfg.Defaults != nil {
					caFile = cfg.Defaults.UpstreamCAFile
				}
				if skipVerify == nil && cfg.Defaults != nil {
					skipVerify = cfg.Defaults.UpstreamSkipTLSVerify
				}
				skip := false
				if skipVerify != nil {
					skip = *skipVerify
				}
				if l.Bind != srv.ListenAddr ||
					l.Upstream != srv.UpstreamURL.String() ||
					accessLog != rt.logPaths[id] ||
					certFile != srv.CertFile ||
					keyFile != srv.KeyFile ||
					caFile != srv.UpstreamCAFile ||
					skip != srv.UpstreamSkipVerify {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = srv.Shutdown(ctx)
					cancel()
					if path, ok := rt.logPaths[id]; ok {
						if lr, ok := rt.loggers[path]; ok {
							lr.ref--
							if lr.ref == 0 {
								if err := lr.l.Close(); err != nil {
									cblog.Errorf("close logger %s: %v", path, err)
								}
								delete(rt.loggers, path)
							}
						}
						delete(rt.logPaths, id)
					}
					newSrv, err := rt.addListener(l, &cfg, defaultEng, rt.suriSet, hub)
					if err != nil {
						return err
					}
					rt.servers[id] = newSrv
					rt.logPaths[id] = l.AccessLog
					rt.wg.Add(1)
					go func(s *proxy.Server) {
						defer rt.wg.Done()
						cblog.Infof("listening on %s (%s)", s.ListenAddr, s.ID)
						if err := s.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
							cblog.Errorf("server %s: %v", s.ID, err)
						}
					}(newSrv)
					continue
				}
			} else {
				srv, err := rt.addListener(l, &cfg, defaultEng, rt.suriSet, hub)
				if err != nil {
					return err
				}
				rt.servers[id] = srv
				rt.logPaths[id] = l.AccessLog
				rt.wg.Add(1)
				go func(s *proxy.Server) {
					defer rt.wg.Done()
					cblog.Infof("listening on %s (%s)", s.ListenAddr, s.ID)
					if err := s.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
						cblog.Errorf("server %s: %v", s.ID, err)
					}
				}(srv)
			}
		}
		// Clean up removed listeners
		for id, srv := range rt.servers {
			if _, ok := currentIDs[id]; !ok {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = srv.Shutdown(ctx)
				cancel()
				if path, ok := rt.logPaths[id]; ok {
					if lr, ok := rt.loggers[path]; ok {
						lr.ref--
						if lr.ref == 0 {
							if err := lr.l.Close(); err != nil {
								cblog.Errorf("close logger %s: %v", path, err)
							}
							delete(rt.loggers, path)
						}
					}
					delete(rt.logPaths, id)
				}
				if p, ok := prevRules[id]; ok {
					rt.loader.RemoveWatch(p)
					delete(prevRules, id)
				}
				delete(rt.servers, id)
			}
		}

		if svc != nil {
			if !equalGalah(prevGalah, cfg.Galah) {
				if *svc != nil {
					if err := (*svc).Close(); err != nil {
						cblog.Errorf("close galah: %v", err)
					}
				}
				var newSvc *galah.Service
				if cfg.Galah != nil && cfg.Galah.Provider != "" {
					opts := galah.Options{
						LLMProvider:    cfg.Galah.Provider,
						LLMModel:       cfg.Galah.Model,
						LLMTemperature: cfg.Galah.Temperature,
						LLMAPIKey:      cfg.Galah.APIKey,
						ConfigFile:     cfg.Galah.ConfigFile,
						CacheDBFile:    cfg.Galah.CacheFile,
						CacheDuration:  cfg.Galah.CacheDuration,
						EventLogFile:   cfg.Galah.EventLogFile,
						LogLevel:       cfg.Galah.LogLevel,
					}
					// galah.NewService mutates the global cblog prefix. Preserve and restore.
					prevPrefix := cblog.GetPrefix()
					newSvc, err = galah.NewService(ctx, opts)
					cblog.SetPrefix(prevPrefix)
					if err != nil {
						return err
					}
				}
				*svc = newSvc
				for _, srv := range rt.servers {
					srv.SetGalahService(newSvc)
					srv.SetGalahOptions(cfg.Galah.CacheEnabled, cfg.Galah.EventLogging)
				}
				prevGalah = cfg.Galah
			} else if cfg.Galah != nil {
				for _, srv := range rt.servers {
					srv.SetGalahOptions(cfg.Galah.CacheEnabled, cfg.Galah.EventLogging)
				}
			} else {
				for _, srv := range rt.servers {
					srv.SetGalahOptions(false, false)
				}
			}
		}
		if sseSrv != nil && hub != nil {
			if !equalSSE(prevSSE, cfg.SSE) {
				if *sseSrv != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = (*sseSrv).Shutdown(ctx)
					cancel()
				}
				var newSrv *sse.Server
				if cfg.SSE != nil && cfg.SSE.Enabled && cfg.SSE.Addr != "" {
					newSrv = sse.NewServer(cfg.SSE.Addr, hub)
					go func() {
						if err := newSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
							cblog.Errorf("sse server: %v", err)
						}
					}()
				}
				*sseSrv = newSrv
				prevSSE = cfg.SSE
			}
		}
		if adminSrv != nil {
			if !equalAdmin(prevAdmin, cfg.Admin) {
				if *adminSrv != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					_ = (*adminSrv).Shutdown(ctx)
					cancel()
				}
				var newSrv *admin.Server
				if cfg.Admin != nil && cfg.Admin.Enabled && cfg.Admin.Addr != "" {
					newSrv = admin.New(cfg.Admin.Addr, cfg.Admin.Token, &cfg, nil, nil, nil, "")
					go func() {
						if err := newSrv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
							cblog.Errorf("admin server: %v", err)
						}
					}()
				}
				*adminSrv = newSrv
				prevAdmin = cfg.Admin
			}
		}
		cblog.Infof("config reloaded from %s", path)
		return nil
	})
	if err != nil {
		return err
	}
	go func() {
		for e := range errCh {
			cblog.Errorf("config reload %s failed: %v", path, e)
		}
	}()
	return nil
}

func equalGalah(a, b *config.GalahConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Provider == b.Provider &&
		a.Model == b.Model &&
		a.Temperature == b.Temperature &&
		a.APIKey == b.APIKey &&
		a.ConfigFile == b.ConfigFile &&
		a.CacheFile == b.CacheFile &&
		a.CacheDuration == b.CacheDuration &&
		a.CacheEnabled == b.CacheEnabled &&
		a.EventLogFile == b.EventLogFile &&
		a.EventLogging == b.EventLogging &&
		a.LogLevel == b.LogLevel
}

func equalSSE(a, b *config.SSEConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Enabled == b.Enabled && a.Addr == b.Addr
}

func equalAdmin(a, b *config.AdminConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Enabled == b.Enabled && a.Addr == b.Addr && a.Token == b.Token
}
