package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cblog "github.com/charmbracelet/log"

	"github.com/0x4D31/finch/internal/admin"
	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/logger"
	"github.com/0x4D31/finch/internal/proxy"
	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/internal/sse"
	galah "github.com/0x4d31/galah/galah"
	suricata "github.com/0x4d31/galah/pkg/suricata"
	_ "github.com/mattn/go-sqlite3"
)

// version is overridden at build time using -ldflags "-X main.version=<version>"
// when building release binaries. It defaults to "dev" for local builds.
var version = "dev"

type runtimeState struct {
	servers     map[string]*proxy.Server
	logPaths    map[string]string
	loader      *Loader
	loggers     map[string]*logRef
	adminSrv    *admin.Server
	galahSvc    *galah.Service
	suriSet     *atomic.Pointer[suricata.RuleSet]
	globalEng   *rules.Engine
	watchCancel context.CancelFunc
	pf          parsedFlags
	wg          *sync.WaitGroup
}

type logRef struct {
	l   *logger.Logger
	ref int
}

func newRuntime(cfg *config.Config, pf parsedFlags, hub *sse.Hub, sseSrv **sse.Server, adminSrv **admin.Server) (*runtimeState, error) {
	rt := &runtimeState{wg: &sync.WaitGroup{}, pf: pf}
	rt.loader = NewLoader(cfg.Defaults.DefaultAction)

	rt.servers = make(map[string]*proxy.Server)
	rt.loggers = make(map[string]*logRef)
	rt.logPaths = make(map[string]string)

	var globalEng *rules.Engine
	var err error
	if !pf.EchoMode && cfg.Defaults.RuleFile != "" {
		globalEng, err = rt.loader.LoadEngine(cfg.Defaults.RuleFile)
		if err != nil {
			return nil, fmt.Errorf("load engine %s: %w", cfg.Defaults.RuleFile, err)
		}
	}

	var suriSet *atomic.Pointer[suricata.RuleSet]
	if !pf.EchoMode && cfg.Suricata != nil && cfg.Suricata.Enabled {
		suriSet, err = rt.loader.LoadSuricata(cfg.Suricata.RulesDir)
		if err != nil {
			return nil, fmt.Errorf("load suricata: %w", err)
		}
	}

	rt.globalEng = globalEng
	rt.suriSet = suriSet

	watchCtx, watchCancel := context.WithCancel(context.Background())
	rt.watchCancel = watchCancel
	if pf.ConfigPath != "" {
		if err := watchConfig(watchCtx, pf.ConfigPath, rt, &rt.galahSvc, cfg.Galah, sseSrv, hub, adminSrv); err != nil {
			return nil, err
		}
	}
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
		rt.galahSvc, err = galah.NewService(context.Background(), opts)
		cblog.SetPrefix(prevPrefix)
		if err != nil {
			return nil, fmt.Errorf("init galah: %w", err)
		}
	}

	for _, l := range cfg.Listeners {
		svr, err := rt.addListener(l, cfg, globalEng, suriSet, hub)
		if err != nil {
			return nil, err
		}
		rt.servers[l.ID] = svr
	}

	if !pf.EchoMode {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		go func() {
			for range hup {
				rt.loader.ReloadEngines()
			}
		}()
	}

	return rt, nil
}

func (rt *runtimeState) addListener(l config.ListenerConfig, cfg *config.Config, globalEng *rules.Engine, suriSet *atomic.Pointer[suricata.RuleSet], hub *sse.Hub) (*proxy.Server, error) {
	if rt.pf.EchoMode {
		// Set up access logging for echo mode
		if l.AccessLog == "" && cfg.Defaults != nil && cfg.Defaults.AccessLog != "" {
			l.AccessLog = cfg.Defaults.AccessLog
		}

		var lgr *logger.Logger
		if l.AccessLog != "" {
			if lr, ok := rt.loggers[l.AccessLog]; ok {
				lgr = lr.l
				lr.ref++
			} else {
				var err error
				lgr, err = logger.New(l.AccessLog)
				if err != nil {
					return nil, fmt.Errorf("logger %s: %w", l.ID, err)
				}
				rt.loggers[l.AccessLog] = &logRef{l: lgr, ref: 1}
			}
		}

		certFile, keyFile := "", ""
		if l.TLS != nil {
			certFile = l.TLS.Cert
			keyFile = l.TLS.Key
		}
		svr, err := proxy.NewEcho(l.ID, l.Bind, certFile, keyFile, lgr)
		if err != nil {
			return nil, err
		}
		rt.logPaths[l.ID] = l.AccessLog
		return svr, nil
	}

	if l.AccessLog == "" && cfg.Defaults != nil {
		l.AccessLog = cfg.Defaults.AccessLog
	}

	var localEng *rules.Engine
	if l.RuleFile != "" {
		var err error
		localEng, err = rt.loader.LoadEngine(l.RuleFile)
		if err != nil {
			return nil, fmt.Errorf("load engine %s: %w", l.RuleFile, err)
		}
	}

	var lgr *logger.Logger
	if lr, ok := rt.loggers[l.AccessLog]; ok {
		lgr = lr.l
		lr.ref++
	} else {
		var err error
		if strings.ToLower(rt.pf.LogLevel) == "debug" {
			lgr, err = logger.NewWithStdout(l.AccessLog)
		} else {
			lgr, err = logger.New(l.AccessLog)
		}
		if err != nil {
			return nil, fmt.Errorf("logger %s: %w", l.ID, err)
		}
		rt.loggers[l.AccessLog] = &logRef{l: lgr, ref: 1}
	}

	certFile, keyFile := "", ""
	if l.TLS != nil {
		certFile = l.TLS.Cert
		keyFile = l.TLS.Key
	}
	svr, err := proxy.New(l.ID, l.Bind, l.Upstream, certFile, keyFile, lgr, localEng, globalEng, suriSet, hub, rt.galahSvc, l.UpstreamCAFile, l.UpstreamSkipTLSVerify)
	if err != nil {
		return nil, fmt.Errorf("server %s: %w", l.ID, err)
	}
	if cfg.Galah != nil {
		svr.SetGalahOptions(cfg.Galah.CacheEnabled, cfg.Galah.EventLogging)
	}
	eng := localEng
	if eng == nil {
		eng = globalEng
	}
	if eng == nil {
		cblog.Warnf("no rules engine loaded for listener %s; traffic will not be filtered", l.ID)
	}
	rt.logPaths[l.ID] = l.AccessLog
	return svr, nil
}

func (rt *runtimeState) Start() {
	for _, s := range rt.servers {
		srv := s
		rt.wg.Add(1)
		go func() {
			defer rt.wg.Done()
			cblog.Infof("listening on %s (%s)", srv.ListenAddr, srv.ID)
			if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				cblog.Errorf("server %s: %v", srv.ID, err)
			}
		}()
	}
}

func startRuntime(cfg *config.Config, pf parsedFlags, hub *sse.Hub, sseSrv **sse.Server, adminSrv **admin.Server) (*runtimeState, error) {
	rt, err := newRuntime(cfg, pf, hub, sseSrv, adminSrv)
	if err != nil {
		return nil, err
	}
	rt.Start()
	return rt, nil
}

func reloadRuntime(old *runtimeState, cfg *config.Config, pf parsedFlags, hub *sse.Hub, sseSrv **sse.Server, adminSrv **admin.Server) (*runtimeState, error) {
	newRT, err := newRuntime(cfg, pf, hub, sseSrv, adminSrv)
	if err != nil {
		return old, err
	}
	newRT.Start()
	if old != nil {
		old.shutdown(pf)
	}
	return newRT, nil
}

func (rt *runtimeState) shutdown(pf parsedFlags) {
	if rt == nil {
		return
	}
	if !pf.EchoMode {
		rt.loader.CancelWatchers()
		if rt.watchCancel != nil {
			rt.watchCancel()
		}
	}

	for _, s := range rt.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.Shutdown(ctx); err != nil {
			cblog.Errorf("shutdown %s: %v", s.ID, err)
		}
		cancel()
	}

	if rt.adminSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := rt.adminSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			cblog.Errorf("shutdown admin: %v", err)
		}
		cancel()
	}

	rt.wg.Wait()

	if !pf.EchoMode {
		for p, lr := range rt.loggers {
			if err := lr.l.Close(); err != nil {
				cblog.Errorf("close logger %s: %v", p, err)
			}
		}
		if rt.galahSvc != nil {
			if err := rt.galahSvc.Close(); err != nil {
				cblog.Errorf("close galah: %v", err)
			}
		}
	}
}
