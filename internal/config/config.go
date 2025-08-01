package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/hashicorp/hcl/v2/hclsimple"

	"github.com/0x4D31/finch/internal/rules"
)

const (
	DefaultAdminAddr = "127.0.0.1:9035"
	DefaultSSEAddr   = "127.0.0.1:9036"
)

// Config represents the top-level configuration file.
type Config struct {
	Admin     *AdminConfig     `hcl:"admin,block" json:"admin,omitempty"`
	SSE       *SSEConfig       `hcl:"sse,block" json:"sse,omitempty"`
	Suricata  *SuricataConfig  `hcl:"suricata,block" json:"suricata,omitempty"`
	Defaults  *Defaults        `hcl:"defaults,block" json:"defaults,omitempty"`
	Galah     *GalahConfig     `hcl:"galah,block" json:"galah,omitempty"`
	Listeners []ListenerConfig `hcl:"listener,block" json:"listeners,omitempty"`
}

type AdminConfig struct {
	Enabled bool   `hcl:"enabled,optional"`
	Addr    string `hcl:"addr,optional"`
	Token   string `hcl:"token,optional" json:"token,omitempty"`
}

type SSEConfig struct {
	Enabled bool   `hcl:"enabled,optional"`
	Addr    string `hcl:"addr,optional"`
}

type SuricataConfig struct {
	Enabled  bool   `hcl:"enabled,optional"`
	RulesDir string `hcl:"rules_dir,optional"`
}

// Defaults holds optional values inherited by listeners.
type Defaults struct {
	RuleFile              string `hcl:"rule_file,optional" json:"rule_file,omitempty"`
	AccessLog             string `hcl:"access_log,optional" json:"access_log,omitempty"`
	DefaultAction         string `hcl:"default_action,optional" json:"default_action,omitempty"`
	ProxyCacheSize        int    `hcl:"proxy_cache_size,optional" json:"proxy_cache_size,omitempty"`
	UpstreamCAFile        string `hcl:"upstream_ca_file,optional" json:"upstream_ca_file,omitempty"`
	UpstreamSkipTLSVerify bool   `hcl:"upstream_skip_tls_verify,optional" json:"upstream_skip_tls_verify,omitempty"`
}

// ListenerConfig defines a single listener instance.
type ListenerConfig struct {
	ID                    string     `hcl:",label" json:"id"`
	Bind                  string     `hcl:"bind" json:"bind"`
	Upstream              string     `hcl:"upstream" json:"upstream"`
	RuleFile              string     `hcl:"rule_file,optional" json:"rule_file,omitempty"`
	AccessLog             string     `hcl:"access_log,optional" json:"access_log,omitempty"`
	TLS                   *TLSConfig `hcl:"tls,block" json:"tls,omitempty"`
	UpstreamCAFile        string     `hcl:"upstream_ca_file,optional" json:"upstream_ca_file,omitempty"`
	UpstreamSkipTLSVerify bool       `hcl:"upstream_skip_tls_verify,optional" json:"upstream_skip_tls_verify,omitempty"`
}

// TLSConfig holds optional TLS certificate paths.
type TLSConfig struct {
	Cert string `hcl:"cert,optional" json:"cert,omitempty"`
	Key  string `hcl:"key,optional" json:"key,omitempty"`
}

// GalahConfig holds configuration for the Galah deception service.
type GalahConfig struct {
	Provider      string  `hcl:"provider,optional" json:"provider,omitempty"`
	Model         string  `hcl:"model,optional" json:"model,omitempty"`
	Temperature   float64 `hcl:"temperature,optional" json:"temperature,omitempty"`
	APIKey        string  `hcl:"api_key,optional" json:"api_key,omitempty"`
	ConfigFile    string  `hcl:"config_file,optional" json:"config_file,omitempty"`
	CacheFile     string  `hcl:"cache_file,optional" json:"cache_file,omitempty"`
	CacheDuration int     `hcl:"cache_duration,optional" json:"cache_duration,omitempty"`
	CacheEnabled  bool    `hcl:"cache_enabled,optional" json:"cache_enabled,omitempty"`
	EventLogFile  string  `hcl:"event_log_file,optional" json:"event_log_file,omitempty"`
	EventLogging  bool    `hcl:"event_logging,optional" json:"event_logging,omitempty"`
	LogLevel      string  `hcl:"log_level,optional" json:"log_level,omitempty"`
}

// RuleSetInfo describes a rule file and the listeners referencing it.
type RuleSetInfo struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Listeners []string `json:"listeners"`
}

// EnumerateRuleSets returns info for all rule files referenced by cfg.
// The returned slice is sorted by path and stable across invocations.
func EnumerateRuleSets(cfg *Config) []RuleSetInfo {
	if cfg == nil {
		return nil
	}
	refs := make(map[string][]string)
	if cfg.Defaults != nil && cfg.Defaults.RuleFile != "" {
		refs[cfg.Defaults.RuleFile] = append(refs[cfg.Defaults.RuleFile], "defaults")
	}
	for _, l := range cfg.Listeners {
		rf := l.RuleFile
		if rf == "" && cfg.Defaults != nil {
			rf = cfg.Defaults.RuleFile
		}
		if rf != "" {
			refs[rf] = append(refs[rf], l.ID)
		}
	}
	paths := make([]string, 0, len(refs))
	for p := range refs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]RuleSetInfo, 0, len(paths))
	for i, p := range paths {
		id := fmt.Sprintf("r%d", i+1)
		out = append(out, RuleSetInfo{ID: id, Path: p, Listeners: refs[p]})
	}
	return out
}

// ResolvePaths updates all path fields in cfg to be absolute by joining them
// with baseDir when they are not already absolute. baseDir is resolved to its
// absolute, symlink-free form before joining, mirroring the behavior of Read.
func ResolvePaths(cfg *Config, baseDir string) error {
	if cfg == nil {
		return nil
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	baseDir = abs

	if cfg.Defaults != nil {
		if cfg.Defaults.RuleFile != "" && !filepath.IsAbs(cfg.Defaults.RuleFile) {
			cfg.Defaults.RuleFile = filepath.Join(baseDir, cfg.Defaults.RuleFile)
		}
		if cfg.Defaults.AccessLog != "" && !filepath.IsAbs(cfg.Defaults.AccessLog) {
			cfg.Defaults.AccessLog = filepath.Join(baseDir, cfg.Defaults.AccessLog)
		}
		if cfg.Defaults.UpstreamCAFile != "" && !filepath.IsAbs(cfg.Defaults.UpstreamCAFile) {
			cfg.Defaults.UpstreamCAFile = filepath.Join(baseDir, cfg.Defaults.UpstreamCAFile)
		}
	}
	if cfg.Galah != nil {
		if cfg.Galah.ConfigFile != "" && !filepath.IsAbs(cfg.Galah.ConfigFile) {
			cfg.Galah.ConfigFile = filepath.Join(baseDir, cfg.Galah.ConfigFile)
		}
		if cfg.Galah.CacheFile != "" && !filepath.IsAbs(cfg.Galah.CacheFile) {
			cfg.Galah.CacheFile = filepath.Join(baseDir, cfg.Galah.CacheFile)
		}
	}
	if cfg.Suricata != nil {
		if cfg.Suricata.RulesDir != "" && !filepath.IsAbs(cfg.Suricata.RulesDir) {
			cfg.Suricata.RulesDir = filepath.Join(baseDir, cfg.Suricata.RulesDir)
		}
	}
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if l.RuleFile != "" && !filepath.IsAbs(l.RuleFile) {
			l.RuleFile = filepath.Join(baseDir, l.RuleFile)
		}
		if l.TLS != nil {
			if l.TLS.Cert != "" && !filepath.IsAbs(l.TLS.Cert) {
				l.TLS.Cert = filepath.Join(baseDir, l.TLS.Cert)
			}
			if l.TLS.Key != "" && !filepath.IsAbs(l.TLS.Key) {
				l.TLS.Key = filepath.Join(baseDir, l.TLS.Key)
			}
		}
		if l.AccessLog != "" && !filepath.IsAbs(l.AccessLog) {
			l.AccessLog = filepath.Join(baseDir, l.AccessLog)
		}
		if l.UpstreamCAFile != "" && !filepath.IsAbs(l.UpstreamCAFile) {
			l.UpstreamCAFile = filepath.Join(baseDir, l.UpstreamCAFile)
		}
	}
	return nil
}

// Read parses the HCL configuration from path without validating mandatory
// fields. Relative paths are resolved against the configuration file's
// directory.
func Read(path string) (Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve path: %w", err)
	}
	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return Config{}, fmt.Errorf("resolve path: %w", err)
	}

	var cfg Config
	if err := hclsimple.DecodeFile(absPath, nil, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if err := ResolvePaths(&cfg, filepath.Dir(absPath)); err != nil {
		return Config{}, err
	}
	if cfg.Admin != nil && cfg.Admin.Enabled && cfg.Admin.Addr == "" {
		cfg.Admin.Addr = DefaultAdminAddr
	}
	if cfg.SSE != nil && cfg.SSE.Enabled && cfg.SSE.Addr == "" {
		cfg.SSE.Addr = DefaultSSEAddr
	}
	return cfg, nil
}

// Validate checks that cfg contains all mandatory fields and no duplicate
// listener IDs.
func Validate(cfg *Config) error {
	if len(cfg.Listeners) == 0 {
		return fmt.Errorf("at least one listener required")
	}
	if cfg.Admin != nil && cfg.Admin.Enabled {
		if cfg.Admin.Addr == "" {
			return fmt.Errorf("admin.addr required when admin.enabled is true")
		}
		if _, port, err := net.SplitHostPort(cfg.Admin.Addr); err != nil || port == "" {
			return fmt.Errorf("admin.addr invalid")
		} else {
			p, err := strconv.Atoi(port)
			if err != nil || p <= 0 || p > 65535 {
				return fmt.Errorf("admin.addr invalid")
			}
		}
	}
	if cfg.SSE != nil && cfg.SSE.Enabled {
		if cfg.SSE.Addr == "" {
			return fmt.Errorf("sse.addr required when sse.enabled is true")
		}
		if _, port, err := net.SplitHostPort(cfg.SSE.Addr); err != nil || port == "" {
			return fmt.Errorf("sse.addr invalid")
		} else {
			p, err := strconv.Atoi(port)
			if err != nil || p <= 0 || p > 65535 {
				return fmt.Errorf("sse.addr invalid")
			}
		}
	}
	if cfg.Defaults != nil {
		if cfg.Defaults.ProxyCacheSize < 0 {
			return fmt.Errorf("defaults.proxy_cache_size must be >= 0")
		}
		if cfg.Defaults.DefaultAction != "" {
			a := cfg.Defaults.DefaultAction
			if a != "allow" && a != "deny" {
				return fmt.Errorf("defaults.default_action must be allow or deny")
			}
		}
		if cfg.Suricata != nil && cfg.Suricata.Enabled {
			if cfg.Suricata.RulesDir == "" {
				return fmt.Errorf("suricata.rules_dir required when suricata.enabled is true")
			}
			info, err := os.Stat(cfg.Suricata.RulesDir)
			if err != nil {
				return fmt.Errorf("suricata.rules_dir: %w (paths are resolved relative to the configuration file)", err)
			}
			if !info.IsDir() {
				return fmt.Errorf("suricata.rules_dir must be a directory")
			}
		}
		if cfg.Defaults.UpstreamCAFile != "" {
			if _, err := os.Stat(cfg.Defaults.UpstreamCAFile); err != nil {
				return fmt.Errorf("defaults.upstream_ca_file: %w", err)
			}
		}
	}

	ids := make(map[string]struct{})
	binds := make(map[string]struct{})
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if l.ID == "" {
			return fmt.Errorf("listener index %d: missing id", i)
		}
		if _, ok := ids[l.ID]; ok {
			return fmt.Errorf("duplicate listener id %s", l.ID)
		}
		ids[l.ID] = struct{}{}
		if l.Bind == "" {
			return fmt.Errorf("listener %s: missing bind address", l.ID)
		}
		_, port, err := net.SplitHostPort(l.Bind)
		if err != nil || port == "" {
			return fmt.Errorf("listener %s: invalid bind address", l.ID)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return fmt.Errorf("listener %s: invalid bind address", l.ID)
		}
		if _, ok := binds[l.Bind]; ok {
			return fmt.Errorf("duplicate bind address %s", l.Bind)
		}
		binds[l.Bind] = struct{}{}
		if l.Upstream == "" {
			return fmt.Errorf("listener %s: missing upstream address", l.ID)
		}
		u, err := url.Parse(l.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("listener %s: invalid upstream address", l.ID)
		}
		if l.RuleFile == "" && (cfg.Defaults == nil || cfg.Defaults.RuleFile == "") {
			return fmt.Errorf("listener %s: missing rule_file path and no defaults.rule_file", l.ID)
		}
		if l.TLS != nil {
			if (l.TLS.Cert == "" && l.TLS.Key != "") || (l.TLS.Cert != "" && l.TLS.Key == "") {
				return fmt.Errorf("listener %s: tls.cert and tls.key must both be set", l.ID)
			}
			if l.TLS.Cert != "" && l.TLS.Key != "" {
				if _, err := os.Stat(l.TLS.Cert); err != nil {
					return fmt.Errorf("listener %s: tls.cert: %w", l.ID, err)
				}
				if _, err := os.Stat(l.TLS.Key); err != nil {
					return fmt.Errorf("listener %s: tls.key: %w", l.ID, err)
				}
			}
		}
		if l.UpstreamCAFile != "" {
			if _, err := os.Stat(l.UpstreamCAFile); err != nil {
				return fmt.Errorf("listener %s: upstream_ca_file: %w", l.ID, err)
			}
		}
	}

	// Check if any rule uses Galah deception mode and validate Galah settings.
	galahUsed := false
	ruleFiles := make(map[string]struct{})
	if cfg.Defaults != nil && cfg.Defaults.RuleFile != "" {
		ruleFiles[cfg.Defaults.RuleFile] = struct{}{}
	}
	for _, l := range cfg.Listeners {
		if l.RuleFile != "" {
			ruleFiles[l.RuleFile] = struct{}{}
		}
	}
	for path := range ruleFiles {
		rs, err := rules.LoadHCL(path)
		if err != nil {
			return fmt.Errorf("load rules %s: %w", path, err)
		}
		for _, r := range rs.Rules {
			if r.Action == rules.ActionDeceive && (r.DeceptionMode == "" || r.DeceptionMode == "galah") {
				galahUsed = true
				break
			}
		}
		if galahUsed {
			break
		}
	}
	if galahUsed {
		if cfg.Galah == nil {
			return fmt.Errorf("galah block required when rules use deception mode galah")
		}
		if cfg.Galah.Provider == "" || cfg.Galah.Model == "" || cfg.Galah.APIKey == "" {
			return fmt.Errorf("galah.provider, galah.model and galah.api_key required when using deception mode galah")
		}
	}
	return nil
}

// Load reads and validates the HCL configuration from path.
func Load(path string) (Config, error) {
	cfg, err := Read(path)
	if err != nil {
		return Config{}, err
	}
	if err := Validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ReadJSON parses the JSON configuration from path without validating mandatory
// fields. Relative paths are resolved against the configuration file's
// directory.
func ReadJSON(path string) (Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve path: %w", err)
	}
	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return Config{}, fmt.Errorf("resolve path: %w", err)
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	if err := ResolvePaths(&cfg, filepath.Dir(absPath)); err != nil {
		return Config{}, err
	}
	if cfg.Admin != nil && cfg.Admin.Enabled && cfg.Admin.Addr == "" {
		cfg.Admin.Addr = DefaultAdminAddr
	}
	if cfg.SSE != nil && cfg.SSE.Enabled && cfg.SSE.Addr == "" {
		cfg.SSE.Addr = DefaultSSEAddr
	}
	return cfg, nil
}

// LoadJSON reads and validates the JSON configuration from path.
func LoadJSON(path string) (Config, error) {
	cfg, err := ReadJSON(path)
	if err != nil {
		return Config{}, err
	}
	if err := Validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// WriteJSON writes cfg encoded as JSON to path.
func WriteJSON(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}
