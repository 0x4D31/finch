package loader

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/proxy"
	"github.com/0x4D31/finch/internal/rules"
)

// Built-in defaults used when synthesising configs.
const (
	DefaultUpstream       = "http://localhost:8080"
	DefaultRuleFile       = "configs/default.rules.hcl"
	DefaultAccessLog      = "events.jsonl"
	DefaultListenBind     = "0.0.0.0:8443"
	DefaultProxyCacheSize = proxy.DefaultProxyCacheSize
)

// Overrides contains CLI override values applied when a main config is loaded.
// Zero-value fields are ignored unless the corresponding Set flag is true.
type Overrides struct {
	Upstream              string
	UpstreamSet           bool
	RuleFile              string
	RuleFileSet           bool
	AccessLog             string
	AccessLogSet          bool
	ProxyCacheSize        int
	ProxyCacheSizeSet     bool
	DefaultAction         string
	DefaultActionSet      bool
	UpstreamCAFile        string
	UpstreamCAFileSet     bool
	UpstreamSkipTLSVerify bool
	UpstreamSkipSet       bool
	AdminEnabled          bool
	AdminEnabledSet       bool
	AdminAddr             string
	AdminAddrSet          bool
	AdminToken            string
	AdminTokenSet         bool
	SSEEnabled            bool
	SSEEnabledSet         bool
	SSEAddr               string
	SSEAddrSet            bool
}

// AbsFromCWD resolves p against the current working directory when not
// already absolute and returns a canonical absolute path.
func AbsFromCWD(p string) (string, error) {
	if p == "" || filepath.IsAbs(p) {
		return p, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	abs := filepath.Join(wd, p)
	abs, err = filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(abs)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// LoadMain reads and validates the HCL configuration at path.
func LoadMain(path string) (config.Config, error) {
	return config.Load(path)
}

// LoadRules loads a rule set from path after resolving it to an absolute path.
func LoadRules(path string) (*rules.RuleSet, error) {
	p, err := AbsFromCWD(path)
	if err != nil {
		return nil, fmt.Errorf("resolve rules path: %w", err)
	}
	return rules.LoadHCL(p)
}

// Merge applies CLI overrides to cfg according to precedence rules.
func Merge(cfg *config.Config, ov Overrides) error {
	if cfg.Defaults == nil {
		cfg.Defaults = &config.Defaults{}
	}
	if ov.RuleFileSet {
		p, err := AbsFromCWD(ov.RuleFile)
		if err != nil {
			return err
		}
		cfg.Defaults.RuleFile = p
	}
	if ov.AccessLogSet {
		p, err := AbsFromCWD(ov.AccessLog)
		if err != nil {
			return err
		}
		cfg.Defaults.AccessLog = p
	}
	if ov.DefaultActionSet {
		cfg.Defaults.DefaultAction = ov.DefaultAction
	}
	if ov.ProxyCacheSizeSet {
		cfg.Defaults.ProxyCacheSize = ov.ProxyCacheSize
	}
	if ov.UpstreamCAFileSet {
		p, err := AbsFromCWD(ov.UpstreamCAFile)
		if err != nil {
			return err
		}
		cfg.Defaults.UpstreamCAFile = p
	}
	if ov.UpstreamSkipSet {
		skip := ov.UpstreamSkipTLSVerify
		cfg.Defaults.UpstreamSkipTLSVerify = &skip
	}

	if cfg.Admin == nil {
		cfg.Admin = &config.AdminConfig{}
	}
	if ov.AdminEnabledSet {
		cfg.Admin.Enabled = ov.AdminEnabled
		if !cfg.Admin.Enabled {
			cfg.Admin.Addr = ""
		}
	}
	if ov.AdminAddrSet {
		cfg.Admin.Addr = ov.AdminAddr
	}
	if ov.AdminTokenSet {
		cfg.Admin.Token = ov.AdminToken
	}

	if cfg.SSE == nil {
		cfg.SSE = &config.SSEConfig{}
	}
	if ov.SSEEnabledSet {
		cfg.SSE.Enabled = ov.SSEEnabled
		if !cfg.SSE.Enabled {
			cfg.SSE.Addr = ""
		}
	}
	if ov.SSEAddrSet {
		cfg.SSE.Addr = ov.SSEAddr
	}

	// Apply defaults to listeners
	for i := range cfg.Listeners {
		l := &cfg.Listeners[i]
		if l.RuleFile == "" {
			l.RuleFile = cfg.Defaults.RuleFile
		}
		if l.AccessLog == "" {
			l.AccessLog = cfg.Defaults.AccessLog
		}
		if l.UpstreamCAFile == "" {
			l.UpstreamCAFile = cfg.Defaults.UpstreamCAFile
		}
		if l.UpstreamSkipTLSVerify == nil {
			l.UpstreamSkipTLSVerify = cfg.Defaults.UpstreamSkipTLSVerify
		}
		if l.Upstream == "" {
			if ov.UpstreamSet {
				l.Upstream = ov.Upstream
			} else {
				l.Upstream = DefaultUpstream
			}
		}
	}
	return config.Validate(cfg)
}

// SynthesiseFromFlags builds a config for quick mode from a cli.Command.
func SynthesiseFromFlags(cmd *cli.Command) (config.Config, error) {
	listens := cmd.StringSlice("listen")
	if len(listens) == 0 {
		listens = []string{DefaultListenBind}
	}
	ruleFile := cmd.String("rules")
	if ruleFile == "" {
		return config.Config{}, fmt.Errorf("--rules required")
	}
	rf, err := AbsFromCWD(ruleFile)
	if err != nil {
		return config.Config{}, err
	}
	accessLog := cmd.String("access-log")
	if accessLog == "" {
		accessLog = DefaultAccessLog
	}
	al, err := AbsFromCWD(accessLog)
	if err != nil {
		return config.Config{}, err
	}
	up := cmd.String("upstream")
	if up == "" {
		up = DefaultUpstream
	}
	caFile, err := AbsFromCWD(cmd.String("upstream-ca-file"))
	if err != nil {
		return config.Config{}, err
	}
	cert, err := AbsFromCWD(cmd.String("cert"))
	if err != nil {
		return config.Config{}, err
	}
	key, err := AbsFromCWD(cmd.String("key"))
	if err != nil {
		return config.Config{}, err
	}
	if (cert == "" && key != "") || (cert != "" && key == "") {
		return config.Config{}, fmt.Errorf("cert and key must both be set")
	}
	skip := cmd.Bool("upstream-skip-tls-verify")
	skipPtr := skip

	adminEnabled := cmd.Bool("enable-admin")
	adminAddr := cmd.String("admin-addr")
	if adminEnabled && adminAddr == "" {
		adminAddr = config.DefaultAdminAddr
	}

	sseEnabled := cmd.Bool("enable-sse")
	sseAddr := cmd.String("sse-addr")
	if sseEnabled && sseAddr == "" {
		sseAddr = config.DefaultSSEAddr
	}

	cfg := config.Config{
		Defaults: &config.Defaults{
			RuleFile:              rf,
			AccessLog:             al,
			UpstreamCAFile:        caFile,
			UpstreamSkipTLSVerify: &skipPtr,
			ProxyCacheSize:        DefaultProxyCacheSize,
		},
		Admin: &config.AdminConfig{
			Enabled: adminEnabled,
			Addr:    adminAddr,
			Token:   cmd.String("admin-token"),
		},
		SSE: &config.SSEConfig{
			Enabled: sseEnabled,
			Addr:    sseAddr,
		},
	}
	cfg.Listeners = make([]config.ListenerConfig, len(listens))
	for i, addr := range listens {
		skipListener := skip
		l := config.ListenerConfig{
			ID:                    fmt.Sprintf("listener%d", i+1),
			Bind:                  addr,
			Upstream:              up,
			RuleFile:              rf,
			AccessLog:             al,
			UpstreamCAFile:        caFile,
			UpstreamSkipTLSVerify: &skipListener,
		}
		if cert != "" {
			l.TLS = &config.TLSConfig{Cert: cert, Key: key}
		}
		cfg.Listeners[i] = l
	}
	return cfg, config.Validate(&cfg)
}
