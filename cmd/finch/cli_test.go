package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/loader"
)

// runServe parses args using the serve flags and returns the resulting config
// after applying overrides or synthesis. It mirrors serveAction without starting
// any servers.
func runServe(args []string) (config.Config, error) {
	var cfg config.Config
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Sources: cli.EnvVars("FINCH_CONFIG")},
			&cli.StringSliceFlag{Name: "listen", Aliases: []string{"l"}, Sources: cli.EnvVars("FINCH_LISTEN")},
			&cli.StringFlag{Name: "rules", Aliases: []string{"r"}, Sources: cli.EnvVars("FINCH_RULE_FILE")},
			&cli.StringFlag{Name: "upstream", Aliases: []string{"u"}, Value: loader.DefaultUpstream, Sources: cli.EnvVars("FINCH_UPSTREAM")},
			&cli.StringFlag{Name: "access-log", Aliases: []string{"o"}, Value: loader.DefaultAccessLog, Sources: cli.EnvVars("FINCH_ACCESS_LOG")},
			&cli.StringFlag{Name: "cert", Aliases: []string{"C"}, Sources: cli.EnvVars("FINCH_CERT")},
			&cli.StringFlag{Name: "key", Aliases: []string{"K"}, Sources: cli.EnvVars("FINCH_KEY")},
			&cli.StringFlag{Name: "upstream-ca-file", Sources: cli.EnvVars("FINCH_UPSTREAM_CA_FILE")},
			&cli.BoolFlag{Name: "upstream-skip-tls-verify", Sources: cli.EnvVars("FINCH_UPSTREAM_SKIP_TLS_VERIFY")},
			&cli.BoolFlag{Name: "enable-admin", Value: true, Sources: cli.EnvVars("FINCH_ENABLE_ADMIN")},
			&cli.StringFlag{Name: "admin-addr", DefaultText: "127.0.0.1:9035", Sources: cli.EnvVars("FINCH_ADMIN_ADDR")},
			&cli.StringFlag{Name: "admin-token", Sources: cli.EnvVars("FINCH_ADMIN_TOKEN")},
			&cli.BoolFlag{Name: "enable-sse", Value: true, Sources: cli.EnvVars("FINCH_ENABLE_SSE")},
			&cli.StringFlag{Name: "sse-addr", DefaultText: "127.0.0.1:9036", Sources: cli.EnvVars("FINCH_SSE_ADDR")},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			listenSet := c.IsSet("listen")
			configSet := c.IsSet("config")
			if listenSet && configSet {
				return fmt.Errorf("--config and --listen are mutually exclusive")
			}
			var err error
			if configSet || !listenSet {
				cfgPath := c.String("config")
				if cfgPath == "" {
					return fmt.Errorf("configuration file required")
				}
				cfg, err = loader.LoadMain(cfgPath)
				if err != nil {
					return err
				}
				ov := loader.Overrides{}
				if c.IsSet("rules") {
					ov.RuleFile = c.String("rules")
					ov.RuleFileSet = true
				}
				if c.IsSet("access-log") {
					ov.AccessLog = c.String("access-log")
					ov.AccessLogSet = true
				}
				if c.IsSet("upstream") {
					ov.Upstream = c.String("upstream")
					ov.UpstreamSet = true
				}
				if c.IsSet("upstream-ca-file") {
					ov.UpstreamCAFile = c.String("upstream-ca-file")
					ov.UpstreamCAFileSet = true
				}
				if c.IsSet("upstream-skip-tls-verify") {
					ov.UpstreamSkipTLSVerify = c.Bool("upstream-skip-tls-verify")
					ov.UpstreamSkipSet = true
				}
				if c.IsSet("enable-admin") {
					ov.AdminEnabled = c.Bool("enable-admin")
					ov.AdminEnabledSet = true
				}
				if c.IsSet("admin-addr") {
					ov.AdminAddr = c.String("admin-addr")
					ov.AdminAddrSet = true
				}
				if c.IsSet("admin-token") {
					ov.AdminToken = c.String("admin-token")
					ov.AdminTokenSet = true
				}
				if c.IsSet("enable-sse") {
					ov.SSEEnabled = c.Bool("enable-sse")
					ov.SSEEnabledSet = true
				}
				if c.IsSet("sse-addr") {
					ov.SSEAddr = c.String("sse-addr")
					ov.SSEAddrSet = true
				}
				return loader.Merge(&cfg, ov)
			}
			cfg, err = loader.SynthesiseFromFlags(c)
			return err
		},
	}
	err := cmd.Run(context.Background(), append([]string{"serve"}, args...))
	return cfg, err
}

func TestServeFlagEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfgPath := filepath.Join(dir, "finch.hcl")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`defaults {
  rule_file = "%s"
  access_log = "config.log"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "http://config"
}
`, rule)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := os.Setenv("FINCH_ACCESS_LOG", filepath.Join(dir, "env.log")); err != nil {
		t.Fatalf("setenv: %v", err)
	}
	defer func() { _ = os.Unsetenv("FINCH_ACCESS_LOG") }()

	cfg, err := runServe([]string{"--config", cfgPath})
	if err != nil {
		t.Fatalf("runServe env: %v", err)
	}
	if !strings.HasSuffix(cfg.Listeners[0].AccessLog, "env.log") {
		t.Fatalf("env access log not applied: %s", cfg.Listeners[0].AccessLog)
	}

	flagLog := filepath.Join(dir, "flag.log")
	cfg, err = runServe([]string{"--config", cfgPath, "--access-log", flagLog})
	if err != nil {
		t.Fatalf("runServe flag: %v", err)
	}
	if !strings.HasSuffix(cfg.Listeners[0].AccessLog, "flag.log") {
		t.Fatalf("flag access log not applied: %s", cfg.Listeners[0].AccessLog)
	}
}

func TestServeMutualExclusion(t *testing.T) {
	_, err := runServe([]string{"--config", "a.hcl", "--listen", ":1", "--rules", "r.hcl"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got %v", err)
	}
}

func TestServeQuickMode(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	logPath := filepath.Join(dir, "log.jsonl")
	cfg, err := runServe([]string{"--listen", "127.0.0.1:1", "--rules", rule, "--upstream", "http://example", "--access-log", logPath, "--enable-admin=false", "--enable-sse=false"})
	if err != nil {
		t.Fatalf("runServe quick: %v", err)
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Bind != "127.0.0.1:1" {
		t.Fatalf("listener not synthesised: %+v", cfg.Listeners)
	}
	if cfg.Defaults.RuleFile != cfg.Listeners[0].RuleFile {
		t.Fatalf("rule file not applied to defaults")
	}
}

func runValidate(args []string) (string, error) {
	buf := new(bytes.Buffer)
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Sources: cli.EnvVars("FINCH_CONFIG")},
			&cli.StringFlag{Name: "rules", Sources: cli.EnvVars("FINCH_RULE_FILE")},
		},
		Action: validateAction,
	}
	cmd.ErrWriter = buf
	err := cmd.Run(context.Background(), append([]string{"validate"}, args...))
	return buf.String(), err
}

func TestValidateCommand(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfgPath := filepath.Join(dir, "finch.hcl")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`defaults {
  rule_file = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "http://example"
}
`, rule)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, err := runValidate([]string{"--config", cfgPath})
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if !strings.Contains(out, "config valid") {
		t.Fatalf("unexpected output %q", out)
	}

	out, err = runValidate([]string{"--rules", rule})
	if err != nil {
		t.Fatalf("validate rules: %v", err)
	}
	if !strings.Contains(out, "rules valid") {
		t.Fatalf("unexpected output %q", out)
	}

	badCfg := filepath.Join(dir, "bad.hcl")
	if err := os.WriteFile(badCfg, []byte(`listener "a" { bind = "127.0.0.1:1" }`), 0o644); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	if _, err := runValidate([]string{"--config", badCfg}); err == nil {
		t.Fatal("expected validation error")
	}
}
