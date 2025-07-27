package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/loader"
)

// TestServeQuickModeMissingRuleFile ensures SynthesiseFromFlags errors when
// --listen is provided without --rule-file.
func TestServeQuickModeMissingRuleFile(t *testing.T) {
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "listen"},
			&cli.StringFlag{Name: "rule-file"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			_, err := loader.SynthesiseFromFlags(c)
			return err
		},
	}
	err := cmd.Run(context.Background(), []string{"serve", "--listen", "127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "--rule-file") {
		t.Fatalf("expected rule-file error, got %v", err)
	}
}

// TestServeQuickModeMultiListen verifies multiple --listen values synthesize
// corresponding listeners.
func TestServeQuickModeMultiListen(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	logPath := filepath.Join(dir, "log.jsonl")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	var cfg config.Config
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "listen"},
			&cli.StringFlag{Name: "rule-file"},
			&cli.StringFlag{Name: "access-log"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			var err error
			cfg, err = loader.SynthesiseFromFlags(c)
			return err
		},
	}
	args := []string{"serve", "--listen", "127.0.0.1:1", "--listen", "127.0.0.1:2", "--rule-file", rule, "--access-log", logPath}
	if err := cmd.Run(context.Background(), args); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(cfg.Listeners) != 2 || cfg.Listeners[0].Bind != "127.0.0.1:1" || cfg.Listeners[1].Bind != "127.0.0.1:2" {
		t.Fatalf("unexpected listeners: %+v", cfg.Listeners)
	}
}

// TestServeConfigOverrides checks that command line flags override values from a config file.
func TestServeConfigOverrides(t *testing.T) {
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfgPath := filepath.Join(dir, "finch.hcl")
	cfgContent := fmt.Sprintf(`defaults {
  rule_file = "%s"
  access_log = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "http://config"
}
`, rule, filepath.Join(dir, "cfg.log"))
	if err := os.WriteFile(filepath.Join(dir, "cfg.log"), nil, 0o644); err != nil {
		t.Fatalf("write cfg log: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	logPath := filepath.Join(dir, "override.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("write override log: %v", err)
	}
	cfg, err := runServe([]string{"--config", cfgPath, "--upstream", "http://flag", "--access-log", logPath})
	if err != nil {
		t.Fatalf("runServe: %v", err)
	}
	if cfg.Listeners[0].Upstream != "http://config" {
		t.Fatalf("upstream unexpectedly overridden: %s", cfg.Listeners[0].Upstream)
	}
	if !strings.HasSuffix(cfg.Listeners[0].AccessLog, "override.log") {
		t.Fatalf("access log not overridden: %s", cfg.Listeners[0].AccessLog)
	}
}

// TestEchoAction runs echoAction and ensures it exits on interrupt.
func TestEchoAction(t *testing.T) {
	if os.Getenv("ECHO_HELPER") == "1" {
		addr := freePort(t)
		cmd := &cli.Command{
			Flags:  []cli.Flag{&cli.StringSliceFlag{Name: "listen"}},
			Action: echoAction,
		}
		go func() {
			time.Sleep(100 * time.Millisecond)
			p, _ := os.FindProcess(os.Getpid())
			_ = p.Signal(os.Interrupt)
		}()
		if err := cmd.Run(context.Background(), []string{"echo", "--listen", addr}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	c := exec.Command(exe, "-test.run=TestEchoAction")
	c.Env = append(os.Environ(), "ECHO_HELPER=1")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("helper err: %v, out=%s", err, out)
	}
}

// TestValidateActionErrors ensures validateAction fails when flags are misused.
func TestValidateActionErrors(t *testing.T) {
	if _, err := runValidate(nil); err == nil {
		t.Fatalf("expected error when no flags")
	}
	dir := t.TempDir()
	rule := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfgPath := filepath.Join(dir, "finch.hcl")
	if err := os.WriteFile(cfgPath, []byte("listener \"a\" { bind = \"127.0.0.1:1\" rule_file = \""+rule+"\" upstream = \"http://example\" }\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := runValidate([]string{"--config", cfgPath, "--rules", rule}); err == nil {
		t.Fatalf("expected error with both flags")
	}
}
