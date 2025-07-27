package loader

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/urfave/cli/v3"

	"github.com/0x4D31/finch/internal/config"
)

func TestMergeOverrides(t *testing.T) {
	tmp := t.TempDir()
	rf := tmp + "/r.rules"
	if err := os.WriteFile(rf, nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := config.Config{
		Defaults:  &config.Defaults{},
		Admin:     &config.AdminConfig{Enabled: false},
		SSE:       &config.SSEConfig{Enabled: false},
		Listeners: []config.ListenerConfig{{ID: "a", Bind: "0.0.0.0:1"}},
	}
	ov := Overrides{
		RuleFile:        rf,
		RuleFileSet:     true,
		Upstream:        "https://up.example",
		UpstreamSet:     true,
		AdminEnabled:    true,
		AdminEnabledSet: true,
		AdminAddr:       ":9000",
		AdminAddrSet:    true,
		SSEEnabled:      true,
		SSEEnabledSet:   true,
		SSEAddr:         ":9001",
		SSEAddrSet:      true,
	}
	if err := Merge(&cfg, ov); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if cfg.Defaults.RuleFile == "" || cfg.Listeners[0].Upstream != "https://up.example" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if !cfg.Admin.Enabled || !cfg.SSE.Enabled {
		t.Fatalf("admin/sse not enabled")
	}
}
func TestSynthesiseFromFlags(t *testing.T) {
	tmp := t.TempDir()
	rule := filepath.Join(tmp, "rules.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cert := filepath.Join(tmp, "cert.pem")
	key := filepath.Join(tmp, "key.pem")
	ca := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(cert, nil, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(key, nil, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(ca, nil, 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	access := filepath.Join(tmp, "acc.log")

	var cfg config.Config
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "listen"},
			&cli.StringFlag{Name: "rule-file"},
			&cli.StringFlag{Name: "upstream"},
			&cli.StringFlag{Name: "access-log"},
			&cli.StringFlag{Name: "cert"},
			&cli.StringFlag{Name: "key"},
			&cli.StringFlag{Name: "upstream-ca-file"},
			&cli.BoolFlag{Name: "upstream-skip-tls-verify"},
			&cli.BoolFlag{Name: "enable-admin", Value: true},
			&cli.StringFlag{Name: "admin-addr"},
			&cli.StringFlag{Name: "admin-token"},
			&cli.BoolFlag{Name: "enable-sse", Value: true},
			&cli.StringFlag{Name: "sse-addr"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			var err error
			cfg, err = SynthesiseFromFlags(c)
			return err
		},
	}
	args := []string{"serve", "--listen", "127.0.0.1:1", "--listen", "127.0.0.1:2", "--rule-file", rule,
		"--upstream", "https://up.example", "--access-log", access, "--cert", cert, "--key", key,
		"--upstream-ca-file", ca, "--upstream-skip-tls-verify", "--admin-addr", ":9000",
		"--admin-token", "tok", "--sse-addr", ":9001"}
	if err := cmd.Run(context.Background(), args); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(cfg.Listeners) != 2 || cfg.Listeners[0].Bind != "127.0.0.1:1" || cfg.Listeners[1].Bind != "127.0.0.1:2" {
		t.Fatalf("unexpected listeners: %+v", cfg.Listeners)
	}
	if cfg.Listeners[0].Upstream != "https://up.example" || cfg.Listeners[0].TLS == nil {
		t.Fatalf("listener fields not applied: %+v", cfg.Listeners[0])
	}
	if cfg.Admin.Addr != ":9000" || cfg.Admin.Token != "tok" || !cfg.Admin.Enabled {
		t.Fatalf("admin fields not applied: %+v", cfg.Admin)
	}
	if cfg.SSE.Addr != ":9001" || !cfg.SSE.Enabled {
		t.Fatalf("sse fields not applied: %+v", cfg.SSE)
	}
}

func TestSynthesiseFromFlags_MissingRuleFile(t *testing.T) {
	cmd := &cli.Command{
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "listen"},
			&cli.StringFlag{Name: "rule-file"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			_, err := SynthesiseFromFlags(c)
			return err
		},
	}
	err := cmd.Run(context.Background(), []string{"serve", "--listen", ":1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestAbsFromCWD_RelativeSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	file := filepath.Join(realDir, "f.txt")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(linkDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	got, err := AbsFromCWD("f.txt")
	if err != nil {
		t.Fatalf("AbsFromCWD: %v", err)
	}
	want, err := filepath.EvalSymlinks(file)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if got != want {
		t.Fatalf("want %s got %s", want, got)
	}
}

func TestAbsFromCWD_MissingWorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fchdir not supported on windows")
	}
	root := t.TempDir()
	wd := filepath.Join(root, "wd")
	if err := os.Mkdir(wd, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dirFD, err := os.Open(wd)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer dirFD.Close()
	origFD, err := os.Open(".")
	if err != nil {
		t.Fatalf("open cwd: %v", err)
	}
	defer func() {
		_ = syscall.Fchdir(int(origFD.Fd()))
		origFD.Close()
	}()
	if err := os.Remove(wd); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := syscall.Fchdir(int(dirFD.Fd())); err != nil {
		t.Fatalf("fchdir: %v", err)
	}

	if _, err := AbsFromCWD("foo"); err == nil {
		t.Fatal("expected error")
	}
}

func TestAbsFromCWD_NonExistingFile(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	p, err := AbsFromCWD("nope.txt")
	if err != nil {
		t.Fatalf("AbsFromCWD: %v", err)
	}
	wantDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	want := filepath.Join(wantDir, "nope.txt")
	if p != want {
		t.Fatalf("want %s got %s", want, p)
	}
}
