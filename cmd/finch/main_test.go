package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/admin"
	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/loader"
	"github.com/0x4D31/finch/internal/proxy"
	"github.com/0x4D31/finch/internal/sse"
	galah "github.com/0x4d31/galah/galah"
	_ "github.com/mattn/go-sqlite3"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return addr
}

// setupWorkDir prepares a temporary working directory with an empty
// configs/default.rules.hcl file. The caller must defer the returned
// cleanup function.
func setupWorkDir(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "configs")
	if err := os.Mkdir(cfgDir, 0o755); err != nil {
		t.Fatalf("mkdir configs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "default.rules.hcl"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	return func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("chdir: %v", err)
		}
	}
}

func TestLoaderReloadEngines(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.hcl")
	// initial rule allows path /
	if err := os.WriteFile(rulesPath, []byte("rule \"r\" {\n  action = \"allow\"\n  when {\n    http_path = [\"/\"]\n  }\n}"), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	l := NewLoader("deny")
	eng, err := l.LoadEngine(rulesPath)
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	if len(eng.Rules) != 1 || eng.Rules[0].Action != "allow" {
		t.Fatalf("unexpected engine state: %+v", eng.Rules)
	}

	// update rule
	if err := os.WriteFile(rulesPath, []byte("rule \"r\" {\n  action = \"deny\"\n  when {\n    http_path = [\"/\"]\n  }\n}"), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	l.ReloadEngines()
	if len(eng.Rules) != 1 || eng.Rules[0].Action != "deny" {
		t.Fatalf("engine not reloaded: %+v", eng.Rules)
	}
}

func TestWatchConfigLoadsNewRules(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "finch.hcl")
	r1 := filepath.Join(dir, "r1.hcl")
	r2 := filepath.Join(dir, "r2.hcl")
	if err := os.WriteFile(r1, nil, 0o644); err != nil {
		t.Fatalf("write r1: %v", err)
	}
	if err := os.WriteFile(r2, nil, 0o644); err != nil {
		t.Fatalf("write r2: %v", err)
	}
	// initial config referencing r1
	cfg1 := fmt.Sprintf(`defaults {
  rule_file = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`, r1)
	if err := os.WriteFile(cfgPath, []byte(cfg1), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	l := NewLoader("allow")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: l, servers: make(map[string]*proxy.Server), loggers: map[string]*logRef{}, logPaths: map[string]string{}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // allow watcher to start

	absR1, err := filepath.EvalSymlinks(r1)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	// modify config to use r2
	cfg2 := fmt.Sprintf(`defaults {
  rule_file = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`, r2)
	if err := os.WriteFile(cfgPath, []byte(cfg2), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	absR2, err := filepath.EvalSymlinks(r2)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	for i := 0; i < 50; i++ {
		l.mu.RLock()
		_, ok2 := l.engineMap[absR2]
		_, ok1 := l.engineMap[absR1]
		_, w1 := l.watchMap[absR1]
		l.mu.RUnlock()
		if ok2 && !ok1 && !w1 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	t.Fatalf("engine maps not updated; map: %#v", l.engineMap)
}

func TestWatchConfigRemovesOldWatch(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "finch.hcl")
	r1 := filepath.Join(dir, "r1.hcl")
	r2 := filepath.Join(dir, "r2.hcl")
	if err := os.WriteFile(r1, nil, 0o644); err != nil {
		t.Fatalf("write r1: %v", err)
	}
	if err := os.WriteFile(r2, nil, 0o644); err != nil {
		t.Fatalf("write r2: %v", err)
	}

	cfg1 := fmt.Sprintf(`listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "%s"
}

listener "b" {
  bind = "127.0.0.1:2"
  upstream = "https://example.com"
  rule_file = "%s"
}
`, r1, r2)
	if err := os.WriteFile(cfgPath, []byte(cfg1), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	l := NewLoader("allow")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: l, servers: make(map[string]*proxy.Server), loggers: map[string]*logRef{}, logPaths: map[string]string{}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	absR2, err := filepath.EvalSymlinks(r2)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	cfg2 := fmt.Sprintf(`listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "%s"
}
`, r1)
	if err := os.WriteFile(cfgPath, []byte(cfg2), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		l.mu.RLock()
		_, ok := l.watchMap[absR2]
		l.mu.RUnlock()
		if !ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("watch for removed path not cancelled")
}

func TestWatchConfigReloadsGalah(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "finch.hcl")
	rulePath := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rulePath, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}
	galahCfg := filepath.Join(strings.TrimSpace(string(out)), "github.com", "0x4d31", "galah@v1.1.1", "config", "config.yaml")

	cfg1 := fmt.Sprintf(`galah {
  provider = "openai"
  model = "gpt-3.5-turbo"
  api_key = "k1"
  config_file = "%s"
}

defaults {
  rule_file = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`, galahCfg, rulePath)
	if err := os.WriteFile(cfgPath, []byte(cfg1), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	l := NewLoader("allow")
	var svc *galah.Service
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: l, servers: make(map[string]*proxy.Server), loggers: map[string]*logRef{}, logPaths: map[string]string{}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, &svc, nil, nil, nil, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	cfg2 := fmt.Sprintf(`galah {
  provider = "openai"
  model = "gpt-3.5-turbo"
  api_key = "k2"
  config_file = "%s"
}

defaults {
  rule_file = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`, galahCfg, rulePath)
	if err := os.WriteFile(cfgPath, []byte(cfg2), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		if svc != nil && svc.LLMConfig.APIKey == "k2" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	if svc == nil {
		t.Fatalf("service not created")
	}
	t.Fatalf("service not reloaded: %v", svc.LLMConfig.APIKey)
}

func TestWatchConfigReloadsSSE(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "finch.hcl")
	addr1 := freePort(t)
	addr2 := freePort(t)
	rule := filepath.Join(dir, "r.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfg1 := fmt.Sprintf(`sse {
  enabled = true
  addr = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "%s"
}
`, addr1, rule)
	if err := os.WriteFile(cfgPath, []byte(cfg1), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	l := NewLoader("allow")
	hub := sse.NewHub()
	sSrv := sse.NewServer(addr1, hub)
	go func() { _ = sSrv.Start() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: l, servers: make(map[string]*proxy.Server), loggers: map[string]*logRef{}, logPaths: map[string]string{}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, &sSrv, hub, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	cfg2 := fmt.Sprintf(`sse {
  enabled = true
  addr = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "%s"
}
`, addr2, rule)
	if err := os.WriteFile(cfgPath, []byte(cfg2), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		if sSrv != nil && sSrv.Addr == addr2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("sse server not restarted: %v", sSrv.Addr)
}

func TestWatchConfigReloadsAdmin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "finch.hcl")
	addr1 := freePort(t)
	addr2 := freePort(t)
	rule := filepath.Join(dir, "r.hcl")
	if err := os.WriteFile(rule, nil, 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfg1 := fmt.Sprintf(`admin {
  enabled = true
  addr = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "%s"
}
`, addr1, rule)
	if err := os.WriteFile(cfgPath, []byte(cfg1), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	l := NewLoader("allow")
	aSrv := admin.New(addr1, "", nil, nil, nil, nil, "")
	go func() { _ = aSrv.Start() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: l, servers: make(map[string]*proxy.Server), loggers: map[string]*logRef{}, logPaths: map[string]string{}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, nil, nil, &aSrv); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	cfg2 := fmt.Sprintf(`admin {
  enabled = true
  addr = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "%s"
}
`, addr2, rule)
	if err := os.WriteFile(cfgPath, []byte(cfg2), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		if aSrv != nil && aSrv.Addr == addr2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("admin server not restarted: %v", aSrv.Addr)
}
func TestStartRuntime_NoTLSQuickMode(t *testing.T) {
	cleanup := setupWorkDir(t)
	defer cleanup()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	rf := filepath.Join(wd, "configs", "default.rules.hcl")
	al := filepath.Join(wd, defaultAccessLog)
	cfg := config.Config{
		Defaults: &config.Defaults{RuleFile: rf, AccessLog: al, ProxyCacheSize: loader.DefaultProxyCacheSize},
		Admin:    &config.AdminConfig{Enabled: true, Addr: config.DefaultAdminAddr},
		SSE:      &config.SSEConfig{Enabled: true, Addr: config.DefaultSSEAddr},
		Listeners: []config.ListenerConfig{
			{ID: "listener1", Bind: "127.0.0.1:1", Upstream: defaultUpstream, RuleFile: rf, AccessLog: al},
			{ID: "listener2", Bind: "127.0.0.1:2", Upstream: defaultUpstream, RuleFile: rf, AccessLog: al},
		},
	}
	pf := parsedFlags{LogLevel: "info", SSEAddr: config.DefaultSSEAddr, SSEEnabled: true, AdminEnabled: true, AdminAddr: config.DefaultAdminAddr}
	rt, err := startRuntime(&cfg, pf, nil, nil, nil)
	if err != nil {
		t.Fatalf("startRuntime: %v", err)
	}
	rt.shutdown(pf)
}

func TestReloadRuntimeRestartsListeners(t *testing.T) {
	cleanup := setupWorkDir(t)
	defer cleanup()

	addr := freePort(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	rf := filepath.Join(wd, "configs", "default.rules.hcl")
	al := filepath.Join(wd, defaultAccessLog)
	cfg := config.Config{
		Defaults: &config.Defaults{RuleFile: rf, AccessLog: al, ProxyCacheSize: loader.DefaultProxyCacheSize},
		Admin:    &config.AdminConfig{Enabled: false},
		SSE:      &config.SSEConfig{Enabled: false},
		Listeners: []config.ListenerConfig{
			{ID: "listener1", Bind: addr, Upstream: defaultUpstream, RuleFile: rf, AccessLog: al},
		},
	}
	pf := parsedFlags{LogLevel: "info", SSEEnabled: false, AdminEnabled: false}
	rt, err := startRuntime(&cfg, pf, nil, nil, nil)
	if err != nil {
		t.Fatalf("startRuntime: %v", err)
	}
	// build new runtime with same address
	newCfg := cfg
	newRT, err := newRuntime(&newCfg, pf, nil, nil, nil)
	if err != nil {
		t.Fatalf("newRuntime: %v", err)
	}

	rt.shutdown(pf)
	newRT.Start()
	time.Sleep(100 * time.Millisecond)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial new runtime: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("conn close: %v", err)
	}
	newRT.shutdown(pf)
}

func TestAdminServerReachable(t *testing.T) {
	cleanup := setupWorkDir(t)
	defer cleanup()

	adminAddr := freePort(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	rf := filepath.Join(wd, "configs", "default.rules.hcl")
	al := filepath.Join(wd, defaultAccessLog)
	cfg := config.Config{
		Defaults:  &config.Defaults{RuleFile: rf, AccessLog: al, ProxyCacheSize: loader.DefaultProxyCacheSize},
		Admin:     &config.AdminConfig{Enabled: true, Addr: adminAddr},
		SSE:       &config.SSEConfig{Enabled: false},
		Listeners: []config.ListenerConfig{{ID: "l1", Bind: "127.0.0.1:0", Upstream: defaultUpstream, RuleFile: rf, AccessLog: al}},
	}
	pf := parsedFlags{LogLevel: "info", AdminEnabled: true, AdminAddr: adminAddr, SSEEnabled: false}
	rt, err := startRuntime(&cfg, pf, nil, nil, nil)
	if err != nil {
		t.Fatalf("startRuntime: %v", err)
	}

	srv := admin.New(adminAddr, "", &cfg, nil, func(c config.Config) error { cfg = c; return nil }, func() { rt.shutdown(pf) }, "")
	rt.adminSrv = srv
	rt.wg.Add(1)
	go func() {
		defer rt.wg.Done()
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("admin server: %v", err)
		}
	}()

	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + adminAddr + "/config")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	rt.shutdown(pf)
}
