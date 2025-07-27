//go:build skipproxy

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/proxy"
)

func TestWatchConfig_ListenerRuleFileUpdate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	r1 := filepath.Join(dir, "r1.hcl")
	r2 := filepath.Join(dir, "r2.hcl")
	os.WriteFile(r1, []byte(`rule "r1" { action = "deny" when { http_path = ["/first"] } }`), 0o644)
	os.WriteFile(r2, []byte(`rule "r2" { action = "deny" when { http_path = ["/second"] } }`), 0o644)

	cfgPath := filepath.Join(dir, "finch.hcl")
	cfgTpl := "listener \"a\" {\n  bind = \"127.0.0.1:12345\"\n  upstream = \"%s\"\n  rule_file = \"%s\"\n}\n"
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(cfgTpl, backend.URL, r1)), 0o644)

	loader := NewLoader("allow")
	eng, err := loader.LoadEngine(r1)
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	srv, err := proxy.New("a", "127.0.0.1:0", backend.URL, "", "", nil, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: loader, servers: map[string]*proxy.Server{"a": srv}, loggers: map[string]*logRef{}, logPaths: map[string]string{"a": ""}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}

	ln, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/first")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp.Body.Close()

	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(cfgTpl, backend.URL, r2)), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err = client.Get("https://" + ln.Addr().String() + "/second")
		if err == nil && resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			break
		}
		if err == nil {
			resp.Body.Close()
		}
	}
	resp, err = client.Get("https://" + ln.Addr().String() + "/second")
	if err != nil {
		t.Fatalf("after reload: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status after reload %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, err = client.Get("https://" + ln.Addr().String() + "/first")
	if err != nil {
		t.Fatalf("get after reload: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first path status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestWatchConfig_SuricataDirUpdate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer backend.Close()

	dir := t.TempDir()
	s1 := filepath.Join(dir, "s1")
	s2 := filepath.Join(dir, "s2")
	os.Mkdir(s1, 0o755)
	os.Mkdir(s2, 0o755)
	os.WriteFile(filepath.Join(s1, "test.rules"), []byte(`alert http any any -> $HOME_NET any (msg:"One"; http.uri; content:"/evil1"; sid:1;)`), 0o644)
	os.WriteFile(filepath.Join(s2, "test.rules"), []byte(`alert http any any -> $HOME_NET any (msg:"Two"; http.uri; content:"/evil2"; sid:2;)`), 0o644)

	rulePath := filepath.Join(dir, "rules.hcl")
	os.WriteFile(rulePath, []byte(`rule "s" { action = "deny" when all { suricata_msg = ["*"] } }`), 0o644)

	cfgPath := filepath.Join(dir, "finch.hcl")
	cfgTpl := "suricata { enabled = true rules_dir = \"%s\" }\nlistener \"a\" { bind=\"127.0.0.1:12345\" upstream=\"%s\" rule_file=\"%s\" }\n"
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(cfgTpl, s1, backend.URL, rulePath)), 0o644)

	loader := NewLoader("allow")
	eng, _ := loader.LoadEngine(rulePath)
	set, _ := loader.LoadSuricata(s1)
	srv, err := proxy.New("a", "127.0.0.1:0", backend.URL, "", "", nil, eng, nil, set, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: loader, servers: map[string]*proxy.Server{"a": srv}, loggers: map[string]*logRef{}, logPaths: map[string]string{"a": ""}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}

	ln, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/evil1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp.Body.Close()

	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(cfgTpl, s2, backend.URL, rulePath)), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err = client.Get("https://" + ln.Addr().String() + "/evil2")
		if err == nil && resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			break
		}
		if err == nil {
			resp.Body.Close()
		}
	}
	resp, err = client.Get("https://" + ln.Addr().String() + "/evil2")
	if err != nil {
		t.Fatalf("after reload: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status after reload %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, err = client.Get("https://" + ln.Addr().String() + "/evil1")
	if err != nil {
		t.Fatalf("get after reload: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("old rule status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestWatchConfig_DefaultRuleFileUpdate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	dir := t.TempDir()
	r1 := filepath.Join(dir, "r1.hcl")
	r2 := filepath.Join(dir, "r2.hcl")
	os.WriteFile(r1, []byte(`rule "r1" { action = "deny" when { http_path = ["/first"] } }`), 0o644)
	os.WriteFile(r2, []byte(`rule "r2" { action = "deny" when { http_path = ["/second"] } }`), 0o644)

	cfgPath := filepath.Join(dir, "finch.hcl")
	cfgTpl := "defaults { rule_file = \"%s\" }\nlistener \"a\" { bind = \"127.0.0.1:12345\" upstream = \"%s\" }\n"
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(cfgTpl, r1, backend.URL)), 0o644)

	loader := NewLoader("allow")
	eng, _ := loader.LoadEngine(r1)
	srv, err := proxy.New("a", "127.0.0.1:0", backend.URL, "", "", nil, nil, eng, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &runtimeState{loader: loader, servers: map[string]*proxy.Server{"a": srv}, loggers: map[string]*logRef{}, logPaths: map[string]string{"a": ""}, wg: &sync.WaitGroup{}}
	if err := watchConfig(ctx, cfgPath, rt, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("watchConfig: %v", err)
	}

	ln, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/first")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp.Body.Close()

	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(cfgTpl, r2, backend.URL)), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err = client.Get("https://" + ln.Addr().String() + "/second")
		if err == nil && resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			break
		}
		if err == nil {
			resp.Body.Close()
		}
	}
	resp, err = client.Get("https://" + ln.Addr().String() + "/second")
	if err != nil {
		t.Fatalf("after reload: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status after reload %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, err = client.Get("https://" + ln.Addr().String() + "/first")
	if err != nil {
		t.Fatalf("get after reload: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first path status %d", resp.StatusCode)
	}
	resp.Body.Close()
}
