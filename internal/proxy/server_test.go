//go:build skipproxy

package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cblog "github.com/charmbracelet/log"

	galah "github.com/0x4d31/galah/galah"
	galahllm "github.com/0x4d31/galah/pkg/llm"
	suricata "github.com/0x4d31/galah/pkg/suricata"
	"github.com/tmc/langchaingo/llms"

	"github.com/0x4D31/finch/internal/fingerprint"
	"github.com/0x4D31/finch/internal/logger"
	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/internal/sse"
)

type dummyModel struct{}

func (dummyModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: `{"headers":{"X-Test":"v"},"body":"hello"}`}}}, nil
}

func (dummyModel) Call(ctx context.Context, prompt string, opts ...llms.CallOption) (string, error) {
	return "", nil
}

type keyModel struct{ key string }

func (m keyModel) GenerateContent(ctx context.Context, msgs []llms.MessageContent, opts ...llms.CallOption) (*llms.ContentResponse, error) {
	resp := fmt.Sprintf(`{"headers":{"X-Key":"%s"},"body":"ok"}`, m.key)
	return &llms.ContentResponse{Choices: []*llms.ContentChoice{{Content: resp}}}, nil
}

func (keyModel) Call(ctx context.Context, prompt string, opts ...llms.CallOption) (string, error) {
	return "", nil
}

func newTestGalahService(model llms.Model, provider, apiKey string) *galah.Service {
	svc := &galah.Service{
		LLMConfig: galahllm.Config{Provider: provider, APIKey: apiKey},
		Logger:    cblog.New(io.Discard),
		Model:     model,
	}
	if cfgField, ok := reflect.TypeOf(*svc).FieldByName("Config"); ok && cfgField.Type.Kind() == reflect.Pointer {
		cfgVal := reflect.New(cfgField.Type.Elem())
		if f := cfgVal.Elem().FieldByName("UserPrompt"); f.IsValid() && f.CanSet() {
			f.SetString("%s")
		}
		reflect.ValueOf(svc).Elem().FieldByName("Config").Set(cfgVal)
	}
	return svc
}

func TestServer_ForwardAndLog(t *testing.T) {
	backendCh := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCh <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	buf := bytes.Buffer{}
	cblog.SetOutput(&buf)
	defer cblog.SetOutput(io.Discard)

	tmp := t.TempDir()
	logPath := tmp + "/events.jsonl"
	t.Logf("log file: %s", logPath)

	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond) // wait for server

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	_ = resp.Body.Close()

	time.Sleep(100 * time.Millisecond)
	_ = lgr.Close()

	hdr := <-backendCh
	if hdr.Get(HeaderJA3) == "" || hdr.Get(HeaderJA4) == "" || hdr.Get(HeaderJA4H) == "" {
		t.Fatalf("fingerprint headers missing: %v", hdr)
	}

	out := buf.String()
	if bytes.Contains([]byte(out), []byte(HeaderJA3)) || bytes.Contains([]byte(out), []byte(HeaderJA4)) || bytes.Contains([]byte(out), []byte(HeaderJA4H)) {
		t.Fatalf("fingerprint headers should not be logged: %s", out)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no json log")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := ev.Headers[HeaderJA3]; ok {
		t.Fatalf("logged %s header: %v", HeaderJA3, v)
	}
	if v, ok := ev.Headers[HeaderJA4]; ok {
		t.Fatalf("logged %s header: %v", HeaderJA4, v)
	}
	if v, ok := ev.Headers[HeaderJA4H]; ok {
		t.Fatalf("logged %s header: %v", HeaderJA4H, v)
	}
	if v, ok := ev.Headers[HeaderHTTP2]; ok {
		t.Fatalf("logged %s header: %v", HeaderHTTP2, v)
	}
}

func TestServer_BlockAction(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	denyRule := &rules.Rule{ID: "b", Action: rules.ActionDeny,
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{denyRule}, DefaultAction: rules.ActionAllow}

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()
	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, nil, eng, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no log output")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Action != rules.ActionDeny || ev.RuleID != "b" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestServer_ForwardAction(t *testing.T) {
	defaultHit := make(chan struct{}, 1)
	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultHit <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer defaultBackend.Close()

	forwardHit := make(chan struct{}, 1)
	forwardBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardHit <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer forwardBackend.Close()

	u, _ := url.Parse(forwardBackend.URL)
	rule := rules.Rule{ID: "forward", Action: rules.ActionRoute, Upstream: u,
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}
	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()
	svr, err := New("test", "127.0.0.1:0", defaultBackend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	select {
	case <-forwardHit:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatal("forward backend not hit")
	}
	if len(defaultHit) > 0 {
		t.Fatal("default backend should not be hit")
	}
}

func TestServer_MalformedUpstream(t *testing.T) {
	defaultHit := make(chan struct{}, 1)
	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultHit <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer defaultBackend.Close()

	up, _ := url.Parse("http://localhost:0")
	rule := rules.Rule{ID: "bad", Action: rules.ActionRoute, Upstream: up,
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", defaultBackend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if len(defaultHit) > 0 {
		t.Fatal("default backend should not be hit")
	}
}

func TestServer_MalformedUpstreamParse(t *testing.T) {
	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("default backend should not be hit")
	}))
	defer defaultBackend.Close()

	up := &url.URL{Scheme: "http", Host: "bad host"}
	rule := rules.Rule{ID: "bad", Action: rules.ActionRoute, Upstream: up,
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", defaultBackend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestServer_LogDestinationAndBackend(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	routed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer routed.Close()

	tests := []struct {
		name       string
		eng        *rules.Engine
		wantTarget string
		wantAction string
	}{
		{
			name: "forward",
			eng: &rules.Engine{Rules: []*rules.Rule{{ID: "f", Action: rules.ActionAllow,
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}}},
			wantTarget: backend.URL,
			wantAction: string(rules.ActionAllow),
		},
		{
			name: "forward",
			eng: &rules.Engine{Rules: []*rules.Rule{{ID: "r", Action: rules.ActionRoute, Upstream: func() *url.URL { u, _ := url.Parse(routed.URL); return u }(),
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}}, DefaultAction: rules.ActionAllow},
			wantTarget: routed.URL,
			wantAction: string(rules.ActionRoute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cblog.SetOutput(io.Discard)
			logPath := t.TempDir() + "/events.jsonl"
			lgr, err := logger.New(logPath)
			if err != nil {
				t.Fatalf("new logger: %v", err)
			}
			defer func() { _ = lgr.Close() }()

			svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, tt.eng, nil, nil, nil, nil, "", false)
			if err != nil {
				t.Fatalf("new server: %v", err)
			}

			ln, err := net.Listen("tcp", svr.ListenAddr)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()

			go func() { _ = svr.Serve(ln) }()
			time.Sleep(100 * time.Millisecond)

			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			resp, err := client.Get("https://" + ln.Addr().String())
			if err != nil {
				t.Fatalf("client get: %v", err)
			}
			_ = resp.Body.Close()

			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read log: %v", err)
			}

			lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
			if len(lines) == 0 {
				t.Fatalf("no log output")
			}

			var ev logger.Event
			if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			host, portStr, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(portStr)

			if ev.DstIP != host {
				t.Fatalf("dst ip want %s got %s", host, ev.DstIP)
			}
			if ev.DstPort != port {
				t.Fatalf("dst port want %d got %d", port, ev.DstPort)
			}
			if ev.Upstream != tt.wantTarget {
				t.Fatalf("target want %s got %s", tt.wantTarget, ev.Upstream)
			}
			if string(ev.Action) != tt.wantAction {
				t.Fatalf("action want %s got %s", tt.wantAction, ev.Action)
			}
		})
	}
}

func TestServer_DeceiveAction(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be hit")
	}))
	defer backend.Close()

	rule := rules.Rule{ID: "d", Action: rules.ActionDeceive, DeceptionMode: "galah",
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	svc := newTestGalahService(dummyModel{}, "openai", "")

	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, svc, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "hello" {
		t.Fatalf("body want hello got %s", body)
	}
	if resp.Header.Get("X-Test") != "v" {
		t.Fatalf("header not set")
	}
}

func TestServer_TarpitConcurrency(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be hit")
	}))
	defer backend.Close()

	oldHandler := tarpitResponder
	oldLimit := tarpitLimit
	tarpitLimit = make(chan struct{}, 1)
	tarpitResponder = newTarpitHandler(TarpitConfig{
		IntervalMin: 10 * time.Millisecond,
		IntervalMax: 10 * time.Millisecond,
		DelayMin:    50 * time.Millisecond,
		DelayMax:    50 * time.Millisecond,
		Concurrency: tarpitLimit,
	})
	defer func() {
		tarpitResponder = oldHandler
		tarpitLimit = oldLimit
	}()

	rule := rules.Rule{ID: "tp", Action: rules.ActionDeceive, DeceptionMode: "tarpit",
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	firstDone := make(chan struct{})
	go func() {
		resp, err := client.Get("https://" + ln.Addr().String())
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		close(firstDone)
	}()

	time.Sleep(20 * time.Millisecond)

	resp2, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp2.StatusCode)
	}
	_ = resp2.Body.Close()

	<-firstDone
}

func TestServer_ForwardExactURL(t *testing.T) {
	defaultBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("default backend should not be hit")
	}))
	defer defaultBackend.Close()

	hit := make(chan *http.Request, 1)
	forwardBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer forwardBackend.Close()

	targetURL := forwardBackend.URL + "/dest/path"
	u, _ := url.Parse(targetURL)
	rule := rules.Rule{ID: "forward", Action: rules.ActionRoute, Upstream: u,
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()
	svr, err := New("test", "127.0.0.1:0", defaultBackend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/orig/path?x=9")
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	select {
	case r := <-hit:
		if r.URL.Path != "/dest/path" {
			t.Fatalf("backend path %s", r.URL.Path)
		}
		if r.URL.RawQuery != "x=9" {
			t.Fatalf("backend query %s", r.URL.RawQuery)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("forward backend not hit")
	}
}

func TestRoutePathMapping(t *testing.T) {
	hit := make(chan *http.Request, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	tests := []struct {
		name      string
		rule      *rules.Rule
		reqPath   string
		wantPath  string
		wantQuery string
	}{
		{"keep", func() *rules.Rule {
			u, _ := url.Parse(backend.URL)
			return &rules.Rule{ID: "k", Action: rules.ActionRoute, Upstream: u,
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/foo", "/foo", ""},
		{"keep-sub", func() *rules.Rule {
			u, _ := url.Parse(backend.URL)
			return &rules.Rule{ID: "k2", Action: rules.ActionRoute, Upstream: u,
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/foo/bar", "/foo/bar", ""},
		{"strip", func() *rules.Rule {
			u, _ := url.Parse(backend.URL + "/")
			return &rules.Rule{ID: "s", Action: rules.ActionRoute, Upstream: u, StripPrefix: "/api/",
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/api/users", "/users", ""},
		{"replace", func() *rules.Rule {
			u, _ := url.Parse(backend.URL + "/v2/")
			return &rules.Rule{ID: "r", Action: rules.ActionRoute, Upstream: u, StripPrefix: "/api/",
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/api/users", "/v2/users", ""},
		{"double-slash", func() *rules.Rule {
			u, _ := url.Parse(backend.URL + "/v2/")
			return &rules.Rule{ID: "d", Action: rules.ActionRoute, Upstream: u, StripPrefix: "/api/",
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/api//x", "/v2/x", ""},
		{"fixed", func() *rules.Rule {
			u, _ := url.Parse(backend.URL + "/yoyo/ex")
			return &rules.Rule{ID: "f", Action: rules.ActionRoute, Upstream: u,
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/foo?id=1", "/yoyo/ex", "id=1"},
		{"encoded", func() *rules.Rule {
			u, _ := url.Parse(backend.URL)
			return &rules.Rule{ID: "e", Action: rules.ActionRoute, Upstream: u,
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/foo%20bar", "/foo bar", ""},
		{"upstream-query", func() *rules.Rule {
			u, _ := url.Parse(backend.URL + "/v2/?id=1")
			return &rules.Rule{ID: "q", Action: rules.ActionRoute, Upstream: u, StripPrefix: "/api/",
				Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
			}
		}(), "/api/foo", "/v2/foo", "id=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &rules.Engine{Rules: []*rules.Rule{tt.rule}, DefaultAction: rules.ActionAllow}
			lgr, err := logger.New(t.TempDir() + "/events.jsonl")
			if err != nil {
				t.Fatalf("new logger: %v", err)
			}
			defer func() { _ = lgr.Close() }()
			svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
			if err != nil {
				t.Fatalf("new server: %v", err)
			}
			ln, err := net.Listen("tcp", svr.ListenAddr)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer func() { _ = ln.Close() }()
			go func() { _ = svr.Serve(ln) }()
			time.Sleep(50 * time.Millisecond)

			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
			resp, err := client.Get("https://" + ln.Addr().String() + tt.reqPath)
			if err != nil {
				t.Fatalf("client get: %v", err)
			}
			_ = resp.Body.Close()

			select {
			case r := <-hit:
				if r.URL.Path != tt.wantPath {
					t.Fatalf("path want %s got %s", tt.wantPath, r.URL.Path)
				}
				if tt.name == "encoded" {
					if r.URL.EscapedPath() != tt.reqPath {
						t.Fatalf("escaped path want %s got %s", tt.reqPath, r.URL.EscapedPath())
					}
				}
				if r.URL.RawQuery != tt.wantQuery {
					t.Fatalf("query want %s got %s", tt.wantQuery, r.URL.RawQuery)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("backend not hit")
			}
		})
	}
}

func TestConcurrentListenersSharedLogger(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	buf := bytes.Buffer{}
	cblog.SetOutput(&buf)
	defer cblog.SetOutput(io.Discard)

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr1, err := New("one", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("server1: %v", err)
	}
	svr2, err := New("two", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("server2: %v", err)
	}

	ln1, err := net.Listen("tcp", svr1.ListenAddr)
	if err != nil {
		t.Fatalf("listen1: %v", err)
	}
	defer func() { _ = ln1.Close() }()

	ln2, err := net.Listen("tcp", svr2.ListenAddr)
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	defer func() { _ = ln2.Close() }()

	go func() { _ = svr1.Serve(ln1) }()
	go func() { _ = svr2.Serve(ln2) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp, err := client.Get("https://" + ln1.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	go func() {
		defer wg.Done()
		resp, err := client.Get("https://" + ln2.Addr().String())
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for i, ln := range lines {
		var ev logger.Event
		if err := json.Unmarshal(ln, &ev); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
	}
}

func TestServer_BodyLogging(t *testing.T) {
	bodyReceived := make(chan []byte, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyReceived <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	body := bytes.Repeat([]byte("x"), 5000)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Post("https://"+ln.Addr().String(), "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("client post: %v", err)
	}
	_ = resp.Body.Close()

	recvd := <-bodyReceived
	if len(recvd) != len(body) {
		t.Fatalf("backend got %d bytes, want %d", len(recvd), len(body))
	}

	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no log output")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ev.Body) != len(body) {
		t.Fatalf("logged body len %d want %d", len(ev.Body), len(body))
	}
	expectedSha := sha256.Sum256(body)
	if ev.BodySha256 != fmt.Sprintf("%x", expectedSha[:]) {
		t.Fatalf("sha mismatch")
	}
}

func TestServer_BodyLimitTruncate(t *testing.T) {
	oldLimit := BodyLimit
	BodyLimit = 1024
	defer func() { BodyLimit = oldLimit }()

	bodyReceived := make(chan struct {
		data []byte
		clen int64
	}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyReceived <- struct {
			data []byte
			clen int64
		}{b, r.ContentLength}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	body := bytes.Repeat([]byte("x"), 2048)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Post("https://"+ln.Addr().String(), "text/plain", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("client post: %v", err)
	}
	_ = resp.Body.Close()

	recvd := <-bodyReceived
	if int64(len(recvd.data)) != int64(len(body)) {
		t.Fatalf("backend got %d bytes want %d", len(recvd.data), len(body))
	}
	if recvd.clen != int64(len(body)) {
		t.Fatalf("backend content length %d want %d", recvd.clen, len(body))
	}

	time.Sleep(100 * time.Millisecond)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no log output")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ev.Body) != int(BodyLimit) {
		t.Fatalf("logged body len %d want %d", len(ev.Body), BodyLimit)
	}
}

func TestServer_SSEPublish(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	hub := sse.NewHub()
	ch := hub.Subscribe(context.Background(), 1)

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, hub, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	body := "hello"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Post("https://"+ln.Addr().String()+"/p", "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("client post: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case b := <-ch:
		var fe logger.Event
		if err := json.Unmarshal(b, &fe); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if fe.Body != body {
			t.Fatalf("body want %q got %q", body, fe.Body)
		}
		sha := sha256.Sum256([]byte(body))
		if fe.BodySha256 != fmt.Sprintf("%x", sha[:]) {
			t.Fatalf("sha mismatch")
		}
		if fe.Method != http.MethodPost {
			t.Fatalf("method want POST got %s", fe.Method)
		}
		if fe.EventTime.IsZero() {
			t.Fatalf("zero event time")
		}
		if fe.SrcIP == "" || fe.SrcPort == 0 || fe.DstPort == 0 {
			t.Fatalf("missing address info: %+v", fe)
		}
		if fe.ProtocolVersion == "" {
			t.Fatalf("missing protocol")
		}
	case <-time.After(time.Second):
		t.Fatal("no sse event")
	}
}

func TestServer_BodyReadError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	addr := ln.Addr().String()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 4\r\n\r\nab", addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()

	time.Sleep(100 * time.Millisecond)

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no log output")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Error == "" {
		t.Fatal("expected error field")
	}
}

func TestServer_LocalDefaultActionNoMatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	eng := &rules.Engine{DefaultAction: rules.ActionDeny}
	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestRuleHandler_LocalDefaultOnFingerprintError(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	h := &ruleHandler{
		listenerAddr: "test",
		local:        &rules.Engine{DefaultAction: rules.ActionDeny},
		global:       &rules.Engine{DefaultAction: rules.ActionAllow},
		defaultURL:   u,
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 got %d", w.Result().StatusCode)
	}
}

func TestServer_SuricataBodyLimitTruncate(t *testing.T) {
	oldLimit := BodyLimit
	BodyLimit = 10
	defer func() { BodyLimit = oldLimit }()

	bodyReceived := make(chan []byte, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyReceived <- b
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rulesDir := t.TempDir()
	rulePath := rulesDir + "/test.rules"
	ruleLine := `alert http any any -> $HOME_NET any (msg:"Evil Body"; http.request_body; content:"evil"; sid:1001;)`
	if err := os.WriteFile(rulePath, []byte(ruleLine), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	rs := suricata.NewRuleSet()
	if err := rs.LoadRules(rulesDir); err != nil {
		t.Fatalf("load suricata rules: %v", err)
	}

	hcl := `rule "suri" {
  action = "deny"
  when all {
    suricata_msg = ["Evil Body"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rsFinch, err := rules.LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load finch rules: %v", err)
	}
	eng := &rules.Engine{Rules: rsFinch.Rules, DefaultAction: rules.ActionAllow}

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	var ptr atomic.Pointer[suricata.RuleSet]
	ptr.Store(rs)
	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, &ptr, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	body := "xxxxxxxxxxevil"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Post("https://"+ln.Addr().String(), "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("client post: %v", err)
	}
	_ = resp.Body.Close()

	recvd := <-bodyReceived
	if int64(len(recvd)) != int64(len(body)) {
		t.Fatalf("backend got %d bytes want %d", len(recvd), len(body))
	}

	time.Sleep(100 * time.Millisecond)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no log output")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ev.SuricataMatches) != 0 {
		t.Fatalf("unexpected suricata match: %+v", ev.SuricataMatches)
	}
	if len(ev.Body) != int(BodyLimit) {
		t.Fatalf("logged body len %d want %d", len(ev.Body), BodyLimit)
	}
}

func TestServer_GalahServiceUpdate(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be hit")
	}))
	defer backend.Close()

	rule := rules.Rule{ID: "galah", Action: rules.ActionDeceive, DeceptionMode: "galah",
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	svc1 := newTestGalahService(keyModel{key: "k1"}, "openai", "k1")

	lgr, err := logger.New(t.TempDir() + "/events.jsonl")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, svc1, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.Header.Get("X-Key") != "k1" {
		t.Fatalf("header want k1 got %s", resp.Header.Get("X-Key"))
	}
	_ = resp.Body.Close()

	svc2 := newTestGalahService(keyModel{key: "k2"}, "openai", "k2")
	svr.SetGalahService(svc2)
	time.Sleep(50 * time.Millisecond)

	resp2, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if resp2.Header.Get("X-Key") != "k2" {
		t.Fatalf("header want k2 got %s", resp2.Header.Get("X-Key"))
	}
	_ = resp2.Body.Close()
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("fail") }
func (failingBody) Close() error             { return nil }

func TestRuleHandler_BodyReadError(t *testing.T) {
	u, _ := url.Parse("http://example.com")
	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	h := &ruleHandler{
		listenerAddr: "test",
		local:        &rules.Engine{DefaultAction: rules.ActionAllow},
		defaultURL:   u,
		bodyLimit:    1024,
		logger:       lgr,
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com", failingBody{})
	req.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 got %d", w.Result().StatusCode)
	}
}

func TestServer_InvalidUpstreamURL(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be hit")
	}))
	defer backend.Close()

	u := &url.URL{Scheme: "http", Host: "localhost:notaport"}
	rule := rules.Rule{ID: "bad", Action: rules.ActionRoute, Upstream: u,
		Expr: rules.Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }},
	}
	eng := &rules.Engine{Rules: []*rules.Rule{&rule}, DefaultAction: rules.ActionAllow}

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestServer_SuricataMatchLogging(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rulesDir := t.TempDir()
	rulePath := rulesDir + "/test.rules"
	ruleLine := `alert http any any -> $HOME_NET any (msg:"Test Suricata"; http.uri; content:"/evil"; sid:1001;)`
	if err := os.WriteFile(rulePath, []byte(ruleLine), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	rs := suricata.NewRuleSet()
	if err := rs.LoadRules(rulesDir); err != nil {
		t.Fatalf("load suricata rules: %v", err)
	}

	hcl := `rule "suri" {
  action = "deny"
  when all {
    suricata_msg = ["Test Suricata"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rsFinch, err := rules.LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load finch rules: %v", err)
	}
	eng := &rules.Engine{Rules: rsFinch.Rules, DefaultAction: rules.ActionAllow}

	logPath := t.TempDir() + "/events.jsonl"
	lgr, err := logger.New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = lgr.Close() }()

	var ptr atomic.Pointer[suricata.RuleSet]
	ptr.Store(rs)
	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", lgr, eng, nil, &ptr, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/evil")
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("no log output")
	}
	var ev logger.Event
	if err := json.Unmarshal(lines[len(lines)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ev.SuricataMatches) == 0 {
		t.Fatalf("no suricata matches logged")
	}
	if ev.SuricataMatches[0].SID != "1001" {
		t.Fatalf("expected SID 1001, got %s", ev.SuricataMatches[0].SID)
	}
}
