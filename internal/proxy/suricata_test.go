//go:build skipproxy

package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/logger"
	"github.com/0x4D31/finch/internal/rules"
	suricata "github.com/0x4d31/galah/pkg/suricata"
)

func TestServer_SuricataMatch(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// suricata rule matching /evil
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

	// finch rule matching on suricata-msg using HCL
	hcl := `rule "suri" {
  action = "deny"
  when all {
    suricata_msg = ["*Test Suricata*"]
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
	if ev.RuleID != "suri" || ev.Action != rules.ActionDeny {
		t.Fatalf("unexpected rule match: %+v", ev)
	}
	if len(ev.SuricataMatches) == 0 {
		t.Fatalf("no suricata matches logged")
	}
	if ev.SuricataMatches[0].SID != "1001" {
		t.Fatalf("expected SID 1001, got %s", ev.SuricataMatches[0].SID)
	}
}

func TestServer_SuricataMatch_NoLogger(t *testing.T) {
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
    suricata_msg = ["*Test Suricata*"]
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

	var ptr atomic.Pointer[suricata.RuleSet]
	ptr.Store(rs)
	svr, err := New("test", "127.0.0.1:0", backend.URL, "", "", nil, eng, nil, &ptr, nil, nil, "", false)
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
}
