package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/rules"
)

func newTestConfig(t *testing.T) (config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.hcl")
	if err := os.WriteFile(rulePath, []byte(`rule "ok" {
  action = "allow"
  when { http_method = ["GET"] }
}`), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	cfg := config.Config{
		Defaults:  &config.Defaults{RuleFile: rulePath},
		Listeners: []config.ListenerConfig{{ID: "l1", Bind: ":8080", Upstream: "http://localhost"}},
	}
	return cfg, rulePath
}

func TestGetConfigJSON(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	srv.wrap(srv.getConfig)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("unexpected content-type %q", ct)
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("missing ETag header")
	}
	var out config.Config
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(out.Listeners) != 1 || out.Listeners[0].ID != "l1" {
		t.Fatal("unexpected config body")
	}
}

func TestLoadConfigETag(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	body := []byte("defaults { rule_file = \"" + rulePath + "\" }\n" +
		"listener \"l1\" {\n  bind = \":8080\"\n  upstream = \"http://other\"\n}\n")

	// missing If-Match
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	srv.loadConfig(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412, got %d", rr.Code)
	}

	// wrong ETag
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", "\"bad\"")
	srv.loadConfig(rr, req)
	if rr.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 for mismatch, got %d", rr.Code)
	}

	// correct ETag
	etag := srv.etag
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", etag)
	srv.loadConfig(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if srv.cfg.Listeners[0].Upstream != "http://other" {
		t.Fatal("config not updated")
	}
	if srv.etag == etag {
		t.Fatal("etag not updated")
	}

	// prevent unused variable warning for rulePath in case future edits
	_ = rulePath
}

func TestLoadConfigJSON(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	body := []byte(`{"defaults":{"rule_file":"` + rulePath + `"},"listeners":[{"id":"l1","bind":":8080","upstream":"http://other"}]}`)

	etag := srv.etag
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", etag)
	req.Header.Set("Content-Type", "application/json")
	srv.loadConfig(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if srv.cfg.Listeners[0].Upstream != "http://other" {
		t.Fatal("config not updated")
	}
	if srv.etag == etag {
		t.Fatal("etag not updated")
	}

	badBody := []byte(`{"defaults":{"rule_file":"` + rulePath + `"},"unknown":true}`)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(badBody))
	req.Header.Set("If-Match", srv.etag)
	req.Header.Set("Content-Type", "application/json")
	srv.loadConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	_ = rulePath
}

func TestRuleSetValidationError(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rulesets/"+id, bytes.NewBufferString("rule \"bad\" {}"))
	srv.handleRuleSet(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleRuleSets(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rulesets", nil)
	srv.handleRuleSets(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("unexpected content-type %q", ct)
	}
	var out []config.RuleSetInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	expect := []config.RuleSetInfo{{ID: "r1", Path: rulePath, Listeners: []string{"defaults", "l1"}}}
	if !reflect.DeepEqual(out, expect) {
		t.Fatalf("unexpected body: %#v", out)
	}
}

func TestGetRuleSet(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rulesets/"+id, nil)
	srv.handleRuleSet(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("unexpected content-type %q", ct)
	}
	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(rr.Body.Bytes(), data) {
		t.Fatalf("unexpected body: %q", rr.Body.Bytes())
	}
}

func TestGetRuleSetNotFound(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rulesets/missing", nil)
	srv.handleRuleSet(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestLoadConfigResolvePaths(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	dir := t.TempDir()
	rule := []byte(`rule "ok" {
  action = "allow"
  when { http_method = ["GET"] }
}`)
	if err := os.WriteFile(filepath.Join(dir, "shared.rules"), rule, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custom.rules"), rule, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	body := []byte(`defaults { rule_file = "shared.rules" }
listener "l1" {
  bind = ":8080"
  upstream = "http://other"
  rule_file = "custom.rules"
}
`)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", srv.etag)
	srv.loadConfig(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if srv.cfg.Defaults.RuleFile != filepath.Join(canonicalDir, "shared.rules") {
		t.Fatalf("defaults.rule_file %s", srv.cfg.Defaults.RuleFile)
	}
	if srv.cfg.Listeners[0].RuleFile != filepath.Join(canonicalDir, "custom.rules") {
		t.Fatalf("listener rule_file %s", srv.cfg.Listeners[0].RuleFile)
	}

}

func TestLoadConfigJSONUnknownKeys(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	body := []byte(fmt.Sprintf(`{"defaults":{"rule_file":"%s"},"listeners":[{"id":"l1","bind":":8080","upstream":"http://other","extra":1}],"unknown":true}`, rulePath))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", srv.etag)
	req.Header.Set("Content-Type", "application/json")
	srv.loadConfig(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if srv.cfg.Listeners[0].Upstream != "http://localhost" {
		t.Fatal("config mutated on failure")
	}
}

func TestAuthToken(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "s3cr3t", &cfg, nil, nil, nil, "")

	// missing token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	srv.wrap(srv.getConfig)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// wrong token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/config", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	srv.wrap(srv.getConfig)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 wrong token, got %d", rr.Code)
	}

	// correct token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/config", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	srv.wrap(srv.getConfig)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAuthTokenLoad(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "s3cr3t", &cfg, nil, nil, nil, "")

	body := []byte("defaults { rule_file = \"" + rulePath + "\" }\n" +
		"listener \"l1\" {\n  bind = \":8080\"\n  upstream = \"http://other\"\n}\n")
	etag := srv.etag

	// missing token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", etag)
	srv.wrap(srv.loadConfig)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// wrong token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", etag)
	req.Header.Set("Authorization", "Bearer wrong")
	srv.wrap(srv.loadConfig)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 wrong token, got %d", rr.Code)
	}

	// correct token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", etag)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	srv.wrap(srv.loadConfig)(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestAuthTokenRuleSets(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "s3cr3t", &cfg, nil, nil, nil, "")

	// missing token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rulesets", nil)
	srv.wrap(srv.handleRuleSets)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// wrong token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/rulesets", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	srv.wrap(srv.handleRuleSets)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 wrong token, got %d", rr.Code)
	}

	// correct token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/rulesets", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	srv.wrap(srv.handleRuleSets)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAuthTokenRule(t *testing.T) {
	cfg, _ := newTestConfig(t)
	srv := New(":0", "s3cr3t", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	path := "/rulesets/" + id + "/rules/ok"

	// missing token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	srv.wrap(srv.handleRuleSet)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// wrong token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer wrong")
	srv.wrap(srv.handleRuleSet)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 wrong token, got %d", rr.Code)
	}

	// correct token
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	srv.wrap(srv.handleRuleSet)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestLoadConfigConcurrent(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	applyCount := 0
	srv := New(":0", "", &cfg, nil, func(c config.Config) error {
		applyCount++
		return nil
	}, nil, "")

	body1 := []byte("defaults { rule_file = \"" + rulePath + "\" }\n" +
		"listener \"l1\" {\n  bind = \":8080\"\n  upstream = \"http://one\"\n}\n")
	body2 := []byte("defaults { rule_file = \"" + rulePath + "\" }\n" +
		"listener \"l1\" {\n  bind = \":8080\"\n  upstream = \"http://two\"\n}\n")

	start := make(chan struct{})
	results := make(chan int, 2)
	etag := srv.etag
	go func() {
		<-start
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body1))
		req.Header.Set("If-Match", etag)
		srv.loadConfig(rr, req)
		results <- rr.Code
	}()
	go func() {
		<-start
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body2))
		req.Header.Set("If-Match", etag)
		srv.loadConfig(rr, req)
		results <- rr.Code
	}()
	close(start)

	code1 := <-results
	code2 := <-results

	if (code1 != http.StatusNoContent || code2 != http.StatusPreconditionFailed) &&
		(code2 != http.StatusNoContent || code1 != http.StatusPreconditionFailed) {
		t.Fatalf("expected one success and one precondition failure, got %d and %d", code1, code2)
	}
	if applyCount != 1 {
		t.Fatalf("expected apply called once, got %d", applyCount)
	}
	if srv.etag == etag {
		t.Fatal("etag not updated")
	}
	if srv.cfg.Listeners[0].Upstream != "http://one" && srv.cfg.Listeners[0].Upstream != "http://two" {
		t.Fatal("config not updated")
	}

	_ = rulePath
}

func TestUpdateListenerRuleset(t *testing.T) {
	dir := t.TempDir()
	rule1 := filepath.Join(dir, "rules1.hcl")
	if err := os.WriteFile(rule1, []byte("rule \"r1\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule1: %v", err)
	}
	rule2 := filepath.Join(dir, "rules2.hcl")
	if err := os.WriteFile(rule2, []byte("rule \"r2\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule2: %v", err)
	}

	cfg := config.Config{
		Listeners: []config.ListenerConfig{
			{ID: "l1", Bind: ":8080", Upstream: "http://localhost", RuleFile: rule1},
			{ID: "l2", Bind: ":8081", Upstream: "http://localhost", RuleFile: rule2},
		},
	}

	applyCalled := false
	srv := New(":0", "", &cfg, nil, func(c config.Config) error {
		applyCalled = true
		return nil
	}, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	var id string
	for _, rs := range sets {
		if rs.Path == rule2 {
			id = rs.ID
			break
		}
	}
	if id == "" {
		t.Fatal("ruleset id not found")
	}

	etag := srv.etag
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/l1/ruleset?id="+id, nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !applyCalled {
		t.Fatal("apply not called")
	}
	if srv.cfg.Listeners[0].RuleFile != rule2 {
		t.Fatalf("listener not updated: %s", srv.cfg.Listeners[0].RuleFile)
	}
	if srv.etag == etag {
		t.Fatal("etag not updated")
	}
}

func TestUpdateListenerRulesetApplyError(t *testing.T) {
	dir := t.TempDir()
	rule1 := filepath.Join(dir, "rules1.hcl")
	if err := os.WriteFile(rule1, []byte("rule \"r1\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule1: %v", err)
	}
	rule2 := filepath.Join(dir, "rules2.hcl")
	if err := os.WriteFile(rule2, []byte("rule \"r2\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule2: %v", err)
	}

	cfg := config.Config{
		Listeners: []config.ListenerConfig{
			{ID: "l1", Bind: ":8080", Upstream: "http://localhost", RuleFile: rule1},
			{ID: "l2", Bind: ":8081", Upstream: "http://localhost", RuleFile: rule2},
		},
	}

	applyCalled := false
	srv := New(":0", "", &cfg, nil, func(c config.Config) error {
		applyCalled = true
		return errors.New("apply fail")
	}, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	var id string
	for _, rs := range sets {
		if rs.Path == rule2 {
			id = rs.ID
			break
		}
	}
	if id == "" {
		t.Fatal("ruleset id not found")
	}

	etag := srv.etag
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/l1/ruleset?id="+id, nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if !applyCalled {
		t.Fatal("apply not called")
	}
	if srv.etag != etag {
		t.Fatal("etag changed on failure")
	}
	if srv.cfg.Listeners[0].RuleFile != rule1 {
		t.Fatal("config mutated on failure")
	}
}

func TestUpdateListenerRulesetNoConfig(t *testing.T) {
	srv := New(":0", "", nil, nil, nil, nil, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/l1/ruleset?id=x", nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestUpdateListenerRulesetSuccess(t *testing.T) {
	dir := t.TempDir()
	rule1 := filepath.Join(dir, "rules1.hcl")
	if err := os.WriteFile(rule1, []byte("rule \"r1\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule1: %v", err)
	}
	rule2 := filepath.Join(dir, "rules2.hcl")
	if err := os.WriteFile(rule2, []byte("rule \"r2\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule2: %v", err)
	}

	cfg := config.Config{
		Listeners: []config.ListenerConfig{
			{ID: "l1", Bind: ":8080", Upstream: "http://localhost", RuleFile: rule1},
			{ID: "l2", Bind: ":8081", Upstream: "http://localhost", RuleFile: rule2},
		},
	}

	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	var id string
	for _, rs := range sets {
		if rs.Path == rule2 {
			id = rs.ID
			break
		}
	}
	if id == "" {
		t.Fatal("ruleset id not found")
	}

	oldETag := srv.etag
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/l1/ruleset?id="+id, nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if srv.etag == oldETag {
		t.Fatal("etag not updated")
	}
	if srv.cfg.Listeners[0].RuleFile != rule2 {
		t.Fatalf("listener not updated: %s", srv.cfg.Listeners[0].RuleFile)
	}
}

func TestUpdateListenerRulesetRulesetNotFound(t *testing.T) {
	cfg, _ := newTestConfig(t)
	// second ruleset to enumerate at least one existing id
	rule2 := filepath.Join(t.TempDir(), "rules2.hcl")
	if err := os.WriteFile(rule2, []byte("rule \"r2\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule2: %v", err)
	}
	cfg.Listeners = append(cfg.Listeners, config.ListenerConfig{ID: "l2", Bind: ":8081", Upstream: "http://localhost", RuleFile: rule2})
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	prev := srv.cfg.Listeners[0].RuleFile
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/l1/ruleset?id=missing", nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
	if srv.cfg.Listeners[0].RuleFile != prev {
		t.Fatal("config mutated on error")
	}
}

func TestUpdateListenerRulesetListenerNotFound(t *testing.T) {
	dir := t.TempDir()
	rule1 := filepath.Join(dir, "rules1.hcl")
	if err := os.WriteFile(rule1, []byte("rule \"r1\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule1: %v", err)
	}
	rule2 := filepath.Join(dir, "rules2.hcl")
	if err := os.WriteFile(rule2, []byte("rule \"r2\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule2: %v", err)
	}

	cfg := config.Config{
		Listeners: []config.ListenerConfig{
			{ID: "l1", Bind: ":8080", Upstream: "http://localhost", RuleFile: rule1},
			{ID: "l2", Bind: ":8081", Upstream: "http://localhost", RuleFile: rule2},
		},
	}

	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	var id string
	for _, rs := range sets {
		if rs.Path == rule2 {
			id = rs.ID
			break
		}
	}
	if id == "" {
		t.Fatal("ruleset id not found")
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/missing/ruleset?id="+id, nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestUpdateListenerRulesetMissingID(t *testing.T) {
	cfg, _ := newTestConfig(t)
	// add a second ruleset to have enumeratable IDs
	rule2 := filepath.Join(t.TempDir(), "rules2.hcl")
	if err := os.WriteFile(rule2, []byte("rule \"r2\" { action = \"allow\" }"), 0o644); err != nil {
		t.Fatalf("write rule2: %v", err)
	}
	cfg.Listeners = append(cfg.Listeners, config.ListenerConfig{ID: "l2", Bind: ":8081", Upstream: "http://localhost", RuleFile: rule2})
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	prev := srv.cfg.Listeners[0].RuleFile
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/config/listeners/l1/ruleset", nil)
	srv.updateListenerRuleset(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if srv.cfg.Listeners[0].RuleFile != prev {
		t.Fatal("config mutated on error")
	}
}

func TestLoadConfigGetwdError(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	body := []byte("defaults { rule_file = \"" + rulePath + "\" }\n" +
		"listener \"l1\" {\n  bind = \":8080\"\n  upstream = \"http://other\"\n}\n")

	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	_ = os.RemoveAll(dir)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", srv.etag)
	done := make(chan struct{})
	go func() { srv.loadConfig(rr, req); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loadConfig hung")
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	if err := os.Chdir(wd); err != nil {
		t.Fatalf("chdir back: %v", err)
	}

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req2.Header.Set("If-Match", srv.etag)
	done2 := make(chan struct{})
	go func() { srv.loadConfig(rr2, req2); close(done2) }()
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Fatal("second call hung")
	}
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr2.Code, rr2.Body.String())
	}

	_ = rulePath
}

func TestLoadConfigPersistsFile(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	path := filepath.Join(t.TempDir(), "finch.json")
	srv := New(":0", "", &cfg, nil, nil, nil, path)

	body := []byte("defaults { rule_file = \"" + rulePath + "\" }\n" +
		"listener \"l1\" {\n  bind = \":8080\"\n  upstream = \"http://other\"\n}\n")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/load", bytes.NewReader(body))
	req.Header.Set("If-Match", srv.etag)
	srv.loadConfig(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Contains(data, []byte("http://other")) {
		t.Fatalf("file not persisted: %s", data)
	}

	_ = rulePath
}

func TestRuleSetConcurrentUpdate(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	body1 := []byte("rule \"r1\" {\n  action = \"allow\"\n  when { http_method = [\"GET\"] }\n}\n")
	body2 := []byte("rule \"r2\" {\n  action = \"deny\"\n  when { http_method = [\"GET\"] }\n}\n")

	start := make(chan struct{})
	wg := sync.WaitGroup{}
	codes := make(chan int, 2)

	post := func(body []byte) {
		defer wg.Done()
		<-start
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/rulesets/"+id, bytes.NewReader(body))
		srv.handleRuleSet(rr, req)
		codes <- rr.Code
	}

	wg.Add(2)
	go post(body1)
	go post(body2)
	close(start)
	wg.Wait()

	code1 := <-codes
	code2 := <-codes
	if code1 != http.StatusNoContent || code2 != http.StatusNoContent {
		t.Fatalf("expected 204/204, got %d and %d", code1, code2)
	}

	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read ruleset: %v", err)
	}
	if string(data) != string(body1) && string(data) != string(body2) {
		t.Fatalf("unexpected file contents: %q", data)
	}
	if _, err := rules.LoadHCL(rulePath); err != nil {
		t.Fatalf("invalid ruleset: %v", err)
	}

	_ = rulePath
}

func TestRuleConcurrentUpdate(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	body1 := []byte("rule \"ok\" {\n  action = \"allow\"\n  when { http_method = [\"GET\"] }\n}\n")
	body2 := []byte("rule \"ok\" {\n  action = \"deny\"\n  when { http_method = [\"GET\"] }\n}\n")

	start := make(chan struct{})
	wg := sync.WaitGroup{}
	codes := make(chan int, 2)

	put := func(body []byte) {
		defer wg.Done()
		<-start
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/rulesets/"+id+"/rules/ok", bytes.NewReader(body))
		srv.handleRule(id, "ok", rr, req)
		codes <- rr.Code
	}

	wg.Add(2)
	go put(body1)
	go put(body2)
	close(start)
	wg.Wait()

	code1 := <-codes
	code2 := <-codes
	if code1 != http.StatusNoContent || code2 != http.StatusNoContent {
		t.Fatalf("expected 204/204, got %d and %d", code1, code2)
	}

	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read ruleset: %v", err)
	}
	if string(data) != string(body1) && string(data) != string(body2) {
		t.Fatalf("unexpected file contents: %q", data)
	}
	if _, err := rules.LoadHCL(rulePath); err != nil {
		t.Fatalf("invalid ruleset: %v", err)
	}

	_ = rulePath
}

func TestHandleRuleCRUD(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	// GET existing rule
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rulesets/"+id+"/rules/ok", nil)
	srv.handleRule(id, "ok", rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	want := "rule \"ok\" {\n  action = \"allow\"\n  when { http_method = [\"GET\"] }\n}"
	if rr.Body.String() != want {
		t.Fatalf("unexpected body: %q", rr.Body.String())
	}

	// POST new rule
	newRule := []byte("rule \"new\" {\n  action = \"deny\"\n  when { http_method = [\"GET\"] }\n}\n")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/rulesets/"+id+"/rules/new", bytes.NewReader(newRule))
	srv.handleRule(id, "new", rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("post expected 204, got %d", rr.Code)
	}
	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != want+"\n"+string(newRule) {
		t.Fatalf("post file contents: %q", data)
	}

	// PUT update existing rule
	update := []byte("rule \"ok\" {\n  action = \"deny\"\n  when { http_method = [\"GET\"] }\n}\n")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/rulesets/"+id+"/rules/ok", bytes.NewReader(update))
	srv.handleRule(id, "ok", rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("put expected 204, got %d", rr.Code)
	}
	data, err = os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	if string(data) != string(update)+string(newRule) {
		t.Fatalf("put file contents: %q", data)
	}

	// DELETE rule
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/rulesets/"+id+"/rules/new", nil)
	srv.handleRule(id, "new", rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete expected 204, got %d", rr.Code)
	}
	rs, err := rules.LoadHCL(rulePath)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].ID != "ok" {
		t.Fatalf("unexpected rules after delete: %v", rs.Rules)
	}

	_ = rulePath
}

func TestRuleSetReplace(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	body := []byte("rule \"r1\" {\n  action = \"allow\"\n  when { http_method = [\"GET\"] }\n}\n")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rulesets/"+id, bytes.NewReader(body))
	srv.handleRuleSet(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}

	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(data) != string(body) {
		t.Fatalf("unexpected ruleset contents: %q", data)
	}
	if _, err := rules.LoadHCL(rulePath); err != nil {
		t.Fatalf("invalid ruleset: %v", err)
	}

	_ = rulePath
}

func TestStopServerCallback(t *testing.T) {
	stopped := false
	srv := New(":0", "", nil, nil, nil, func() { stopped = true }, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/stop", nil)
	srv.wrap(srv.stopServer)(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if !stopped {
		t.Fatal("stop not called")
	}

	stopped = false
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/stop", nil)
	srv.wrap(srv.stopServer)(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if stopped {
		t.Fatal("stop called on GET")
	}
}

func TestGetConfigNoConfig(t *testing.T) {
	srv := New(":0", "", nil, nil, nil, nil, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	srv.wrap(srv.getConfig)(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestStopServer(t *testing.T) {
	called := false
	srv := New(":0", "", nil, nil, nil, func() { called = true }, "")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/stop", nil)
	srv.stopServer(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if !called {
		t.Fatal("stop callback not executed")
	}
}

func TestDeleteRuleSetForce(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/rulesets/"+id, nil)
	srv.handleRuleSet(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
	if _, err := os.Stat(rulePath); err != nil {
		t.Fatalf("rule file removed unexpectedly: %v", err)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/rulesets/"+id+"?force=true", nil)
	srv.handleRuleSet(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if _, err := os.Stat(rulePath); !os.IsNotExist(err) {
		t.Fatalf("rule file not deleted: %v", err)
	}

	_ = rulePath
}

func TestGetRuleSetMissingFile(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	if err := os.Remove(rulePath); err != nil {
		t.Fatalf("remove: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rulesets/"+id, nil)
	srv.handleRuleSet(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}

	_ = rulePath
}

func TestRuleIDMismatch(t *testing.T) {
	cfg, rulePath := newTestConfig(t)
	srv := New(":0", "", &cfg, nil, nil, nil, "")

	sets := config.EnumerateRuleSets(&cfg)
	if len(sets) == 0 {
		t.Fatal("no rulesets")
	}
	id := sets[0].ID

	body := []byte("rule \"bar\" {\n  action = \"allow\"\n  when { http_method = [\"GET\"] }\n}\n")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rulesets/"+id+"/rules/foo", bytes.NewReader(body))
	srv.handleRule(id, "foo", rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("post expected 400, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/rulesets/"+id+"/rules/foo", bytes.NewReader(body))
	srv.handleRule(id, "foo", rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("put expected 400, got %d", rr.Code)
	}

	_ = rulePath
}
