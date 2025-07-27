package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	data := `
listener "a" {
  bind      = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
  access_log = "a.jsonl"
}

listener "b" {
  bind      = "127.0.0.1:2"
  upstream  = "https://other.example"
  rule_file = "r.rules"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(filepath.Join(tmp, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Listeners) != 2 {
		t.Fatalf("want 2 listeners got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].ID != "a" || cfg.Listeners[1].Bind != "127.0.0.1:2" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadDefaultRules(t *testing.T) {
	data := `
defaults {
  rule_file = "shared.rules"
}

listener "a" {
  bind     = "127.0.0.1:1"
  upstream = "https://example.com"
}

listener "b" {
  bind      = "127.0.0.1:2"
  upstream  = "https://other.example"
  rule_file = "custom.rules"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(filepath.Join(tmp, "shared.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "custom.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listeners[0].RuleFile != "" {
		t.Fatalf("listener a rule_file %s", cfg.Listeners[0].RuleFile)
	}
	canonicalTmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if cfg.Listeners[1].RuleFile != filepath.Join(canonicalTmp, "custom.rules") {
		t.Fatalf("listener b rule_file %s", cfg.Listeners[1].RuleFile)
	}
}

func TestLoadMissingRulesError(t *testing.T) {
	data := `
listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing rules")
	}
}

func TestLoadMissingListenError(t *testing.T) {
	data := `
listener "a" {
  upstream  = "https://example.com"
  rule_file = "r.rules"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing listen address")
	}
}

func TestLoadMissingUpstreamError(t *testing.T) {
	data := `
listener "a" {
  bind = "127.0.0.1:1"
  rule_file = "r.rules"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing upstream address")
	}
}

func TestLoadInvalid(t *testing.T) {
	tmp := t.TempDir()
	path := tmp + "/bad.hcl"
	if err := os.WriteFile(path, []byte("["), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid hcl")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load("/nonexistent/foo.hcl"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadDuplicateListenerID(t *testing.T) {
	data := `
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
}

listener "a" {
  bind = "127.0.0.1:2"
  upstream  = "https://example.org"
  rule_file = "r.rules"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate id error")
	}
}

func TestLoadDuplicateBind(t *testing.T) {
	data := `
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
}

listener "b" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.org"
  rule_file = "r.rules"
}
`
	tmp := t.TempDir()
	path := tmp + "/cfg.hcl"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate bind error")
	}
}

func TestLoadRelativePaths(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.hcl")
	data := `
defaults {
  rule_file = "shared.rules"
}

listener "a" {
  bind      = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "rules/a.rules"
  tls {
    cert = "certs/a.pem"
    key  = "certs/a-key.pem"
  }
  access_log = "logs/a.log"
}
`
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shared.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "a.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "certs"), 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certs", "a.pem"), nil, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certs", "a-key.pem"), nil, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if cfg.Defaults.RuleFile != filepath.Join(canonicalDir, "shared.rules") {
		t.Fatalf("defaults.rule_file got %s", cfg.Defaults.RuleFile)
	}
	l := cfg.Listeners[0]
	if l.RuleFile != filepath.Join(canonicalDir, "rules/a.rules") || l.TLS.Cert != filepath.Join(canonicalDir, "certs/a.pem") || l.TLS.Key != filepath.Join(canonicalDir, "certs/a-key.pem") || l.AccessLog != filepath.Join(canonicalDir, "logs/a.log") {
		t.Fatalf("listener paths not resolved: %+v", l)
	}
}

func TestLoadRelativeConfigPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.hcl")
	data := `
defaults {
  rule_file = "shared.rules"
}

listener "a" {
  bind      = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "rules/a.rules"
  tls {
    cert = "certs/a.pem"
    key  = "certs/a-key.pem"
  }
  access_log = "logs/a.log"
}
`
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shared.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "a.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "certs"), 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certs", "a.pem"), nil, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "certs", "a-key.pem"), nil, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	subDir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(subDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(wd) }()

	cfg, err := Load("../cfg.hcl")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if cfg.Defaults.RuleFile != filepath.Join(canonicalDir, "shared.rules") {
		t.Fatalf("defaults.rule_file got %s", cfg.Defaults.RuleFile)
	}
	l := cfg.Listeners[0]
	if l.RuleFile != filepath.Join(canonicalDir, "rules/a.rules") || l.TLS.Cert != filepath.Join(canonicalDir, "certs/a.pem") || l.TLS.Key != filepath.Join(canonicalDir, "certs/a-key.pem") || l.AccessLog != filepath.Join(canonicalDir, "logs/a.log") {
		t.Fatalf("listener paths not resolved: %+v", l)
	}
}

func TestLoadSymlinkedDir(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfgPath := filepath.Join(realDir, "cfg.hcl")
	data := `
defaults {
  rule_file = "shared.rules"
}

listener "a" {
  bind      = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "rules/a.rules"
  access_log = "logs/a.log"
}
`
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "shared.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(realDir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "rules", "a.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	cfg, err := Load(filepath.Join(linkDir, "cfg.hcl"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	canonicalDir, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if cfg.Defaults.RuleFile != filepath.Join(canonicalDir, "shared.rules") {
		t.Fatalf("defaults.rule_file got %s", cfg.Defaults.RuleFile)
	}
	l := cfg.Listeners[0]
	if l.RuleFile != filepath.Join(canonicalDir, "rules/a.rules") || l.AccessLog != filepath.Join(canonicalDir, "logs/a.log") {
		t.Fatalf("listener paths not resolved: %+v", l)
	}
}

func TestLoadDefaultAction(t *testing.T) {
	data := `
defaults {
  rule_file = "r.rules.hcl"
  default_action = "deny"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(tmp, "r.rules.hcl"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Defaults.DefaultAction != "deny" {
		t.Fatalf("defaults.default_action got %s", cfg.Defaults.DefaultAction)
	}
}

func TestLoadInvalidDefaultAction(t *testing.T) {
	data := `
defaults {
  default_action = "bogus"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules.hcl"
}
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.hcl")
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid default_action")
	}
}

func TestLoadSuricataEnabledMissingDir(t *testing.T) {
	data := `
suricata {
  enabled = true
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
}
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.hcl")
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing suricata_rules_dir")
	}
}

func TestLoadSuricataRulesDirRelative(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.hcl")
	data := `
suricata {
  enabled = true
  rules_dir = "rules"
}

defaults {
  rule_file = "r.rules"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if cfg.Suricata.RulesDir != filepath.Join(canonicalDir, "rules") {
		t.Fatalf("suricata_rules_dir got %s", cfg.Suricata.RulesDir)
	}
}

func TestLoadSuricataRulesDirMissing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.hcl")
	data := fmt.Sprintf(`
suricata {
  enabled = true
  rules_dir = "%s"
}

defaults {
  rule_file = "r.rules"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`, filepath.Join(dir, "missing"))
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for missing suricata rules dir")
	}
}

func TestLoadSuricataRulesDirNotDir(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "file")
	if err := os.WriteFile(notDir, nil, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	cfgPath := filepath.Join(dir, "cfg.hcl")
	data := fmt.Sprintf(`
suricata {
  enabled = true
  rules_dir = "%s"
}

defaults {
  rule_file = "r.rules"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
}
`, notDir)
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for suricata rules dir not a directory")
	}
}

func TestLoadProxyCacheSize(t *testing.T) {
	dir := t.TempDir()
	cfg := `defaults {
  proxy_cache_size = 64
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}`
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Defaults.ProxyCacheSize != 64 {
		t.Fatalf("cache size %d", c.Defaults.ProxyCacheSize)
	}
}

func TestLoadAdminSSEBlocks(t *testing.T) {
	dir := t.TempDir()
	cfg := `admin {
  enabled = true
  addr = ":9000"
}
sse {
  enabled = true
  addr = ":9001"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}`
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Admin == nil || !c.Admin.Enabled || c.Admin.Addr != ":9000" {
		t.Fatalf("admin block not loaded: %+v", c.Admin)
	}
	if c.SSE == nil || !c.SSE.Enabled || c.SSE.Addr != ":9001" {
		t.Fatalf("sse block not loaded: %+v", c.SSE)
	}
}

func TestLoadTLSOnlyCertError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	data := fmt.Sprintf(`
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
  tls {
    cert = "%s"
  }
}
`, certPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for tls cert only")
	}
}

func TestLoadTLSOnlyKeyError(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, []byte("key"), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	data := fmt.Sprintf(`
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
  tls {
    key = "%s"
  }
}
`, keyPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for tls key only")
	}
}

func TestLoadTLSCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	data := fmt.Sprintf(`
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
  tls {
    cert = "%s"
    key  = "%s"
  }
}
`, certPath, keyPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err != nil {
		t.Fatalf("load: %v", err)
	}
}

func TestLoadTLSCertMissingFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, []byte("key"), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	certPath := filepath.Join(dir, "missing.pem")
	data := fmt.Sprintf(`
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
  tls {
    cert = "%s"
    key  = "%s"
  }
}
`, certPath, keyPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for missing tls cert file")
	}
}

func TestLoadTLSKeyMissingFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyPath := filepath.Join(dir, "missing.pem")
	data := fmt.Sprintf(`
listener "a" {
  bind = "127.0.0.1:1"
  upstream  = "https://example.com"
  rule_file = "r.rules"
  tls {
    cert = "%s"
    key  = "%s"
  }
}
`, certPath, keyPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for missing tls key file")
	}
}

func TestLoadDefaultsUpstreamCAFileMissing(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	cfg := fmt.Sprintf(`
defaults {
  upstream_ca_file = "%s"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}
`, caPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for missing upstream ca file in defaults")
	}
}

func TestLoadListenerUpstreamCAFileMissing(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	data := fmt.Sprintf(`
listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
  upstream_ca_file = "%s"
}
`, caPath)
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error for missing upstream ca file")
	}
}

func TestLoadNoListeners(t *testing.T) {
	data := `
defaults {
  rule_file = "shared.rules"
}
`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.hcl")
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing listeners")
	}
}

func TestLoadGalahMissingBlock(t *testing.T) {
	dir := t.TempDir()
	rule := `
rule "a" {
  action = "deceive"
  when {}
}
`
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), []byte(rule), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := `
listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}
`
	path := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for missing galah block")
	}
}

func TestLoadGalahOK(t *testing.T) {
	dir := t.TempDir()
	rule := `
rule "a" {
  action = "deceive"
  when {}
}
`
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), []byte(rule), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := `
galah {
  provider = "openai"
  model = "gpt"
  api_key = "abc"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}
`
	path := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
}

func TestLoadGalahRelativePaths(t *testing.T) {
	dir := t.TempDir()
	rule := `
rule "a" {
  action = "deceive"
  when {}
}`
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), []byte(rule), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := `
galah {
  provider = "openai"
  model = "gpt"
  api_key = "abc"
  config_file = "galah.hcl"
  cache_file = "cache.db"
}

listener "a" {
  bind = "127.0.0.1:1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}`
	cfgPath := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "galah.hcl"), nil, 0o644); err != nil {
		t.Fatalf("write galah config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cache.db"), nil, 0o644); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	cfgLoaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("evalsymlink: %v", err)
	}
	if cfgLoaded.Galah.ConfigFile != filepath.Join(canonicalDir, "galah.hcl") || cfgLoaded.Galah.CacheFile != filepath.Join(canonicalDir, "cache.db") {
		t.Fatalf("galah paths not resolved: %+v", cfgLoaded.Galah)
	}
}

func TestLoadInvalidBindAddress(t *testing.T) {
	data := `
listener "a" {
  bind = "127.0.0.1"
  upstream = "https://example.com"
  rule_file = "r.rules"
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid bind address")
	}
}

func TestLoadInvalidUpstreamURL(t *testing.T) {
	data := `
listener "a" {
  bind = "127.0.0.1:1"
  upstream = "example.com"
  rule_file = "r.rules"
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.hcl")
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid upstream url")
	}
}

func TestLoadJSON(t *testing.T) {
	data := `{"listeners": [
                {"id":"a","bind":"127.0.0.1:1","upstream":"https://example.com","rule_file":"r.rules","access_log":"a.jsonl"},
                {"id":"b","bind":"127.0.0.1:2","upstream":"https://other.example","rule_file":"r.rules"}
        ]}`
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	if err := os.WriteFile(filepath.Join(tmp, "r.rules"), nil, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadJSON(path)
	if err != nil {
		t.Fatalf("load json: %v", err)
	}
	if len(cfg.Listeners) != 2 || cfg.Listeners[0].ID != "a" || cfg.Listeners[1].Bind != "127.0.0.1:2" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestWriteJSON(t *testing.T) {
	cfg := Config{
		Listeners: []ListenerConfig{{ID: "a", Bind: "127.0.0.1:1", Upstream: "https://example.com"}},
	}
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfg.json")
	if err := WriteJSON(path, &cfg); err != nil {
		t.Fatalf("write json: %v", err)
	}
	cfg2, err := ReadJSON(path)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	if len(cfg2.Listeners) != 1 || cfg2.Listeners[0].ID != "a" {
		t.Fatalf("unexpected read config: %+v", cfg2)
	}
}

func TestWriteJSONFileMode(t *testing.T) {
	cfg := Config{
		Listeners: []ListenerConfig{{ID: "a", Bind: "127.0.0.1:1", Upstream: "https://example.com"}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := WriteJSON(path, &cfg); err != nil {
		t.Fatalf("write json: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v want 0600", info.Mode().Perm())
	}
}

func TestResolvePathsSymlinkDir(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	cfg := Config{
		Defaults: &Defaults{RuleFile: "shared.rules"},
		Suricata: &SuricataConfig{RulesDir: "suricata"},
		Galah:    &GalahConfig{ConfigFile: "galah.hcl"},
		Listeners: []ListenerConfig{{
			ID:             "a",
			Bind:           "127.0.0.1:1",
			Upstream:       "https://example.com",
			RuleFile:       "rules/a.rules",
			TLS:            &TLSConfig{Cert: "certs/a.pem", Key: "certs/a-key.pem"},
			AccessLog:      "logs/a.log",
			UpstreamCAFile: "ca.pem",
		}},
	}
	if err := ResolvePaths(&cfg, linkDir); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	canonical, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if cfg.Defaults.RuleFile != filepath.Join(canonical, "shared.rules") {
		t.Fatalf("defaults.rule_file %s", cfg.Defaults.RuleFile)
	}
	if cfg.Suricata.RulesDir != filepath.Join(canonical, "suricata") {
		t.Fatalf("suricata.rules_dir %s", cfg.Suricata.RulesDir)
	}
	if cfg.Galah.ConfigFile != filepath.Join(canonical, "galah.hcl") {
		t.Fatalf("galah.config_file %s", cfg.Galah.ConfigFile)
	}
	l := cfg.Listeners[0]
	if l.RuleFile != filepath.Join(canonical, "rules/a.rules") ||
		l.TLS.Cert != filepath.Join(canonical, "certs/a.pem") ||
		l.TLS.Key != filepath.Join(canonical, "certs/a-key.pem") ||
		l.AccessLog != filepath.Join(canonical, "logs/a.log") ||
		l.UpstreamCAFile != filepath.Join(canonical, "ca.pem") {
		t.Fatalf("listener paths not resolved: %+v", l)
	}
}
