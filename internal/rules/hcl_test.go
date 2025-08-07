package rules

import (
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/0x4D31/finch/internal/fingerprint"
)

func TestLoadHCLAndMatch(t *testing.T) {
	hcl := `rule "deny-bot" {
  action = "deny"
  when all {
    tls_ja3    = ["abcd"]
    http_ja4h  = ["^ bad"]
    http_http2 = ["h2fp"]
    http_path  = ["/foo"]
    client_ip  = ["192.168.0.0/16"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rs, err := LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule")
	}
	r := rs.Rules[0]
	ctx := &fingerprint.RequestCtx{
		JA3:   "abcd",
		JA4H:  "badfinger",
		HTTP2: "h2fp",
		Path:  "/foo",
		SrcIP: net.ParseIP("192.168.0.1"),
	}
	if !r.Expr.Eval(ctx) {
		t.Fatal("expected match")
	}
}

func TestLoadHCLUnknownField(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  when all {
    unknown.field = ["x"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = LoadHCL(tmp.Name())
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadHCLHeaderNotQuoted(t *testing.T) {
	hcl := `rule "bad" {
  action = "deny"
  when {
    http_header[X-Test] = ["v"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for unquoted header name")
	}
}

func TestLoadHCLHeaderMap(t *testing.T) {
	hcl := `rule "good" {
  action = "deny"
  when {
    http_header = {
      "X-Test" = ["val"]
    }
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rs, err := LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule")
	}
	ctx := &fingerprint.RequestCtx{Headers: http.Header{"X-Test": {"val"}}}
	if !rs.Rules[0].Expr.Eval(ctx) {
		t.Fatal("expected match")
	}
}

func TestLoadHCLInvalidWhenLabel(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  when xyz {
    http_path = ["/foo"]
    tls_ja3   = ["abcd"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for unknown when label")
	}
}

func TestLoadHCLWhenDefaultAll(t *testing.T) {
	hcl := `rule "match-path" {
  action = "allow"
  when {
    http_path = ["/foo"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rs, err := LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule")
	}
	r := rs.Rules[0]
	ctx := &fingerprint.RequestCtx{Path: "/foo"}
	if !r.Expr.Eval(ctx) {
		t.Fatal("expected match")
	}
}

func TestLoadHCLStripPrefixNonString(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  strip_prefix = false

  when {
    http_path = ["/foo"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = LoadHCL(tmp.Name())
	if err == nil {
		t.Fatal("expected error for non-string strip_prefix")
	}
}

func TestLoadHCLDuplicateRuleName(t *testing.T) {
	hcl := `rule "dup" {
  action = "allow"
  when { http_path = ["/foo"] }
}

rule "dup" {
  action = "allow"
  when { http_path = ["/bar"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected duplicate rule id error")
	}
}

func TestLoadHCLMissingAction(t *testing.T) {
	hcl := `rule "bad" {
  when { http_path = ["/foo"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = LoadHCL(tmp.Name())
	if err == nil {
		t.Fatal("expected error for missing action")
	}
	if !strings.Contains(err.Error(), "missing action") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadHCLUpstreamRequiresRoute(t *testing.T) {
	hcl := `rule "bad" {
  action = "deny"
  upstream = "https://example.com"
  when { http_path = ["/"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for upstream with non-route action")
	}
}

func TestLoadHCLRouteMissingUpstream(t *testing.T) {
	hcl := `rule "bad" {
  action = "route"
  when { http_path = ["/"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = LoadHCL(tmp.Name())
	if err == nil {
		t.Fatal("expected error for missing upstream")
	}
	if !strings.Contains(err.Error(), "missing upstream") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadHCLStripPrefixRequiresRoute(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  strip_prefix = "/foo"
  when { http_path = ["/foo"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for strip_prefix with non-route action")
	}
}

func TestLoadHCLStripPrefixNeedsSlash(t *testing.T) {
	hcl := `rule "bad" {
  action = "route"
  upstream = "https://example.com"
  strip_prefix = "foo"
  when { http_path = ["/foo"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for strip_prefix without leading slash")
	}
}

func TestLoadHCLInvalidAttributeExpressions(t *testing.T) {
	cases := []string{
		`rule "bad" {
  action = foo
  when { http_path = ["/a"] }
}`,
		`rule "bad" {
  action = "allow"
  upstream = bar
  when { http_path = ["/a"] }
}`,
		`rule "bad" {
  action = "allow"
  expires = baz
  when { http_path = ["/a"] }
}`,
	}

	for i, hcl := range cases {
		tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
		if err != nil {
			t.Fatalf("temp %d: %v", i, err)
		}
		if _, err := tmp.WriteString(hcl); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if err := tmp.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
		if _, err := LoadHCL(tmp.Name()); err == nil {
			t.Fatalf("expected error for invalid attribute expression %d", i)
		}
	}
}

func TestLoadHCLLiteralPreserved(t *testing.T) {
	hcl := `rule "msg" {
  action = "deny"
  when {
    suricata_msg = ["suricata.msg http_path tls_ja3"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rs, err := LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	ctx := &fingerprint.RequestCtx{SuricataMsgs: []string{"suricata.msg http_path tls_ja3"}}
	if !rs.Rules[0].Expr.Eval(ctx) {
		t.Fatal("expected match")
	}
}

func TestLoadHCLMultipleWhenBlocks(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  when { http_path = ["/a"] }
  when { http_method = ["GET"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for multiple when blocks")
	}
}

func TestLoadHCLUnknownRuleAttribute(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  unknown = true
  when { http_path = ["/"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for unknown attribute")
	}
}

func TestLoadHCLUnknownRuleBlock(t *testing.T) {
	hcl := `rule "bad" {
  action = "allow"
  foo {}
  when { http_path = ["/"] }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := LoadHCL(tmp.Name()); err == nil {
		t.Fatal("expected error for unknown block")
	}
}

func TestLoadHCLInvalidClientIP(t *testing.T) {
	hcl := `rule "bad" {
  action = "deny"
  when {
    client_ip = ["bad"]
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = LoadHCL(tmp.Name())
	if err == nil {
		t.Fatal("expected error for invalid ip")
	}
	if !strings.Contains(err.Error(), "invalid ip") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadHCLDeceiveModes(t *testing.T) {
	cases := []struct {
		name string
		hcl  string
		want string
	}{
		{
			name: "default-mode",
			hcl: `rule "d" {
  action = "deceive"
  when {}
}`,
			want: "galah",
		},
		{
			name: "explicit-galah",
			hcl: `rule "d" {
  action = "deceive"
  deception_mode = "galah"
  when {}
}`,
			want: "galah",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
			if err != nil {
				t.Fatalf("temp: %v", err)
			}
			if _, err := tmp.WriteString(tt.hcl); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := tmp.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			rs, err := LoadHCL(tmp.Name())
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(rs.Rules) != 1 {
				t.Fatalf("expected 1 rule")
			}
			r := rs.Rules[0]
			if r.Action != ActionDeceive {
				t.Fatalf("want action deceive got %s", r.Action)
			}
			if r.DeceptionMode != tt.want {
				t.Fatalf("mode want %s got %s", tt.want, r.DeceptionMode)
			}
		})
	}
}

func TestLoadHCLTarpitAction(t *testing.T) {
	hcl := `rule "t" {
  action = "tarpit"
  when {}
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	rs, err := LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule")
	}
	r := rs.Rules[0]
	if r.Action != ActionTarpit {
		t.Fatalf("want action tarpit got %s", r.Action)
	}
	if r.DeceptionMode != "" {
		t.Fatalf("expected empty deception_mode got %s", r.DeceptionMode)
	}
}

func TestLoadHCLNestedWhenAny(t *testing.T) {
	hcl := `rule "nested" {
  action = "deny"
  when {
    http_path = ["/foo"]
    when any {
      tls_ja3    = ["abcd"]
      http_method = ["POST"]
    }
  }
}`
	tmp, err := os.CreateTemp(t.TempDir(), "rule-*.hcl")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.WriteString(hcl); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	rs, err := LoadHCL(tmp.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("expected 1 rule")
	}
	r := rs.Rules[0]
	cases := []struct {
		ctx   fingerprint.RequestCtx
		match bool
	}{
		{ctx: fingerprint.RequestCtx{Path: "/foo", JA3: "abcd"}, match: true},
		{ctx: fingerprint.RequestCtx{Path: "/foo", Method: "POST"}, match: true},
		{ctx: fingerprint.RequestCtx{Path: "/foo"}, match: false},
		{ctx: fingerprint.RequestCtx{JA3: "abcd"}, match: false},
	}
	for i, tt := range cases {
		if r.Expr.Eval(&tt.ctx) != tt.match {
			t.Fatalf("case %d expected %v", i, tt.match)
		}
	}
}
