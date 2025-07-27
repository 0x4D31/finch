package rules

import (
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/fingerprint"
)

func loadRuleFromString(t *testing.T, hcl string) *Engine {
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
	return &Engine{Rules: rs.Rules, DefaultAction: ActionAllow}
}

func TestRuleExpiration(t *testing.T) {
	hcl := `rule "exp" {
  action = "deny"
  expires = "2000-01-01T00:00:00Z"
  when { http_path = ["/"] }
}`
	eng := loadRuleFromString(t, hcl)
	ctx := &fingerprint.RequestCtx{Path: "/"}
	if r := eng.EvalRule(ctx); r != nil {
		t.Fatalf("expected no rule match, got %s", r.ID)
	}
}

func TestRuleExpirationFuture(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).UTC()
	eng := &Engine{Rules: []*Rule{{ID: "exp", Action: ActionDeny, Expires: &exp, Expr: Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }}}}, DefaultAction: ActionAllow}
	if r := eng.EvalRule(&fingerprint.RequestCtx{}); r == nil || r.ID != "exp" {
		t.Fatalf("expected rule match before expiry")
	}
}

func TestDefaultActionUpdate(t *testing.T) {
	eng := &Engine{DefaultAction: ActionAllow}
	eng.Load(&RuleSet{})
	eng.DefaultAction = ActionDeny
	a, _, _ := eng.Eval(&fingerprint.RequestCtx{})
	if a != ActionDeny {
		t.Fatalf("default action not updated")
	}
}

func TestRuleOrdering(t *testing.T) {
	r1 := &Rule{ID: "one", Action: ActionDeny, Expr: Cond{Matcher: func(c *fingerprint.RequestCtx) bool { return c.Path == "/foo" }}}
	r2 := &Rule{ID: "two", Action: ActionAllow, Expr: Cond{Matcher: func(c *fingerprint.RequestCtx) bool { return c.Path == "/foo" }}}
	eng := &Engine{Rules: []*Rule{r1, r2}, DefaultAction: ActionAllow}
	r := eng.EvalRule(&fingerprint.RequestCtx{Path: "/foo"})
	if r == nil || r.ID != "one" {
		t.Fatalf("expected first rule to match")
	}
	past := time.Now().Add(-time.Hour)
	r1.Expires = &past
	r = eng.EvalRule(&fingerprint.RequestCtx{Path: "/foo"})
	if r == nil || r.ID != "two" {
		t.Fatalf("expected second rule after first expired")
	}
}

func TestRuleConditions(t *testing.T) {
	tests := []struct {
		name string
		hcl  string
		expr Expr
		ctx  fingerprint.RequestCtx
	}{
		{
			name: "tls_ja3",
			hcl: `rule "r" {
  action = "deny"
  when {
    tls_ja3 = ["abcd"]
  }
}`,
			ctx: fingerprint.RequestCtx{JA3: "abcd"},
		},
		{
			name: "tls_ja4",
			hcl: `rule "r" {
  action = "deny"
  when {
    tls_ja4 = ["qwer"]
  }
}`,
			ctx: fingerprint.RequestCtx{JA4: "qwer"},
		},
		{
			name: "http_ja4h",
			hcl: `rule "r" {
  action = "deny"
  when {
    http_ja4h = ["^ finger"]
  }
}`,
			ctx: fingerprint.RequestCtx{JA4H: "fingerprint"},
		},
		{
			name: "http_http2",
			hcl: `rule "r" {
  action = "deny"
  when {
    http_http2 = ["h2fp"]
  }
}`,
			ctx: fingerprint.RequestCtx{HTTP2: "h2fp"},
		},
		{
			name: "http_method",
			hcl: `rule "r" {
  action = "deny"
  when {
    http_method = ["POST"]
  }
}`,
			ctx: fingerprint.RequestCtx{Method: "POST"},
		},
		{
			name: "http_path",
			hcl: `rule "r" {
  action = "deny"
  when {
    http_path = ["/foo"]
  }
}`,
			ctx: fingerprint.RequestCtx{Path: "/foo"},
		},
		{
			name: "http_header",
			expr: func() Expr {
				e, err := compileFieldCond("http_header[\"X-Test\"]", []string{"i:^ value"})
				if err != nil {
					panic(err)
				}
				return e
			}(),
			ctx: fingerprint.RequestCtx{Headers: http.Header{"X-Test": {"Value123"}}},
		},
		{
			name: "http_header rule non-canonical",
			expr: func() Expr {
				e, err := compileFieldCond("http_header[\"x-test\"]", []string{"i:^ value"})
				if err != nil {
					panic(err)
				}
				return e
			}(),
			ctx: fingerprint.RequestCtx{Headers: http.Header{"X-Test": {"Value123"}}},
		},
		{
			name: "http_header regex ci lowercase",
			expr: func() Expr {
				e, err := compileFieldCond("http_header[\"X-Reg\"]", []string{"i:~ FoO"})
				if err != nil {
					panic(err)
				}
				return e
			}(),
			ctx: fingerprint.RequestCtx{Headers: http.Header{"X-Reg": {"foo"}}},
		},
		{
			name: "http_header regex ci uppercase",
			expr: func() Expr {
				e, err := compileFieldCond("http_header[\"X-Reg\"]", []string{"i:~ FoO"})
				if err != nil {
					panic(err)
				}
				return e
			}(),
			ctx: fingerprint.RequestCtx{Headers: http.Header{"X-Reg": {"FOO"}}},
		},
		{
			name: "http_header glob ci",
			expr: func() Expr {
				e, err := compileFieldCond("http_header[\"X-Glob\"]", []string{"i:^ Val"})
				if err != nil {
					panic(err)
				}
				return e
			}(),
			ctx: fingerprint.RequestCtx{Headers: http.Header{"X-Glob": {"VALUE123"}}},
		},
		{
			name: "client_ip",
			hcl: `rule "r" {
  action = "deny"
  when {
    client_ip = ["192.168.0.0/16"]
  }
}`,
			ctx: fingerprint.RequestCtx{SrcIP: net.ParseIP("192.168.0.5")},
		},
		{
			name: "client_ip ipv6",
			hcl: `rule "r" {
  action = "deny"
  when {
    client_ip = ["2001:db8::/32"]
  }
}`,
			ctx: fingerprint.RequestCtx{SrcIP: net.ParseIP("2001:db8::1")},
		},
		{
			name: "suricata_msg",
			hcl: `rule "r" {
  action = "deny"
  when {
    suricata_msg = ["^ alert"]
  }
}`,
			ctx: fingerprint.RequestCtx{SuricataMsgs: []string{"alert test"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var eng *Engine
			if tt.expr != nil {
				eng = &Engine{Rules: []*Rule{{ID: "r", Action: ActionDeny, Expr: tt.expr}}, DefaultAction: ActionAllow}
			} else {
				eng = loadRuleFromString(t, tt.hcl)
			}
			c := tt.ctx
			if r := eng.EvalRule(&c); r == nil || r.ID != "r" {
				t.Fatalf("rule did not match")
			}
		})
	}
}

func TestEvalCompositeLocalDefault(t *testing.T) {
	local := &Engine{DefaultAction: ActionDeny}
	ctx := &fingerprint.RequestCtx{}
	a, up, id, r, _ := EvalComposite(local, nil, ctx)
	if a != ActionDeny || up != "" || id != "" || r != nil {
		t.Fatalf("unexpected result: %v %q %q %v", a, up, id, r)
	}
}

func TestEvalCompositeGlobalDefault(t *testing.T) {
	global := &Engine{DefaultAction: ActionDeny}
	ctx := &fingerprint.RequestCtx{}
	a, up, id, r, _ := EvalComposite(nil, global, ctx)
	if a != ActionDeny || up != "" || id != "" || r != nil {
		t.Fatalf("unexpected result: %v %q %q %v", a, up, id, r)
	}
}

func TestSuricataMsgCaseInsensitive(t *testing.T) {
	expr, err := compileFieldCond("suricata_msg", []string{"i:alert"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := &fingerprint.RequestCtx{SuricataMsgs: []string{"ALERT"}}
	if !expr.Eval(ctx) {
		t.Fatal("expected match")
	}
}

func TestSuricataMsgCaseSensitive(t *testing.T) {
	expr, err := compileFieldCond("suricata_msg", []string{"ALERT"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx := &fingerprint.RequestCtx{SuricataMsgs: []string{"alert"}}
	if expr.Eval(ctx) {
		t.Fatal("expected no match")
	}
}

func TestRuleNoMatchWithoutFingerprint(t *testing.T) {
	expr, err := compileFieldCond("tls_ja3", []string{"abcd"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	eng := &Engine{Rules: []*Rule{{ID: "r", Action: ActionDeny, Expr: expr}}, DefaultAction: ActionAllow}
	ctx := &fingerprint.RequestCtx{}
	if r := eng.EvalRule(ctx); r != nil {
		t.Fatalf("expected no match, got %s", r.ID)
	}
	a, _, id := eng.Eval(ctx)
	if a != ActionAllow || id != "" {
		t.Fatalf("unexpected result: %v %q", a, id)
	}
}
