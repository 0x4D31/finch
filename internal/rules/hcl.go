package rules

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/0x4D31/finch/internal/fingerprint"
)

// New rule engine structures inspired by HCL based DSL.

// Expr represents a boolean expression node.
type Expr interface {
	Eval(*fingerprint.RequestCtx) bool
}

type And struct{ Kids []Expr }

func (a And) Eval(c *fingerprint.RequestCtx) bool {
	for _, k := range a.Kids {
		if !k.Eval(c) {
			return false
		}
	}
	return true
}

type Or struct{ Kids []Expr }

func (o Or) Eval(c *fingerprint.RequestCtx) bool {
	for _, k := range o.Kids {
		if k.Eval(c) {
			return true
		}
	}
	return false
}

// Cond wraps a matcher function.
type Cond struct {
	Matcher func(*fingerprint.RequestCtx) bool
}

func (c Cond) Eval(ctx *fingerprint.RequestCtx) bool { return c.Matcher(ctx) }

// Rule is a compiled rule from the HCL file.
type Rule struct {
	ID            string
	Action        Action
	DeceptionMode string
	Upstream      *url.URL
	StripPrefix   string
	Expires       *time.Time
	Expr          Expr
}

// RuleSet is a set of compiled rules.
type RuleSet struct{ Rules []*Rule }

// FieldGetter returns zero or more values for a field.
type FieldGetter func(*fingerprint.RequestCtx) []string

var registry = map[string]FieldGetter{
	"tls_ja3":     func(c *fingerprint.RequestCtx) []string { return []string{c.JA3} },
	"tls_ja4":     func(c *fingerprint.RequestCtx) []string { return []string{c.JA4} },
	"http_ja4h":   func(c *fingerprint.RequestCtx) []string { return []string{c.JA4H} },
	"http_http2":  func(c *fingerprint.RequestCtx) []string { return []string{c.HTTP2} },
	"http_method": func(c *fingerprint.RequestCtx) []string { return []string{c.Method} },
	"http_path":   func(c *fingerprint.RequestCtx) []string { return []string{c.Path} },
	"client_ip": func(c *fingerprint.RequestCtx) []string {
		if c.SrcIP != nil {
			return []string{c.SrcIP.String()}
		}
		return nil
	},
	// suricata_msg and http_header handled separately
}

// withRange appends line and column information to an error using the provided range.
func withRange(err error, r hcl.Range) error {
	return fmt.Errorf("%w at %d:%d", err, r.Start.Line, r.Start.Column)
}

// rangeFromDiags returns the first diagnostic's subject range, if any.
func rangeFromDiags(diags hcl.Diagnostics) hcl.Range {
	for _, d := range diags {
		if d.Subject != nil {
			return *d.Subject
		}
	}
	return hcl.Range{}
}

type ruleBlock struct {
	Name          string    `hcl:",label"`
	Action        string    `hcl:"action"`
	DeceptionMode string    `hcl:"deception_mode,optional"`
	Upstream      string    `hcl:"upstream,optional"`
	StripPrefix   string    `hcl:"strip_prefix,optional"`
	Expires       string    `hcl:"expires,optional"`
	When          whenBlock `hcl:"when,block"`
}

type whenBlock struct {
	Type string      `hcl:",label,optional"`
	Body hcl.Body    `hcl:",remain"`
	Kids []whenBlock `hcl:"when,block"`
}

func decodeRuleBlock(b *hcl.Block) (ruleBlock, error) {
	var rb ruleBlock
	if len(b.Labels) != 1 {
		return rb, withRange(fmt.Errorf("rule block missing name"), b.DefRange)
	}
	rb.Name = b.Labels[0]

	body, ok := b.Body.(*hclsyntax.Body)
	if !ok {
		return rb, withRange(fmt.Errorf("unexpected body type"), b.DefRange)
	}

	// Validate attributes upfront to catch unknown keys.
	for name, attr := range body.Attributes {
		switch name {
		case "action", "deception_mode", "upstream", "strip_prefix", "expires":
			// allowed
		default:
			return rb, withRange(fmt.Errorf("rule %s: unknown attribute %s", rb.Name, name), attr.SrcRange)
		}
	}

	if attr, ok := body.Attributes["action"]; ok {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return rb, withRange(fmt.Errorf("rule %s: invalid action", rb.Name), rangeFromDiags(diags))
		}
		if v.Type() != cty.String {
			return rb, withRange(fmt.Errorf("rule %s: action must be a string", rb.Name), attr.SrcRange)
		}
		rb.Action = v.AsString()
	}
	if attr, ok := body.Attributes["deception_mode"]; ok {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return rb, withRange(fmt.Errorf("rule %s: invalid deception_mode", rb.Name), rangeFromDiags(diags))
		}
		if v.Type() != cty.String {
			return rb, withRange(fmt.Errorf("rule %s: deception_mode must be a string", rb.Name), attr.SrcRange)
		}
		rb.DeceptionMode = v.AsString()
	}
	if attr, ok := body.Attributes["upstream"]; ok {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return rb, withRange(fmt.Errorf("rule %s: invalid upstream", rb.Name), rangeFromDiags(diags))
		}
		if v.Type() != cty.String {
			return rb, withRange(fmt.Errorf("rule %s: upstream must be a string", rb.Name), attr.SrcRange)
		}
		rb.Upstream = v.AsString()
	}
	if attr, ok := body.Attributes["strip_prefix"]; ok {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return rb, withRange(fmt.Errorf("rule %s: invalid strip_prefix", rb.Name), rangeFromDiags(diags))
		}
		if v.Type() != cty.String {
			return rb, withRange(fmt.Errorf("rule %s: strip_prefix must be a string", rb.Name), attr.SrcRange)
		}
		rb.StripPrefix = v.AsString()
	}
	if attr, ok := body.Attributes["expires"]; ok {
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			return rb, withRange(fmt.Errorf("rule %s: invalid expires", rb.Name), rangeFromDiags(diags))
		}
		if v.Type() != cty.String {
			return rb, withRange(fmt.Errorf("rule %s: expires must be a string", rb.Name), attr.SrcRange)
		}
		rb.Expires = v.AsString()
	}

	var whenBlk *hclsyntax.Block
	for _, blk := range body.Blocks {
		switch blk.Type {
		case "when":
			if whenBlk != nil {
				return rb, withRange(fmt.Errorf("rule %s: multiple when blocks", rb.Name), blk.TypeRange)
			}
			whenBlk = blk
		default:
			return rb, withRange(fmt.Errorf("rule %s: unknown block %s", rb.Name, blk.Type), blk.TypeRange)
		}
	}
	if whenBlk == nil {
		return rb, withRange(fmt.Errorf("rule %s: missing when block", rb.Name), b.DefRange)
	}

	wb, err := decodeWhenBlock(whenBlk)
	if err != nil {
		return rb, err
	}
	rb.When = wb
	return rb, nil
}

func decodeWhenBlock(b *hclsyntax.Block) (whenBlock, error) {
	var wb whenBlock
	if len(b.Labels) > 0 {
		wb.Type = b.Labels[0]
	}

	body := b.Body

	attrBody := &hclsyntax.Body{Attributes: map[string]*hclsyntax.Attribute{}, SrcRange: body.SrcRange}
	for name, attr := range body.Attributes {
		attrBody.Attributes[name] = attr
	}
	wb.Body = attrBody

	for _, blk := range body.Blocks {
		if blk.Type != "when" {
			continue
		}
		sub, err := decodeWhenBlock(blk)
		if err != nil {
			return wb, err
		}
		wb.Kids = append(wb.Kids, sub)
	}

	return wb, nil
}

// LoadHCL loads rules from an HCL file.
func LoadHCL(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadHCLBytes(data)
}

// LoadHCLBytes loads rules from an HCL byte slice.
func LoadHCLBytes(data []byte) (*RuleSet, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(data, "<mem>")
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: "rule", LabelNames: []string{"name"}}},
	}
	content, diags := file.Body.Content(schema)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	rs := &RuleSet{}
	ids := make(map[string]struct{})
	for _, blk := range content.Blocks {
		rb, err := decodeRuleBlock(blk)
		if err != nil {
			return nil, err
		}
		if _, ok := ids[rb.Name]; ok {
			return nil, fmt.Errorf("duplicate rule id %s", rb.Name)
		}
		ids[rb.Name] = struct{}{}
		r, err := compileRule(rb)
		if err != nil {
			return nil, err
		}
		rs.Rules = append(rs.Rules, r)
	}
	return rs, nil
}

func compileRule(rb ruleBlock) (*Rule, error) {
	var r Rule
	r.ID = rb.Name
	if rb.Action == "" {
		return nil, fmt.Errorf("rule %s: missing action", rb.Name)
	}
	switch rb.Action {
	case string(ActionAllow), string(ActionDeny), string(ActionRoute), string(ActionDeceive), string(ActionTarpit):
		r.Action = Action(rb.Action)
	default:
		return nil, fmt.Errorf("rule %s: invalid action", rb.Name)
	}
	if rb.DeceptionMode != "" && r.Action != ActionDeceive {
		return nil, fmt.Errorf("rule %s: deception_mode requires action \"deceive\"", rb.Name)
	}
	if rb.Upstream != "" && r.Action != ActionRoute {
		return nil, fmt.Errorf("rule %s: upstream requires action \"route\"", rb.Name)
	}
	if r.Action == ActionRoute && rb.Upstream == "" {
		return nil, fmt.Errorf("rule %s: missing upstream", rb.Name)
	}
	if rb.StripPrefix != "" {
		if r.Action != ActionRoute {
			return nil, fmt.Errorf("rule %s: strip_prefix requires action \"route\"", rb.Name)
		}
		if !strings.HasPrefix(rb.StripPrefix, "/") {
			return nil, fmt.Errorf("rule %s: strip_prefix must begin with '/'", rb.Name)
		}
	}
	if r.Action == ActionDeceive {
		mode := strings.ToLower(rb.DeceptionMode)
		if mode == "" {
			mode = "galah"
		}
		if mode != "galah" {
			return nil, fmt.Errorf("rule %s: invalid deception_mode", rb.Name)
		}
		r.DeceptionMode = mode
	}
	if rb.Upstream != "" {
		u, err := url.Parse(rb.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("rule %s: invalid upstream", rb.Name)
		}
		r.Upstream = u
	}
	if rb.Expires != "" {
		t, err := time.Parse(time.RFC3339, rb.Expires)
		if err != nil {
			return nil, fmt.Errorf("rule %s: bad expires", rb.Name)
		}
		r.Expires = &t
	}
	expr, err := compileWhen(rb.When)
	if err != nil {
		return nil, err
	}
	r.Expr = expr
	r.StripPrefix = rb.StripPrefix
	return &r, nil
}

func compileWhen(w whenBlock) (Expr, error) {
	var kids []Expr
	if w.Body != nil {
		attrs, _ := w.Body.JustAttributes()
		for name, attr := range attrs {
			if name == "http_header" {
				v, diags := attr.Expr.Value(nil)
				if diags.HasErrors() {
					return nil, withRange(fmt.Errorf("decode http_header map"), rangeFromDiags(diags))
				}
				if !v.Type().IsObjectType() && !v.Type().IsMapType() {
					return nil, withRange(fmt.Errorf("http_header must be an object"), attr.Range)
				}
				it := v.ElementIterator()
				for it.Next() {
					k, val := it.Element()
					vs, err := decodeStringsValue(val)
					if err != nil {
						return nil, withRange(err, attr.Range)
					}
					cond, err := compileHeaderCond(k.AsString(), vs)
					if err != nil {
						return nil, withRange(err, attr.Range)
					}
					kids = append(kids, cond)
				}
				continue
			}

			vs, err := decodeStrings(attr.Expr)
			if err != nil {
				return nil, withRange(err, attr.Range)
			}
			cond, err := compileFieldCond(name, vs)
			if err != nil {
				return nil, withRange(err, attr.Range)
			}
			kids = append(kids, cond)
		}
	}
	for _, sub := range w.Kids {
		e, err := compileWhen(sub)
		if err != nil {
			return nil, err
		}
		kids = append(kids, e)
	}
	if len(kids) == 0 {
		return Cond{Matcher: func(*fingerprint.RequestCtx) bool { return true }}, nil
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	t := w.Type
	if t == "" {
		t = "all"
	}
	switch t {
	case "all":
		return And{Kids: kids}, nil
	case "any":
		return Or{Kids: kids}, nil
	default:
		return nil, fmt.Errorf("unknown when block %s", t)
	}
}

func decodeStrings(expr hcl.Expression) ([]string, error) {
	v, diags := expr.Value(nil)
	if diags.HasErrors() {
		return nil, withRange(fmt.Errorf("decode value"), rangeFromDiags(diags))
	}
	switch {
	case v.Type().IsTupleType() || v.Type().IsListType():
		var out []string
		it := v.ElementIterator()
		for it.Next() {
			_, ev := it.Element()
			out = append(out, ev.AsString())
		}
		return out, nil
	case v.Type() == cty.String:
		return []string{v.AsString()}, nil
	default:
		return nil, withRange(fmt.Errorf("unsupported value type"), expr.Range())
	}
}

func decodeStringsValue(v cty.Value) ([]string, error) {
	switch {
	case v.Type().IsTupleType() || v.Type().IsListType():
		var out []string
		it := v.ElementIterator()
		for it.Next() {
			_, ev := it.Element()
			out = append(out, ev.AsString())
		}
		return out, nil
	case v.Type() == cty.String:
		return []string{v.AsString()}, nil
	default:
		return nil, fmt.Errorf("unsupported value type")
	}
}

func compileFieldCond(name string, vals []string) (Expr, error) {
	if strings.HasPrefix(name, "http_header[") && strings.HasSuffix(name, "]") {
		hname := strings.TrimSuffix(strings.TrimPrefix(name, "http_header["), "]")
		if len(hname) < 2 || hname[0] != '"' || hname[len(hname)-1] != '"' {
			return nil, fmt.Errorf("header name must be quoted")
		}
		hname = hname[1 : len(hname)-1]
		return compileHeaderCond(hname, vals)
	}
	if name == "suricata_msg" {
		return compileSuricataCond(vals)
	}
	if name == "client_ip" {
		return compileIPCond(vals)
	}
	if name == "http_path" {
		return compilePathCond(vals)
	}
	getter, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown field %s", name)
	}
	matchers := make([]func(string) bool, 0, len(vals))
	for _, p := range vals {
		m, err := compilePattern(p, false)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return Cond{Matcher: func(ctx *fingerprint.RequestCtx) bool {
		for _, val := range getter(ctx) {
			for _, m := range matchers {
				if m(val) {
					return true
				}
			}
		}
		return false
	}}, nil
}

func compileHeaderCond(name string, vals []string) (Expr, error) {
	var matchers []func(string) bool
	for _, p := range vals {
		ci := false
		if strings.HasPrefix(p, "i:") {
			ci = true
			p = strings.TrimPrefix(p, "i:")
		}
		m, err := compilePattern(p, ci)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	cname := http.CanonicalHeaderKey(name)
	return Cond{Matcher: func(ctx *fingerprint.RequestCtx) bool {
		vals := ctx.Headers.Values(cname)
		for _, v := range vals {
			for _, m := range matchers {
				if m(v) {
					return true
				}
			}
		}
		return false
	}}, nil
}

func compileSuricataCond(vals []string) (Expr, error) {
	matchers := make([]func(string) bool, 0, len(vals))
	for _, p := range vals {
		ci := false
		if strings.HasPrefix(p, "i:") {
			ci = true
			p = strings.TrimPrefix(p, "i:")
		}
		m, err := compilePattern(p, ci)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return Cond{Matcher: func(ctx *fingerprint.RequestCtx) bool {
		for _, msg := range ctx.SuricataMsgs {
			for _, m := range matchers {
				if m(msg) {
					return true
				}
			}
		}
		return false
	}}, nil
}

func compileIPCond(vals []string) (Expr, error) {
	var nets []*net.IPNet
	var ips []net.IP
	for _, p := range vals {
		if strings.Contains(p, "/") {
			_, n, err := net.ParseCIDR(p)
			if err != nil {
				return nil, err
			}
			nets = append(nets, n)
		} else {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("invalid ip %s", p)
			}
			ips = append(ips, ip)
		}
	}
	return Cond{Matcher: func(ctx *fingerprint.RequestCtx) bool {
		ip := ctx.SrcIP
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		for _, x := range ips {
			if ip.Equal(x) {
				return true
			}
		}
		return false
	}}, nil
}

func compilePathCond(vals []string) (Expr, error) {
	type matcher struct {
		match  func(string) bool
		prefix func(string) string
	}
	matchers := make([]matcher, 0, len(vals))
	for _, p := range vals {
		m, pref, err := compilePathPattern(p)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher{match: m, prefix: pref})
	}
	return Cond{Matcher: func(ctx *fingerprint.RequestCtx) bool {
		for _, val := range registry["http_path"](ctx) {
			for _, m := range matchers {
				if m.match(val) {
					if ctx.PathPrefix == "" {
						ctx.PathPrefix = m.prefix(val)
					}
					return true
				}
			}
		}
		return false
	}}, nil
}

func compilePathPattern(p string) (func(string) bool, func(string) string, error) {
	op := byte('=')
	if len(p) > 0 {
		switch p[0] {
		case '=', '^', '~':
			op = p[0]
			p = strings.TrimSpace(p[1:])
		}
	}

	switch op {
	case '=':
		exact := p
		return func(s string) bool { return s == exact }, func(string) string { return exact }, nil
	case '^':
		pref := p
		return func(s string) bool { return strings.HasPrefix(s, pref) }, func(s string) string {
			if strings.HasPrefix(s, pref) {
				return pref
			}
			return ""
		}, nil
	case '~':
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, nil, err
		}
		return func(s string) bool { return re.MatchString(s) }, func(s string) string {
			if loc := re.FindStringIndex(s); loc != nil && loc[0] == 0 {
				return s[:loc[1]]
			}
			return ""
		}, nil
	}

	return nil, nil, fmt.Errorf("unknown operator")
}

func compilePattern(p string, ci bool) (func(string) bool, error) {
	op := byte('=')
	if len(p) > 0 {
		switch p[0] {
		case '=', '^', '~':
			op = p[0]
			p = strings.TrimSpace(p[1:])
		default:
			if strings.ContainsRune("?!@#$%&*+", rune(p[0])) {
				return nil, fmt.Errorf("unknown operator")
			}
		}
	}

	switch op {
	case '=':
		exact := p
		if ci {
			exact = strings.ToLower(exact)
		}
		return func(s string) bool {
			if ci {
				s = strings.ToLower(s)
			}
			return s == exact
		}, nil
	case '^':
		pref := p
		if ci {
			pref = strings.ToLower(pref)
		}
		return func(s string) bool {
			if ci {
				s = strings.ToLower(s)
			}
			return strings.HasPrefix(s, pref)
		}, nil
	case '~':
		pat := p
		if ci {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		return func(s string) bool {
			return re.MatchString(s)
		}, nil
	}

	return nil, fmt.Errorf("unknown operator")
}
