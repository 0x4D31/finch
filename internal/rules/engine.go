package rules

import (
	"fmt"
	"sync"
	"time"

	"github.com/0x4D31/finch/internal/fingerprint"
)

// Engine evaluates incoming requests against loaded rules.
type Engine struct {
	mu            sync.RWMutex
	Rules         []*Rule
	DefaultAction Action
}

// Load replaces the engine rule set atomically.
func (e *Engine) Load(rs *RuleSet) {
	e.mu.Lock()
	e.Rules = rs.Rules
	if e.DefaultAction == "" {
		e.DefaultAction = ActionAllow
	}
	e.mu.Unlock()
}

// LoadFromFile loads rule definitions from an HCL file.
func (e *Engine) LoadFromFile(path string) error {
	rs, err := LoadHCL(path)
	if err != nil {
		return fmt.Errorf("load rules file: %w", err)
	}
	e.Load(rs)
	return nil
}

func (r *Rule) Matches(ctx *fingerprint.RequestCtx) bool {
	if r.Expires != nil && time.Now().UTC().After(*r.Expires) {
		return false
	}
	return r.Expr.Eval(ctx)
}

// Eval finds the first matching rule for the request context.
// If no rule matches, ActionAllow and empty ruleID are returned.
func (e *Engine) EvalRule(ctx *fingerprint.RequestCtx) *Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for i := range e.Rules {
		ctx.PathPrefix = ""
		if e.Rules[i].Matches(ctx) {
			return e.Rules[i]
		}
	}
	ctx.PathPrefix = ""
	return nil
}

func (e *Engine) Eval(ctx *fingerprint.RequestCtx) (action Action, upstream, ruleID string) {
	if r := e.EvalRule(ctx); r != nil {
		if r.Upstream != nil {
			return r.Action, r.Upstream.String(), r.ID
		}
		return r.Action, "", r.ID
	}
	e.mu.RLock()
	def := e.DefaultAction
	e.mu.RUnlock()
	return def, "", ""
}

// EvalComposite evaluates the request against a listener-specific engine first
// and then the global engine. The global engine's DefaultAction is used when no
// rule matches. Either engine may be nil.
func EvalComposite(local, global *Engine, ctx *fingerprint.RequestCtx) (action Action, upstream, ruleID string, rule *Rule, prefix string) {
	if local != nil {
		if r := local.EvalRule(ctx); r != nil {
			up := ""
			if r.Upstream != nil {
				up = r.Upstream.String()
			}
			return r.Action, up, r.ID, r, ctx.PathPrefix
		}
	}
	if global != nil {
		if r := global.EvalRule(ctx); r != nil {
			up := ""
			if r.Upstream != nil {
				up = r.Upstream.String()
			}
			return r.Action, up, r.ID, r, ctx.PathPrefix
		}
		global.mu.RLock()
		def := global.DefaultAction
		global.mu.RUnlock()
		return def, "", "", nil, ""
	}
	if local != nil {
		local.mu.RLock()
		def := local.DefaultAction
		local.mu.RUnlock()
		return def, "", "", nil, ""
	}
	return ActionAllow, "", "", nil, ""
}
