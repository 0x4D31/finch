package rules

// Action is the result of a matching rule.
type Action string

const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionRoute   Action = "route"
	ActionDeceive Action = "deceive"
)
