// Package logger exposes Finch's standard JSONL access events and writer for
// custom handlers and standalone collectors.
package logger

import (
	"net/http"

	internal "github.com/0x4D31/finch/internal/logger"
	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/pkg/fingerprint"
)

type (
	// Event is Finch's existing access-event schema, with unchanged JSON names.
	Event = internal.Event
	// Logger is the JSONL writer used by Finch.
	Logger = internal.Logger
	// SuricataMatch identifies a matched signature.
	SuricataMatch = internal.SuricataMatch
	// GalahInfo records optional response-generation metadata.
	GalahInfo = internal.GalahInfo
	// Action describes the selected request action.
	Action = rules.Action
)

const (
	ActionAllow   = rules.ActionAllow
	ActionDeny    = rules.ActionDeny
	ActionRoute   = rules.ActionRoute
	ActionDeceive = rules.ActionDeceive
	ActionTarpit  = rules.ActionTarpit
)

// New opens the standard JSONL writer. An empty path selects stdout.
// It retains Finch's existing file permissions and append behavior; callers
// collecting sensitive payloads should use a private parent directory.
func New(path string) (*Logger, error) {
	return internal.New(path)
}

// NewWithStdout opens a writer that also echoes events through the console
// logger. See New for file and privacy behavior.
func NewWithStdout(path string) (*Logger, error) {
	return internal.NewWithStdout(path)
}

// NewRequestEvent builds the common request fields using Finch's shared event
// builder. It neither reads nor replaces r.Body. body is exactly the captured
// byte slice to include and hash; a prefix produces a prefix hash, not a hash of
// the full request. The caller owns capture limits and completeness tracking.
//
// The legacy schema joins duplicate header values and stores the body as a JSON
// string, so it is not a lossless wire capture. Keep binary artifacts separately
// when exact evidence matters. Action, rule, listener and response fields are
// left to the caller; creating or logging this event does not prove delivery.
func NewRequestEvent(r *http.Request, ctx fingerprint.RequestCtx, body []byte) Event {
	return internal.NewRequestEvent(r, ctx, body)
}
