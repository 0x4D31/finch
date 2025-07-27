package logger

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	cblog "github.com/charmbracelet/log"

	"github.com/0x4D31/finch/internal/rules"
)

// Event represents a single request log entry.
type SuricataMatch struct {
	Msg string `json:"msg"`
	SID string `json:"sid"`
}

type Event struct {
	EventTime       time.Time         `json:"eventTime"`
	SrcIP           string            `json:"srcIP"`
	SrcPort         int               `json:"srcPort"`
	DstIP           string            `json:"dstIP"`
	DstPort         int               `json:"dstPort"`
	Method          string            `json:"method"`
	Request         string            `json:"request"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	BodySha256      string            `json:"bodySha256"`
	ProtocolVersion string            `json:"protocolVersion"`
	UserAgent       string            `json:"userAgent"`
	JA3             string            `json:"ja3"`
	JA4             string            `json:"ja4"`
	JA4H            string            `json:"ja4h"`
	HTTP2           string            `json:"http2"`
	RuleID          string            `json:"ruleID"`
	Action          rules.Action      `json:"action"`
	Upstream        string            `json:"upstream"`
	SuricataMatches []SuricataMatch   `json:"suricataMatches,omitempty"`
	ListenerAddr    string            `json:"listenerAddr,omitempty"`
	Error           string            `json:"error,omitempty"`
	DeceptionMode   string            `json:"deceptionMode,omitempty"`
	GalahInfo       *GalahInfo        `json:"galahInfo,omitempty"`
}

// GalahInfo holds details about a Galah-generated response.
type GalahInfo struct {
	Provider        string            `json:"provider,omitempty"`
	Model           string            `json:"model,omitempty"`
	Temperature     float64           `json:"temperature,omitempty"`
	ResponseBody    string            `json:"responseBody,omitempty"`
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
}

// Logger writes JSONL events to a file or stdout.
type Logger struct {
	mu   sync.Mutex
	enc  *json.Encoder
	c    io.Closer
	echo bool
}

// New creates a Logger writing to path. If path is empty, stdout is used.
func New(path string) (*Logger, error) {
	var w io.WriteCloser
	var c io.Closer
	if path == "" {
		w = os.Stdout
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		w = f
		c = f
	}
	l := &Logger{enc: json.NewEncoder(w), c: c}
	l.enc.SetEscapeHTML(false)
	return l, nil
}

// NewWithStdout creates a Logger that writes JSONL to the given path and also
// echoes each record to stdout. If path is empty, stdout is used exclusively.
func NewWithStdout(path string) (*Logger, error) {
	var w io.Writer
	var c io.Closer
	if path == "" {
		w = io.Discard
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, err
		}
		w = f
		c = f
	}
	l := &Logger{enc: json.NewEncoder(w), c: c, echo: true}
	l.enc.SetEscapeHTML(false)
	return l, nil
}

// Close closes underlying writer if it is a file.
func (l *Logger) Close() error {
	if l.c != nil {
		return l.c.Close()
	}
	return nil
}

// Log writes the event as a single JSON line.
func (l *Logger) Log(ev Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.EventTime.IsZero() {
		ev.EventTime = time.Now().UTC()
	}
	if l.echo {
		b, err := json.Marshal(ev)
		if err == nil {
			styled := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(string(b))
			cblog.WithPrefix("EVT").Info(styled)
		} else {
			cblog.WithPrefix("EVT").Errorf("marshal event: %v", err)
		}
	}
	return l.enc.Encode(ev)
}
