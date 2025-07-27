package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/rules"
	cblog "github.com/charmbracelet/log"
)

func TestLoggerLogToFile(t *testing.T) {
	tmp := t.TempDir()
	file := tmp + "/log.jsonl"
	l, err := New(file)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer func() { _ = l.Close() }()

	ev := Event{
		EventTime:       time.Unix(0, 0).UTC(),
		SrcIP:           "1.1.1.1",
		SrcPort:         1234,
		DstIP:           "2.2.2.2",
		DstPort:         443,
		Method:          "GET",
		Request:         "/",
		Headers:         map[string]string{"User-Agent": "Go"},
		ProtocolVersion: "HTTP/1.1",
		UserAgent:       "Go",
		JA3:             "aaa",
		JA4:             "bbb",
		RuleID:          "r1",
		Action:          rules.ActionAllow,
		Upstream:        "default",
		Error:           "test err",
	}
	if err := l.Log(ev); err != nil {
		t.Fatalf("log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var out Event
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.RuleID != ev.RuleID || out.Action != ev.Action || out.SrcIP != ev.SrcIP || out.Request != ev.Request || out.Error != ev.Error {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestLoggerNewWithStdout(t *testing.T) {
	tmp := t.TempDir()
	file := tmp + "/log.jsonl"

	buf := bytes.Buffer{}
	cblog.SetOutput(&buf)
	defer cblog.SetOutput(io.Discard)

	l, err := NewWithStdout(file)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	ev := Event{JA3: "a"}
	if err := l.Log(ev); err != nil {
		t.Fatalf("log: %v", err)
	}
	_ = l.Close()

	if buf.Len() == 0 {
		t.Fatal("no stdout output")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		t.Fatal("file empty")
	}
}

func TestLoggerCloseDoesNotCloseStdout(t *testing.T) {
	tmpDir := t.TempDir()
	fakeOut, err := os.CreateTemp(tmpDir, "stdout")
	if err != nil {
		t.Fatalf("create temp stdout: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = fakeOut
	defer func() {
		os.Stdout = origStdout
		_ = fakeOut.Close()
	}()

	l, err := New("")
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}
	if _, err := os.Stdout.Write([]byte("ok")); err != nil {
		t.Fatalf("stdout closed: %v", err)
	}
}

func TestEventJSONKeys(t *testing.T) {
	ev := Event{
		EventTime: time.Unix(0, 0).UTC(),
		SrcIP:     "1.2.3.4",
		SrcPort:   80,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"eventTime", "srcIP", "srcPort"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %s missing", k)
		}
	}
}
