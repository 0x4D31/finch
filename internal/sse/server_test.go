package sse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	cblog "github.com/charmbracelet/log"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/logger"
)

func TestEventJSONKeys(t *testing.T) {
	ev := logger.Event{
		EventTime: time.Unix(0, 0).UTC(),
		SrcIP:     "1.2.3.4",
		HTTP2:     "true",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"eventTime", "srcIP", "http2"} {
		if _, ok := m[k]; !ok {
			t.Errorf("key %s missing", k)
		}
	}
}

type brokenWriter struct {
	header  http.Header
	flushed bool
}

func (b *brokenWriter) Header() http.Header { return b.header }
func (b *brokenWriter) Write(p []byte) (int, error) {
	if b.flushed {
		return 0, fmt.Errorf("write after flush")
	}
	return len(p), nil
}
func (b *brokenWriter) WriteHeader(statusCode int) {}
func (b *brokenWriter) Flush()                     { b.flushed = true }
func (b *brokenWriter) FlushErr() error {
	if b.flushed {
		return fmt.Errorf("flush error")
	}
	return nil
}

func TestEventsBrokenConnection(t *testing.T) {
	hub := NewHub()
	srv := NewServer(":0", hub)

	req := httptest.NewRequest("GET", "/events", nil)

	bw := &brokenWriter{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		srv.events(bw, req)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	hub.Publish([]byte("{}"))

	select {
	case <-done:
		// ok
	case <-time.After(100 * time.Millisecond):
		t.Fatal("handler did not exit")
	}
}

type flushRecorder struct {
	header http.Header
	count  int
}

func (f *flushRecorder) Header() http.Header         { return f.header }
func (f *flushRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (f *flushRecorder) WriteHeader(statusCode int)  {}
func (f *flushRecorder) Flush()                      { f.count++ }
func (f *flushRecorder) FlushErr() error             { return nil }

func TestEventsFlushHeaders(t *testing.T) {
	hub := NewHub()
	srv := NewServer(":0", hub)

	req := httptest.NewRequest("GET", "/events", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)

	fr := &flushRecorder{header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		srv.events(fr, req)
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("handler did not exit")
	}

	if fr.count == 0 {
		t.Fatal("headers were not flushed")
	}
}

func TestEventsLogFlushError(t *testing.T) {
	hub := NewHub()
	srv := NewServer(":0", hub)

	var buf bytes.Buffer
	cblog.SetOutput(&buf)
	defer cblog.SetOutput(io.Discard)

	req := httptest.NewRequest("GET", "/events", nil)

	bw := &brokenWriter{header: make(http.Header)}
	srv.events(bw, req)

	if !strings.Contains(buf.String(), "flush headers") {
		t.Fatal("expected flush error log")
	}
}

func TestServerStartAndShutdown(t *testing.T) {
	hub := NewHub()

	// allocate a free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	srv := NewServer(addr, hub)

	done := make(chan error, 1)
	go func() { done <- srv.Start() }()

	// wait for server to start
	for i := 0; i < 50; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := http.Get("http://" + addr + "/events")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	hub.Publish([]byte(`{"hi":"there"}`))

	r := bufio.NewReader(resp.Body)
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(line, "hi") {
		t.Fatalf("unexpected event line %q", line)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("server did not shut down")
	}
}
