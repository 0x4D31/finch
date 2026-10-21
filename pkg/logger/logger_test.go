package logger_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/0x4D31/finch/pkg/fingerprint"
	"github.com/0x4D31/finch/pkg/logger"
	"github.com/0x4D31/fingerproxy/pkg/proxyserver"
)

func TestNewRequestEvent(t *testing.T) {
	body := []byte("captured prefix")
	r := httptest.NewRequest("POST", "https://example.test/a%2Fb?x=1", bytes.NewReader(body))
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Add("X-Duplicate", "first")
	r.Header.Add("X-Duplicate", "second")
	r.Header.Set("User-Agent", "test-agent")
	for _, k := range []string{"X-JA3-Fingerprint", "X-JA4-Fingerprint", "X-JA4H-Fingerprint", "X-HTTP2-Fingerprint"} {
		r.Header.Set(k, "forged")
	}
	local := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, local))
	headers := r.Header.Clone()
	ctx := fingerprint.RequestCtx{
		JA3: "observed-ja3", JA3Raw: "raw-ja3", JA4: "observed-ja4",
		JA4H: "observed-ja4h", HTTP2: "observed-http2",
	}
	ev := logger.NewRequestEvent(r, ctx, body)
	if ev.SrcIP != "2001:db8::1" || ev.SrcPort != 1234 || ev.DstIP != "2001:db8::2" ||
		ev.DstPort != 443 || ev.Request != r.URL.String() || ev.Method != "POST" ||
		ev.ProtocolVersion != r.Proto || ev.UserAgent != "test-agent" {
		t.Fatalf("request metadata mismatch: %+v", ev)
	}
	if ev.JA3 != ctx.JA3 || ev.JA3Raw != ctx.JA3Raw || ev.JA4 != ctx.JA4 ||
		ev.JA4H != ctx.JA4H || ev.HTTP2 != ctx.HTTP2 {
		t.Fatal("observed fingerprints lost")
	}
	if ev.Headers["X-Duplicate"] != "first,second" || len(ev.Headers) != 2 {
		t.Fatalf("legacy header representation changed: %v", ev.Headers)
	}
	hash := sha256.Sum256(body)
	if ev.Body != string(body) || ev.BodySha256 != hex.EncodeToString(hash[:]) {
		t.Fatal("captured body/hash mismatch")
	}
	remaining, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(remaining, body) || !reflect.DeepEqual(r.Header, headers) {
		t.Fatal("event builder consumed or mutated request")
	}
	if ev.EventTime.IsZero() || ev.EventTime.Location() != time.UTC {
		t.Fatal("missing UTC timestamp")
	}
}

func TestPublicLoggerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	l, err := logger.New(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := logger.NewRequestEvent(httptest.NewRequest("GET", "https://example.test/", nil),
		fingerprint.RequestCtx{JA3: "observed"}, nil)
	ev.Action = logger.ActionDeceive
	ev.GalahInfo = &logger.GalahInfo{ResponseBody: "fixture"}
	ev.SuricataMatches = []logger.SuricataMatch{{SID: "1", Msg: "fixture"}}
	if err := l.Log(ev); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(data), want) {
		t.Fatal("public logger changed event encoding")
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"eventTime", "srcIP", "srcPort", "dstIP", "dstPort", "method",
		"request", "headers", "body", "bodySha256", "protocolVersion", "userAgent",
		"ja3", "ja3Raw", "ja4", "ja4h", "http2", "ruleID", "action", "upstream"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing standard key %q", key)
		}
	}
}

func TestPublicPackagesWithFingerproxyListener(t *testing.T) {
	certSource := httptest.NewTLSServer(http.NotFoundHandler())
	certificates := certSource.TLS.Certificates
	certSource.Close()
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			events := make(chan logger.Event, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fp, err := fingerprint.New(r)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
				if err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				ev := logger.NewRequestEvent(r, fp, body)
				ev.Action = logger.ActionDeceive
				events <- ev
				w.Header().Add("Set-Cookie", "a=1")
				w.Header().Add("Set-Cookie", "b=2")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("custom response"))
			})
			server := proxyserver.NewServer(ctx, handler, &tls.Config{
				Certificates: certificates, NextProtos: []string{"h2", "http/1.1"},
				MinVersion: tls.VersionTLS12,
			})
			server.TLSHandshakeTimeout = 2 * time.Second
			server.HTTPServer.ReadHeaderTimeout = 2 * time.Second
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, http.ErrServerClosed) {
						t.Errorf("shutdown: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Error("server did not stop")
				}
			}()
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // local test certificate only
				ForceAttemptHTTP2: h2,
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			body := []byte{0, 255, 'x'}
			req, _ := http.NewRequest("POST", "https://"+listener.Addr().String()+"/probe", bytes.NewReader(body))
			for _, k := range []string{"X-JA3-Fingerprint", "X-JA4-Fingerprint", "X-JA4H-Fingerprint"} {
				req.Header.Set(k, "forged")
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil || res.StatusCode != 201 || string(response) != "custom response" ||
				len(res.Header.Values("Set-Cookie")) != 2 || (res.ProtoMajor == 2) != h2 {
				t.Fatal("custom response/protocol semantics changed")
			}
			select {
			case ev := <-events:
				if ev.JA3 == "" || ev.JA3 == "forged" || ev.JA3Raw == "" || ev.JA4 == "" ||
					ev.JA4 == "forged" || ev.JA4H == "" || ev.JA4H == "forged" {
					t.Fatalf("missing or spoofed fingerprints: %+v", ev)
				}
				if h2 && ev.HTTP2 == "" {
					t.Fatal("HTTP/2 fingerprint missing")
				}
				if ev.Body != string(body) {
					t.Fatal("body bytes changed before encoding")
				}
			case <-time.After(time.Second):
				t.Fatal("no standard access event")
			}
		})
	}
}
