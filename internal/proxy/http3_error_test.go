package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"github.com/quic-go/quic-go/http3"
)

func TestNewH3ServerPortInUse(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = pc.Close() }()

	_, err = newH3Server(pc.LocalAddr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), &tls.Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestH3ServerNil(t *testing.T) {
	var h *h3Server
	if err := h.Serve(); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

type dummyPacketConn struct{}

func (d dummyPacketConn) ReadFrom(p []byte) (int, net.Addr, error)  { return 0, nil, nil }
func (d dummyPacketConn) WriteTo(p []byte, a net.Addr) (int, error) { return len(p), nil }
func (d dummyPacketConn) Close() error                              { return nil }
func (d dummyPacketConn) LocalAddr() net.Addr                       { return &net.IPAddr{} }
func (d dummyPacketConn) SetDeadline(t time.Time) error             { return nil }
func (d dummyPacketConn) SetReadDeadline(t time.Time) error         { return nil }
func (d dummyPacketConn) SetWriteDeadline(t time.Time) error        { return nil }

func TestInspectConnUnsupported(t *testing.T) {
	ic := newInspectConn(dummyPacketConn{})
	if _, err := ic.SyscallConn(); err == nil {
		t.Fatal("expected error from SyscallConn")
	}
	if err := ic.SetReadBuffer(1); err == nil {
		t.Fatal("expected read buffer error")
	}
	if err := ic.SetWriteBuffer(1); err == nil {
		t.Fatal("expected write buffer error")
	}
	if err := ic.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestGCLoopStopsOnClose(t *testing.T) {
	ic := newInspectConn(dummyPacketConn{})
	start := time.Now()
	if err := ic.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("close took too long")
	}
}

func TestParserLoopStopsOnClose(t *testing.T) {
	ic := newInspectConn(dummyPacketConn{})
	start := time.Now()
	if err := ic.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("close took too long")
	}
}

func TestInspectConnFeatures(t *testing.T) {
	ic := newInspectConn(dummyPacketConn{})
	ic.ttl = 20 * time.Millisecond
	ic.add("1.1.1.1", []byte("a"))
	ic.add("1.1.1.1", []byte("b"))
	if rec := ic.get("1.1.1.1:1234"); string(rec) != "a" {
		t.Fatalf("want first record, got %q", rec)
	}
	if r := ic.get("1.1.1.1"); r != nil {
		t.Fatalf("expected record cleared")
	}
	ic.add("2.2.2.2", []byte("x"))
	time.Sleep(30 * time.Millisecond)
	if r := ic.get("2.2.2.2:99"); r != nil {
		t.Fatalf("expected ttl expiry")
	}
	for i := 0; i < inspectConnLimit+5; i++ {
		ic.add(fmt.Sprintf("10.0.0.%d", i), []byte("d"))
	}
	time.Sleep(25 * time.Millisecond)
	if len(ic.md) != inspectConnLimit {
		t.Fatalf("limit not enforced: %d", len(ic.md))
	}
	ic.add("3.3.3.3", []byte("k"))
	if rec := ic.get("3.3.3.3:1"); string(rec) != "k" {
		t.Fatalf("ip-only key failed")
	}
	_ = ic.Close()
}

func TestH3ServerServeQUIC(t *testing.T) {
	cert, err := selfSignedCert("127.0.0.1:0")
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}

	fpCh := make(chan []byte, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if md, ok := metadata.FromContext(r.Context()); ok {
			fpCh <- md.ClientHelloRecord
		}
		w.WriteHeader(http.StatusOK)
	})

	h3, err := newH3Server("127.0.0.1:0", handler, tlsConf)
	if err != nil {
		t.Fatalf("newH3Server: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- h3.Serve() }()
	time.Sleep(100 * time.Millisecond)

	tr := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}}
	defer func() { _ = tr.Close() }()
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://" + h3.pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case rec := <-fpCh:
		if len(rec) == 0 {
			t.Fatal("empty fingerprint")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for fingerprint")
	}

	if err := h3.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := <-serveErr; err != http.ErrServerClosed {
		t.Fatalf("serve err: %v", err)
	}
}
