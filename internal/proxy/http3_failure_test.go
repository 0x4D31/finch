package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test that the HTTPS server still starts when the UDP port is already in use.
func TestServer_UDPPortInUse(t *testing.T) {
	// occupy UDP port
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	defer func() { _ = udpLn.Close() }()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	svr, err := New("t", udpLn.LocalAddr().String(), backend.URL, "", "", nil, nil, nil, nil, nil, nil, "", false)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ln, err := net.Listen("tcp", svr.ListenAddr)
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() { _ = svr.Serve(ln) }()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
