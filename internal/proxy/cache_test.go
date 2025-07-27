//go:build skipproxy

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/0x4D31/fingerproxy/pkg/reverseproxy"
)

// countingConn wraps a net.Conn and counts the number of times Close is called.
type countingConn struct {
	net.Conn
	closed int32
}

func (c *countingConn) Close() error {
	atomic.AddInt32(&c.closed, 1)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func TestProxyCache_LRUEviction(t *testing.T) {
	c := newProxyCache(2)

	h1 := &reverseproxy.HTTPHandler{}
	h2 := &reverseproxy.HTTPHandler{}
	h3 := &reverseproxy.HTTPHandler{}

	c.Add("a", h1, nil)
	c.Add("b", h2, nil)

	if _, ok := c.Get("a"); !ok {
		t.Fatalf("expected key a present")
	}

	c.Add("c", h3, nil)

	if _, ok := c.Get("b"); ok {
		t.Fatalf("key b should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatalf("key a missing after eviction")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatalf("key c missing after eviction")
	}
}

func TestProxyCache_CloseIdleConnections(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var cc *countingConn
	tr := &http.Transport{}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cc = &countingConn{Conn: conn}
		return cc, nil
	}

	cache := newProxyCache(1)
	cache.Add("first", &reverseproxy.HTTPHandler{}, tr)

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("client get: %v", err)
	}
	_ = resp.Body.Close()

	cache.Add("second", &reverseproxy.HTTPHandler{}, &http.Transport{})

	if cc == nil {
		t.Fatalf("dial did not occur")
	}
	if atomic.LoadInt32(&cc.closed) == 0 {
		t.Fatalf("CloseIdleConnections was not called")
	}
}
