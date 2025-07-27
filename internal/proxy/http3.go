package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/0x4D31/finch/pkg/quic"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"github.com/quic-go/quic-go/http3"
)

type inspectConn struct {
	net.PacketConn
	mu     sync.Mutex
	md     map[string]mdEntry
	order  []string
	ttl    time.Duration
	parser *quic.Parser
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

type mdEntry struct {
	data []byte
	ts   time.Time
}

const inspectConnTTL = 30 * time.Second
const inspectConnLimit = 64

func newInspectConn(pc net.PacketConn) *inspectConn {
	ic := &inspectConn{
		PacketConn: pc,
		md:         make(map[string]mdEntry),
		ttl:        inspectConnTTL,
		parser:     quic.NewParser(),
		done:       make(chan struct{}),
	}
	ic.wg.Add(1)
	go func() {
		defer ic.wg.Done()
		ic.gcLoop()
	}()
	return ic
}

func hostOnly(a string) string {
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return a
}

func (c *inspectConn) add(addr string, rec []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.md[addr]; ok {
		return
	}
	if len(c.md) >= inspectConnLimit {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.md, old)
	}
	c.md[addr] = mdEntry{data: rec, ts: time.Now()}
	c.order = append(c.order, addr)
}

func (c *inspectConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil && n > 0 {
		data := make([]byte, n)
		copy(data, p[:n])
		if rec, err := c.parser.ExtractClientHello(data); err == nil {
			c.add(hostOnly(addr.String()), rec)
		}
	}
	return n, addr, err
}

func (c *inspectConn) get(addr string) []byte {
	key := hostOnly(addr)
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.md[key]; ok {
		delete(c.md, key)
		for i, k := range c.order {
			if k == key {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
		if time.Since(e.ts) <= c.ttl {
			return e.data
		}
	}
	return nil
}

func (c *inspectConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("SyscallConn not supported")
}

func (c *inspectConn) SetReadBuffer(bytes int) error {
	if conn, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return conn.SetReadBuffer(bytes)
	}
	return errors.New("SetReadBuffer not supported")
}

func (c *inspectConn) SetWriteBuffer(bytes int) error {
	if conn, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return errors.New("SetWriteBuffer not supported")
}

func (c *inspectConn) gcLoop() {
	t := time.NewTicker(c.ttl)
	for {
		select {
		case <-t.C:
			cutoff := time.Now().Add(-c.ttl)
			c.mu.Lock()
			for k, v := range c.md {
				if v.ts.Before(cutoff) {
					delete(c.md, k)
					for i, kk := range c.order {
						if kk == k {
							c.order = append(c.order[:i], c.order[i+1:]...)
							break
						}
					}
				}
			}
			c.mu.Unlock()
		case <-c.done:
			t.Stop()
			return
		}
	}
}

func (c *inspectConn) Close() error {
	if c.parser != nil {
		c.parser.Close()
	}
	c.once.Do(func() { close(c.done) })
	c.wg.Wait()
	return c.PacketConn.Close()
}

type h3Server struct {
	srv     *http3.Server
	pc      *inspectConn
	handler http.Handler
}

func newH3Server(addr string, handler http.Handler, tlsConf *tls.Config) (*h3Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	ic := newInspectConn(pc)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec := ic.get(r.RemoteAddr); rec != nil {
			md := &metadata.Metadata{ClientHelloRecord: rec, IsQUIC: true}
			ctx := context.WithValue(r.Context(), metadata.FingerproxyContextKey, md)
			r = r.WithContext(ctx)
		}
		handler.ServeHTTP(w, r)
	})
	conf := http3.ConfigureTLSConfig(tlsConf)
	s := &http3.Server{TLSConfig: conf, Handler: h}
	return &h3Server{srv: s, pc: ic, handler: handler}, nil
}

func (h *h3Server) Serve() error {
	if h == nil || h.srv == nil || h.pc == nil {
		return nil
	}
	err := h.srv.Serve(h.pc)
	return err
}

func (h *h3Server) Close() error {
	if h == nil {
		return nil
	}
	var err1, err2 error
	if h.srv != nil {
		err1 = h.srv.Close()
	}
	if h.pc != nil {
		err2 = h.pc.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}
