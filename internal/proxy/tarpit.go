package proxy

import (
	"crypto/rand"
	"math/big"
	"net/http"
	"time"

	"github.com/0x4D31/finch/internal/sse"
)

// tarpitLimit is a semaphore controlling the maximum number of concurrent
// tarpit responses. Tests may override this value.
var tarpitLimit = make(chan struct{}, 16)

// tarpitResponder is the shared handler used for the "tarpit" deception mode.
var tarpitResponder = newTarpitHandler(TarpitConfig{Concurrency: tarpitLimit})

// TarpitConfig configures the tarpit handler.
type TarpitConfig struct {
	// StatusCode is the HTTP status written once the connection is accepted.
	// If zero, http.StatusOK is used.
	StatusCode int

	// IntervalMin and IntervalMax define the range for random intervals between
	// writes. Defaults are 3s and 7s respectively when unset.
	IntervalMin time.Duration
	IntervalMax time.Duration

	// DelayMin and DelayMax bound the total duration of the tarpit. Defaults are
	// 45s and 120s when unset.
	DelayMin time.Duration
	DelayMax time.Duration

	// Concurrency is an optional semaphore channel that limits the maximum
	// number of concurrent tarpits. If nil, no limit is applied.
	Concurrency chan struct{}
}

func (c *TarpitConfig) defaults() {
	if c.StatusCode == 0 {
		c.StatusCode = http.StatusOK
	}
	if c.IntervalMin == 0 {
		c.IntervalMin = 3 * time.Second
	}
	if c.IntervalMax == 0 {
		c.IntervalMax = 7 * time.Second
	}
	if c.DelayMin == 0 {
		c.DelayMin = 45 * time.Second
	}
	if c.DelayMax == 0 {
		c.DelayMax = 120 * time.Second
	}
}

func randomInterval(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	diff := max - min
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	if err != nil {
		return min
	}
	return min + time.Duration(n.Int64())
}

func randomBytes() []byte {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		n = big.NewInt(0)
	}
	l := n.Int64() + 1
	b := make([]byte, l)
	_, _ = rand.Read(b)
	return b
}

// tarpitHandler serves slow drip responses to frustrate scanners.
type tarpitHandler struct {
	cfg TarpitConfig
}

func newTarpitHandler(cfg TarpitConfig) *tarpitHandler {
	cfg.defaults()
	return &tarpitHandler{cfg: cfg}
}

func (h *tarpitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg := h.cfg
	if cfg.Concurrency != nil {
		select {
		case cfg.Concurrency <- struct{}{}:
			defer func() { <-cfg.Concurrency }()
		default:
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Connection", "close")
	w.WriteHeader(cfg.StatusCode)

	fl, _ := w.(http.Flusher)
	if fl != nil {
		_ = sse.Flush(fl)
	}

	total := randomInterval(cfg.DelayMin, cfg.DelayMax)
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(randomInterval(cfg.IntervalMin, cfg.IntervalMax)):
			b := randomBytes()
			if _, err := w.Write(b); err != nil {
				return
			}
			if fl != nil {
				if err := sse.Flush(fl); err != nil {
					return
				}
			}
		}
	}
}
