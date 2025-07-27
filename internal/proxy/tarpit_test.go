//go:build skipproxy

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTarpitHandler_DelayAndChunked(t *testing.T) {
	cfg := TarpitConfig{
		IntervalMin: 10 * time.Millisecond,
		IntervalMax: 10 * time.Millisecond,
		DelayMin:    50 * time.Millisecond,
		DelayMax:    50 * time.Millisecond,
	}
	h := newTarpitHandler(cfg)

	r := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	start := time.Now()
	h.ServeHTTP(rr, r)
	dur := time.Since(start)
	if dur < 50*time.Millisecond {
		t.Fatalf("handler returned too quickly: %v", dur)
	}

	res := rr.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.Header.Get("Transfer-Encoding") != "chunked" {
		t.Fatalf("expected chunked Transfer-Encoding, got %q", res.Header.Get("Transfer-Encoding"))
	}
	if rr.Body.Len() == 0 {
		t.Fatalf("expected response body")
	}
}

func TestTarpitHandler_ConcurrencyCap(t *testing.T) {
	sem := make(chan struct{}, 1)
	cfg := TarpitConfig{
		IntervalMin: 10 * time.Millisecond,
		IntervalMax: 10 * time.Millisecond,
		DelayMin:    50 * time.Millisecond,
		DelayMax:    50 * time.Millisecond,
		Concurrency: sem,
	}
	h := newTarpitHandler(cfg)

	done := make(chan struct{})
	r1 := httptest.NewRequest("GET", "/", nil)
	rr1 := httptest.NewRecorder()
	go func() {
		h.ServeHTTP(rr1, r1)
		close(done)
	}()

	// Wait until the first request has acquired the semaphore.
	for i := 0; i < 50; i++ {
		if len(sem) == 1 {
			break
		}
		time.Sleep(1 * time.Millisecond)
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	rr2 := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rr2, r2)
	dur := time.Since(start)

	if rr2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr2.Code)
	}
	if dur > 30*time.Millisecond {
		t.Fatalf("second request took too long: %v", dur)
	}

	<-done
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request status %d", rr1.Code)
	}
}
