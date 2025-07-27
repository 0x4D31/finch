//go:build skipproxy

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x4D31/fingerproxy/pkg/metadata"
)

type failWriter struct {
	*httptest.ResponseRecorder
	fail bool
}

func (w *failWriter) Write(b []byte) (int, error) {
	if w.fail {
		w.fail = false
		return 0, fmt.Errorf("fail")
	}
	return w.ResponseRecorder.Write(b)
}

func newRequest(t *testing.T, path string) *http.Request {
	baseCtx, md := metadata.NewContext(context.Background())
	md.ClientHelloRecord = hexToBytes(t, quicHelloHex)
	return httptest.NewRequest("GET", "http://example"+path, nil).WithContext(baseCtx)
}

func TestEchoHandler_IndexEncodeError(t *testing.T) {
	r := newRequest(t, "/")
	rr := httptest.NewRecorder()
	fw := &failWriter{ResponseRecorder: rr, fail: true}
	echoHandler(fw, r)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

func TestEchoHandler_JSONEncodeError(t *testing.T) {
	r := newRequest(t, "/fp/detail")
	rr := httptest.NewRecorder()
	fw := &failWriter{ResponseRecorder: rr, fail: true}
	echoHandler(fw, r)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}
