package proxy

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestUpstreamTLSVerification(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	h := &ruleHandler{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://host/", nil)

	h.getProxy(u).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}

	// write upstream cert to file
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.pem")
	cert := upstream.TLS.Certificates[0].Certificate[0]
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	h = &ruleHandler{upstreamCAFile: caPath}
	rr = httptest.NewRecorder()
	h.getProxy(u).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with ca file, got %d", rr.Code)
	}

	h = &ruleHandler{upstreamSkipTLSVerify: true}
	rr = httptest.NewRecorder()
	h.getProxy(u).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with skip verify, got %d", rr.Code)
	}
}
