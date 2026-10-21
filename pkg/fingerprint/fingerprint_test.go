package fingerprint_test

import (
	"net/http/httptest"
	"testing"

	"github.com/0x4D31/finch/pkg/fingerprint"
)

func TestMissingMetadataDoesNotTrustHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.test/probe", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	for _, h := range []string{"X-JA3-Fingerprint", "X-JA4-Fingerprint", "X-JA4H-Fingerprint", "X-HTTP2-Fingerprint"} {
		r.Header.Set(h, "forged")
	}
	ctx, err := fingerprint.New(r)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.JA3 != "" || ctx.JA3Raw != "" || ctx.JA4 != "" || ctx.JA4H != "" || ctx.HTTP2 != "" {
		t.Fatal("used unobserved fingerprint values")
	}
	if ctx.Path != "/probe" || ctx.Method != "GET" || ctx.SrcIP.String() != "192.0.2.1" {
		t.Fatal("ordinary request metadata lost")
	}
}
