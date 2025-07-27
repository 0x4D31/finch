//go:build skipproxy

package proxy

import (
	"context"
	"encoding/hex"
	"net/http/httptest"
	"testing"

	"github.com/0x4D31/finch/internal/fingerprint"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
)

// sample QUIC client hello record from quicfp tests
const quicHelloHex = "1603010077010000730303a4b9f667f45a582a22e99360a97e87de5d3e2cbfe9a524b16ba423473d0a8a1d20e66b3ad64af1bf659ef90b50353f446932b385955ceddeee672ca7e820de025a0026c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035c012000a1301130213030100000400390000"

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestJA4FingerprintQUIC(t *testing.T) {
	baseCtx, md := metadata.NewContext(context.Background())
	md.ClientHelloRecord = hexToBytes(t, quicHelloHex)
	md.IsQUIC = true
	r := httptest.NewRequest("GET", "http://example", nil).WithContext(baseCtx)
	reqCtx, err := fingerprint.New(r)
	if err != nil {
		t.Fatalf("new req ctx: %v", err)
	}
	if reqCtx.JA4 == "" || reqCtx.JA4[0] != 'q' {
		t.Fatalf("expected JA4 starting with q, got %s", reqCtx.JA4)
	}
}
