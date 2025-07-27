package fingerprint

import (
	"context"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/0x4D31/fingerproxy/pkg/metadata"
)

const clientHelloHex = "1603010128010001240303f0f6e094c19da3bb1b9ad2d58ce7fe994b86217cd14ec57429d1469d05d05c5e20610152e722007ea38d6fc24c89ff04a684a3f5c9e88e8a01844f3db1caeb4b560062130313021301cca9cca8ccaac030c02cc028c024c014c00a009f006b0039ff8500c400880081009d003d003500c00084c02fc02bc027c023c013c009009e0067003300be0045009c003c002f00ba0041c011c00700050004c012c0080016000a00ff01000079002b0009080304030303020301003300260024001d002082251e0d3dfa75ff2a1909274f910bb8cb4e67f4d98a220f97adf3f1086a7a18000b00020100000a000a0008001d001700180019000d00180016080606010603080505010503080404010403020102030010000e000c02683208687474702f312e31"

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewContextSuccess(t *testing.T) {
	const (
		expJA3  = "4f2655722e37c542ebeaf1eed48cbbbb"
		expJA4  = "t13i4906h2_0d8feac7bc37_7395dae3b2f3"
		expH2   = "3:100;4:10485760;2:0|1048510465|0|m,s,a,p"
		expJA4H = "ge20cr020000_5594a17e7e7e_ca8064b27201_5c8e7d6b8092"
	)

	baseCtx, md := metadata.NewContext(context.Background())
	md.ClientHelloRecord = hexToBytes(t, clientHelloHex)
	md.ConnectionState.NegotiatedProtocol = "h2"
	md.HTTP2Frames = metadata.HTTP2FingerprintingFrames{
		Settings:              []metadata.Setting{{Id: 3, Val: 100}, {Id: 4, Val: 10485760}, {Id: 2, Val: 0}},
		WindowUpdateIncrement: 1048510465,
		Headers: []metadata.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: ":path", Value: "/foo"},
			{Name: "user-agent", Value: "curl/8.7.1"},
			{Name: "accept", Value: "*/*"},
		},
	}

	r := httptest.NewRequest("GET", "https://example.com/foo", nil).WithContext(baseCtx)
	r.RemoteAddr = "192.168.0.1:12345"
	r.Proto = "HTTP/2.0"
	r.ProtoMajor = 2
	r.ProtoMinor = 0
	r.Header.Set("User-Agent", "curl/8.7.1")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Cookie", "SID=123; theme=dark")
	r.Header.Set("Referer", "https://example.com/start")

	ctx, err := New(r)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	if ctx.JA3 != expJA3 {
		t.Fatalf("JA3 mismatch: %s vs %s", ctx.JA3, expJA3)
	}
	if ctx.JA4 != expJA4 {
		t.Fatalf("JA4 mismatch: %s vs %s", ctx.JA4, expJA4)
	}
	if ctx.JA4H != expJA4H {
		t.Fatalf("JA4H mismatch: %s vs %s", ctx.JA4H, expJA4H)
	}
	if ctx.HTTP2 != expH2 {
		t.Fatalf("HTTP2 mismatch: %s vs %s", ctx.HTTP2, expH2)
	}
	if ctx.SrcIP == nil || !ctx.SrcIP.Equal(net.ParseIP("192.168.0.1")) {
		t.Fatalf("src ip mismatch: %v", ctx.SrcIP)
	}
	if ctx.Path != "/foo" {
		t.Fatalf("path mismatch: %s", ctx.Path)
	}
	if ctx.Method != "GET" {
		t.Fatalf("method mismatch: %s", ctx.Method)
	}
	if ctx.Headers.Get("User-Agent") != "curl/8.7.1" ||
		ctx.Headers.Get("Cookie") != "SID=123; theme=dark" ||
		ctx.Headers.Get("Referer") != "https://example.com/start" {
		t.Fatalf("headers missing: %v", ctx.Headers)
	}

	// ensure headers are cloned
	r.Header.Set("User-Agent", "changed")
	r.Header.Set("Cookie", "changed")
	r.Header.Set("Referer", "changed")
	if ctx.Headers.Get("User-Agent") != "curl/8.7.1" ||
		ctx.Headers.Get("Cookie") != "SID=123; theme=dark" ||
		ctx.Headers.Get("Referer") != "https://example.com/start" {
		t.Fatalf("headers not cloned")
	}
}

func TestNewContextMissingMetadata(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = "10.1.1.1:12345"
	ctx, err := New(r)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if ctx.JA3 != "" || ctx.JA4 != "" || ctx.JA4H != "" || ctx.HTTP2 != "" {
		t.Fatalf("expected empty fingerprints, got %+v", ctx)
	}
	if ctx.SrcIP == nil || !ctx.SrcIP.Equal(net.ParseIP("10.1.1.1")) {
		t.Fatalf("src ip mismatch: %v", ctx.SrcIP)
	}
	if ctx.Path != "/" {
		t.Fatalf("path mismatch: %s", ctx.Path)
	}
	if ctx.Method != "GET" {
		t.Fatalf("method mismatch: %s", ctx.Method)
	}
}
