package fingerprint

import (
	"math"
	"net"
	"net/http"

	fp "github.com/0x4D31/fingerproxy/pkg/fingerprint"
	fpja4h "github.com/0x4D31/fingerproxy/pkg/ja4h"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
)

// RequestCtx contains request metadata needed for rule evaluation.
type RequestCtx struct {
	JA3          string
	JA4          string
	JA4H         string
	HTTP2        string
	SrcIP        net.IP
	Path         string
	Method       string
	Headers      http.Header
	SuricataMsgs []string
	PathPrefix   string
}

// New extracts fingerprint information from the request context.
func New(r *http.Request) (RequestCtx, error) {
	md, ok := metadata.FromContext(r.Context())

	ctx := RequestCtx{
		Path:    r.URL.Path,
		Method:  r.Method,
		Headers: r.Header.Clone(),
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ctx.SrcIP = net.ParseIP(host)

	if !ok {
		return ctx, nil
	}

	ja3, err := fp.JA3Fingerprint(md)
	if err != nil {
		return RequestCtx{}, err
	}
	ja4, err := fp.JA4Fingerprint(md)
	if err != nil {
		return RequestCtx{}, err
	}
	ja4h := fpja4h.FromRequest(r, md.OrderedHeaders())
	h2p := &fp.HTTP2FingerprintParam{MaxPriorityFrames: math.MaxUint}
	http2fp, err := h2p.HTTP2Fingerprint(md)
	if err != nil {
		return RequestCtx{}, err
	}

	ctx.JA3 = ja3
	ctx.JA4 = ja4
	ctx.JA4H = ja4h
	ctx.HTTP2 = http2fp

	return ctx, nil
}
