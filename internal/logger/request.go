package logger

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0x4D31/finch/internal/fingerprint"
)

// NewRequestEvent constructs the common request fields for both Finch's proxy
// and public logger package. It does not consume or mutate the request.
func NewRequestEvent(r *http.Request, ctx fingerprint.RequestCtx, body []byte) Event {
	srcHost, srcPortStr, _ := net.SplitHostPort(r.RemoteAddr)
	srcPort := parsePort(srcPortStr)
	dstHost, dstPort := "", 0
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		var port string
		dstHost, port, _ = net.SplitHostPort(addr.String())
		dstPort = parsePort(port)
	}
	headers := make(map[string]string, len(r.Header))
	for k, values := range r.Header {
		// Preserve the proxy's existing schema: fingerprint headers are omitted
		// and observed values come from context, never from request headers.
		switch k {
		case "X-Ja3-Fingerprint", "X-Ja4-Fingerprint", "X-Ja4h-Fingerprint", "X-Http2-Fingerprint":
			continue
		}
		headers[k] = strings.Join(values, ",")
	}
	sum := sha256.Sum256(body)
	return Event{
		EventTime:       time.Now().UTC(),
		SrcIP:           srcHost,
		SrcPort:         srcPort,
		DstIP:           dstHost,
		DstPort:         dstPort,
		Method:          r.Method,
		Request:         r.URL.String(),
		Headers:         headers,
		Body:            string(body),
		BodySha256:      hex.EncodeToString(sum[:]),
		ProtocolVersion: r.Proto,
		UserAgent:       r.UserAgent(),
		JA3:             ctx.JA3,
		JA3Raw:          ctx.JA3Raw,
		JA4:             ctx.JA4,
		JA4H:            ctx.JA4H,
		HTTP2:           ctx.HTTP2,
	}
}

func parsePort(s string) int {
	port, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return port
}
