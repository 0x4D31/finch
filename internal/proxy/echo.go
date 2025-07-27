package proxy

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	cblog "github.com/charmbracelet/log"
	"github.com/dreadl0ck/tlsx"
	"github.com/refraction-networking/utls/dicttls"

	"github.com/0x4D31/finch/internal/fingerprint"

	fpja3 "github.com/0x4D31/fingerproxy/pkg/ja3"
	fpja4 "github.com/0x4D31/fingerproxy/pkg/ja4"
	"github.com/0x4D31/fingerproxy/pkg/metadata"
	"github.com/0x4D31/fingerproxy/pkg/proxyserver"
)

type httpInfo struct {
	JA4H           string                             `json:"ja4h"`
	HTTP2          string                             `json:"http2"`
	Headers        http.Header                        `json:"headers"`
	OrderedHeaders []string                           `json:"orderedHeaders"`
	HTTP2Frames    metadata.HTTP2FingerprintingFrames `json:"http2Frames"`
}

type tlsInfo struct {
	JA4                         string                `json:"ja4"`
	JA3                         string                `json:"ja3"`
	JA3Raw                      string                `json:"ja3Raw"`
	ClientHello                 tlsx.ClientHelloBasic `json:"clientHello"`
	ClientHelloHex              string                `json:"clientHelloHex"`
	IsQUIC                      bool                  `json:"isQUIC"`
	ReadableCipherSuites        []string              `json:"readableCipherSuites"`
	ReadableAllExtensions       []string              `json:"readableAllExtensions"`
	ReadableJA4Extensions       []string              `json:"readableJA4Extensions"`
	ReadableSupportedGroups     []string              `json:"readableSupportedGroups"`
	ReadableSignatureAlgorithms []string              `json:"readableSignatureAlgorithms"`
}

type detailResponse struct {
	UserAgent string   `json:"userAgent"`
	HTTP      httpInfo `json:"http"`
	TLS       tlsInfo  `json:"tls"`
}

type summaryResponse struct {
	UserAgent string `json:"userAgent"`
	JA3       string `json:"ja3"`
	JA4       string `json:"ja4"`
	JA4H      string `json:"ja4h"`
	HTTP2     string `json:"http2"`
}

func readableCipherSuites(list []uint16) []string {
	out := make([]string, len(list))
	for i, v := range list {
		if name, ok := dicttls.DictCipherSuiteValueIndexed[v]; ok {
			out[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			out[i] = fmt.Sprintf("UNKNOWN (0x%x)", v)
		}
	}
	return out
}

func readableExtensions(list []uint16) []string {
	out := make([]string, len(list))
	for i, v := range list {
		if name, ok := dicttls.DictExtTypeValueIndexed[v]; ok {
			out[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			out[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}
	return out
}

func readableGroups(list []uint16) []string {
	out := make([]string, len(list))
	for i, v := range list {
		if name, ok := dicttls.DictSupportedGroupsValueIndexed[v]; ok {
			out[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			out[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}
	return out
}

func readableSigAlgs(list []uint16) []string {
	out := make([]string, len(list))
	for i, v := range list {
		if name, ok := dicttls.DictSignatureAlgorithmValueIndexed[uint8(v)]; ok {
			out[i] = fmt.Sprintf("%s (0x%x)", name, v)
		} else {
			out[i] = fmt.Sprintf("unknown (0x%x)", v)
		}
	}
	return out
}

func makeDetail(md *metadata.Metadata, r *http.Request, ctx fingerprint.RequestCtx) (*detailResponse, error) {
	ch := &tlsx.ClientHelloBasic{}
	if err := ch.Unmarshal(md.ClientHelloRecord); err != nil {
		return nil, err
	}
	ja3Raw := fpja3.Bare(ch)

	j4 := &fpja4.JA4Fingerprint{}
	if err := j4.UnmarshalBytes(md.ClientHelloRecord, 't'); err != nil {
		return nil, err
	}

	d := &detailResponse{
		UserAgent: r.UserAgent(),
		HTTP: httpInfo{
			JA4H:           ctx.JA4H,
			HTTP2:          ctx.HTTP2,
			HTTP2Frames:    md.HTTP2Frames,
			Headers:        r.Header.Clone(),
			OrderedHeaders: md.OrderedHeaders(),
		},
		TLS: tlsInfo{
			JA4:                         ctx.JA4,
			JA3:                         ctx.JA3,
			JA3Raw:                      string(ja3Raw),
			ClientHello:                 *ch,
			ClientHelloHex:              hex.EncodeToString(md.ClientHelloRecord),
			IsQUIC:                      md.IsQUIC,
			ReadableCipherSuites:        readableCipherSuites(j4.CipherSuites),
			ReadableJA4Extensions:       readableExtensions(j4.Extensions),
			ReadableAllExtensions:       readableExtensions(ch.AllExtensions),
			ReadableSupportedGroups:     readableGroups(ch.SupportedGroups),
			ReadableSignatureAlgorithms: readableSigAlgs(j4.SignatureAlgorithms),
		},
	}
	return d, nil
}

// echoHandler serves fingerprint details of the client.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	ctx, err := fingerprint.New(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch r.URL.Path {
	case "/", "":
		resp := summaryResponse{
			UserAgent: r.UserAgent(),
			JA3:       ctx.JA3,
			JA4:       ctx.JA4,
			JA4H:      ctx.JA4H,
			HTTP2:     ctx.HTTP2,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := indexTmpl.Execute(w, resp); err != nil {
			cblog.Errorf("render index: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "/fp", "/fp/":
		resp := summaryResponse{
			UserAgent: r.UserAgent(),
			JA3:       ctx.JA3,
			JA4:       ctx.JA4,
			JA4H:      ctx.JA4H,
			HTTP2:     ctx.HTTP2,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			cblog.Errorf("encode summary: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "/fp/detail":
		md, ok := metadata.FromContext(r.Context())
		if !ok {
			http.Error(w, "missing metadata", http.StatusInternalServerError)
			return
		}
		resp, err := makeDetail(md, r, ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			cblog.Errorf("encode detail: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	case "/fp/clienthello":
		md, ok := metadata.FromContext(r.Context())
		if !ok {
			http.Error(w, "missing metadata", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Disposition", "attachment; filename=clienthello.hex")
		_, _ = io.WriteString(w, hex.EncodeToString(md.ClientHelloRecord))
	default:
		http.NotFound(w, r)
	}
}

// NewEcho creates a Server that returns fingerprint information for every
// request instead of proxying to an upstream.
func NewEcho(id, listenAddr, certFile, keyFile string) (*Server, error) {
	// reuse New with nil engines and local upstream since we're not proxying
	return newServerWithHandler(id, listenAddr, certFile, keyFile, http.HandlerFunc(echoHandler))
}

// newServerWithHandler is a helper that mirrors New but allows a custom handler.
func newServerWithHandler(id, listenAddr, certFile, keyFile string, handler http.Handler) (*Server, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("cert and key must both be provided")
		}
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
	} else {
		cert, err = selfSignedCert(listenAddr)
	}
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos: []string{
			"h3", "h3-34", "h3-33", "h3-32", "h3-31", "h3-30", "h3-29",
			"h2", "http/1.1",
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	ctx, cancel := context.WithCancel(context.Background())
	svr := proxyserver.NewServer(ctx, handler, tlsConfig)

	h3svr, err := newH3Server(listenAddr, handler, tlsConfig)
	if err != nil {
		cblog.WithPrefix("H3").Errorf("http3 disabled: %v", err)
		h3svr = nil
	}

	return &Server{Server: svr, ID: id, ListenAddr: listenAddr, cancel: cancel, h3: h3svr}, nil
}
