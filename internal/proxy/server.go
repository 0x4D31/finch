package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	cblog "github.com/charmbracelet/log"

	"github.com/0x4D31/finch/internal/fingerprint"
	"github.com/0x4D31/finch/internal/logger"
	"github.com/0x4D31/finch/internal/rules"
	"github.com/0x4D31/finch/internal/sse"
	fingerproxy "github.com/0x4D31/fingerproxy"
	"github.com/0x4D31/fingerproxy/pkg/proxyserver"
	"github.com/0x4D31/fingerproxy/pkg/reverseproxy"
	galah "github.com/0x4d31/galah/galah"
	galahllm "github.com/0x4d31/galah/pkg/llm"
	suricata "github.com/0x4d31/galah/pkg/suricata"
)

const DefaultBodyLimit int64 = 1 << 20 // 1MB

// ProxyCacheSize defines the maximum number of cached reverse proxies.
// It can be overridden for testing or via configuration.
var ProxyCacheSize int = DefaultProxyCacheSize

// BodyLimit controls how many bytes of the request body are captured for
// logging and Suricata matching. The full body is still forwarded upstream.
// The value can be adjusted for testing or tuning.
var BodyLimit int64 = DefaultBodyLimit

const (
	HeaderJA3   = "X-JA3-Fingerprint"
	HeaderJA4   = "X-JA4-Fingerprint"
	HeaderJA4H  = "X-JA4H-Fingerprint"
	HeaderHTTP2 = "X-HTTP2-Fingerprint"
)

func emojiForAction(action rules.Action) string {
	switch action {
	case rules.ActionAllow:
		return "✅"
	case rules.ActionDeny:
		return "⛔"
	case rules.ActionRoute:
		return "↪️"
	case rules.ActionDeceive:
		return "🎭"
	case rules.ActionTarpit:
		return "🐌"
	default:
		return "❓"
	}
}

// Server wraps proxyserver.Server and holds minimal configuration.
type Server struct {
	*proxyserver.Server
	ID           string
	ListenAddr   string
	UpstreamURL  *url.URL
	LocalEngine  *rules.Engine
	GlobalEngine *rules.Engine
	Logger       *logger.Logger
	Hub          *sse.Hub
	Service      atomic.Pointer[galah.Service]
	cancel       context.CancelFunc

	SuricataSet *atomic.Pointer[suricata.RuleSet]

	ruleHandler *ruleHandler

	cacheEnabled   atomic.Bool
	logGalahEvents atomic.Bool

	CertFile           string
	KeyFile            string
	UpstreamCAFile     string
	UpstreamSkipVerify bool

	h3 *h3Server

	h3Err chan error
}

// New creates a Server that listens on listenAddr and forwards to upstreamURL.
// A self-signed certificate is generated if certFile and keyFile are empty.
// The provided logger records request events and can be shared by multiple servers.
func New(id, listenAddr, upstreamURL, certFile, keyFile string, lgr *logger.Logger, localEng, globalEng *rules.Engine, suriSet *atomic.Pointer[suricata.RuleSet], hub *sse.Hub, svc *galah.Service, upstreamCAFile string, upstreamSkipVerify bool) (*Server, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	var cert tls.Certificate
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

	injectors := fingerproxy.DefaultHeaderInjectors()

	rh := &ruleHandler{
		listenerAddr:          listenAddr,
		local:                 localEng,
		global:                globalEng,
		logger:                lgr,
		hub:                   hub,
		defaultURL:            u,
		injectors:             injectors,
		cache:                 newProxyCache(ProxyCacheSize),
		suricataSet:           suriSet,
		bodyLimit:             BodyLimit,
		upstreamCAFile:        upstreamCAFile,
		upstreamSkipTLSVerify: upstreamSkipVerify,
	}
	var handler http.Handler = rh

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	ctx, cancel := context.WithCancel(context.Background())
	svr := proxyserver.NewServer(ctx, mux, tlsConfig)

	h3svr, err := newH3Server(listenAddr, mux, tlsConfig)
	if err != nil {
		cblog.WithPrefix("H3").Errorf("http3 disabled: %v", err)
	}

	srv := &Server{
		Server:             svr,
		ID:                 id,
		ListenAddr:         listenAddr,
		UpstreamURL:        u,
		LocalEngine:        localEng,
		GlobalEngine:       globalEng,
		Logger:             lgr,
		Hub:                hub,
		cancel:             cancel,
		SuricataSet:        suriSet,
		ruleHandler:        rh,
		h3:                 h3svr,
		CertFile:           certFile,
		KeyFile:            keyFile,
		UpstreamCAFile:     upstreamCAFile,
		UpstreamSkipVerify: upstreamSkipVerify,
	}
	srv.SetGalahService(svc)
	srv.SetGalahOptions(false, false)
	return srv, nil
}

// Start runs the HTTPS server.
func (s *Server) Start() error {
	if s.h3 != nil {
		s.h3Err = make(chan error, 1)
		go func() {
			s.h3Err <- s.h3.Serve()
			close(s.h3Err)
		}()
	}

	httpErr := s.ListenAndServe(s.ListenAddr)

	var h3Err error
	if s.h3Err != nil {
		if httpErr != nil {
			_ = s.h3.Close()
			select {
			case h3Err = <-s.h3Err:
			default:
			}
		} else {
			h3Err = <-s.h3Err
		}
	}

	if httpErr != nil && h3Err != nil {
		return errors.Join(httpErr, h3Err)
	}
	if httpErr != nil {
		return httpErr
	}
	return h3Err
}

// Shutdown gracefully stops the server, waiting for active requests to finish.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	var h3Err, httpErr error
	if s.h3 != nil {
		h3Err = s.h3.Close()
	}
	httpErr = s.HTTPServer.Shutdown(ctx)

	if s.ruleHandler != nil && s.ruleHandler.cache != nil {
		s.ruleHandler.cache.closeAll()
	}

	if h3Err != nil && httpErr != nil {
		return errors.Join(httpErr, h3Err)
	}
	if httpErr != nil {
		return httpErr
	}
	return h3Err
}

// Close immediately closes the server.
func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	var h3Err, httpErr error
	if s.h3 != nil {
		h3Err = s.h3.Close()
	}
	httpErr = s.HTTPServer.Close()

	if s.ruleHandler != nil && s.ruleHandler.cache != nil {
		s.ruleHandler.cache.closeAll()
	}

	if h3Err != nil && httpErr != nil {
		return errors.Join(httpErr, h3Err)
	}
	if httpErr != nil {
		return httpErr
	}
	return h3Err
}

// SetGalahService stores svc atomically and updates the rule handler.
func (s *Server) SetGalahService(svc *galah.Service) {
	s.Service.Store(svc)
	if s.ruleHandler != nil {
		s.ruleHandler.SetGalahService(svc)
	}
}

// SetGalahOptions updates Galah cache and event logging settings.
func (s *Server) SetGalahOptions(cache, events bool) {
	s.cacheEnabled.Store(cache)
	s.logGalahEvents.Store(events)
	if s.ruleHandler != nil {
		s.ruleHandler.SetGalahOptions(cache, events)
	}
}

// SetLocalEngine replaces the listener-specific rule engine.
func (s *Server) SetLocalEngine(eng *rules.Engine) {
	s.LocalEngine = eng
	if s.ruleHandler != nil {
		s.ruleHandler.local = eng
	}
}

// SetGlobalEngine replaces the shared rule engine.
func (s *Server) SetGlobalEngine(eng *rules.Engine) {
	s.GlobalEngine = eng
	if s.ruleHandler != nil {
		s.ruleHandler.global = eng
	}
}

// SetSuricataSet replaces the active Suricata rule set.
func (s *Server) SetSuricataSet(set *atomic.Pointer[suricata.RuleSet]) {
	s.SuricataSet = set
	if s.ruleHandler != nil {
		s.ruleHandler.suricataSet = set
	}
}

// selfSignedCert creates a temporary self-signed certificate.
func selfSignedCert(listenAddr string) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Base cert template: always include localhost DNS SAN
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// If the bind address was a concrete host:port, add it as an IP or DNS SAN
	if host, _, err := net.SplitHostPort(listenAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}

	// Always also include the normal loopback addresses
	if ip := net.ParseIP("127.0.0.1"); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	if ip := net.ParseIP("::1"); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ruleHandler evaluates requests using the rule engine before forwarding.
type ruleHandler struct {
	listenerAddr string
	local        *rules.Engine
	global       *rules.Engine
	logger       *logger.Logger
	hub          *sse.Hub
	defaultURL   *url.URL
	injectors    []reverseproxy.HeaderInjector
	cache        *proxyCache

	upstreamCAFile        string
	upstreamSkipTLSVerify bool

	service atomic.Pointer[galah.Service]

	cacheEnabled   atomic.Bool
	logGalahEvents atomic.Bool

	suricataSet *atomic.Pointer[suricata.RuleSet]

	bodyLimit int64
}

func (h *ruleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	svc := h.service.Load()
	action := rules.ActionAllow
	targetURL := ""
	ruleID := ""
	var matchedRule *rules.Rule
	var pathPrefix string
	var reqCtx fingerprint.RequestCtx
	var ctxErr error
	var fpErr string
	if ctx, err := fingerprint.New(r); err == nil {
		reqCtx = ctx
	} else {
		ctxErr = err
		fpErr = err.Error()
	}

	origReqURL := r.URL.String()
	target := h.defaultURL

	var bodyBytes []byte
	readErr := false
	if h.logger != nil || h.suricataSet != nil {
		limit := h.bodyLimit
		if limit <= 0 {
			limit = DefaultBodyLimit
		}
		rb, err := io.ReadAll(io.LimitReader(r.Body, limit))
		if err != nil && err != io.EOF {
			fpErr = err.Error()
			readErr = true
			cblog.WithPrefix("REQ").Errorf("read body: %v", err)
		}
		bodyBytes = rb
		if !readErr {
			r.Body = struct {
				io.Reader
				io.Closer
			}{Reader: io.MultiReader(bytes.NewReader(rb), r.Body), Closer: r.Body}
		}
	}

	var surMatches []logger.SuricataMatch
	var suriRules []suricata.Rule
	if h.suricataSet != nil {
		if rs := h.suricataSet.Load(); rs != nil {
			matches := rs.Match(r, string(bodyBytes))
			suriRules = matches
			for _, m := range matches {
				surMatches = append(surMatches, logger.SuricataMatch{Msg: m.Msg, SID: m.SID})
				reqCtx.SuricataMsgs = append(reqCtx.SuricataMsgs, m.Msg)
			}
		}
	}

	var upstreamParseErr string
	var invalidUpstream bool
	if ctxErr == nil {
		action, targetURL, ruleID, matchedRule, pathPrefix = rules.EvalComposite(h.local, h.global, &reqCtx)
		if action == rules.ActionRoute && targetURL != "" {
			if u, err := url.Parse(targetURL); err == nil {
				target = &url.URL{Scheme: u.Scheme, Host: u.Host}
				newPath, newRawPath, q := mapPath(r.URL.Path, r.URL.EscapedPath(), r.URL.RawQuery, u.RequestURI(), matchedRule, pathPrefix)
				r.URL.Path = newPath
				r.URL.RawPath = newRawPath
				r.URL.RawQuery = q
			} else {
				cblog.WithPrefix("RULE").Errorf("invalid upstream %q: %v", targetURL, err)
				upstreamParseErr = err.Error()
				invalidUpstream = true
			}
		}
	} else {
		if h.local != nil {
			action = h.local.DefaultAction
		} else if h.global != nil {
			action = h.global.DefaultAction
		}
	}

	// Map request path/query onto default upstream base path (no rule override).
	// This aligns default upstream semantics with rule-based routing, including
	// canonical joining and query merging handled by mapPath.
	if matchedRule == nil && target != nil && ((target.Path != "" && target.Path != "/") || target.RawQuery != "") {
		dest := target.RequestURI()
		newPath, newRawPath, q := mapPath(
			r.URL.Path,
			r.URL.EscapedPath(),
			r.URL.RawQuery,
			dest,
			nil, // no matched rule
			"",
		)
		r.URL.Path = newPath
		r.URL.RawPath = newRawPath
		r.URL.RawQuery = q
		// keep only scheme/host on the target; path/query already applied to r.URL
		target = &url.URL{Scheme: target.Scheme, Host: target.Host}
	}

	// Prepare deception response early so it can be logged and reused.
	var deceiveResp galahllm.JSONResponse
	var deceiveErr error
	deceptionMode := ""
	respSource := ""
	if action == rules.ActionDeceive {
		if matchedRule != nil {
			deceptionMode = matchedRule.DeceptionMode
		}
		if deceptionMode == "" {
			deceptionMode = "galah"
		}
		if deceptionMode == "galah" && svc != nil {
			port := ""
			if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
				_, p, _ := net.SplitHostPort(addr.String())
				port = p
			}
			if h.cacheEnabled.Load() {
				if cb, err := svc.CheckCache(r, port); err == nil && cb != nil {
					if err := json.Unmarshal(cb, &deceiveResp); err == nil {
						respSource = "cache"
					} else {
						cblog.WithPrefix("GALAH").Errorf("invalid cached galah response: %v", err)
					}
				} else if err != nil {
					cblog.WithPrefix("GALAH").Errorf("check cache: %v", err)
				}
			}
			if respSource == "" {
				var b []byte
				b, deceiveErr = svc.GenerateHTTPResponse(r, port)
				if deceiveErr == nil {
					if err := json.Unmarshal(b, &deceiveResp); err != nil {
						cblog.WithPrefix("GALAH").Errorf("invalid galah response: %v", err)
						deceiveErr = err
					} else {
						respSource = "llm"
					}
				} else {
					cblog.WithPrefix("GALAH").Errorf("deceive response: %v", deceiveErr)
				}
			}
			if deceiveErr == nil && h.logGalahEvents.Load() {
				svc.LogEvent(r, deceiveResp, port, respSource, suriRules)
			}
		}
	}

	if h.logger != nil {
		srcHost, srcPortStr, _ := net.SplitHostPort(r.RemoteAddr)
		srcPort := 0
		if p, err := strconv.Atoi(srcPortStr); err == nil {
			srcPort = p
		}
		dstHost, dstPort := "", 0
		if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			h, pstr, _ := net.SplitHostPort(addr.String())
			dstHost = h
			if p, err := strconv.Atoi(pstr); err == nil {
				dstPort = p
			}
		}
		hdr := r.Header.Clone()
		hdr.Del(HeaderJA3)
		hdr.Del(HeaderJA4)
		hdr.Del(HeaderJA4H)
		hdr.Del(HeaderHTTP2)

		if matchedRule != nil || h.global != nil {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			emoji := emojiForAction(action)
			method := lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Render(r.Method)
			path := lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Render(r.URL.Path)
			hostColored := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(host)
			dispID := ruleID
			if dispID == "" {
				dispID = "default"
			}
			ruleColored := lipgloss.NewStyle().Foreground(lipgloss.Color("69")).Render(dispID)
			actionColored := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Render(string(action))
			cblog.WithPrefix("REQ").Infof("%s  %s request %s from %s matched %s rule, action: %s",
				emoji, method, path, hostColored, ruleColored, actionColored,
			)
		}

		headers := make(map[string]string, len(hdr))
		for k, v := range hdr {
			headers[k] = strings.Join(v, ",")
		}

		sha := sha256.Sum256(bodyBytes)

		now := time.Now().UTC()
		id := ruleID
		if id == "" && (h.local != nil || h.global != nil) {
			id = "default"
		}
		errMsg := fpErr
		if upstreamParseErr != "" {
			if errMsg != "" {
				errMsg += "; "
			}
			errMsg += upstreamParseErr
		}

		upstreamStr := target.String()
		if invalidUpstream {
			upstreamStr = targetURL
		}
		var galahInfo *logger.GalahInfo
		if deceptionMode == "galah" && svc != nil && deceiveErr == nil {
			galahInfo = &logger.GalahInfo{
				Provider:        svc.LLMConfig.Provider,
				Model:           svc.LLMConfig.Model,
				Temperature:     svc.LLMConfig.Temperature,
				ResponseBody:    deceiveResp.Body,
				ResponseHeaders: deceiveResp.Headers,
			}
		}

		ev := logger.Event{
			EventTime:       now,
			SrcIP:           srcHost,
			SrcPort:         srcPort,
			DstIP:           dstHost,
			DstPort:         dstPort,
			Method:          r.Method,
			Request:         origReqURL,
			Headers:         headers,
			Body:            string(bodyBytes),
			BodySha256:      fmt.Sprintf("%x", sha[:]),
			ProtocolVersion: r.Proto,
			UserAgent:       r.UserAgent(),
			JA3:             reqCtx.JA3,
			JA3Raw:          reqCtx.JA3Raw,
			JA4:             reqCtx.JA4,
			JA4H:            reqCtx.JA4H,
			HTTP2:           reqCtx.HTTP2,
			RuleID:          id,
			Action:          action,
			Upstream:        upstreamStr,
			SuricataMatches: surMatches,
			ListenerAddr:    h.listenerAddr,
			Error:           errMsg,
			DeceptionMode:   deceptionMode,
			GalahInfo:       galahInfo,
		}
		_ = h.logger.Log(ev)
		if h.hub != nil {
			fe := logger.Event{
				EventTime:       ev.EventTime,
				SrcIP:           ev.SrcIP,
				SrcPort:         ev.SrcPort,
				DstPort:         ev.DstPort,
				Method:          ev.Method,
				Request:         ev.Request,
				Headers:         ev.Headers,
				Body:            ev.Body,
				BodySha256:      ev.BodySha256,
				ProtocolVersion: ev.ProtocolVersion,
				UserAgent:       ev.UserAgent,
				JA3:             ev.JA3,
				JA3Raw:          ev.JA3Raw,
				JA4:             ev.JA4,
				JA4H:            ev.JA4H,
				HTTP2:           ev.HTTP2,
				SuricataMatches: ev.SuricataMatches,
				Error:           errMsg,
				DeceptionMode:   ev.DeceptionMode,
				GalahInfo:       ev.GalahInfo,
			}
			if b, err := json.Marshal(fe); err == nil {
				h.hub.Publish(b)
			}
		}
	}

	if invalidUpstream {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if readErr {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if action == rules.ActionDeny {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if action == rules.ActionTarpit {
		tarpitResponder.ServeHTTP(w, r)
		return
	}
	if action == rules.ActionDeceive {
		if svc == nil || deceiveErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for k, v := range deceiveResp.Headers {
			w.Header().Set(k, v)
		}
		_, _ = w.Write([]byte(deceiveResp.Body))
		return
	}

	h.getProxy(target).ServeHTTP(w, r)
}

func (h *ruleHandler) getProxy(u *url.URL) http.Handler {
	key := u.String()
	if h.cache == nil {
		h.cache = newProxyCache(ProxyCacheSize)
	}
	if p, ok := h.cache.Get(key); ok {
		return p
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{}
	}
	if pool, err := x509.SystemCertPool(); err == nil && pool != nil {
		tr.TLSClientConfig.RootCAs = pool
	}
	if h.upstreamCAFile != "" {
		data, err := os.ReadFile(h.upstreamCAFile)
		if err != nil {
			cblog.WithPrefix("TLS").Errorf("load upstream ca file %s: %v", h.upstreamCAFile, err)
		} else {
			if tr.TLSClientConfig.RootCAs == nil {
				tr.TLSClientConfig.RootCAs = x509.NewCertPool()
			}
			tr.TLSClientConfig.RootCAs.AppendCertsFromPEM(data)
		}
	}
	if h.upstreamSkipTLSVerify {
		tr.TLSClientConfig.InsecureSkipVerify = true
		cblog.WithPrefix("TLS").Warn("upstream TLS verification disabled")
	}
	p := reverseproxy.NewHTTPHandler(
		u,
		&httputil.ReverseProxy{
			ErrorLog:      cblog.StandardLog(),
			Transport:     tr,
			FlushInterval: time.Second,
		},
		h.injectors,
	)
	h.cache.Add(key, p, tr)
	return p
}

// SetGalahService stores svc atomically for h.
func (h *ruleHandler) SetGalahService(svc *galah.Service) {
	h.service.Store(svc)
}

// SetGalahOptions updates cache and event logging flags for h.
func (h *ruleHandler) SetGalahOptions(cache, events bool) {
	h.cacheEnabled.Store(cache)
	h.logGalahEvents.Store(events)
}
