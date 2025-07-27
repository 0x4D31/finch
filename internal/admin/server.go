package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hashicorp/hcl/v2/hclsimple"

	cblog "github.com/charmbracelet/log"

	"github.com/0x4D31/finch/internal/config"
	"github.com/0x4D31/finch/internal/rules"
)

// Server exposes administrative endpoints.
type Server struct {
	Addr  string
	token string
	path  string

	mu     sync.RWMutex
	ruleMu sync.Mutex
	cfg    *config.Config
	etag   string
	data   []byte

	apply func(config.Config) error
	stop  func()

	server *http.Server
}

// New returns a new admin server.
//
// addr specifies the address the server listens on.
// cfg provides the initial configuration served at /config; it may be nil.
// data is the raw form of cfg used when computing the initial ETag.
// apply is invoked with a new configuration when /load is called.
// stop is called when /stop is requested.
// path specifies where to persist configuration updates; if empty, updates are not written to disk.
func New(addr, token string, cfg *config.Config, data []byte, apply func(config.Config) error, stop func(), path string) *Server {
	s := &Server{Addr: addr, token: token, cfg: cfg, data: data, apply: apply, stop: stop, path: path}
	s.updateETag()
	mux := http.NewServeMux()
	mux.HandleFunc("/config", s.wrap(s.getConfig))
	mux.HandleFunc("/load", s.wrap(s.loadConfig))
	mux.HandleFunc("/stop", s.wrap(s.stopServer))
	mux.HandleFunc("/rulesets", s.wrap(s.handleRuleSets))
	mux.HandleFunc("/rulesets/", s.wrap(s.handleRuleSet))
	mux.HandleFunc("/config/listeners/", s.wrap(s.updateListenerRuleset))
	s.server = &http.Server{Addr: addr, Handler: mux}
	return s
}

func (s *Server) updateETag() {
	if len(s.data) == 0 && s.cfg == nil {
		s.etag = ""
		return
	}
	data := s.data
	if len(data) == 0 {
		data, _ = json.Marshal(s.cfg)
	}
	h := sha256.Sum256(data)
	s.etag = fmt.Sprintf("\"%x\"", h[:])
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	if s.token == "" {
		return true
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	token := h[len(prefix):]
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) wrap(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(w, r) {
			return
		}
		h(w, r)
	}
}

// Start begins listening for connections.
func (s *Server) Start() error { return s.server.ListenAndServe() }

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error { return s.server.Shutdown(ctx) }

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil {
		http.Error(w, "no config", http.StatusNotFound)
		return
	}
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", s.etag)
	_, _ = w.Write(data)
}

func (s *Server) loadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" || ifMatch != s.etag {
		s.mu.Unlock()
		http.Error(w, "etag mismatch", http.StatusPreconditionFailed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ct := r.Header.Get("Content-Type")
	name := "config.hcl"
	if strings.Contains(ct, "json") {
		name = "config.json"
	}
	var cfg config.Config
	if err := hclsimpleDecode(name, body, &cfg); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	baseDir, err := os.Getwd()
	if err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Resolve any relative paths in the new configuration against the
	// server's current working directory.
	cblog.Infof("admin load: resolving paths relative to %s", baseDir)
	if err := config.ResolvePaths(&cfg, baseDir); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := config.Validate(&cfg); err != nil {
		s.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.apply != nil {
		if err := s.apply(cfg); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if s.path != "" {
		if err := config.WriteJSON(s.path, &cfg); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.cfg = &cfg
	s.data = body
	s.updateETag()
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) stopServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.stop != nil {
		s.stop()
	}
	w.WriteHeader(http.StatusNoContent)
}

func hclsimpleDecode(name string, data []byte, out *config.Config) error {
	if len(data) == 0 {
		return errors.New("empty body")
	}
	if strings.HasSuffix(name, ".json") {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(out); err != nil {
			return err
		}
		return nil
	}
	// use hclsimple.Decode to parse HCL input (also accepts JSON but without
	// unknown field checks)
	if err := hclsimple.Decode(name, data, nil, out); err != nil {
		return err
	}
	return nil
}

func (s *Server) handleRuleSets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	sets := config.EnumerateRuleSets(s.cfg)
	s.mu.RUnlock()
	data, err := json.MarshalIndent(sets, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (s *Server) handleRuleSet(w http.ResponseWriter, r *http.Request) {
	pathRest := strings.TrimPrefix(r.URL.Path, "/rulesets/")
	if pathRest == "" {
		http.NotFound(w, r)
		return
	}

	// check for rule subpath
	if i := strings.Index(pathRest, "/rules/"); i >= 0 {
		id := pathRest[:i]
		ruleID := strings.TrimPrefix(pathRest[i+len("/rules/"):], "/")
		if ruleID == "" {
			http.NotFound(w, r)
			return
		}
		s.handleRule(id, ruleID, w, r)
		return
	}

	id := pathRest
	s.mu.RLock()
	sets := config.EnumerateRuleSets(s.cfg)
	var path string
	for _, rs := range sets {
		if rs.ID == id {
			path = rs.Path
			break
		}
	}
	s.mu.RUnlock()
	if path == "" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, err.Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(data)
	case http.MethodPost:
		s.ruleMu.Lock()
		defer s.ruleMu.Unlock()
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		dir := filepath.Dir(path)
		tmp, err := os.CreateTemp(dir, ".rules-*")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		name := tmp.Name()
		if _, err := tmp.Write(body); err != nil {
			_ = tmp.Close()
			_ = os.Remove(name)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(name)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, err := rules.LoadHCL(name); err != nil {
			_ = os.Remove(name)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := os.Rename(name, path); err != nil {
			_ = os.Remove(name)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		s.ruleMu.Lock()
		defer s.ruleMu.Unlock()
		force := r.URL.Query().Get("force") == "true"
		s.mu.RLock()
		sets = config.EnumerateRuleSets(s.cfg)
		var inUse bool
		for _, rs := range sets {
			if rs.Path == path && len(rs.Listeners) > 0 {
				inUse = true
				break
			}
		}
		s.mu.RUnlock()
		if inUse && !force {
			http.Error(w, "ruleset in use", http.StatusConflict)
			return
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRule(id, ruleID string, w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	sets := config.EnumerateRuleSets(s.cfg)
	var path string
	for _, rs := range sets {
		if rs.ID == id {
			path = rs.Path
			break
		}
	}
	s.mu.RUnlock()
	if path == "" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		pos, data, err := parseFile(path)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rp, exists := pos[ruleID]
		if !exists {
			http.NotFound(w, r)
			return
		}
		snippet := data[rp.start:rp.end]
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(snippet)
	case http.MethodPost:
		s.ruleMu.Lock()
		defer s.ruleMu.Unlock()
		pos, data, err := parseFile(path)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, exists := pos[ruleID]; exists {
			http.Error(w, "rule exists", http.StatusConflict)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = bytes.TrimSpace(body)
		idFromSnippet, err := parseRule(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if idFromSnippet != ruleID {
			http.Error(w, "id mismatch", http.StatusBadRequest)
			return
		}
		body = append(body, '\n')
		newData := data
		if len(newData) > 0 && newData[len(newData)-1] != '\n' {
			newData = append(newData, '\n')
		}
		newData = append(newData, body...)
		if err := writeAtomic(path, newData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut:
		s.ruleMu.Lock()
		defer s.ruleMu.Unlock()
		pos, data, err := parseFile(path)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rp, exists := pos[ruleID]
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = bytes.TrimSpace(body)
		idFromSnippet, err := parseRule(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if idFromSnippet != ruleID {
			http.Error(w, "id mismatch", http.StatusBadRequest)
			return
		}
		body = append(body, '\n')
		var newData []byte
		if exists {
			newData = append(data[:rp.start], append(body, data[rp.end:]...)...)
		} else {
			newData = data
			if len(newData) > 0 && newData[len(newData)-1] != '\n' {
				newData = append(newData, '\n')
			}
			newData = append(newData, body...)
		}
		if err := writeAtomic(path, newData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		s.ruleMu.Lock()
		defer s.ruleMu.Unlock()
		pos, data, err := parseFile(path)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rp, exists := pos[ruleID]
		if !exists {
			http.NotFound(w, r)
			return
		}
		newData := append(data[:rp.start], data[rp.end:]...)
		if err := writeAtomic(path, newData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) updateListenerRuleset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	prefix := "/config/listeners/"
	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, "/ruleset") {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/ruleset")
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	if s.cfg == nil {
		s.mu.Unlock()
		http.Error(w, "no config loaded", http.StatusNotFound)
		return
	}
	prevCfg := *s.cfg
	prevCfg.Listeners = append([]config.ListenerConfig(nil), s.cfg.Listeners...)
	prevData := s.data
	sets := config.EnumerateRuleSets(s.cfg)
	var path string
	for _, rs := range sets {
		if rs.ID == id {
			path = rs.Path
			break
		}
	}
	if path == "" {
		s.mu.Unlock()
		http.Error(w, "ruleset not found", http.StatusNotFound)
		return
	}
	found := false
	for i := range s.cfg.Listeners {
		if s.cfg.Listeners[i].ID == name {
			s.cfg.Listeners[i].RuleFile = path
			found = true
			break
		}
	}
	if !found {
		s.mu.Unlock()
		http.Error(w, "listener not found", http.StatusNotFound)
		return
	}
	cfgCopy := *s.cfg
	if s.apply != nil {
		if err := s.apply(cfgCopy); err != nil {
			s.cfg = &prevCfg
			s.data = prevData
			s.updateETag()
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.data = nil
	s.updateETag()
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}
