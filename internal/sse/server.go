package sse

import (
	"context"
	"fmt"
	"net/http"
	"time"

	cblog "github.com/charmbracelet/log"
)

// Server exposes events over Server-Sent Events.
type Server struct {
	Addr   string
	Hub    *Hub
	server *http.Server
}

// NewServer creates a new SSE server bound to addr.
func NewServer(addr string, hub *Hub) *Server {
	s := &Server{Addr: addr, Hub: hub}
	mux := http.NewServeMux()
	mux.HandleFunc("/events", s.events)
	s.server = &http.Server{Addr: addr, Handler: mux}
	return s
}

// Start begins listening for connections.
func (s *Server) Start() error { return s.server.ListenAndServe() }

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error { return s.server.Shutdown(ctx) }

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := Flush(fl); err != nil {
		cblog.Errorf("flush headers: %v", err)
		return
	}

	ch := s.Hub.Subscribe(r.Context(), 64)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				cblog.Errorf("write event: %v", err)
				return
			}
			if err := Flush(fl); err != nil {
				cblog.Errorf("flush event: %v", err)
				return
			}
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				cblog.Errorf("write ping: %v", err)
				return
			}
			if err := Flush(fl); err != nil {
				cblog.Errorf("flush ping: %v", err)
				return
			}
		}
	}
}
