package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/config"
)

func TestAddListenerSkipVerifyOverride(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "log")
	rt := &runtimeState{
		loader:   NewLoader(""),
		loggers:  make(map[string]*logRef),
		logPaths: make(map[string]string),
		pf:       parsedFlags{},
	}
	tru := true
	fal := false
	cfg := &config.Config{Defaults: &config.Defaults{AccessLog: log, UpstreamSkipTLSVerify: &tru}}
	l := config.ListenerConfig{
		ID:                    "a",
		Bind:                  "127.0.0.1:0",
		Upstream:              "http://example.com",
		AccessLog:             "",
		UpstreamSkipTLSVerify: &fal,
	}
	srv, err := rt.addListener(l, cfg, nil, nil, nil)
	if err != nil {
		t.Fatalf("addListener: %v", err)
	}
	if srv.UpstreamSkipVerify {
		t.Fatalf("expected skip verify false, got true")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	_ = srv.Shutdown(ctx)
	cancel()
}
