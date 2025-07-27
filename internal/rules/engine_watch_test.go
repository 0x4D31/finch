package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x4D31/finch/internal/watch"
)

func waitForEngine(t *testing.T, e *Engine, cond func([]*Rule) bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		e.mu.RLock()
		rules := append([]*Rule(nil), e.Rules...)
		e.mu.RUnlock()
		if cond(rules) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout waiting for condition")
}

func TestEngineWatchFileModify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.hcl")

	rules1 := `rule "one" {
  action = "allow"
  when {
    http_path = ["/a"]
  }
}`
	if err := os.WriteFile(path, []byte(rules1), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	eng := &Engine{}
	if err := eng.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := watch.Watch(ctx, path, func() error { return eng.LoadFromFile(path) })
	if err != nil {
		t.Fatalf("watchfile: %v", err)
	}

	rules2 := `rule "two" {
  action = "allow"
  when {
    http_path = ["/b"]
  }
}`
	if err := os.WriteFile(path, []byte(rules2), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForEngine(t, eng, func(r []*Rule) bool { return len(r) == 1 && r[0].ID == "two" })
}

func TestEngineWatchFileRecreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.hcl")

	rules1 := `rule "one" {
  action = "allow"
  when {
    http_path = ["/a"]
  }
}`
	if err := os.WriteFile(path, []byte(rules1), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	eng := &Engine{}
	if err := eng.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := watch.Watch(ctx, path, func() error { return eng.LoadFromFile(path) })
	if err != nil {
		t.Fatalf("watchfile: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// wait longer than the previous retry timeout to ensure the watcher keeps trying
	time.Sleep(6 * time.Second)

	rules2 := `rule "two" {
  action = "allow"
  when {
    http_path = ["/b"]
  }
}`
	if err := os.WriteFile(path, []byte(rules2), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForEngine(t, eng, func(r []*Rule) bool { return len(r) == 1 && r[0].ID == "two" })
}

func TestEngineWatchReloadFail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.hcl")

	good := `rule "good" {
  action = "allow"
  when { http_path = ["/a"] }
}`
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	eng := &Engine{}
	if err := eng.LoadFromFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh, err := watch.Watch(ctx, path, func() error { return eng.LoadFromFile(path) })
	if err != nil {
		t.Fatalf("watchfile: %v", err)
	}

	bad := `rule "bad" {
  action = "foo"
}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error")
	}

	waitForEngine(t, eng, func(r []*Rule) bool { return len(r) == 1 && r[0].ID == "good" })

	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForEngine(t, eng, func(r []*Rule) bool { return len(r) == 1 && r[0].ID == "good" })
}
