package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func waitForCount(t *testing.T, c *atomic.Int32, n int32) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c.Load() >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout waiting for count")
}

func TestWatchModify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("a"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var cnt atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Watch(ctx, path, func() error {
		cnt.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	if err := os.WriteFile(path, []byte("b"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForCount(t, &cnt, 1)
}

func TestWatchRecreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("a"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	var cnt atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Watch(ctx, path, func() error {
		cnt.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	time.Sleep(6 * time.Second)

	if err := os.WriteFile(path, []byte("b"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForCount(t, &cnt, 1)
}

func TestWatchDirAdd(t *testing.T) {
	dir := t.TempDir()

	var cnt atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Watch(ctx, dir, func() error {
		cnt.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForCount(t, &cnt, 1)
}

func TestWatchError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("a"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh, err := Watch(ctx, path, func() error { return errors.New("fail") })
	if err != nil {
		t.Fatalf("watch: %v", err)
	}

	if err := os.WriteFile(path, []byte("b"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case e := <-errCh:
		if e == nil {
			t.Fatalf("expected error, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error")
	}
}
