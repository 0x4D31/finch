package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBytesEmpty(t *testing.T) {
	pos, err := parseBytes(nil)
	if err != nil {
		t.Fatalf("parseBytes: %v", err)
	}
	if len(pos) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(pos))
	}
}

func TestParseBytesMalformed(t *testing.T) {
	_, err := parseBytes([]byte("rule \"x"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.hcl")
	rule := []byte("rule \"ok\" { action = \"allow\" }\n")
	if err := os.WriteFile(path, rule, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	pos, data, err := parseFile(path)
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	if len(pos) != 1 || pos["ok"].start != 0 {
		t.Fatalf("unexpected positions: %#v", pos)
	}
	if string(data) != string(rule) {
		t.Fatalf("unexpected data: %q", data)
	}
	empty := filepath.Join(dir, "empty.hcl")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty: %v", err)
	}
	pos, data, err = parseFile(empty)
	if err != nil {
		t.Fatalf("empty parse: %v", err)
	}
	if len(pos) != 0 || len(data) != 0 {
		t.Fatalf("expected empty result, got %#v %q", pos, data)
	}
	bad := filepath.Join(dir, "bad.hcl")
	if err := os.WriteFile(bad, []byte("rule \"x"), 0o644); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, _, err := parseFile(bad); err == nil {
		t.Fatal("expected error")
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := writeAtomic(path, []byte("first")); err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "first" {
		t.Fatalf("want first got %q", data)
	}
	if err := writeAtomic(path, []byte("second")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read2: %v", err)
	}
	if string(data) != "second" {
		t.Fatalf("want second got %q", data)
	}
	files, _ := filepath.Glob(filepath.Join(dir, ".admin-*"))
	if len(files) != 0 {
		t.Fatalf("temp files not cleaned: %v", files)
	}
}

func TestWriteAtomicPreserveMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeAtomic(path, []byte("second")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
}
