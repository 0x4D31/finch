package rules

import "testing"

func TestCompilePatternCaseInsensitive(t *testing.T) {
	r, err := compilePattern("~ FoO.*", true)
	if err != nil {
		t.Fatalf("compile regex: %v", err)
	}
	if !r("foobar") {
		t.Fatal("case-insensitive regex failed")
	}

	g, err := compilePattern("^ BaR", true)
	if err != nil {
		t.Fatalf("compile glob: %v", err)
	}
	if !g("barbaz") {
		t.Fatal("case-insensitive glob failed")
	}

	e, err := compilePattern("= BaZ", true)
	if err != nil {
		t.Fatalf("compile exact: %v", err)
	}
	if !e("baz") {
		t.Fatal("case-insensitive exact failed")
	}
}

func TestCompilePatternErrors(t *testing.T) {
	if _, err := compilePattern("~[", false); err == nil {
		t.Fatal("expected regex error")
	}
	if _, err := compilePattern("? foo", false); err == nil {
		t.Fatal("expected unknown operator")
	}
}

func TestCompilePatternDefaults(t *testing.T) {
	m, err := compilePattern("foo", false)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !m("foo") || m("bar") {
		t.Fatal("exact match failed")
	}
}

func TestCompilePathPattern(t *testing.T) {
	ex, pref, err := compilePathPattern("= /a")
	if err != nil {
		t.Fatalf("exact: %v", err)
	}
	if !ex("/a") || ex("/b") || pref("/a") != "/a" {
		t.Fatal("exact path failed")
	}
	pfx, prefFn, err := compilePathPattern("^ /foo")
	if err != nil {
		t.Fatalf("prefix: %v", err)
	}
	if !pfx("/foobar") || prefFn("/foobar") != "/foo" {
		t.Fatal("prefix path failed")
	}
	rx, prefFn2, err := compilePathPattern("~ ^/ba[rz]")
	if err != nil {
		t.Fatalf("regex: %v", err)
	}
	if !rx("/bar") || prefFn2("/bar") != "/bar" {
		t.Fatal("regex path failed")
	}
	if _, _, err := compilePathPattern("~[bad"); err == nil {
		t.Fatal("expected regex error")
	}
}
