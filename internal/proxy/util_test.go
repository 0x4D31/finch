//go:build skipproxy

package proxy

import (
	"testing"

	"github.com/0x4D31/finch/internal/rules"
)

func TestMapPath(t *testing.T) {
	tests := []struct {
		name         string
		rule         *rules.Rule
		upstreamPath string
		reqPath      string
		reqRawPath   string
		reqQuery     string
		prefix       string
		wantPath     string
		wantRawPath  string
		wantQuery    string
	}{
		{"keep-original", nil, "", "/foo", "/foo", "", "", "/foo", "/foo", ""},
		{"strip-prefix", &rules.Rule{StripPrefix: "/api/"}, "/", "/api/users", "/api/users", "", "", "/users", "/users", ""},
		{"replace-prefix", &rules.Rule{StripPrefix: "/api/"}, "/v2/", "/api/users", "/api/users", "", "", "/v2/users", "/v2/users", ""},
		{"fixed", &rules.Rule{}, "/dest/ex", "/foo", "/foo", "", "", "/dest/ex", "/dest/ex", ""},
		{"double-slash", &rules.Rule{StripPrefix: "/api/"}, "/v2/", "/api//x", "/api//x", "", "", "/v2/x", "/v2/x", ""},
		{"encoded", nil, "", "/foo bar", "/foo%20bar", "", "", "/foo bar", "/foo%20bar", ""},
		{"query-upstream", &rules.Rule{StripPrefix: "/api/"}, "/v2/?id=1", "/api/foo", "/api/foo", "", "", "/v2/foo", "/v2/foo", "id=1"},
		{"strip-prefix-encoded", &rules.Rule{StripPrefix: "/a%2Fb/"}, "/v2/", "/a%2Fb/x", "/a%2Fb/x", "", "", "/v2/x", "/v2/x", ""},
		{"encoded-path", nil, "/v2/", "/foo%2Fbar", "/foo%2Fbar", "", "", "/v2/foo%2Fbar", "/v2/foo%2Fbar", ""},
		{"auto-prefix", nil, "/v2/", "/api/x", "/api/x", "", "/api/", "/v2/x", "/v2/x", ""},
		{"merge-query", nil, "/v2/", "/foo", "/foo", "x=1", "", "/v2/foo", "/v2/foo", "x=1"},
		{"merge-upstream", nil, "/v2/?id=1", "/foo", "/foo", "x=1", "", "/v2/foo", "/v2/foo", "id=1&x=1"},
		{"query-no-slash", nil, "/v2?id=2", "/foo", "/foo", "", "", "/v2", "/v2", "id=2"},
		{"only-query", nil, "?a=1", "/foo", "/foo", "", "", "", "", "a=1"},
		{"full-url", nil, "https://up/v2/?q=3", "/bar", "/bar", "", "", "/v2/bar", "/v2/bar", "q=3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotRaw, gotQuery := mapPath(tt.reqPath, tt.reqRawPath, tt.reqQuery, tt.upstreamPath, tt.rule, tt.prefix)
			if gotPath != tt.wantPath {
				t.Fatalf("path want %s got %s", tt.wantPath, gotPath)
			}
			if gotRaw != tt.wantRawPath {
				t.Fatalf("rawpath want %s got %s", tt.wantRawPath, gotRaw)
			}
			if gotQuery != tt.wantQuery {
				t.Fatalf("query want %s got %s", tt.wantQuery, gotQuery)
			}
		})
	}
}
