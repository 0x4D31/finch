package proxy

import (
	"net/url"
	"strings"

	"github.com/0x4D31/finch/internal/rules"
)

func singleSlashJoin(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	as := strings.HasSuffix(a, "/")
	bs := strings.HasPrefix(b, "/")
	switch {
	case as && bs:
		return a + strings.TrimPrefix(b, "/")
	case !as && !bs:
		return a + "/" + b
	default:
		return a + b
	}
}

// mapPath rewrites reqPath based on upstreamPath and matched rule.
// If upstreamPath is empty, the original path is returned.
// If upstreamPath ends with a slash, the prefix or exact path of the matched
// rule is stripped from the request path and appended to upstreamPath.
// Otherwise upstreamPath replaces the request path completely.
// mapPath rewrites reqPath and reqRawPath based on upstreamPath and matched rule.
// It returns the rewritten path, raw path and query string.
// If upstreamPath is empty, the original values are returned.
// When upstreamPath contains a query, it is merged with the original query string,
// with upstream parameters taking precedence on key conflicts.
func mapPath(reqPath, reqRawPath, reqQuery, upstreamPath string, rule *rules.Rule, matchedPrefix string) (string, string, string) {
	newPath := reqPath
	newRawPath := reqRawPath
	mergedQuery := reqQuery

	if upstreamPath == "" {
		return newPath, newRawPath, mergedQuery
	}

	upPath := upstreamPath
	upQuery := ""
	if up, err := url.Parse(upstreamPath); err == nil {
		upPath = up.Path
		upQuery = up.RawQuery
	}

	if strings.HasSuffix(upPath, "/") {
		restPath := newPath
		restRawPath := newRawPath
		if rule != nil && rule.StripPrefix != "" {
			restPath = strings.TrimPrefix(newPath, rule.StripPrefix)
			restRawPath = strings.TrimPrefix(newRawPath, rule.StripPrefix)
		} else if matchedPrefix != "" {
			restPath = strings.TrimPrefix(newPath, matchedPrefix)
			restRawPath = strings.TrimPrefix(newRawPath, matchedPrefix)
		}
		newPath = singleSlashJoin(upPath, restPath)
		newRawPath = singleSlashJoin(upPath, restRawPath)
	} else {
		newPath = upPath
		newRawPath = upPath
	}

	if upQuery != "" {
		reqVals, _ := url.ParseQuery(reqQuery)
		upVals, _ := url.ParseQuery(upQuery)
		for k, v := range upVals {
			reqVals[k] = v
		}
		mergedQuery = reqVals.Encode()
	}

	return newPath, newRawPath, mergedQuery
}
