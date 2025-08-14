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

// mapPath rewrites reqPath and reqRawPath based on upstreamPath and matched rule.
// Returns (newPath, newRawPath, mergedQuery).
// Semantics:
//   - If upstreamPath is empty: return original values.
//   - If upstreamPath has a query: merge it with reqQuery (upstream keys win).
//   - If upstreamPath ends with '/': strip rule.StripPrefix or matchedPrefix from request,
//     then append the remainder under upstreamPath.
//   - Otherwise (no trailing slash):
//       * If rule != nil: upstreamPath replaces the request path (legacy route semantics).
//       * If rule == nil and upstreamPath is non-empty and not "/": treat it as a base path:
//           - req "/" → upstreamPath
//           - req "/x" → upstreamPath + "/x"
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
        // Default-upstream special case: treat a non-empty, non-"/" upstream path
        // as a base path when no rule matched. Root ("/") maps to the base path
        // itself; non-root requests are joined under the base path.
        if rule == nil && upPath != "" && upPath != "/" {
            if reqPath != "/" && reqPath != "" {
                upWithSlash := upPath + "/"
                newPath = singleSlashJoin(upWithSlash, newPath)
                newRawPath = singleSlashJoin(upWithSlash, newRawPath)
            } else {
                newPath = upPath
                newRawPath = upPath
            }
        } else {
            newPath = upPath
            newRawPath = upPath
        }
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
