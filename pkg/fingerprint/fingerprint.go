// Package fingerprint extracts Finch's client fingerprints from request
// metadata captured by a fingerproxy listener.
package fingerprint

import (
	"net/http"

	internal "github.com/0x4D31/finch/internal/fingerprint"
)

// RequestCtx contains the observed fingerprint and request fields. This is the
// same type used by Finch's rule engine; fingerprint fields are not populated
// from client-supplied X-JA* headers.
type RequestCtx = internal.RequestCtx

// New extracts JA3, raw JA3, JA4, JA4H and HTTP/2 fingerprints. Requests without
// fingerproxy context metadata retain their ordinary request fields but have
// empty fingerprint fields. A plain net/http TLS listener does not capture the
// metadata required for these fingerprints.
func New(r *http.Request) (RequestCtx, error) {
	return internal.New(r)
}
