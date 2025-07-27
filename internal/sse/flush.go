package sse

import "net/http"

// flusherErr wraps http.Flusher with an error-returning FlushErr.
type flusherErr interface {
	http.Flusher
	FlushErr() error
}

// Flush calls Flush on fl and returns any FlushErr result.
func Flush(fl http.Flusher) error {
	fl.Flush()
	if fe, ok := fl.(flusherErr); ok {
		return fe.FlushErr()
	}
	return nil
}
