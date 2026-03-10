// Package registry provides trust registry management.
// This file contains shared HTTP utility functions.
package registry

import (
	"fmt"
	"io"
)

// MaxResponseBodyBytes is the maximum allowed HTTP response body size (10 MB).
// This prevents unbounded memory consumption from malicious or misconfigured endpoints.
const MaxResponseBodyBytes = 10 * 1024 * 1024

// LimitedReader wraps an io.Reader with a size limit.
// If the reader produces more than MaxResponseBodyBytes, reads will return an error.
func LimitedReader(r io.Reader) io.Reader {
	return io.LimitReader(r, MaxResponseBodyBytes+1)
}

// ReadLimitedBody reads up to MaxResponseBodyBytes from r.
// Returns an error if the body exceeds the limit.
func ReadLimitedBody(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, MaxResponseBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds maximum size of %d bytes", MaxResponseBodyBytes)
	}
	return data, nil
}
