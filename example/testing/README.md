# Go-Trust Testing Examples

This directory contains example code for testing applications that integrate with go-trust.

## Files

| File | Description |
|------|-------------|
| `didweb-registry-example.go` | Demonstrates programmatic use of the did:web registry |
| `testserver-example.go` | Shows how to use the embedded test server for integration testing |

## Running Examples

```bash
# DID Web registry example
go run example/testing/didweb-registry-example.go

# Test server example  
go run example/testing/testserver-example.go
```

## Test Server Overview

The `testserver` package provides an embedded test server for integration testing. This allows dependent applications to test their AuthZEN client integrations without running a full go-trust service.

```go
import (
    "testing"
    "github.com/sirosfoundation/go-trust/pkg/testserver"
)

func TestMyApplication(t *testing.T) {
    // Create a test server that accepts all trust requests
    srv := testserver.New(testserver.WithAcceptAll())
    defer srv.Close()

    // Use srv.URL() to get the server address
    // Make AuthZEN requests to the server
}
```

### Test Server Options

| Option | Description |
|--------|-------------|
| `WithAcceptAll()` | Accept all trust requests |
| `WithRejectAll()` | Reject all trust requests |
| `WithMockRegistry(name, decision, types)` | Add a mock registry |
| `WithDecisionFunc(fn)` | Dynamic trust decisions |

See the main project [README](../../README.md) for complete documentation.
