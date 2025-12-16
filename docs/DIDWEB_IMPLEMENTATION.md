# DID Web Registry Implementation

## Summary

This implementation adds support for the **did:web** method specification to go-trust, enabling resolution and validation of decentralized identifiers (DIDs) via HTTPS. The implementation follows the [W3C DID Method Web specification](https://w3c-ccg.github.io/did-method-web/).

## Implementation Details

### Files Created

1. **`pkg/registry/didweb/didweb_registry.go`** (414 lines)
   - Core registry implementation
   - HTTPS-based DID resolution
   - JWK matching and validation
   - TLS security configuration per W3C spec
   - Implements `TrustRegistry` interface

2. **`pkg/registry/didweb/didweb_registry_test.go`** (317 lines)
   - Comprehensive test suite
   - URL parsing tests (7 scenarios)
   - JWK comparison tests (5 scenarios)
   - Integration tests
   - All tests passing ✅

3. **`example/didweb-usage.yaml`** (110 lines)
   - Example DID documents
   - AuthZEN request/response examples
   - Security notes and configuration guidance

4. **`example/didweb-registry-example.go`** (188 lines)
   - Working code examples
   - Basic usage demonstration
   - Multi-registry integration example
   - Ready to compile and run

### Features Implemented

#### ✅ DID Resolution
- Converts `did:web:` identifiers to HTTPS URLs
- Handles bare domains: `did:web:example.com` → `https://example.com/.well-known/did.json`
- Handles paths: `did:web:example.com:user:alice` → `https://example.com/user/alice/did.json`
- Handles ports: `did:web:example.com%3A3000` → `https://example.com:3000/.well-known/did.json`
- Handles port+path combinations

#### ✅ Security (per W3C spec)
- **TLS 1.2+** enforcement
- Strong cipher suites:
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305`
  - `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305`
- TLS certificate validation (can be disabled for testing)
- DID document ID verification
- HTTPS-only (no HTTP fallback)

#### ✅ Key Type Support
- **Ed25519** (OKP with crv=Ed25519)
- **P-256, P-384** (EC curves)
- **RSA** (2048+ bits)
- Extensible for additional key types

#### ✅ AuthZEN Integration
- Implements `TrustRegistry` interface
- Supports `"jwk"` resource type
- Returns decision with detailed context
- Includes resolution timing metrics
- Compatible with `RegistryManager` routing

#### ✅ Registry Manager Integration
- Auto-routing based on `resource.type`
- Works with all resolution strategies:
  - `FirstMatch` (default)
  - `AllRegistries`
  - `BestMatch`
  - `Sequential`
- Circuit breaker protection
- Health checks

### Test Coverage

All tests passing with comprehensive coverage:

```
TestDIDToHTTPURL                    ✅ 7 scenarios
TestJWKsMatch                       ✅ 5 scenarios
TestResolveDID                      ✅ URL parsing
TestEvaluate                        ✅ Request validation
TestSupportedResourceTypes          ✅
TestInfo                            ✅
TestHealthy                         ✅
TestRefresh                         ✅
```

### Integration Status

- ✅ Compiles cleanly with no warnings
- ✅ All existing tests still pass
- ✅ Integrates with existing multi-registry architecture
- ✅ Documentation updated in README.md
- ✅ Example code provided and tested

## Usage Example

```go
import (
    "github.com/sirosfoundation/go-trust/pkg/registry/didweb"
    "github.com/sirosfoundation/go-trust/pkg/authzen"
)

// Create registry
registry, err := didweb.NewDIDWebRegistry(didweb.Config{
    Timeout:     30 * time.Second,
    Description: "DID Web Resolver",
})

// Evaluate a DID
req := &authzen.EvaluationRequest{
    Subject: authzen.Subject{
        Type: "key",
        ID:   "did:web:example.com",
    },
    Resource: authzen.Resource{
        Type: "jwk",
        ID:   "did:web:example.com",
        Key:  []interface{}{/* JWK */},
    },
}

resp, err := registry.Evaluate(context.Background(), req)
if resp.Decision {
    // Key is valid!
}
```

## Compliance

This implementation adheres to:

- ✅ [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- ✅ [W3C DID Method Web Specification](https://w3c-ccg.github.io/did-method-web/)
- ✅ [AuthZEN Trust Registry Profile](https://openid.github.io/authzen/)
- ✅ [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) (TLS guidance)

## Future Enhancements

Potential improvements for future versions:

1. **X.509 Support**: Add `resource.type = "x5c"` support
2. **Caching**: Cache resolved DID documents with TTL
3. **DNS over HTTPS**: Integrate DoH for privacy
4. **Additional Key Types**: Support more verification method types
5. **DID Document Validation**: JSON-LD processing and schema validation
6. **Metrics**: Detailed resolution time and success rate metrics

## References

- W3C DID Method Web: https://w3c-ccg.github.io/did-method-web/
- W3C DID Core: https://www.w3.org/TR/did-core/
- Reference implementations:
  - https://github.com/uport-project/https-did-resolver
  - https://github.com/transmute-industries/restricted-resolver
  - https://github.com/reinkrul/java-did-resolvers
