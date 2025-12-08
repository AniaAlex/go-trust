# Trust Metadata & DID Resolution Implementation Plan

## Overview

This document describes the implementation plan for fully supporting DID resolution and `trust_metadata` in go-trust, as specified in the updated `draft-johansson-authzen-trust` specification.

## Specification Requirements

Based on the AuthZEN Trust Registry Profile specification:

### 1. Optional `type` and `key` Fields

> Some trust registries support unambiguous name-to-key discovery. For such trust registries `key` and `type` MAY be elided from the Resource.

This means requests can be:
- **Full validation**: `type` + `key` present → validate key binding
- **Resolution only**: `type` + `key` absent → resolve metadata only

### 2. `trust_metadata` in Response

> The Authorization Response MAY return metadata associated with `subject.id` in the response using the `trust_metadata` field. When the request `type` is absent then the `trust_metadata` field SHOULD be present.

Response structure:
```json
{
  "decision": true,
  "context": {
    "trust_metadata": {
      "@context": ["https://www.w3.org/ns/did/v1", ...],
      "id": "did:example:123",
      ...
    }
  }
}
```

### 3. AuthZEN Trust as a DID Resolver

> As should be obvious from the specification above, a DID resolver as specified in section 7 of [DID] share many properties with this specification.

---

## Implementation Phases

### Phase 1: Update Core Types for `trust_metadata` Support ✅

**Files Modified:**
- `pkg/authzen/types.go`

**Changes:**
1. Add `TrustMetadata` field to `EvaluationResponseContext`
2. Update `Validate()` to make `type` and `key` optional
3. Add `IsResolutionOnlyRequest()` helper method

### Phase 2: Enhance TrustRegistry Interface

**Files Modified:**
- `pkg/registry/interface.go`

**Changes:**
1. Add `SupportsResolutionOnly() bool` method to interface
2. Document resolution-only behavior

### Phase 3: Enhance DID:web Registry

**Files Modified:**
- `pkg/registry/didweb/didweb_registry.go`
- `pkg/registry/didweb/didweb_registry_test.go`

**Changes:**
1. Implement `SupportsResolutionOnly()`
2. Return DID document as `trust_metadata` in responses
3. Support resolution-only requests (no key validation)
4. Add tests for new functionality

### Phase 4: Implement Generic DID Resolver

**Files Created:**
- `pkg/registry/did/resolver.go`
- `pkg/registry/did/method.go`
- `pkg/registry/did/key.go` (did:key method)
- `pkg/registry/did/resolver_test.go`

**Changes:**
1. Create unified DID resolver supporting multiple methods
2. Implement `did:key` method (self-resolving)
3. Refactor `did:web` to use common interfaces

### Phase 5: Enhance OpenID Federation Registry for `trust_metadata`

**Files Modified:**
- `pkg/registry/oidfed/oidfed_registry.go`
- `pkg/registry/oidfed/oidfed_registry_test.go`

**Changes:**
1. Implement `SupportsResolutionOnly()`
2. Return entity configuration as `trust_metadata`
3. Include trust chain metadata in responses
4. Add tests for new functionality

### Phase 6: Update API Handlers

**Files Modified:**
- `pkg/api/handlers.go`

**Changes:**
1. Handle resolution-only requests
2. Ensure `trust_metadata` is properly serialized
3. Update API documentation/swagger

### Phase 7: Integration Testing & Documentation

**Files Created:**
- `pkg/registry/did/integration_test.go`

**Changes:**
1. Comprehensive integration tests for DID resolution flow
2. Tests for resolution-only requests with `trust_metadata` responses
3. AuthZEN protocol compliance tests
4. Multi-method DID resolver tests

---

## Priority & Timeline

| Phase | Description | Priority | Status |
|-------|-------------|----------|--------|
| 1 | Core types update | High | ✅ Complete |
| 2 | TrustRegistry interface update | High | ✅ Complete |
| 3 | DID:web `trust_metadata` support | High | ✅ Complete |
| 4 | Generic DID resolver + `did:key` | Medium | ✅ Complete |
| 5 | OpenID Federation `trust_metadata` | High | ✅ Complete |
| 6 | API handlers update | Medium | ✅ Complete |
| 7 | Integration testing | Medium | ✅ Complete |

---

## Backwards Compatibility

- All existing APIs remain unchanged for requests that include `type` and `key`
- New `trust_metadata` field is optional and only present when resolution provides metadata
- Existing clients that don't parse `trust_metadata` will continue working

---

## Test Coverage Requirements

1. **Resolution-only requests** - Verify `trust_metadata` is returned when `type`/`key` are absent
2. **DID document in response** - Verify full DID document structure in `trust_metadata`
3. **OpenID Federation entity config** - Verify entity configuration is returned
4. **Mixed validation + metadata** - Verify both key validation and metadata work together
5. **Error cases** - Verify `trust_metadata` can be returned even when validation fails

---

## References

- [draft-johansson-authzen-trust](https://leifj.github.io/draft-johansson-authzen-trust/)
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [W3C DID Method Web](https://w3c-ccg.github.io/did-method-web/)
- [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html)
