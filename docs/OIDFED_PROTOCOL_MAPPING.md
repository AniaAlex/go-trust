# OpenID Federation AuthZEN Protocol Mapping

This document describes how OpenID Federation concepts are mapped to the AuthZEN Trust Registry Profile (`draft-johansson-authzen-trust`) and identifies areas where the protocol specification may need clarification.

## Architecture

go-trust provides a **protocol-agnostic** interface to trust infrastructure:

```
Client (VC pkg) → Generic AuthZEN API → go-trust Server → Registry abstraction → OIDF/ETSI/DID/etc.
```

**Key principle**: Clients should NOT know which trust infrastructure is being used. The generic AuthZEN interface abstracts over:
- OpenID Federation
- ETSI Trust Status Lists
- DID methods
- Other trust registries

All OIDF-specific logic is **server-side only**. Clients use the standard `EvaluateX5C()`, `EvaluateJWK()`, and `Evaluate()` methods.

## Protocol Mapping

### Subject Mapping

| OIDF Concept | AuthZEN Field | Example |
|--------------|---------------|---------|
| Entity Identifier | `subject.id` | `https://wallet.example.com` |
| Fixed type | `subject.type` | `"key"` |

The entity identifier URL serves as the "name" in the name-to-key binding model.

### Resource Mapping

| OIDF Concept | AuthZEN Field | Example |
|--------------|---------------|---------|
| Entity Identifier | `resource.id` | `https://wallet.example.com` |
| Key type | `resource.type` | `"jwk"` or `"x5c"` |
| Cryptographic key | `resource.key` | JWK or certificate chain |

For **resolution-only** requests (no key validation), `resource.type` and `resource.key` are omitted.

### Action Mapping

| OIDF Concept | AuthZEN Field | Example |
|--------------|---------------|---------|
| Role/purpose | `action.name` | `"openid_credential_issuer"` |

The `action.name` can represent:
1. An entity type (for filtering)
2. A purpose/capability the entity must have
3. A trust mark type that must be present

### Context Mapping (Proposed Extension)

The current specification states:

> The `context` datafield MAY be present in requests but MUST NOT contain information that is **critical for the correct processing** of the request.

We interpret OpenID Federation constraints as **refinements** rather than critical information:
- Without these constraints, a basic trust evaluation still succeeds
- The constraints filter/narrow the acceptable results
- Unknown constraints can be safely ignored by implementations

| Context Key | Type | Purpose |
|-------------|------|---------|
| `required_trust_marks` | `[]string` | Trust marks that MUST be present |
| `allowed_entity_types` | `[]string` | Entity type filter |
| `include_trust_chain` | `bool` | Include full chain in response |
| `include_certificates` | `bool` | Include X.509 certs from JWKS |
| `max_chain_depth` | `int` | Limit trust chain resolution depth |
| `cache_control` | `string` | Cache behavior hints |

### Response Mapping

The `trust_metadata` response field contains:

```json
{
  "iss": "https://wallet.example.com",
  "sub": "https://wallet.example.com", 
  "entity_id": "https://wallet.example.com",
  "trust_anchor": "https://federation.example.eu",
  "metadata": {
    "entity_types": ["openid_credential_issuer"],
    "trust_marks": ["https://example.eu/trust-mark/wallet"]
  },
  "trust_chain": [/* if requested */],
  "jwks": {/* entity JWKS */},
  "iat": 1234567890,
  "exp": 1234571490,
  "evaluated_at": "2024-01-15T10:00:00Z"
}
```

## Protocol Issues and Recommendations

### Issue 1: Context Criticality Definition

**Problem**: The spec says context "MUST NOT contain information that is critical for the correct processing" but doesn't define what "critical" means.

**Impact**: Implementations may disagree on whether trust marks are "critical":
- Interpretation A: Trust marks are critical because without them the decision would be wrong
- Interpretation B: Trust marks are refinements - the base evaluation works, marks narrow it

**Recommendation**: Add to spec:
> Critical information is data without which the request cannot be processed at all.
> Constraint information (e.g., required trust marks) that filters otherwise valid results
> is not considered critical and MAY be placed in context.

### Issue 2: No Standard Federation Context Keys

**Problem**: The profile doesn't define standard context keys for federation-specific constraints.

**Impact**: Implementations will use ad-hoc keys, reducing interoperability.

**Recommendation**: Define a registry of standard context keys:
```
oidfed:required_trust_marks   - Trust marks that must be present
oidfed:allowed_entity_types   - Entity type filter
oidfed:max_chain_depth        - Limit resolution depth
```

Or use a namespaced extension mechanism:
```json
{
  "context": {
    "oidfed": {
      "required_trust_marks": [...],
      "allowed_entity_types": [...]
    }
  }
}
```

### Issue 3: Trust Mark vs Action Ambiguity

**Problem**: Both `action.name` and context `required_trust_marks` could express trust mark requirements.

**Current behavior**:
- `action.name` is typically a single role/purpose
- `required_trust_marks` is a list of required attestations

**Recommendation**: Clarify in spec:
> The `action.name` specifies the primary role or capability being requested.
> Additional requirements (such as multiple trust marks) should be specified in context.

### Issue 4: Resolution-Only Semantics

**Problem**: The spec doesn't explicitly define resolution-only requests.

**Current behavior**: When `resource.type` and `resource.key` are absent, we return entity metadata without validating a specific key binding.

**Recommendation**: Add explicit language:
> When `resource.type` and `resource.key` are absent, the PDP SHALL perform
> metadata resolution only, returning `decision: true` with entity metadata
> in `trust_metadata` if the entity is trusted, without validating a specific key.

### Issue 5: Cache Control

**Problem**: No standard way to control caching behavior.

**Recommendation**: Define standard cache control:
```json
{
  "context": {
    "cache_control": "no-cache"  // or "max-age=3600"
  }
}
```

### Issue 6: Error Responses

**Problem**: The spec doesn't detail error response structure for federation-specific failures.

**Recommendation**: Define standard reason codes:
```json
{
  "decision": false,
  "context": {
    "reason": {
      "code": "oidfed:missing_trust_marks",
      "message": "Required trust marks not present",
      "required": ["https://example.eu/tm/wallet"],
      "present": ["https://example.eu/tm/eidas"]
    }
  }
}
```

## Implementation Status

The go-trust implementation provides:

| Feature | Status | Notes |
|---------|--------|-------|
| Basic OIDF evaluation | ✅ Complete | Trust chain resolution via go-oidfed/lib |
| Trust mark validation | ✅ Complete | Server-side configuration |
| Entity type filtering | ✅ Complete | Server-side configuration |
| Metadata caching | ✅ Complete | TTL-based cache with configurable size |
| Trust chain inclusion | ✅ Complete | Included in trust_metadata response |
| Certificate extraction | ✅ Complete | Included in trust_metadata response |
| Resolution-only | ✅ Complete | Omit resource.type and resource.key |

## Usage Examples

Clients use the **generic AuthZEN interface** - they don't need to know about OpenID Federation:

### Basic Trust Evaluation (X.509 Certificate)

```go
client := authzenclient.New(baseURL)

// Client doesn't know this goes to OIDF - it's protocol-agnostic
resp, err := client.EvaluateX5C(ctx, "https://wallet.example.com", certChain)
if resp.Decision {
    // Entity is trusted
    // trust_metadata contains OIDF-specific details (if OIDF registry was used)
}
```

### Resolution-Only (Get Entity Metadata)

```go
// Resolution-only: omit key to just resolve the entity
resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
    Subject:  authzen.Subject{Type: "key", ID: "https://wallet.example.com"},
    Resource: authzen.Resource{ID: "https://wallet.example.com"},
    // No resource.type or resource.key = resolution only
})

// trust_metadata contains entity configuration
```

### Server-Side Configuration

Trust marks and entity types are configured **on the server**, not by clients:

```yaml
# go-trust server configuration
registries:
  - name: eu-wallet-federation
    type: openid_federation
    trust_anchors:
      - entity_id: https://federation.example.eu
    required_trust_marks:
      - https://example.eu/trust-mark/wallet-provider
    entity_types:
      - openid_credential_issuer
    cache_ttl: 1h
    max_cache_size: 1000
```

### Policy-Based Routing

The `action.name` field enables **protocol-agnostic** policy routing. Clients specify their role/purpose, and the server applies appropriate constraints:

```yaml
# Server policy configuration
policies:
  # Policy for credential issuer verification
  credential-issuer:
    registries:
      - eu-wallet-federation     # Only use this registry
    oidfed:
      required_trust_marks:
        - https://example.eu/tm/issuer
      allowed_entity_types:
        - openid_credential_issuer
  
  # Policy for credential verifier
  credential-verifier:
    registries:
      - eu-wallet-federation
      - eidas-registry
    oidfed:
      required_trust_marks:
        - https://example.eu/tm/verifier
      allowed_entity_types:
        - openid_credential_verifier
  
  # Policy for PID providers (stricter requirements)
  pid-provider:
    registries:
      - eu-wallet-federation
    oidfed:
      required_trust_marks:
        - https://example.eu/tm/pid-provider
        - https://example.eu/tm/eidas-qualified
      allowed_entity_types:
        - openid_credential_issuer
    etsi:
      trust_service_types:
        - QCert

# Default policy when no action.name matches
default_policy: credential-verifier
```

**Client usage** - clients only specify what they need:

```go
client := authzenclient.New(baseURL)

// Client specifies the role/purpose via action.name
// Server applies "credential-issuer" policy constraints
resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
    Subject:  authzen.Subject{Type: "key", ID: entityID},
    Resource: authzen.Resource{ID: entityID, Type: "jwk", Key: jwk},
    Action:   authzen.Action{Name: "credential-issuer"},
})
```

**How it works**:
1. Client sends request with `action.name: "credential-issuer"`
2. Server's PolicyManager looks up the "credential-issuer" policy
3. Policy specifies which registries to use and what constraints to apply
4. OIDF registry applies required trust marks and entity type filters
5. Response includes policy metadata showing which policy was used

**Benefits**:
- Clients remain **protocol-agnostic** - they don't know about OIDF, ETSI, etc.
- Constraints are **centrally managed** on the server
- Different policies can use different **trust infrastructures**
- Easy to add new policies without changing clients

## Future Work

1. **Standardize context keys** - Propose standard keys to AuthZEN spec
2. **Trust mark verification** - Verify trust mark signatures, not just presence
3. **Metadata policy evaluation** - Apply trust anchor metadata policies
4. **Batch evaluation** - Evaluate multiple entities in one request
5. **WebSocket streaming** - Stream trust chain updates for long-lived sessions
