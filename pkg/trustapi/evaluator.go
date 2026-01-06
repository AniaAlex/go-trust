package trustapi

import (
	"context"
	"crypto"
)

// TrustEvaluator evaluates whether a name-to-key binding is trusted.
//
// Implementations can use:
//   - go-trust AuthZEN client (for federation/trust framework queries)
//   - Local trust lists (for offline validation against configured anchors)
//   - Composite evaluators (try multiple sources)
//
// This interface supports validation scenarios where the key is already known
// (SD-JWT x5c, mDOC certificates). For DID-based credentials where the key
// must be fetched, use KeyResolver.
type TrustEvaluator interface {
	// Evaluate checks if the given key is trusted for the specified subject and role.
	// Returns a TrustDecision indicating whether the binding is trusted.
	// Should not return an error for "not trusted" cases; use Trusted=false.
	Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)

	// SupportsKeyType returns true if this evaluator can handle the given key type.
	SupportsKeyType(kt KeyType) bool

	// Name returns a human-readable name for this evaluator.
	Name() string

	// Healthy returns true if the evaluator is operational.
	// For remote evaluators, this indicates connectivity to the backend.
	Healthy() bool
}

// KeyResolver resolves public keys from identifiers.
// This is used when the key needs to be fetched (DID-based credentials).
type KeyResolver interface {
	// ResolveKey retrieves the public key for the given verification method.
	// The verificationMethod is typically a DID URL (e.g., "did:web:example.com#key-1").
	ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
}

// CombinedTrustService combines evaluation and resolution capabilities.
// This is the full interface for trust management across all credential formats.
type CombinedTrustService interface {
	TrustEvaluator
	KeyResolver
}
