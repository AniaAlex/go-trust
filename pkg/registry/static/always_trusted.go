package static

import (
	"context"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// AlwaysTrustedRegistry is a TrustRegistry that always returns decision=true.
// This is intended ONLY for testing and development environments.
//
// WARNING: Do NOT use this registry in production - it bypasses all trust evaluation.
type AlwaysTrustedRegistry struct {
	name        string
	description string
}

// NewAlwaysTrustedRegistry creates a new always-trusted registry with the given name.
func NewAlwaysTrustedRegistry(name string) *AlwaysTrustedRegistry {
	if name == "" {
		name = "always-trusted"
	}
	return &AlwaysTrustedRegistry{
		name:        name,
		description: "Always returns trusted (FOR TESTING ONLY)",
	}
}

// Evaluate always returns decision=true regardless of the request.
func (r *AlwaysTrustedRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry": r.name,
				"type":     "always_trusted",
				"warning":  "This registry always returns trusted - do not use in production",
			},
		},
	}, nil
}

// SupportedResourceTypes returns all resource types since this registry
// accepts any input.
func (r *AlwaysTrustedRegistry) SupportedResourceTypes() []string {
	return []string{"*"} // Accept all resource types
}

// SupportsResolutionOnly returns true since this registry can handle any request.
func (r *AlwaysTrustedRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *AlwaysTrustedRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:           r.name,
		Type:           "static_always_trusted",
		Description:    r.description,
		Version:        "1.0.0",
		TrustAnchors:   []string{}, // No trust anchors - trusts everything
		ResourceTypes:  []string{"*"},
		ResolutionOnly: true,
		Healthy:        true,
	}
}

// Healthy always returns true.
func (r *AlwaysTrustedRegistry) Healthy() bool {
	return true
}

// Refresh is a no-op for this registry.
func (r *AlwaysTrustedRegistry) Refresh(ctx context.Context) error {
	return nil
}

// Compile-time check that AlwaysTrustedRegistry implements TrustRegistry
var _ registry.TrustRegistry = (*AlwaysTrustedRegistry)(nil)
