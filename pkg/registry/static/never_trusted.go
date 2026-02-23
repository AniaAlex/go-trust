package static

import (
	"context"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// NeverTrustedRegistry is a TrustRegistry that always returns decision=false.
// This is useful for testing denial scenarios or as a fallback registry.
type NeverTrustedRegistry struct {
	name        string
	description string
	reason      string
}

// NeverTrustedConfig provides optional configuration for NeverTrustedRegistry.
type NeverTrustedConfig struct {
	// Name is a human-readable name for the registry
	Name string

	// Description provides additional context
	Description string

	// Reason is the denial reason included in the response context
	Reason string
}

// NewNeverTrustedRegistry creates a new never-trusted registry with the given name.
func NewNeverTrustedRegistry(name string) *NeverTrustedRegistry {
	if name == "" {
		name = "never-trusted"
	}
	return &NeverTrustedRegistry{
		name:        name,
		description: "Always returns untrusted",
		reason:      "denied by never-trusted registry",
	}
}

// NewNeverTrustedRegistryWithConfig creates a new never-trusted registry with full configuration.
func NewNeverTrustedRegistryWithConfig(cfg NeverTrustedConfig) *NeverTrustedRegistry {
	if cfg.Name == "" {
		cfg.Name = "never-trusted"
	}
	if cfg.Description == "" {
		cfg.Description = "Always returns untrusted"
	}
	if cfg.Reason == "" {
		cfg.Reason = "denied by never-trusted registry"
	}
	return &NeverTrustedRegistry{
		name:        cfg.Name,
		description: cfg.Description,
		reason:      cfg.Reason,
	}
}

// Evaluate always returns decision=false regardless of the request.
func (r *NeverTrustedRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry": r.name,
				"type":     "never_trusted",
				"error":    r.reason,
			},
		},
	}, nil
}

// SupportedResourceTypes returns all resource types since this registry
// handles (rejects) any input.
func (r *NeverTrustedRegistry) SupportedResourceTypes() []string {
	return []string{"*"} // Accept all resource types (to reject them)
}

// SupportsResolutionOnly returns true since this registry can handle
// (and reject) any request.
func (r *NeverTrustedRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *NeverTrustedRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:           r.name,
		Type:           "static_never_trusted",
		Description:    r.description,
		Version:        "1.0.0",
		TrustAnchors:   []string{}, // No trust anchors - trusts nothing
		ResourceTypes:  []string{"*"},
		ResolutionOnly: true,
		Healthy:        true,
	}
}

// Healthy always returns true (the registry is operational, it just denies everything).
func (r *NeverTrustedRegistry) Healthy() bool {
	return true
}

// Refresh is a no-op for this registry.
func (r *NeverTrustedRegistry) Refresh(ctx context.Context) error {
	return nil
}

// Compile-time check that NeverTrustedRegistry implements TrustRegistry
var _ registry.TrustRegistry = (*NeverTrustedRegistry)(nil)
