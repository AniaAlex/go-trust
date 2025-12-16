package did_test

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTrustMetadataIntegration tests the complete trust_metadata flow
// as specified in draft-johansson-authzen-trust.
func TestTrustMetadataIntegration(t *testing.T) {
	t.Run("did:key resolution-only returns trust_metadata", func(t *testing.T) {
		registry := did.NewGenericDIDRegistryWithKeyMethod(did.GenericDIDRegistryConfig{
			Description: "Integration Test Registry",
		})
		ctx := context.Background()

		// Create a resolution-only request per the specification
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{
				Type: "key",
				ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			},
			Resource: authzen.Resource{
				ID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
				// No type or key = resolution-only
			},
		}

		// Verify this is recognized as resolution-only
		assert.True(t, req.IsResolutionOnlyRequest())
		assert.NoError(t, req.Validate())

		// Verify registry supports resolution-only
		assert.True(t, registry.SupportsResolutionOnly())

		// Execute the evaluation
		resp, err := registry.Evaluate(ctx, req)
		require.NoError(t, err)

		// Per the specification, resolution-only should return decision=true
		assert.True(t, resp.Decision)

		// Verify context contains trust_metadata
		require.NotNil(t, resp.Context)
		require.NotNil(t, resp.Context.TrustMetadata)

		// Verify trust_metadata structure matches DID Document format
		trustMeta, ok := resp.Context.TrustMetadata.(map[string]interface{})
		require.True(t, ok)

		// Check required DID Document fields
		assert.Equal(t, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", trustMeta["id"])
		assert.NotNil(t, trustMeta["@context"])
		assert.NotNil(t, trustMeta["verificationMethod"])

		// Check verification method structure
		vms, ok := trustMeta["verificationMethod"].([]map[string]interface{})
		require.True(t, ok)
		require.Len(t, vms, 1)
		assert.Contains(t, vms[0]["id"], "did:key:z6Mkha")
		assert.NotNil(t, vms[0]["publicKeyJwk"])

		// Verify reason includes resolution_only flag
		assert.Equal(t, true, resp.Context.Reason["resolution_only"])
	})

	t.Run("did:key full evaluation also returns trust_metadata", func(t *testing.T) {
		registry := did.NewGenericDIDRegistryWithKeyMethod(did.GenericDIDRegistryConfig{})
		ctx := context.Background()

		// First, do resolution-only to get the key
		resolveReq := &authzen.EvaluationRequest{
			Subject: authzen.Subject{
				Type: "key",
				ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			},
			Resource: authzen.Resource{
				ID: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			},
		}

		resolveResp, err := registry.Evaluate(ctx, resolveReq)
		require.NoError(t, err)
		require.True(t, resolveResp.Decision)

		// Extract the public key from trust_metadata
		trustMeta := resolveResp.Context.TrustMetadata.(map[string]interface{})
		vms := trustMeta["verificationMethod"].([]map[string]interface{})
		publicKeyJwk := vms[0]["publicKeyJwk"].(map[string]interface{})

		// Now do full evaluation with the extracted key
		fullReq := &authzen.EvaluationRequest{
			Subject: authzen.Subject{
				Type: "key",
				ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			},
			Resource: authzen.Resource{
				Type: "jwk",
				ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
				Key:  []interface{}{publicKeyJwk},
			},
		}

		// Should NOT be resolution-only
		assert.False(t, fullReq.IsResolutionOnlyRequest())
		assert.NoError(t, fullReq.Validate())

		// Execute full evaluation
		fullResp, err := registry.Evaluate(ctx, fullReq)
		require.NoError(t, err)

		// Should succeed since key matches
		assert.True(t, fullResp.Decision)

		// Full evaluation should also include trust_metadata
		require.NotNil(t, fullResp.Context)
		require.NotNil(t, fullResp.Context.TrustMetadata)

		// Resolution_only flag should NOT be set for full evaluation
		_, hasResolutionOnly := fullResp.Context.Reason["resolution_only"]
		assert.False(t, hasResolutionOnly)
	})
}

// TestAuthZENProtocolCompliance tests compliance with draft-johansson-authzen-trust
func TestAuthZENProtocolCompliance(t *testing.T) {
	t.Run("request validation allows resolution-only", func(t *testing.T) {
		// Per spec: type and key fields are optional for resolution-only requests
		tests := []struct {
			name             string
			req              authzen.EvaluationRequest
			isResolutionOnly bool
			shouldValidate   bool
		}{
			{
				name: "full request with type and key",
				req: authzen.EvaluationRequest{
					Subject: authzen.Subject{Type: "key", ID: "did:web:example.com"},
					Resource: authzen.Resource{
						Type: "jwk",
						ID:   "did:web:example.com",
						Key:  []interface{}{map[string]interface{}{"kty": "EC"}},
					},
				},
				isResolutionOnly: false,
				shouldValidate:   true,
			},
			{
				name: "resolution-only - no type or key",
				req: authzen.EvaluationRequest{
					Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
					Resource: authzen.Resource{ID: "did:web:example.com"},
				},
				isResolutionOnly: true,
				shouldValidate:   true,
			},
			{
				name: "resolution-only - type but no key",
				req: authzen.EvaluationRequest{
					Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
					Resource: authzen.Resource{Type: "jwk", ID: "did:web:example.com"},
				},
				isResolutionOnly: true,
				shouldValidate:   true,
			},
			{
				name: "resolution-only - no resource fields",
				req: authzen.EvaluationRequest{
					Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
					Resource: authzen.Resource{},
				},
				isResolutionOnly: true,
				shouldValidate:   true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.isResolutionOnly, tt.req.IsResolutionOnlyRequest())
				err := tt.req.Validate()
				if tt.shouldValidate {
					assert.NoError(t, err)
				} else {
					assert.Error(t, err)
				}
			})
		}
	})

	t.Run("response includes trust_metadata per spec", func(t *testing.T) {
		// Create a response with trust_metadata as per spec example
		response := authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				TrustMetadata: map[string]interface{}{
					"@context": []string{"https://www.w3.org/ns/did/v1"},
					"id":       "did:web:example.com",
					"verificationMethod": []map[string]interface{}{
						{
							"id":           "did:web:example.com#key-1",
							"type":         "JsonWebKey2020",
							"controller":   "did:web:example.com",
							"publicKeyJwk": map[string]string{"kty": "EC", "crv": "P-256"},
						},
					},
				},
			},
		}

		// Verify structure
		assert.True(t, response.Decision)
		assert.NotNil(t, response.Context)
		assert.NotNil(t, response.Context.TrustMetadata)

		// Trust metadata should be a valid DID document structure
		trustMeta := response.Context.TrustMetadata.(map[string]interface{})
		assert.Equal(t, "did:web:example.com", trustMeta["id"])
	})
}

// TestDIDResolverRegistration tests dynamic DID resolver registration
func TestDIDResolverRegistration(t *testing.T) {
	registry := did.NewGenericDIDRegistry(did.GenericDIDRegistryConfig{})

	// Initially no resolvers
	assert.False(t, registry.Healthy())
	info := registry.Info()
	assert.Empty(t, info.TrustAnchors)

	// Register did:key resolver
	registry.RegisterResolver(did.NewDIDKeyResolver())

	// Now should be healthy
	assert.True(t, registry.Healthy())
	info = registry.Info()
	assert.Contains(t, info.TrustAnchors, "did:key")

	// Should handle did:key requests
	ctx := context.Background()
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		},
		Resource: authzen.Resource{},
	}

	resp, err := registry.Evaluate(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Decision)

	// But not did:web
	req2 := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:example.com",
		},
		Resource: authzen.Resource{},
	}

	resp2, err := registry.Evaluate(ctx, req2)
	require.NoError(t, err)
	assert.False(t, resp2.Decision)
	assert.Contains(t, resp2.Context.Reason["error"], "no resolver registered")
}
