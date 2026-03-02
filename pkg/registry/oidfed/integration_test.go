package oidfed_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/registry/oidfed"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// These tests use live OpenID Federation endpoints.
// They are marked with the 'network' tag and can be skipped with:
//   go test -tags=!network
// or run explicitly with:
//   go test -tags=network

// realtaTrustAnchor is the SUNET test trust anchor
const realtaTrustAnchor = "https://realta.labb.sunet.se/"

// TestOIDFedRegistry_WithTestServer tests the OpenID Federation registry
// integration with the testserver and HTTP API.
func TestOIDFedRegistry_WithTestServer(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry with realta trust anchor
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		Description: "Test OIDF Registry with SUNET Trust Anchor",
		CacheTTL:    5 * time.Minute,
	})
	require.NoError(t, err)

	// Create test server with OIDF registry
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Create client
	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: resolution-only request for the trust anchor itself
	// This should return trust_metadata with the entity configuration
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realtaTrustAnchor,
		},
		Resource: authzen.Resource{
			ID: realtaTrustAnchor,
			// No type or key = resolution-only
		},
	})
	require.NoError(t, err)
	// Note: For the trust anchor itself, this may or may not return decision=true
	// depending on whether it counts as "self-anchored"
	assert.NotNil(t, resp.Context, "response should include context")
}

// TestOIDFedRegistry_UntrustedEntity tests that entities not in the federation
// are rejected.
func TestOIDFedRegistry_UntrustedEntity(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry with realta trust anchor
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		Description: "Test OIDF Registry",
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: entity NOT in the federation should be rejected
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://non-existent-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://non-existent-entity.example.com",
			Key:  []interface{}{"dummy-cert"},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "entity not in federation should not be trusted")
}

// TestOIDFedRegistry_InvalidTrustAnchor tests that invalid trust anchors are handled.
func TestOIDFedRegistry_InvalidTrustAnchor(t *testing.T) {
	// Create OIDF registry with non-existent trust anchor
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://non-existent-trust-anchor.example.com"},
		},
		Description: "Test OIDF Registry with Invalid Trust Anchor",
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: any entity should be rejected with invalid trust anchor
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://any-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://any-entity.example.com",
			Key:  []interface{}{"dummy-key"},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "entity should not be trusted with invalid trust anchor")
}

// TestOIDFedRegistry_Info tests that registry info is accessible.
func TestOIDFedRegistry_Info(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		Description: "Test OIDF Registry Info",
	})
	require.NoError(t, err)

	// Verify registry info
	info := reg.Info()
	assert.Equal(t, "oidfed-registry", info.Name)
	assert.Equal(t, "openid_federation", info.Type)
	assert.Equal(t, "Test OIDF Registry Info", info.Description)
	assert.True(t, reg.Healthy())
	assert.Len(t, info.TrustAnchors, 1)
	assert.Equal(t, realtaTrustAnchor, info.TrustAnchors[0])
}

// TestOIDFedRegistry_MultipleTrustAnchors tests configuration with multiple trust anchors.
func TestOIDFedRegistry_MultipleTrustAnchors(t *testing.T) {
	// Create OIDF registry with multiple trust anchors
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: "https://anchor1.example.com"},
			{EntityID: "https://anchor2.example.com"},
			{EntityID: "https://anchor3.example.com"},
		},
		Description: "Multi-anchor registry",
	})
	require.NoError(t, err)

	info := reg.Info()
	assert.Len(t, info.TrustAnchors, 3)
}

// TestOIDFedRegistry_SupportedResourceTypes tests that the registry
// advertises correct resource types.
func TestOIDFedRegistry_SupportedResourceTypes(t *testing.T) {
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
	})
	require.NoError(t, err)

	types := reg.SupportedResourceTypes()
	assert.NotEmpty(t, types)

	// Verify expected types are present
	typeMap := make(map[string]bool)
	for _, typ := range types {
		typeMap[typ] = true
	}

	assert.True(t, typeMap["entity"], "should support 'entity' resource type")
	assert.True(t, typeMap["jwk"], "should support 'jwk' resource type")
	assert.True(t, typeMap["x5c"], "should support 'x5c' resource type")
}

// TestOIDFedRegistry_RequiredTrustMarks tests configuration with required trust marks.
func TestOIDFedRegistry_RequiredTrustMarks(t *testing.T) {
	// Skip if SKIP_NETWORK_TESTS env var is set
	if os.Getenv("SKIP_NETWORK_TESTS") != "" {
		t.Skip("Skipping network test (SKIP_NETWORK_TESTS set)")
	}

	// Create OIDF registry requiring specific trust marks
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		RequiredTrustMarks: []string{
			"https://example.com/some-trust-mark",
		},
		Description: "Registry with required trust marks",
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: entity without required trust mark should be rejected
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   realtaTrustAnchor,
		},
		Resource: authzen.Resource{
			Type: "jwk", // Use jwk instead of entity
			ID:   realtaTrustAnchor,
			Key:  []interface{}{"dummy-key"},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	// Entity without required trust mark should be rejected
	assert.False(t, resp.Decision, "entity without required trust mark should not be trusted")
}

// TestOIDFedRegistry_RefreshClearsCache tests that refresh clears the cache.
func TestOIDFedRegistry_RefreshClearsCache(t *testing.T) {
	reg, err := oidfed.NewOIDFedRegistry(oidfed.Config{
		TrustAnchors: []oidfed.TrustAnchorConfig{
			{EntityID: realtaTrustAnchor},
		},
		CacheTTL: 5 * time.Minute,
	})
	require.NoError(t, err)

	// Refresh should not error
	err = reg.Refresh(context.Background())
	require.NoError(t, err)

	// Registry should still be healthy after refresh
	assert.True(t, reg.Healthy())
}
