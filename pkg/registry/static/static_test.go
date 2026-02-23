package static

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

func TestAlwaysTrustedRegistry_NewWithName(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test-always")
	assert.Equal(t, "test-always", reg.name)
}

func TestAlwaysTrustedRegistry_NewWithEmptyName(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("")
	assert.Equal(t, "always-trusted", reg.name)
}

func TestAlwaysTrustedRegistry_Evaluate_AlwaysTrue(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test")
	ctx := context.Background()

	tests := []struct {
		name    string
		request *authzen.EvaluationRequest
	}{
		{
			name: "x5c request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "test-subject",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "test-subject",
					Key:  []interface{}{"dummy-cert"},
				},
			},
		},
		{
			name: "jwk request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "test-subject",
				},
				Resource: authzen.Resource{
					Type: "jwk",
					ID:   "test-subject",
					Key:  []interface{}{map[string]interface{}{"kty": "RSA"}},
				},
			},
		},
		{
			name: "resolution-only request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "did:example:123",
				},
				Resource: authzen.Resource{
					ID: "did:example:123",
				},
			},
		},
		{
			name: "empty request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "test",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := reg.Evaluate(ctx, tt.request)
			require.NoError(t, err)
			assert.True(t, resp.Decision, "AlwaysTrustedRegistry should always return true")
			assert.NotNil(t, resp.Context)
			assert.Contains(t, resp.Context.Reason["warning"], "do not use in production")
		})
	}
}

func TestAlwaysTrustedRegistry_SupportedResourceTypes(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test")
	types := reg.SupportedResourceTypes()
	assert.Contains(t, types, "*")
}

func TestAlwaysTrustedRegistry_SupportsResolutionOnly(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test")
	assert.True(t, reg.SupportsResolutionOnly())
}

func TestAlwaysTrustedRegistry_Info(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test-registry")
	info := reg.Info()

	assert.Equal(t, "test-registry", info.Name)
	assert.Equal(t, "static_always_trusted", info.Type)
	assert.True(t, info.Healthy)
	assert.True(t, info.ResolutionOnly)
}

func TestAlwaysTrustedRegistry_Healthy(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test")
	assert.True(t, reg.Healthy())
}

func TestAlwaysTrustedRegistry_Refresh(t *testing.T) {
	reg := NewAlwaysTrustedRegistry("test")
	err := reg.Refresh(context.Background())
	assert.NoError(t, err)
}

func TestAlwaysTrustedRegistry_ImplementsInterface(t *testing.T) {
	var _ registry.TrustRegistry = (*AlwaysTrustedRegistry)(nil)
}

// NeverTrustedRegistry tests

func TestNeverTrustedRegistry_NewWithName(t *testing.T) {
	reg := NewNeverTrustedRegistry("test-never")
	assert.Equal(t, "test-never", reg.name)
}

func TestNeverTrustedRegistry_NewWithEmptyName(t *testing.T) {
	reg := NewNeverTrustedRegistry("")
	assert.Equal(t, "never-trusted", reg.name)
}

func TestNeverTrustedRegistry_NewWithConfig(t *testing.T) {
	reg := NewNeverTrustedRegistryWithConfig(NeverTrustedConfig{
		Name:        "custom-deny",
		Description: "Custom denial registry",
		Reason:      "access denied by policy",
	})

	assert.Equal(t, "custom-deny", reg.name)
	assert.Equal(t, "Custom denial registry", reg.description)
	assert.Equal(t, "access denied by policy", reg.reason)
}

func TestNeverTrustedRegistry_Evaluate_AlwaysFalse(t *testing.T) {
	reg := NewNeverTrustedRegistry("test")
	ctx := context.Background()

	tests := []struct {
		name    string
		request *authzen.EvaluationRequest
	}{
		{
			name: "x5c request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "test-subject",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "test-subject",
					Key:  []interface{}{"dummy-cert"},
				},
			},
		},
		{
			name: "jwk request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "test-subject",
				},
				Resource: authzen.Resource{
					Type: "jwk",
					ID:   "test-subject",
					Key:  []interface{}{map[string]interface{}{"kty": "RSA"}},
				},
			},
		},
		{
			name: "resolution-only request",
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "did:example:123",
				},
				Resource: authzen.Resource{
					ID: "did:example:123",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := reg.Evaluate(ctx, tt.request)
			require.NoError(t, err)
			assert.False(t, resp.Decision, "NeverTrustedRegistry should always return false")
			assert.NotNil(t, resp.Context)
			assert.Contains(t, resp.Context.Reason["error"], "denied by never-trusted registry")
		})
	}
}

func TestNeverTrustedRegistry_Evaluate_CustomReason(t *testing.T) {
	reg := NewNeverTrustedRegistryWithConfig(NeverTrustedConfig{
		Reason: "custom denial reason",
	})

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "test"},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Equal(t, "custom denial reason", resp.Context.Reason["error"])
}

func TestNeverTrustedRegistry_SupportedResourceTypes(t *testing.T) {
	reg := NewNeverTrustedRegistry("test")
	types := reg.SupportedResourceTypes()
	assert.Contains(t, types, "*")
}

func TestNeverTrustedRegistry_SupportsResolutionOnly(t *testing.T) {
	reg := NewNeverTrustedRegistry("test")
	assert.True(t, reg.SupportsResolutionOnly())
}

func TestNeverTrustedRegistry_Info(t *testing.T) {
	reg := NewNeverTrustedRegistry("test-registry")
	info := reg.Info()

	assert.Equal(t, "test-registry", info.Name)
	assert.Equal(t, "static_never_trusted", info.Type)
	assert.True(t, info.Healthy)
	assert.True(t, info.ResolutionOnly)
}

func TestNeverTrustedRegistry_Healthy(t *testing.T) {
	reg := NewNeverTrustedRegistry("test")
	assert.True(t, reg.Healthy())
}

func TestNeverTrustedRegistry_Refresh(t *testing.T) {
	reg := NewNeverTrustedRegistry("test")
	err := reg.Refresh(context.Background())
	assert.NoError(t, err)
}

func TestNeverTrustedRegistry_ImplementsInterface(t *testing.T) {
	var _ registry.TrustRegistry = (*NeverTrustedRegistry)(nil)
}
