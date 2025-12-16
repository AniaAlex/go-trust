package oidfed

import (
	"context"
	"testing"

	oidfedjwx "github.com/go-oidfed/lib/jwx"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestNewOIDFedRegistry(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with one trust anchor",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: "https://ta.example.com"},
				},
				Description: "Test registry",
			},
			wantErr: false,
		},
		{
			name: "valid config with multiple trust anchors",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: "https://ta1.example.com"},
					{EntityID: "https://ta2.example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config with trust marks",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: "https://ta.example.com"},
				},
				RequiredTrustMarks: []string{
					"https://example.com/trustmark/level1",
				},
			},
			wantErr: false,
		},
		{
			name: "no trust anchors - should fail",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{},
			},
			wantErr: true,
		},
		{
			name: "empty entity ID - should fail",
			config: Config{
				TrustAnchors: []TrustAnchorConfig{
					{EntityID: ""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, err := NewOIDFedRegistry(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewOIDFedRegistry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if registry == nil {
					t.Error("NewOIDFedRegistry() returned nil registry")
					return
				}
				if len(registry.trustAnchors) != len(tt.config.TrustAnchors) {
					t.Errorf("NewOIDFedRegistry() trust anchors count = %d, want %d",
						len(registry.trustAnchors), len(tt.config.TrustAnchors))
				}
			}
		})
	}
}

func TestOIDFedRegistry_Name(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	if name := registry.Name(); name != "oidfed-registry" {
		t.Errorf("Name() = %v, want %v", name, "oidfed-registry")
	}
}

func TestOIDFedRegistry_SupportedResourceTypes(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	types := registry.SupportedResourceTypes()
	if len(types) == 0 {
		t.Error("SupportedResourceTypes() returned empty slice")
	}

	expectedTypes := map[string]bool{
		"entity":            true,
		"openid_provider":   true,
		"relying_party":     true,
		"oauth_client":      true,
		"oauth_server":      true,
		"federation_entity": true,
	}

	for _, typ := range types {
		if !expectedTypes[typ] {
			t.Errorf("SupportedResourceTypes() contains unexpected type: %s", typ)
		}
	}
}

func TestOIDFedRegistry_Healthy(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	if !registry.Healthy() {
		t.Error("Healthy() = false, want true")
	}
}

func TestOIDFedRegistry_Info(t *testing.T) {
	config := Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta1.example.com"},
			{EntityID: "https://ta2.example.com"},
		},
		Description: "Test OpenID Federation Registry",
	}

	registry, _ := NewOIDFedRegistry(config)
	info := registry.Info()

	if info.Name != "oidfed-registry" {
		t.Errorf("Info().Name = %v, want %v", info.Name, "oidfed-registry")
	}

	if info.Type != "openid_federation" {
		t.Errorf("Info().Type = %v, want %v", info.Type, "openid_federation")
	}

	if info.Description != config.Description {
		t.Errorf("Info().Description = %v, want %v", info.Description, config.Description)
	}

	if len(info.TrustAnchors) != 2 {
		t.Errorf("Info().TrustAnchors count = %d, want 2", len(info.TrustAnchors))
	}
}

func TestOIDFedRegistry_extractEntityID(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name    string
		req     *authzen.EvaluationRequest
		want    string
		wantErr bool
	}{
		{
			name: "extract from subject.id (https)",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "https://entity.example.com",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "https://entity.example.com",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "https://entity.example.com",
			wantErr: false,
		},
		{
			name: "extract from subject.id (http)",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "http://entity.example.com",
				},
				Resource: authzen.Resource{
					Type: "jwk",
					ID:   "http://entity.example.com",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "http://entity.example.com",
			wantErr: false,
		},
		{
			name: "extract from resource.id when subject.id is not URL",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "some-identifier",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "https://entity.example.com",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "https://entity.example.com",
			wantErr: false,
		},
		{
			name: "no valid entity ID",
			req: &authzen.EvaluationRequest{
				Subject: authzen.Subject{
					Type: "key",
					ID:   "not-a-url",
				},
				Resource: authzen.Resource{
					Type: "x5c",
					ID:   "also-not-a-url",
					Key:  []interface{}{"dummy"},
				},
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := registry.extractEntityID(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractEntityID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractEntityID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDFedRegistry_Evaluate_NoValidChain(t *testing.T) {
	// This test uses a non-existent entity, so trust chain resolution will fail
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://non-existent-ta.example.com"},
		},
	})

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://non-existent-entity.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://non-existent-entity.example.com",
			Key:  []interface{}{"dummy-cert"},
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v, want nil", err)
	}

	if resp.Decision {
		t.Error("Evaluate() decision = true, want false (no valid chain)")
	}

	if resp.Context == nil || resp.Context.Reason == nil {
		t.Error("Evaluate() response should include context with reason")
	}
}

func TestOIDFedRegistry_Refresh(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Refresh should not fail (it's a no-op for this implementation)
	err := registry.Refresh(context.Background())
	if err != nil {
		t.Errorf("Refresh() error = %v, want nil", err)
	}
}

func TestTrustAnchorConfig_WithJWKS(t *testing.T) {
	// Test that we can create a registry with explicit JWKS
	jwks := &oidfedjwx.JWKS{}

	config := Config{
		TrustAnchors: []TrustAnchorConfig{
			{
				EntityID: "https://ta.example.com",
				JWKS:     jwks,
			},
		},
	}

	registry, err := NewOIDFedRegistry(config)
	if err != nil {
		t.Fatalf("NewOIDFedRegistry() error = %v, want nil", err)
	}

	if len(registry.trustAnchors) != 1 {
		t.Errorf("trust anchors count = %d, want 1", len(registry.trustAnchors))
	}
}
