package oidfed

import (
	"context"
	"testing"
	"time"

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
		"jwk":               true,
		"x5c":               true,
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

	// Refresh should not fail (it clears the cache)
	err := registry.Refresh(context.Background())
	if err != nil {
		t.Errorf("Refresh() error = %v, want nil", err)
	}
}

func TestOIDFedRegistry_CacheConfig(t *testing.T) {
	// Test with cache configuration
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
		CacheTTL:     5 * time.Minute,
		MaxCacheSize: 100,
	})

	stats := registry.GetCacheStats()
	if !stats["enabled"].(bool) {
		t.Error("Cache should be enabled")
	}
	if stats["max_size"].(int) != 100 {
		t.Errorf("Cache max_size = %v, want 100", stats["max_size"])
	}
}

func TestMetadataCache(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 10)

	// Test Set and Get
	cache.Set("entity1", []string{"tm1"}, []string{"openid_provider"}, nil, "anchor1")
	entry := cache.Get("entity1", []string{"tm1"}, []string{"openid_provider"})
	if entry == nil {
		t.Error("Cache Get returned nil, expected entry")
	}

	// Test cache miss with different parameters
	entry = cache.Get("entity1", []string{"tm2"}, []string{"openid_provider"})
	if entry != nil {
		t.Error("Cache Get should return nil for different trust marks")
	}

	// Test Clear
	cache.Clear()
	entry = cache.Get("entity1", []string{"tm1"}, []string{"openid_provider"})
	if entry != nil {
		t.Error("Cache Get should return nil after Clear")
	}

	// Test Invalidate
	cache.Set("entity2", nil, nil, nil, "anchor1")
	cache.Invalidate("entity2", nil, nil)
	entry = cache.Get("entity2", nil, nil)
	if entry != nil {
		t.Error("Cache Get should return nil after Invalidate")
	}
}

func TestExtractConstraintsFromContext(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors:       []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
		RequiredTrustMarks: []string{"default-mark"},
		EntityTypes:        []string{"default-type"},
	})

	tests := []struct {
		name             string
		context          map[string]interface{}
		wantTrustMarks   []string
		wantEntityTypes  []string
		wantIncludeChain bool
		wantIncludeCerts bool
	}{
		{
			name:            "nil context uses defaults",
			context:         nil,
			wantTrustMarks:  []string{"default-mark"},
			wantEntityTypes: []string{"default-type"},
		},
		{
			name: "context adds trust marks",
			context: map[string]interface{}{
				"required_trust_marks": []string{"extra-mark"},
			},
			wantTrustMarks:  []string{"default-mark", "extra-mark"},
			wantEntityTypes: []string{"default-type"},
		},
		{
			name: "context replaces entity types",
			context: map[string]interface{}{
				"allowed_entity_types": []string{"new-type"},
			},
			wantTrustMarks:  []string{"default-mark"},
			wantEntityTypes: []string{"new-type"},
		},
		{
			name: "include flags",
			context: map[string]interface{}{
				"include_trust_chain":  true,
				"include_certificates": true,
			},
			wantTrustMarks:   []string{"default-mark"},
			wantEntityTypes:  []string{"default-type"},
			wantIncludeChain: true,
			wantIncludeCerts: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}

			trustMarks, entityTypes, includeChain, includeCerts, _ := registry.extractConstraintsFromContext(req)

			if !equalStringSlices(trustMarks, tt.wantTrustMarks) {
				t.Errorf("trustMarks = %v, want %v", trustMarks, tt.wantTrustMarks)
			}
			if !equalStringSlices(entityTypes, tt.wantEntityTypes) {
				t.Errorf("entityTypes = %v, want %v", entityTypes, tt.wantEntityTypes)
			}
			if includeChain != tt.wantIncludeChain {
				t.Errorf("includeChain = %v, want %v", includeChain, tt.wantIncludeChain)
			}
			if includeCerts != tt.wantIncludeCerts {
				t.Errorf("includeCerts = %v, want %v", includeCerts, tt.wantIncludeCerts)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
