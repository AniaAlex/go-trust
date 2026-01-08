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

func TestMetadataCache_TTLExpiration(t *testing.T) {
	// Create cache with very short TTL
	cache := NewMetadataCache(10*time.Millisecond, 10)

	// Add entry
	cache.Set("entity1", []string{"tm1"}, []string{"type1"}, nil, "anchor1")

	// Verify it exists immediately
	entry := cache.Get("entity1", []string{"tm1"}, []string{"type1"})
	if entry == nil {
		t.Error("Cache Get returned nil immediately after Set")
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Verify entry is expired (Get should return nil)
	entry = cache.Get("entity1", []string{"tm1"}, []string{"type1"})
	if entry != nil {
		t.Error("Cache Get should return nil after TTL expiration")
	}
}

func TestMetadataCache_Eviction(t *testing.T) {
	// Create cache with max size of 3
	cache := NewMetadataCache(1*time.Hour, 3)

	// Add 3 entries
	cache.Set("entity1", nil, nil, nil, "anchor1")
	cache.Set("entity2", nil, nil, nil, "anchor1")
	cache.Set("entity3", nil, nil, nil, "anchor1")

	// Verify all exist
	if cache.Get("entity1", nil, nil) == nil {
		t.Error("entity1 should be in cache")
	}
	if cache.Get("entity2", nil, nil) == nil {
		t.Error("entity2 should be in cache")
	}
	if cache.Get("entity3", nil, nil) == nil {
		t.Error("entity3 should be in cache")
	}

	// Add one more - should evict the oldest
	cache.Set("entity4", nil, nil, nil, "anchor1")

	// entity4 should exist
	if cache.Get("entity4", nil, nil) == nil {
		t.Error("entity4 should be in cache after Set")
	}

	// Cache size should still be 3
	size, _, _ := cache.Stats()
	if size > 3 {
		t.Errorf("Cache size = %d, want <= 3", size)
	}
}

func TestMetadataCache_Stats(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	// Empty cache
	size, hits, misses := cache.Stats()
	if size != 0 {
		t.Errorf("Empty cache size = %d, want 0", size)
	}
	if hits != 0 || misses != 0 {
		t.Errorf("Empty cache hits=%d, misses=%d, want 0,0", hits, misses)
	}

	// Add entries
	cache.Set("entity1", nil, nil, nil, "anchor1")
	cache.Set("entity2", nil, nil, nil, "anchor1")

	size, _, _ = cache.Stats()
	if size != 2 {
		t.Errorf("Cache size = %d, want 2", size)
	}
}

func TestMetadataCache_Invalidate(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 10)

	// Add entries with same entity but different constraints
	cache.Set("entity1", []string{"tm1"}, nil, nil, "anchor1")
	cache.Set("entity1", []string{"tm2"}, nil, nil, "anchor1")
	cache.Set("entity2", []string{"tm1"}, nil, nil, "anchor1")

	// Invalidate specific entry (entity1 with tm1)
	cache.Invalidate("entity1", []string{"tm1"}, nil)

	// entity1 with tm1 should be gone
	if cache.Get("entity1", []string{"tm1"}, nil) != nil {
		t.Error("entity1 with tm1 should be invalidated")
	}

	// entity1 with tm2 should still exist (Invalidate is specific to the full key)
	if cache.Get("entity1", []string{"tm2"}, nil) == nil {
		t.Error("entity1 with tm2 should still be in cache")
	}

	// entity2 should still exist
	if cache.Get("entity2", []string{"tm1"}, nil) == nil {
		t.Error("entity2 should still be in cache")
	}
}

func TestCacheKey(t *testing.T) {
	cache := NewMetadataCache(1*time.Hour, 100)

	tests := []struct {
		name        string
		entityID    string
		trustMarks  []string
		entityTypes []string
		wantDiff    bool // should different inputs produce different keys
	}{
		{
			name:        "same entity different trust marks",
			entityID:    "https://entity.example.com",
			trustMarks:  []string{"tm1", "tm2"},
			entityTypes: nil,
			wantDiff:    true,
		},
		{
			name:        "same entity different entity types",
			entityID:    "https://entity.example.com",
			trustMarks:  nil,
			entityTypes: []string{"type1"},
			wantDiff:    true,
		},
		{
			name:        "nil vs empty slices",
			entityID:    "https://entity.example.com",
			trustMarks:  nil,
			entityTypes: nil,
			wantDiff:    false,
		},
	}

	baseKey := cache.cacheKey("https://entity.example.com", nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cache.cacheKey(tt.entityID, tt.trustMarks, tt.entityTypes)
			isDifferent := key != baseKey
			if tt.wantDiff && !isDifferent {
				t.Errorf("cacheKey() should produce different key for %s", tt.name)
			}
		})
	}
}

func TestShouldBypassCache(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name    string
		context map[string]interface{}
		want    bool
	}{
		{
			name:    "nil context",
			context: nil,
			want:    false,
		},
		{
			name:    "empty context",
			context: map[string]interface{}{},
			want:    false,
		},
		{
			name: "no-cache",
			context: map[string]interface{}{
				"cache_control": "no-cache",
			},
			want: true,
		},
		{
			name: "no-store",
			context: map[string]interface{}{
				"cache_control": "no-store",
			},
			want: true,
		},
		{
			name: "other cache control value",
			context: map[string]interface{}{
				"cache_control": "max-age=300",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}
			if got := registry.shouldBypassCache(req); got != tt.want {
				t.Errorf("shouldBypassCache() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractConstraintsFromContext_InterfaceSlices(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	tests := []struct {
		name            string
		context         map[string]interface{}
		wantTrustMarks  []string
		wantEntityTypes []string
	}{
		{
			name: "trust marks as []interface{}",
			context: map[string]interface{}{
				"required_trust_marks": []interface{}{"mark1", "mark2"},
			},
			wantTrustMarks:  []string{"mark1", "mark2"},
			wantEntityTypes: nil,
		},
		{
			name: "entity types as []interface{}",
			context: map[string]interface{}{
				"allowed_entity_types": []interface{}{"type1", "type2"},
			},
			wantTrustMarks:  nil,
			wantEntityTypes: []string{"type1", "type2"},
		},
		{
			name: "max chain depth as int",
			context: map[string]interface{}{
				"max_chain_depth": 5,
			},
			wantTrustMarks:  nil,
			wantEntityTypes: nil,
		},
		{
			name: "max chain depth as float64",
			context: map[string]interface{}{
				"max_chain_depth": float64(7),
			},
			wantTrustMarks:  nil,
			wantEntityTypes: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &authzen.EvaluationRequest{
				Subject:  authzen.Subject{Type: "key", ID: "https://entity.example.com"},
				Resource: authzen.Resource{ID: "https://entity.example.com"},
				Context:  tt.context,
			}
			trustMarks, entityTypes, _, _, maxDepth := registry.extractConstraintsFromContext(req)

			if tt.wantTrustMarks != nil && !equalStringSlices(trustMarks, tt.wantTrustMarks) {
				t.Errorf("trustMarks = %v, want %v", trustMarks, tt.wantTrustMarks)
			}
			if tt.wantEntityTypes != nil && !equalStringSlices(entityTypes, tt.wantEntityTypes) {
				t.Errorf("entityTypes = %v, want %v", entityTypes, tt.wantEntityTypes)
			}
			if tt.context["max_chain_depth"] != nil && maxDepth == 10 {
				// maxDepth should be changed from default
				t.Errorf("maxDepth should be changed from default 10")
			}
		})
	}
}

func TestMergeStringSlices(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{
			name: "no duplicates",
			a:    []string{"a", "b"},
			b:    []string{"c", "d"},
			want: []string{"a", "b", "c", "d"},
		},
		{
			name: "with duplicates",
			a:    []string{"a", "b"},
			b:    []string{"b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty slices",
			a:    []string{},
			b:    []string{},
			want: []string{},
		},
		{
			name: "nil slices",
			a:    nil,
			b:    nil,
			want: []string{},
		},
		{
			name: "one nil",
			a:    []string{"a"},
			b:    nil,
			want: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeStringSlices(tt.a, tt.b)
			if !equalStringSlices(got, tt.want) {
				t.Errorf("mergeStringSlices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDFedRegistry_Description(t *testing.T) {
	tests := []struct {
		name        string
		description string
		want        string
	}{
		{
			name:        "custom description",
			description: "My Custom Registry",
			want:        "My Custom Registry",
		},
		{
			name:        "empty description gets default",
			description: "",
			want:        "OpenID Federation Registry with 1 trust anchor(s)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, _ := NewOIDFedRegistry(Config{
				TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
				Description:  tt.description,
			})
			if got := registry.Description(); got != tt.want {
				t.Errorf("Description() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDFedRegistry_SupportsResolutionOnly(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	if !registry.SupportsResolutionOnly() {
		t.Error("SupportsResolutionOnly() = false, want true")
	}
}

func TestOIDFedRegistry_MaxChainDepth(t *testing.T) {
	tests := []struct {
		name        string
		configDepth int
		wantDepth   int
	}{
		{
			name:        "default depth",
			configDepth: 0,
			wantDepth:   10,
		},
		{
			name:        "custom depth",
			configDepth: 5,
			wantDepth:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, _ := NewOIDFedRegistry(Config{
				TrustAnchors:  []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
				MaxChainDepth: tt.configDepth,
			})
			if registry.maxChainDepth != tt.wantDepth {
				t.Errorf("maxChainDepth = %d, want %d", registry.maxChainDepth, tt.wantDepth)
			}
		})
	}
}

func TestOIDFedRegistry_GetTrustAnchorEntityIDs(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{
			{EntityID: "https://ta1.example.com"},
			{EntityID: "https://ta2.example.com"},
			{EntityID: "https://ta3.example.com"},
		},
	})

	ids := registry.getTrustAnchorEntityIDs()
	if len(ids) != 3 {
		t.Errorf("getTrustAnchorEntityIDs() returned %d IDs, want 3", len(ids))
	}

	expected := []string{"https://ta1.example.com", "https://ta2.example.com", "https://ta3.example.com"}
	for i, id := range ids {
		if id != expected[i] {
			t.Errorf("getTrustAnchorEntityIDs()[%d] = %s, want %s", i, id, expected[i])
		}
	}
}

func TestOIDFedRegistry_Evaluate_MissingEntityID(t *testing.T) {
	registry, _ := NewOIDFedRegistry(Config{
		TrustAnchors: []TrustAnchorConfig{{EntityID: "https://ta.example.com"}},
	})

	// Request with no valid entity ID
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "not-a-url",
		},
		Resource: authzen.Resource{
			Type: "entity",
			ID:   "also-not-a-url",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("Evaluate() decision = true, want false for missing entity ID")
	}

	if resp.Context == nil || resp.Context.Reason == nil {
		t.Error("Evaluate() should include error reason in context")
	}
}

func TestOIDFedRegistry_Evaluate_WithCacheBypass(t *testing.T) {
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
			Type: "entity",
			ID:   "https://non-existent-entity.example.com",
		},
		Context: map[string]interface{}{
			"cache_control": "no-cache",
		},
	}

	resp, err := registry.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// Should still fail gracefully
	if resp.Decision {
		t.Error("Evaluate() decision = true, want false")
	}
}

func TestContextKeys(t *testing.T) {
	// Verify context key constants are properly defined
	tests := []struct {
		key  string
		want string
	}{
		{ContextKeyRequiredTrustMarks, "required_trust_marks"},
		{ContextKeyAllowedEntityTypes, "allowed_entity_types"},
		{ContextKeyIncludeTrustChain, "include_trust_chain"},
		{ContextKeyIncludeCertificates, "include_certificates"},
		{ContextKeyMaxChainDepth, "max_chain_depth"},
		{ContextKeyCacheControl, "cache_control"},
	}

	for _, tt := range tests {
		if tt.key != tt.want {
			t.Errorf("Context key = %s, want %s", tt.key, tt.want)
		}
	}
}

func TestMetadataKeys(t *testing.T) {
	// Verify metadata key constants are properly defined
	tests := []struct {
		key  string
		want string
	}{
		{MetadataKeyEntityConfiguration, "entity_configuration"},
		{MetadataKeyTrustChain, "trust_chain"},
		{MetadataKeyTrustAnchor, "trust_anchor"},
		{MetadataKeyTrustMarks, "trust_marks"},
		{MetadataKeyEntityTypes, "entity_types"},
		{MetadataKeyJWKS, "jwks"},
		{MetadataKeyResolvedAt, "resolved_at"},
		{MetadataKeyCachedUntil, "cached_until"},
	}

	for _, tt := range tests {
		if tt.key != tt.want {
			t.Errorf("Metadata key = %s, want %s", tt.key, tt.want)
		}
	}
}
