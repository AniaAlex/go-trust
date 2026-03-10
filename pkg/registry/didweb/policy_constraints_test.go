package didweb

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestExtractDomainFromDIDWeb tests domain extraction from did:web identifiers.
func TestExtractDomainFromDIDWeb(t *testing.T) {
	tests := []struct {
		name   string
		did    string
		expect string
	}{
		{"simple domain", "did:web:example.com", "example.com"},
		{"domain with path", "did:web:example.com:path:to:doc", "example.com"},
		{"domain with port", "did:web:example.com%3A8080", "example.com:8080"},
		{"domain with port lowercase", "did:web:example.com%3a8080", "example.com:8080"},
		{"subdomain", "did:web:sub.example.com", "sub.example.com"},
		{"not did:web", "did:key:z6MkTest", ""},
		{"empty", "", ""},
		{"did:web only", "did:web:", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractDomainFromDIDWeb(tc.did)
			if result != tc.expect {
				t.Errorf("extractDomainFromDIDWeb(%q) = %q, want %q", tc.did, result, tc.expect)
			}
		})
	}
}

// TestMatchesDomain tests domain matching with wildcard support.
func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name           string
		domain         string
		allowedDomains []string
		expect         bool
	}{
		{"exact match", "example.com", []string{"example.com"}, true},
		{"no match", "other.com", []string{"example.com"}, false},
		{"wildcard match", "sub.example.com", []string{"*.example.com"}, true},
		{"wildcard no match for base", "example.com", []string{"*.example.com"}, false},
		{"wildcard deep sub", "a.b.example.com", []string{"*.example.com"}, true},
		{"multiple allowed exact", "b.com", []string{"a.com", "b.com", "c.com"}, true},
		{"multiple allowed wildcard", "sub.b.com", []string{"a.com", "*.b.com"}, true},
		{"empty allowed", "example.com", []string{}, false},
		{"empty domain", "", []string{"example.com"}, false},
		{"port in domain", "example.com:8080", []string{"example.com:8080"}, true},
		{"port mismatch", "example.com:8080", []string{"example.com:9090"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matchesDomain(tc.domain, tc.allowedDomains)
			if result != tc.expect {
				t.Errorf("matchesDomain(%q, %v) = %v, want %v", tc.domain, tc.allowedDomains, result, tc.expect)
			}
		})
	}
}

// TestExtractStringSlice tests context value extraction.
func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name   string
		ctx    map[string]interface{}
		key    string
		expect []string
	}{
		{
			"string slice",
			map[string]interface{}{"key": []string{"a", "b"}},
			"key",
			[]string{"a", "b"},
		},
		{
			"interface slice",
			map[string]interface{}{"key": []interface{}{"a", "b"}},
			"key",
			[]string{"a", "b"},
		},
		{
			"interface slice with non-strings",
			map[string]interface{}{"key": []interface{}{"a", 42, "b"}},
			"key",
			[]string{"a", "b"},
		},
		{
			"missing key",
			map[string]interface{}{},
			"key",
			nil,
		},
		{
			"wrong type",
			map[string]interface{}{"key": 42},
			"key",
			nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractStringSlice(tc.ctx, tc.key)
			if len(result) != len(tc.expect) {
				t.Errorf("extractStringSlice() returned %d items, want %d", len(result), len(tc.expect))
				return
			}
			for i, v := range result {
				if v != tc.expect[i] {
					t.Errorf("extractStringSlice()[%d] = %q, want %q", i, v, tc.expect[i])
				}
			}
		})
	}
}

// TestHasRequiredServices tests DID document service matching.
func TestHasRequiredServices(t *testing.T) {
	services := []interface{}{
		map[string]interface{}{"id": "#svc-1", "type": "LinkedDomains", "serviceEndpoint": "https://example.com"},
		map[string]interface{}{"id": "#svc-2", "type": "CredentialRegistry", "serviceEndpoint": "https://registry.example.com"},
	}

	tests := []struct {
		name     string
		service  interface{}
		required []string
		expect   bool
	}{
		{"all present", services, []string{"LinkedDomains"}, true},
		{"multiple present", services, []string{"LinkedDomains", "CredentialRegistry"}, true},
		{"missing service", services, []string{"LinkedDomains", "DIDCommMessaging"}, false},
		{"nil services", nil, []string{"LinkedDomains"}, false},
		{"empty required", services, []string{}, true},
		{"wrong type (string)", "not-an-array", []string{"LinkedDomains"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hasRequiredServices(tc.service, tc.required)
			if result != tc.expect {
				t.Errorf("hasRequiredServices() = %v, want %v", result, tc.expect)
			}
		})
	}
}

// TestCheckPolicyConstraints_NilContext verifies no filtering when context is nil.
func TestCheckPolicyConstraints_NilContext(t *testing.T) {
	reg, err := NewDIDWebRegistry(Config{Description: "test-policy"})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	req := &authzen.EvaluationRequest{
		Context: nil,
	}
	didDoc := &DIDDocument{ID: "did:web:example.com"}

	resp := reg.checkPolicyConstraints(req, didDoc, "did:web:example.com", time.Now())
	if resp != nil {
		t.Error("expected nil response when context is nil")
	}
}

// TestCheckPolicyConstraints_AllowedDomains tests domain filtering.
func TestCheckPolicyConstraints_AllowedDomains(t *testing.T) {
	reg, err := NewDIDWebRegistry(Config{Description: "test-policy-domain"})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	tests := []struct {
		name        string
		did         string
		allowed     []string
		expectAllow bool
	}{
		{"allowed exact", "did:web:example.com", []string{"example.com"}, true},
		{"denied", "did:web:evil.com", []string{"example.com"}, false},
		{"allowed wildcard", "did:web:sub.example.com", []string{"*.example.com"}, true},
		{"no domains = no filter", "did:web:anything.com", []string{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if len(tc.allowed) > 0 {
				ctx["allowed_domains"] = tc.allowed
			}
			req := &authzen.EvaluationRequest{
				Context: ctx,
			}
			didDoc := &DIDDocument{ID: tc.did}

			resp := reg.checkPolicyConstraints(req, didDoc, tc.did, time.Now())
			if tc.expectAllow {
				if resp != nil {
					t.Errorf("expected nil (allowed) but got deny response")
				}
			} else {
				if resp == nil || resp.Decision {
					t.Errorf("expected deny response but got nil or allow")
				}
			}
		})
	}
}

// TestCheckPolicyConstraints_RequiredServices tests service type filtering.
func TestCheckPolicyConstraints_RequiredServices(t *testing.T) {
	reg, err := NewDIDWebRegistry(Config{Description: "test-policy-svc"})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	tests := []struct {
		name        string
		services    interface{}
		required    []string
		expectAllow bool
	}{
		{
			"has required service",
			[]interface{}{
				map[string]interface{}{"type": "LinkedDomains"},
			},
			[]string{"LinkedDomains"},
			true,
		},
		{
			"missing required service",
			[]interface{}{
				map[string]interface{}{"type": "LinkedDomains"},
			},
			[]string{"CredentialRegistry"},
			false,
		},
		{
			"no required = no filter",
			nil,
			[]string{},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if len(tc.required) > 0 {
				ctx["required_services"] = tc.required
			}
			req := &authzen.EvaluationRequest{
				Context: ctx,
			}
			didDoc := &DIDDocument{
				ID:      "did:web:example.com",
				Service: tc.services,
			}

			resp := reg.checkPolicyConstraints(req, didDoc, "did:web:example.com", time.Now())
			if tc.expectAllow {
				if resp != nil {
					t.Errorf("expected nil (allowed) but got deny response")
				}
			} else {
				if resp == nil || resp.Decision {
					t.Errorf("expected deny response but got nil or allow")
				}
			}
		})
	}
}

// TestCheckPolicyConstraints_CombinedFilters tests both domain and service filtering together.
func TestCheckPolicyConstraints_CombinedFilters(t *testing.T) {
	reg, err := NewDIDWebRegistry(Config{Description: "test-combined"})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Domain allowed, service present → allow
	req := &authzen.EvaluationRequest{
		Context: map[string]interface{}{
			"allowed_domains":   []string{"example.com"},
			"required_services": []string{"LinkedDomains"},
		},
	}
	didDoc := &DIDDocument{
		ID: "did:web:example.com",
		Service: []interface{}{
			map[string]interface{}{"type": "LinkedDomains"},
		},
	}

	resp := reg.checkPolicyConstraints(req, didDoc, "did:web:example.com", time.Now())
	if resp != nil {
		t.Error("expected nil (allowed) for matching domain and service")
	}

	// Domain allowed, service missing → deny
	didDoc.Service = nil
	resp = reg.checkPolicyConstraints(req, didDoc, "did:web:example.com", time.Now())
	if resp == nil || resp.Decision {
		t.Error("expected deny for missing required service")
	}

	// Domain denied → deny (service check not reached)
	resp = reg.checkPolicyConstraints(req, didDoc, "did:web:evil.com", time.Now())
	if resp == nil || resp.Decision {
		t.Error("expected deny for unallowed domain")
	}
}
