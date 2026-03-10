package didwebvh

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// TestExtractDomainFromDIDWebVH tests domain extraction from did:webvh identifiers.
func TestExtractDomainFromDIDWebVH(t *testing.T) {
	tests := []struct {
		name   string
		did    string
		expect string
	}{
		{"standard format", "did:webvh:QmScid123:example.com", "example.com"},
		{"with path", "did:webvh:QmScid123:example.com:path:to:doc", "example.com"},
		{"with port", "did:webvh:QmScid123:example.com%3A8080", "example.com:8080"},
		{"subdomain", "did:webvh:QmScid123:sub.example.com", "sub.example.com"},
		{"missing domain", "did:webvh:QmScid123", ""},
		{"not did:webvh", "did:web:example.com", ""},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractDomainFromDIDWebVH(tc.did)
			if result != tc.expect {
				t.Errorf("extractDomainFromDIDWebVH(%q) = %q, want %q", tc.did, result, tc.expect)
			}
		})
	}
}

// TestMatchesDomainPattern tests domain pattern matching with wildcard support.
func TestMatchesDomainPattern(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		allowed []string
		expect  bool
	}{
		{"exact match", "example.com", []string{"example.com"}, true},
		{"no match", "other.com", []string{"example.com"}, false},
		{"wildcard match", "sub.example.com", []string{"*.example.com"}, true},
		{"wildcard no match base", "example.com", []string{"*.example.com"}, false},
		{"deep subdomain", "a.b.example.com", []string{"*.example.com"}, true},
		{"multiple allowed", "b.com", []string{"a.com", "b.com"}, true},
		{"empty allowed", "example.com", []string{}, false},
		{"empty domain", "", []string{"example.com"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := matchesDomainPattern(tc.domain, tc.allowed)
			if result != tc.expect {
				t.Errorf("matchesDomainPattern(%q, %v) = %v, want %v", tc.domain, tc.allowed, result, tc.expect)
			}
		})
	}
}

// TestExtractStringSliceFromContext tests context value extraction.
func TestExtractStringSliceFromContext(t *testing.T) {
	tests := []struct {
		name   string
		ctx    map[string]interface{}
		key    string
		expect int // expected length
	}{
		{"string slice", map[string]interface{}{"k": []string{"a", "b"}}, "k", 2},
		{"interface slice", map[string]interface{}{"k": []interface{}{"a", "b"}}, "k", 2},
		{"missing key", map[string]interface{}{}, "k", 0},
		{"wrong type", map[string]interface{}{"k": 42}, "k", 0},
		{"interface with non-strings", map[string]interface{}{"k": []interface{}{"a", 42}}, "k", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractStringSliceFromContext(tc.ctx, tc.key)
			if len(result) != tc.expect {
				t.Errorf("extractStringSliceFromContext() returned %d items, want %d", len(result), tc.expect)
			}
		})
	}
}

// TestDIDDocHasRequiredServices tests DID document service type checking.
func TestDIDDocHasRequiredServices(t *testing.T) {
	services := []interface{}{
		map[string]interface{}{"id": "#svc-1", "type": "LinkedDomains"},
		map[string]interface{}{"id": "#svc-2", "type": "CredentialRegistry"},
	}

	tests := []struct {
		name     string
		service  interface{}
		required []string
		expect   bool
	}{
		{"single required present", services, []string{"LinkedDomains"}, true},
		{"multiple required present", services, []string{"LinkedDomains", "CredentialRegistry"}, true},
		{"missing required", services, []string{"DIDCommMessaging"}, false},
		{"nil services", nil, []string{"LinkedDomains"}, false},
		{"empty required", services, []string{}, true},
		{"wrong type", "not-array", []string{"Test"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := didDocHasRequiredServices(tc.service, tc.required)
			if result != tc.expect {
				t.Errorf("didDocHasRequiredServices() = %v, want %v", result, tc.expect)
			}
		})
	}
}

// TestCheckPolicyConstraints_NilContext_WebVH verifies no filtering when context is nil.
func TestCheckPolicyConstraints_NilContext_WebVH(t *testing.T) {
	reg, _ := NewDIDWebVHRegistry(Config{Description: "test-policy-webvh"})
	req := &authzen.EvaluationRequest{Context: nil}
	didDoc := &DIDDocument{ID: "did:webvh:QmScid:example.com"}

	resp := reg.checkPolicyConstraints(req, didDoc, "did:webvh:QmScid:example.com", time.Now())
	if resp != nil {
		t.Error("expected nil response when context is nil")
	}
}

// TestCheckPolicyConstraints_AllowedDomains_WebVH tests domain filtering for did:webvh.
func TestCheckPolicyConstraints_AllowedDomains_WebVH(t *testing.T) {
	reg, _ := NewDIDWebVHRegistry(Config{Description: "test-domain-webvh"})

	tests := []struct {
		name        string
		did         string
		allowed     []string
		expectAllow bool
	}{
		{"allowed", "did:webvh:QmScid:example.com", []string{"example.com"}, true},
		{"denied", "did:webvh:QmScid:evil.com", []string{"example.com"}, false},
		{"wildcard", "did:webvh:QmScid:sub.example.com", []string{"*.example.com"}, true},
		{"no filter", "did:webvh:QmScid:anything.com", []string{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if len(tc.allowed) > 0 {
				ctx["allowed_domains"] = tc.allowed
			}
			req := &authzen.EvaluationRequest{Context: ctx}
			didDoc := &DIDDocument{ID: tc.did}

			resp := reg.checkPolicyConstraints(req, didDoc, tc.did, time.Now())
			if tc.expectAllow {
				if resp != nil {
					t.Errorf("expected nil (allowed) but got deny")
				}
			} else {
				if resp == nil || resp.Decision {
					t.Errorf("expected deny but got nil or allow")
				}
			}
		})
	}
}

// TestCheckPolicyConstraints_RequiredServices_WebVH tests service type filtering for did:webvh.
func TestCheckPolicyConstraints_RequiredServices_WebVH(t *testing.T) {
	reg, _ := NewDIDWebVHRegistry(Config{Description: "test-svc-webvh"})

	tests := []struct {
		name        string
		services    interface{}
		required    []string
		expectAllow bool
	}{
		{
			"has required",
			[]interface{}{map[string]interface{}{"type": "LinkedDomains"}},
			[]string{"LinkedDomains"},
			true,
		},
		{
			"missing required",
			[]interface{}{map[string]interface{}{"type": "Other"}},
			[]string{"LinkedDomains"},
			false,
		},
		{
			"no filter",
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
			req := &authzen.EvaluationRequest{Context: ctx}
			didDoc := &DIDDocument{
				ID:      "did:webvh:QmScid:example.com",
				Service: tc.services,
			}

			resp := reg.checkPolicyConstraints(req, didDoc, "did:webvh:QmScid:example.com", time.Now())
			if tc.expectAllow {
				if resp != nil {
					t.Errorf("expected nil (allowed) but got deny")
				}
			} else {
				if resp == nil || resp.Decision {
					t.Errorf("expected deny but got nil or allow")
				}
			}
		})
	}
}
