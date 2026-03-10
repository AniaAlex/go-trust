package did

import (
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
)

// TestExtractDomainFromDID tests domain extraction from various DID formats.
func TestExtractDomainFromDID(t *testing.T) {
	tests := []struct {
		name   string
		did    string
		expect string
	}{
		{"did:web simple", "did:web:example.com", "example.com"},
		{"did:web with path", "did:web:example.com:path:to:doc", "example.com"},
		{"did:web with port", "did:web:example.com%3A8080", "example.com:8080"},
		{"did:webvh", "did:webvh:QmScid:example.com", "example.com"},
		{"did:webvh with path", "did:webvh:QmScid:example.com:path", "example.com"},
		{"did:key - no domain", "did:key:z6MkTest", ""},
		{"did:pkh - no domain", "did:pkh:eip155:1:0xabc", ""},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractDomainFromDID(tc.did)
			assert.Equal(t, tc.expect, result)
		})
	}
}

// TestDomainMatchesPatterns tests domain pattern matching.
func TestDomainMatchesPatterns(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		allowed []string
		expect  bool
	}{
		{"exact match", "example.com", []string{"example.com"}, true},
		{"no match", "other.com", []string{"example.com"}, false},
		{"wildcard match", "sub.example.com", []string{"*.example.com"}, true},
		{"wildcard no base", "example.com", []string{"*.example.com"}, false},
		{"deep subdomain", "a.b.example.com", []string{"*.example.com"}, true},
		{"multiple", "b.com", []string{"a.com", "b.com"}, true},
		{"empty allowed", "example.com", []string{}, false},
		{"empty domain", "", []string{"example.com"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := domainMatchesPatterns(tc.domain, tc.allowed)
			assert.Equal(t, tc.expect, result)
		})
	}
}

// TestExtractStringSliceFromCtx tests context value extraction.
func TestExtractStringSliceFromCtx(t *testing.T) {
	tests := []struct {
		name   string
		ctx    map[string]interface{}
		key    string
		expect int
	}{
		{"string slice", map[string]interface{}{"k": []string{"a", "b"}}, "k", 2},
		{"interface slice", map[string]interface{}{"k": []interface{}{"a", "b"}}, "k", 2},
		{"missing", map[string]interface{}{}, "k", 0},
		{"wrong type", map[string]interface{}{"k": 42}, "k", 0},
		{"mixed types", map[string]interface{}{"k": []interface{}{"a", 42}}, "k", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractStringSliceFromCtx(tc.ctx, tc.key)
			assert.Len(t, result, tc.expect)
		})
	}
}

// TestDIDDocServicesMatch tests DID document service type matching.
func TestDIDDocServicesMatch(t *testing.T) {
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
		{"single present", services, []string{"LinkedDomains"}, true},
		{"multiple present", services, []string{"LinkedDomains", "CredentialRegistry"}, true},
		{"missing", services, []string{"DIDCommMessaging"}, false},
		{"nil", nil, []string{"LinkedDomains"}, false},
		{"empty required", services, []string{}, true},
		{"wrong type", "not-array", []string{"Test"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := didDocServicesMatch(tc.service, tc.required)
			assert.Equal(t, tc.expect, result)
		})
	}
}

// TestCheckDIDPolicyConstraints_NilContext verifies no filtering when context is nil.
func TestCheckDIDPolicyConstraints_NilContext(t *testing.T) {
	req := &authzen.EvaluationRequest{Context: nil}
	didDoc := &DIDDocument{ID: "did:key:z6MkTest"}

	resp := checkDIDPolicyConstraints(req, didDoc, time.Now())
	assert.Nil(t, resp)
}

// TestCheckDIDPolicyConstraints_AllowedDomains tests domain filtering.
func TestCheckDIDPolicyConstraints_AllowedDomains(t *testing.T) {
	tests := []struct {
		name        string
		subjectID   string
		allowed     []string
		expectAllow bool
	}{
		{"allowed did:web", "did:web:example.com", []string{"example.com"}, true},
		{"denied did:web", "did:web:evil.com", []string{"example.com"}, false},
		{"wildcard", "did:web:sub.example.com", []string{"*.example.com"}, true},
		{"did:key no domain - allowed", "did:key:z6MkTest", []string{"example.com"}, true}, // no domain = skip check
		{"no filter", "did:web:anything.com", []string{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]interface{}{}
			if len(tc.allowed) > 0 {
				ctx["allowed_domains"] = tc.allowed
			}
			req := &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: tc.subjectID},
				Context: ctx,
			}
			didDoc := &DIDDocument{ID: tc.subjectID}

			resp := checkDIDPolicyConstraints(req, didDoc, time.Now())
			if tc.expectAllow {
				assert.Nil(t, resp, "expected nil (allowed)")
			} else {
				assert.NotNil(t, resp, "expected deny response")
				if resp != nil {
					assert.False(t, resp.Decision)
				}
			}
		})
	}
}

// TestCheckDIDPolicyConstraints_RequiredServices tests service type filtering.
func TestCheckDIDPolicyConstraints_RequiredServices(t *testing.T) {
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
			req := &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "did:web:example.com"},
				Context: ctx,
			}
			didDoc := &DIDDocument{
				ID:      "did:web:example.com",
				Service: tc.services,
			}

			resp := checkDIDPolicyConstraints(req, didDoc, time.Now())
			if tc.expectAllow {
				assert.Nil(t, resp, "expected nil (allowed)")
			} else {
				assert.NotNil(t, resp, "expected deny response")
				if resp != nil {
					assert.False(t, resp.Decision)
				}
			}
		})
	}
}

// TestCheckDIDPolicyConstraints_Combined tests both domain and service filters together.
func TestCheckDIDPolicyConstraints_Combined(t *testing.T) {
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "did:web:example.com"},
		Context: map[string]interface{}{
			"allowed_domains":   []string{"example.com"},
			"required_services": []string{"LinkedDomains"},
		},
	}

	// Both match → allow
	didDoc := &DIDDocument{
		ID:      "did:web:example.com",
		Service: []interface{}{map[string]interface{}{"type": "LinkedDomains"}},
	}
	resp := checkDIDPolicyConstraints(req, didDoc, time.Now())
	assert.Nil(t, resp, "both match should allow")

	// Domain matches, service missing → deny
	didDoc.Service = nil
	resp = checkDIDPolicyConstraints(req, didDoc, time.Now())
	assert.NotNil(t, resp, "missing service should deny")
	assert.False(t, resp.Decision)

	// Domain denied → deny
	req.Subject.ID = "did:web:evil.com"
	resp = checkDIDPolicyConstraints(req, didDoc, time.Now())
	assert.NotNil(t, resp, "wrong domain should deny")
	assert.False(t, resp.Decision)
}
