package registry

import (
	"testing"
)

func TestPolicyManager_Basic(t *testing.T) {
	pm := NewPolicyManager()

	policy := &Policy{
		Name:        "wallet-provider",
		Description: "Trust policy for wallet providers",
		Registries:  []string{"eu-wallet-federation"},
		OIDFed: &OIDFedPolicyConstraints{
			RequiredTrustMarks: []string{"https://example.eu/tm/wallet"},
			EntityTypes:        []string{"openid_credential_issuer"},
		},
	}

	pm.RegisterPolicy(policy)

	// Test GetPolicy with matching action
	got := pm.GetPolicy("wallet-provider")
	if got == nil {
		t.Fatal("GetPolicy returned nil for registered policy")
	}
	if got.Name != "wallet-provider" {
		t.Errorf("GetPolicy returned wrong policy: %s", got.Name)
	}

	// Test GetPolicy with unknown action (no default)
	got = pm.GetPolicy("unknown")
	if got != nil {
		t.Error("GetPolicy should return nil for unknown action without default")
	}

	// Test GetPolicy with empty action (no default)
	got = pm.GetPolicy("")
	if got != nil {
		t.Error("GetPolicy should return nil for empty action without default")
	}
}

func TestPolicyManager_DefaultPolicy(t *testing.T) {
	pm := NewPolicyManager()

	defaultPolicy := &Policy{
		Name:        "default",
		Description: "Default trust policy",
	}

	specificPolicy := &Policy{
		Name:        "specific",
		Description: "Specific policy",
	}

	pm.SetDefaultPolicy(defaultPolicy)
	pm.RegisterPolicy(specificPolicy)

	// Empty action should return default
	got := pm.GetPolicy("")
	if got == nil || got.Name != "default" {
		t.Error("GetPolicy('') should return default policy")
	}

	// Unknown action should return default
	got = pm.GetPolicy("unknown")
	if got == nil || got.Name != "default" {
		t.Error("GetPolicy('unknown') should return default policy")
	}

	// Specific action should return specific policy
	got = pm.GetPolicy("specific")
	if got == nil || got.Name != "specific" {
		t.Error("GetPolicy('specific') should return specific policy")
	}
}

func TestPolicyManager_ListPolicies(t *testing.T) {
	pm := NewPolicyManager()

	pm.RegisterPolicy(&Policy{Name: "policy-a"})
	pm.RegisterPolicy(&Policy{Name: "policy-b"})
	pm.RegisterPolicy(&Policy{Name: "policy-c"})

	names := pm.ListPolicies()
	if len(names) != 3 {
		t.Errorf("ListPolicies returned %d policies, want 3", len(names))
	}

	// Check all names are present (order may vary)
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	for _, expected := range []string{"policy-a", "policy-b", "policy-c"} {
		if !nameSet[expected] {
			t.Errorf("ListPolicies missing %s", expected)
		}
	}
}

func TestPolicyManager_AllowedRegistries(t *testing.T) {
	pm := NewPolicyManager()

	pm.RegisterPolicy(&Policy{
		Name:       "restricted",
		Registries: []string{"reg-a", "reg-b"},
	})

	pm.RegisterPolicy(&Policy{
		Name: "unrestricted",
		// No Registries = all allowed
	})

	// Restricted policy
	allowed := pm.GetAllowedRegistries("restricted")
	if len(allowed) != 2 {
		t.Errorf("GetAllowedRegistries('restricted') returned %d, want 2", len(allowed))
	}

	// Unrestricted policy
	allowed = pm.GetAllowedRegistries("unrestricted")
	if allowed != nil {
		t.Error("GetAllowedRegistries('unrestricted') should return nil")
	}
}

func TestPolicyContext_Helpers(t *testing.T) {
	// Test with nil policy
	pc := &PolicyContext{}
	if pc.HasOIDFedConstraints() {
		t.Error("HasOIDFedConstraints should be false for nil policy")
	}
	if pc.GetOIDFedTrustMarks() != nil {
		t.Error("GetOIDFedTrustMarks should return nil for nil policy")
	}

	// Test with OIDF constraints
	pc = &PolicyContext{
		Policy: &Policy{
			OIDFed: &OIDFedPolicyConstraints{
				RequiredTrustMarks: []string{"tm1", "tm2"},
				EntityTypes:        []string{"et1"},
			},
		},
	}

	if !pc.HasOIDFedConstraints() {
		t.Error("HasOIDFedConstraints should be true")
	}

	marks := pc.GetOIDFedTrustMarks()
	if len(marks) != 2 || marks[0] != "tm1" {
		t.Error("GetOIDFedTrustMarks returned wrong values")
	}

	types := pc.GetOIDFedEntityTypes()
	if len(types) != 1 || types[0] != "et1" {
		t.Error("GetOIDFedEntityTypes returned wrong values")
	}

	// Test ETSI constraints
	pc = &PolicyContext{
		Policy: &Policy{
			ETSI: &ETSIPolicyConstraints{
				ServiceTypes: []string{"st1"},
			},
		},
	}

	if !pc.HasETSIConstraints() {
		t.Error("HasETSIConstraints should be true")
	}

	serviceTypes := pc.GetETSIServiceTypes()
	if len(serviceTypes) != 1 || serviceTypes[0] != "st1" {
		t.Error("GetETSIServiceTypes returned wrong values")
	}
}
