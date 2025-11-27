package didweb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTradeTrustDIDStructures tests JWK matching with DID document structures inspired by TradeTrust/Singapore
// These tests validate the key matching logic handles multiple modern key types as used by trustvc.github.io/did/1
func TestTradeTrustMultikeyMatching(t *testing.T) {
	// DID document inspired by TradeTrust's trustvc.github.io/did/1
	// Contains mix of different Multikey types as used in production
	tradeTrustStyleDID := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/bls12381-2020/v1",
			"https://w3id.org/security/multikey/v1",
		},
		ID: "did:web:example.tradetrust.io",
		VerificationMethod: []VerificationMethod{
			// Modern Multikey with Ed25519 (commonly used for signing)
			{
				ID:         "did:web:example.tradetrust.io#multikey-1",
				Type:       "Multikey",
				Controller: "did:web:example.tradetrust.io",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
			// Modern Multikey with P-384 (higher security level)
			{
				ID:         "did:web:example.tradetrust.io#multikey-2",
				Type:       "Multikey",
				Controller: "did:web:example.tradetrust.io",
				PublicKeyJwk: map[string]interface{}{
					"kty": "EC",
					"crv": "P-384",
					"x":   "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoXrUOMHEwfL",
					"y":   "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w0-bOLKLAJKFU",
				},
			},
			// P-256 for compatibility
			{
				ID:         "did:web:example.tradetrust.io#multikey-3",
				Type:       "Multikey",
				Controller: "did:web:example.tradetrust.io",
				PublicKeyJwk: map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
					"y":   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
				},
			},
		},
	}

	registry := &DIDWebRegistry{}

	testCases := []struct {
		name         string
		jwk          map[string]interface{}
		shouldMatch  bool
		expectedVMID string
	}{
		{
			name: "Ed25519 Multikey",
			jwk: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			shouldMatch:  true,
			expectedVMID: "did:web:example.tradetrust.io#multikey-1",
		},
		{
			name: "P-384 Multikey",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-384",
				"x":   "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoXrUOMHEwfL",
				"y":   "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w0-bOLKLAJKFU",
			},
			shouldMatch:  true,
			expectedVMID: "did:web:example.tradetrust.io#multikey-2",
		},
		{
			name: "P-256 Multikey",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
				"y":   "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
			},
			shouldMatch:  true,
			expectedVMID: "did:web:example.tradetrust.io#multikey-3",
		},
		{
			name: "Non-matching Ed25519 key",
			jwk: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			shouldMatch: false,
		},
		{
			name: "Non-matching P-384 key",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "P-384",
				"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"y":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched, vm, err := registry.matchJWK([]interface{}{tc.jwk}, tradeTrustStyleDID)
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.True(t, matched, "Expected key to match for %s", tc.name)
				require.NotNil(t, vm, "Expected verification method for %s", tc.name)
				assert.Equal(t, tc.expectedVMID, vm.ID, "Expected correct verification method ID")
			} else {
				assert.False(t, matched, "Expected key NOT to match for %s", tc.name)
			}
		})
	}
}

// TestOpenAttestationKeyTypes tests secp256k1 keys as used by OpenAttestation for Ethereum-based verification
func TestOpenAttestationKeyTypes(t *testing.T) {
	openAttestationDID := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/secp256k1recovery-2020/v2",
		},
		ID: "did:web:example.openattestation.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.openattestation.com#controller",
				Type:       "EcdsaSecp256k1RecoveryMethod2020",
				Controller: "did:web:example.openattestation.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "EC",
					"crv": "secp256k1",
					"x":   "NtngWpJUr-rlNNbs0u-Aa8e16OwSJu6UiFf0Rdo1oJ4",
					"y":   "qN1jKupJlFsPFc1UkWinqljv4YE0mq_Ickwnjgasvmo",
				},
			},
		},
	}

	registry := &DIDWebRegistry{}

	testCases := []struct {
		name        string
		jwk         map[string]interface{}
		shouldMatch bool
	}{
		{
			name: "Matching secp256k1 key",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "secp256k1",
				"x":   "NtngWpJUr-rlNNbs0u-Aa8e16OwSJu6UiFf0Rdo1oJ4",
				"y":   "qN1jKupJlFsPFc1UkWinqljv4YE0mq_Ickwnjgasvmo",
			},
			shouldMatch: true,
		},
		{
			name: "Non-matching secp256k1 key",
			jwk: map[string]interface{}{
				"kty": "EC",
				"crv": "secp256k1",
				"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"y":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			},
			shouldMatch: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched, vm, err := registry.matchJWK([]interface{}{tc.jwk}, openAttestationDID)
			require.NoError(t, err)

			if tc.shouldMatch {
				assert.True(t, matched, "Expected key to match")
				require.NotNil(t, vm)
				assert.Equal(t, "did:web:example.openattestation.com#controller", vm.ID)
			} else {
				assert.False(t, matched, "Expected key NOT to match")
			}
		})
	}
}
