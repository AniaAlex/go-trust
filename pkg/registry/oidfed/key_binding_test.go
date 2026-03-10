package oidfed

import (
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// TestJWKKeyToMap verifies that jwkKeyToMap serializes various key-like objects.
func TestJWKKeyToMap(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		check func(map[string]interface{}) bool
	}{
		{
			name: "EC key map",
			input: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc123",
				"y":   "def456",
			},
			check: func(m map[string]interface{}) bool {
				return m["kty"] == "EC" && m["crv"] == "P-256" && m["x"] == "abc123" && m["y"] == "def456"
			},
		},
		{
			name: "RSA key map",
			input: map[string]interface{}{
				"kty": "RSA",
				"n":   "mod_value",
				"e":   "AQAB",
			},
			check: func(m map[string]interface{}) bool {
				return m["kty"] == "RSA" && m["n"] == "mod_value" && m["e"] == "AQAB"
			},
		},
		{
			name: "OKP key map",
			input: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "okp_x_value",
			},
			check: func(m map[string]interface{}) bool {
				return m["kty"] == "OKP" && m["crv"] == "Ed25519" && m["x"] == "okp_x_value"
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := jwkKeyToMap(tc.input)
			if err != nil {
				t.Fatalf("jwkKeyToMap failed: %v", err)
			}
			if !tc.check(m) {
				t.Errorf("unexpected result: %v", m)
			}
		})
	}
}

// TestJWKKeyToMap_NonSerializable verifies error on non-serializable input.
func TestJWKKeyToMap_NonSerializable(t *testing.T) {
	// A channel can't be serialized to JSON
	_, err := jwkKeyToMap(make(chan int))
	if err == nil {
		t.Error("expected error for non-serializable input")
	}
}

// TestJWKsMatch tests key material comparison for different key types.
func TestJWKsMatch(t *testing.T) {
	tests := []struct {
		name   string
		jwk1   map[string]interface{}
		jwk2   map[string]interface{}
		expect bool
	}{
		{
			name: "EC keys match",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc",
				"y":   "def",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc",
				"y":   "def",
				"kid": "key-1", // extra fields are ignored
			},
			expect: true,
		},
		{
			name: "EC keys different curve",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc",
				"y":   "def",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-384",
				"x":   "abc",
				"y":   "def",
			},
			expect: false,
		},
		{
			name: "EC keys different x",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc",
				"y":   "def",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "xyz",
				"y":   "def",
			},
			expect: false,
		},
		{
			name: "RSA keys match",
			jwk1: map[string]interface{}{
				"kty": "RSA",
				"n":   "modulus_value",
				"e":   "AQAB",
			},
			jwk2: map[string]interface{}{
				"kty": "RSA",
				"n":   "modulus_value",
				"e":   "AQAB",
			},
			expect: true,
		},
		{
			name: "RSA keys different modulus",
			jwk1: map[string]interface{}{
				"kty": "RSA",
				"n":   "modulus_1",
				"e":   "AQAB",
			},
			jwk2: map[string]interface{}{
				"kty": "RSA",
				"n":   "modulus_2",
				"e":   "AQAB",
			},
			expect: false,
		},
		{
			name: "OKP keys match",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "okp_x",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "okp_x",
			},
			expect: true,
		},
		{
			name: "OKP keys different x",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "okp_x_1",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "okp_x_2",
			},
			expect: false,
		},
		{
			name: "different key types",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "abc",
				"y":   "def",
			},
			jwk2: map[string]interface{}{
				"kty": "RSA",
				"n":   "mod",
				"e":   "AQAB",
			},
			expect: false,
		},
		{
			name:   "missing kty in first",
			jwk1:   map[string]interface{}{"crv": "P-256"},
			jwk2:   map[string]interface{}{"kty": "EC", "crv": "P-256"},
			expect: false,
		},
		{
			name:   "missing kty in second",
			jwk1:   map[string]interface{}{"kty": "EC", "crv": "P-256"},
			jwk2:   map[string]interface{}{"crv": "P-256"},
			expect: false,
		},
		{
			name: "unknown key type",
			jwk1: map[string]interface{}{
				"kty": "XYZ",
				"x":   "abc",
			},
			jwk2: map[string]interface{}{
				"kty": "XYZ",
				"x":   "abc",
			},
			expect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := registry.JWKsMatch(tc.jwk1, tc.jwk2)
			if result != tc.expect {
				t.Errorf("JWKsMatch() = %v, want %v", result, tc.expect)
			}
		})
	}
}

// TestJWKKeyToMap_RoundTrip verifies JSON serialization round-trip.
func TestJWKKeyToMap_RoundTrip(t *testing.T) {
	original := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test_x",
		"y":   "test_y",
		"kid": "test-key-id",
	}

	m, err := jwkKeyToMap(original)
	if err != nil {
		t.Fatalf("jwkKeyToMap failed: %v", err)
	}

	// Verify all fields survived the round trip
	if m["kty"] != "EC" {
		t.Errorf("kty: got %v, want EC", m["kty"])
	}
	if m["crv"] != "P-256" {
		t.Errorf("crv: got %v, want P-256", m["crv"])
	}
	if m["x"] != "test_x" {
		t.Errorf("x: got %v, want test_x", m["x"])
	}
	if m["y"] != "test_y" {
		t.Errorf("y: got %v, want test_y", m["y"])
	}
	if m["kid"] != "test-key-id" {
		t.Errorf("kid: got %v, want test-key-id", m["kid"])
	}
}

// TestJWKsMatch_EmptyMaps verifies comparison of empty maps.
func TestJWKsMatch_EmptyMaps(t *testing.T) {
	result := registry.JWKsMatch(map[string]interface{}{}, map[string]interface{}{})
	if result {
		t.Error("expected false for empty maps (no kty)")
	}
}

// Ensure json is used (it's imported by the package under test).
var _ = json.Marshal
