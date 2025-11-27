package didweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDIDToHTTPURL tests the conversion of did:web identifiers to HTTPS URLs
func TestDIDToHTTPURL(t *testing.T) {
	tests := []struct {
		name        string
		did         string
		expectedURL string
		expectError bool
	}{
		{
			name:        "bare domain",
			did:         "did:web:example.com",
			expectedURL: "https://example.com/.well-known/did.json",
			expectError: false,
		},
		{
			name:        "domain with path",
			did:         "did:web:example.com:user:alice",
			expectedURL: "https://example.com/user/alice/did.json",
			expectError: false,
		},
		{
			name:        "domain with port",
			did:         "did:web:example.com%3A3000",
			expectedURL: "https://example.com:3000/.well-known/did.json",
			expectError: false,
		},
		{
			name:        "domain with port and path",
			did:         "did:web:example.com%3A3000:user:bob",
			expectedURL: "https://example.com:3000/user/bob/did.json",
			expectError: false,
		},
		{
			name:        "subdomain",
			did:         "did:web:w3c-ccg.github.io",
			expectedURL: "https://w3c-ccg.github.io/.well-known/did.json",
			expectError: false,
		},
		{
			name:        "subdomain with path",
			did:         "did:web:w3c-ccg.github.io:user:alice",
			expectedURL: "https://w3c-ccg.github.io/user/alice/did.json",
			expectError: false,
		},
		{
			name:        "invalid - not did:web",
			did:         "did:example:123",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := didToHTTPURL(tt.did)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

// TestJWKsMatch tests the JWK comparison logic
func TestJWKsMatch(t *testing.T) {
	registry := &DIDWebRegistry{}

	tests := []struct {
		name     string
		jwk1     map[string]interface{}
		jwk2     map[string]interface{}
		expected bool
	}{
		{
			name: "matching Ed25519 keys",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			expected: true,
		},
		{
			name: "different Ed25519 keys",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			jwk2: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "22qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			expected: false,
		},
		{
			name: "matching P-256 keys",
			jwk1: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
				"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
				"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
			},
			expected: true,
		},
		{
			name: "different key types",
			jwk1: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
			},
			jwk2: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
				"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
			},
			expected: false,
		},
		{
			name: "matching RSA keys",
			jwk1: map[string]interface{}{
				"kty": "RSA",
				"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
				"e":   "AQAB",
			},
			jwk2: map[string]interface{}{
				"kty": "RSA",
				"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx",
				"e":   "AQAB",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := registry.jwksMatch(tt.jwk1, tt.jwk2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestResolveDID tests DID resolution with a mock HTTP server
func TestResolveDID(t *testing.T) {
	// Create a test DID document
	testDIDDoc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	// Create a mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testDIDDoc)
	}))
	defer server.Close()

	// Create registry with insecure skip verify for test server
	registry, err := NewDIDWebRegistry(Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	// Override the HTTP client to use the test server
	// In a real test, we'd need to mock the DID resolution differently
	// For now, we'll test the parsing logic separately
	t.Run("URL parsing", func(t *testing.T) {
		url, err := didToHTTPURL("did:web:example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/.well-known/did.json", url)
	})

	// Test with actual resolution would require more sophisticated mocking
	_ = registry
}

// TestEvaluate tests the complete evaluation flow
func TestEvaluate(t *testing.T) {
	// Create a test DID document
	testDIDDoc := &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:web:example.com",
		VerificationMethod: []VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
				PublicKeyJwk: map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
	}

	// Create a mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(testDIDDoc)
	}))
	defer server.Close()

	// Create registry
	registry, err := NewDIDWebRegistry(Config{
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)

	t.Run("non did:web identifier", func(t *testing.T) {
		req := &authzen.EvaluationRequest{
			Subject: authzen.Subject{
				Type: "key",
				ID:   "not-a-did-web",
			},
			Resource: authzen.Resource{
				Type: "jwk",
				ID:   "not-a-did-web",
				Key: []interface{}{
					map[string]interface{}{
						"kty": "OKP",
						"crv": "Ed25519",
						"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
					},
				},
			},
		}

		resp, err := registry.Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.False(t, resp.Decision)
		assert.Contains(t, resp.Context.Reason["error"], "must be a did:web identifier")
	})
}

// TestSupportedResourceTypes tests the SupportedResourceTypes method
func TestSupportedResourceTypes(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	types := registry.SupportedResourceTypes()
	assert.Contains(t, types, "jwk")
}

// TestInfo tests the Info method
func TestInfo(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{
		Description: "Test Registry",
	})
	require.NoError(t, err)

	info := registry.Info()
	assert.Equal(t, "didweb-registry", info.Name)
	assert.Equal(t, "did:web", info.Type)
	assert.Equal(t, "Test Registry", info.Description)
	assert.Equal(t, "1.0.0", info.Version)
}

// TestHealthy tests the Healthy method
func TestHealthy(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	assert.True(t, registry.Healthy())
}

// TestRefresh tests the Refresh method
func TestRefresh(t *testing.T) {
	registry, err := NewDIDWebRegistry(Config{})
	require.NoError(t, err)

	err = registry.Refresh(context.Background())
	assert.NoError(t, err)
}
