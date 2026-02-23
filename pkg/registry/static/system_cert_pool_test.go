package static

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

func TestSystemCertPoolRegistry_New(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{
		Name:        "test-system",
		Description: "Test system cert pool",
	})
	// Note: This may fail on Windows or other platforms without system cert pool
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	assert.Equal(t, "test-system", reg.name)
	assert.Equal(t, "Test system cert pool", reg.description)
	assert.True(t, reg.Healthy())
}

func TestSystemCertPoolRegistry_NewDefaults(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	assert.Equal(t, "system-cert-pool", reg.name)
	assert.Equal(t, "System X.509 certificate pool", reg.description)
}

func TestSystemCertPoolRegistry_SupportedResourceTypes(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	types := reg.SupportedResourceTypes()
	assert.Contains(t, types, "x5c")
	assert.Contains(t, types, "jwk")
}

func TestSystemCertPoolRegistry_SupportsResolutionOnly(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	assert.False(t, reg.SupportsResolutionOnly())
}

func TestSystemCertPoolRegistry_Info(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{
		Name: "test-info",
	})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	info := reg.Info()
	assert.Equal(t, "test-info", info.Name)
	assert.Equal(t, "static_system_cert_pool", info.Type)
	assert.False(t, info.ResolutionOnly)
	assert.True(t, info.Healthy)
	assert.Contains(t, info.TrustAnchors, "system")
}

func TestSystemCertPoolRegistry_Refresh(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	err = reg.Refresh(context.Background())
	assert.NoError(t, err)
	assert.True(t, reg.Healthy())
}

func TestSystemCertPoolRegistry_Evaluate_ResolutionOnly(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			ID: "did:example:123",
			// No Type or Key = resolution-only
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "does not support resolution-only")
}

func TestSystemCertPoolRegistry_Evaluate_UnsupportedType(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "unsupported",
			ID:   "test",
			Key:  []interface{}{"data"},
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "unsupported resource type")
}

func TestSystemCertPoolRegistry_Evaluate_InvalidCert(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	// Invalid base64
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{"not-valid-base64!!!"},
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestSystemCertPoolRegistry_Evaluate_SelfSignedCert(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	// Create a self-signed certificate (should not be trusted by system pool)
	cert := generateSelfSignedCert(t)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{certB64},
		},
	})

	require.NoError(t, err)
	// Self-signed cert should NOT be trusted by system pool
	assert.False(t, resp.Decision)
	// Should have error containing "certificate signed by unknown authority" or similar
	assert.NotNil(t, resp.Context.Reason["error"])
}

func TestSystemCertPoolRegistry_Evaluate_JWKFormat(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	// Create a self-signed certificate
	cert := generateSelfSignedCert(t)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	// JWK with x5c claim
	jwk := map[string]interface{}{
		"kty": "EC",
		"x5c": []interface{}{certB64},
	}

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "test",
			Key:  []interface{}{jwk},
		},
	})

	require.NoError(t, err)
	// Self-signed cert should NOT be trusted
	assert.False(t, resp.Decision)
}

func TestSystemCertPoolRegistry_Evaluate_JWKWithoutX5C(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	// JWK without x5c claim
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
	}

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "test",
			Key:  []interface{}{jwk},
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["error"], "x5c")
}

func TestSystemCertPoolRegistry_Evaluate_EmptyKey(t *testing.T) {
	reg, err := NewSystemCertPoolRegistry(SystemCertPoolConfig{})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{}, // Empty key array
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)
}

func TestSystemCertPoolRegistry_ImplementsInterface(t *testing.T) {
	var _ registry.TrustRegistry = (*SystemCertPoolRegistry)(nil)
}

// generateSelfSignedCert creates a self-signed certificate for testing
func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
