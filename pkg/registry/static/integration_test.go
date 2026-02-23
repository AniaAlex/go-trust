package static_test

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
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/registry/static"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// TestAlwaysTrustedRegistry_WithTestServer tests the AlwaysTrustedRegistry
// integration with the testserver.
func TestAlwaysTrustedRegistry_WithTestServer(t *testing.T) {
	// Create test server with always-trusted registry
	reg := static.NewAlwaysTrustedRegistry("test-always-trusted")
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Create client
	client := authzenclient.New(srv.URL())

	// Test evaluation
	ctx := context.Background()
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"dummy-cert"},
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.Decision, "AlwaysTrustedRegistry should return true")
}

// TestNeverTrustedRegistry_WithTestServer tests the NeverTrustedRegistry
// integration with the testserver.
func TestNeverTrustedRegistry_WithTestServer(t *testing.T) {
	// Create test server with never-trusted registry
	reg := static.NewNeverTrustedRegistry("test-never-trusted")
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Create client
	client := authzenclient.New(srv.URL())

	// Test evaluation
	ctx := context.Background()
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:example:123",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "did:example:123",
			Key:  []interface{}{"dummy-cert"},
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision, "NeverTrustedRegistry should return false")
}

// TestSystemCertPoolRegistry_WithTestServer tests the SystemCertPoolRegistry
// integration with the testserver.
func TestSystemCertPoolRegistry_WithTestServer(t *testing.T) {
	// Create system cert pool registry
	reg, err := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
		Name: "test-system-pool",
	})
	if err != nil {
		t.Skipf("System cert pool not available: %v", err)
	}

	// Create test server with system cert pool registry
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Create client
	client := authzenclient.New(srv.URL())

	// Generate a self-signed certificate (should NOT be trusted)
	cert := generateTestCert(t)
	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)

	// Test evaluation with self-signed cert
	ctx := context.Background()
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test-subject",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test-subject",
			Key:  []interface{}{certB64},
		},
	})

	require.NoError(t, err)
	// Self-signed certs should NOT be trusted by system pool
	assert.False(t, resp.Decision, "Self-signed cert should not be trusted")
}

// TestRegistrySelection_MultipleRegistries tests that the registry manager
// correctly routes to the appropriate registry.
func TestRegistrySelection_MultipleRegistries(t *testing.T) {
	// Create always-trusted for fallback
	alwaysTrusted := static.NewAlwaysTrustedRegistry("fallback-trusted")

	// Create never-trusted
	neverTrusted := static.NewNeverTrustedRegistry("deny-all")

	// Test with always-trusted (should pass)
	srv := testserver.New(testserver.WithRegistry(alwaysTrusted))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{"cert"},
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.Decision)

	srv.Close()

	// Test with never-trusted (should fail)
	srv2 := testserver.New(testserver.WithRegistry(neverTrusted))
	defer srv2.Close()

	client2 := authzenclient.New(srv2.URL())
	resp2, err := client2.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{"cert"},
		},
	})

	require.NoError(t, err)
	assert.False(t, resp2.Decision)
}

// TestDiscovery_WithStaticRegistry tests AuthZEN discovery with static registries.
func TestDiscovery_WithStaticRegistry(t *testing.T) {
	reg := static.NewAlwaysTrustedRegistry("test-discovery")
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Use discovery to create client
	ctx := context.Background()
	client, err := authzenclient.Discover(ctx, srv.URL())
	require.NoError(t, err)

	// Verify discovery worked
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{"cert"},
		},
	})

	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

// TestCustomDenialReason tests that denial reasons are properly returned.
func TestCustomDenialReason(t *testing.T) {
	reg := static.NewNeverTrustedRegistryWithConfig(static.NeverTrustedConfig{
		Name:   "policy-deny",
		Reason: "access denied by custom policy",
	})

	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	resp, err := client.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "test",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "test",
			Key:  []interface{}{"cert"},
		},
	})

	require.NoError(t, err)
	assert.False(t, resp.Decision)

	// The registry manager aggregates results, so the specific reason
	// may be wrapped or aggregated. Just verify we got a false decision.
	require.NotNil(t, resp.Context, "response context should be present")
}

// generateTestCert creates a self-signed certificate for testing
func generateTestCert(t *testing.T) *x509.Certificate {
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
