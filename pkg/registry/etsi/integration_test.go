package etsi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

// generateTestCertChain creates a CA and leaf certificate pair for testing
func generateTestCertChain(t *testing.T) (caCert *x509.Certificate, caPEM []byte, leafCert *x509.Certificate, leafB64 string) {
	t.Helper()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CA certificate
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA Root",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err = x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate CA PEM
	caPEM = append([]byte("-----BEGIN CERTIFICATE-----\n"),
		[]byte(base64.StdEncoding.EncodeToString(caCertDER))...)
	caPEM = append(caPEM, []byte("\n-----END CERTIFICATE-----\n")...)

	// Generate leaf key
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create leaf certificate signed by CA
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
			CommonName:   "Test Leaf Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err = x509.ParseCertificate(leafCertDER)
	require.NoError(t, err)

	leafB64 = base64.StdEncoding.EncodeToString(leafCertDER)

	return caCert, caPEM, leafCert, leafB64
}

// TestETSIRegistry_WithTestServer tests the ETSI TSL registry
// integration with the testserver and HTTP API.
func TestETSIRegistry_WithTestServer(t *testing.T) {
	// Generate test certificate chain
	_, caPEM, _, leafB64 := generateTestCertChain(t)

	// Write CA certificate to temp file
	tmpDir := t.TempDir()
	caBundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(caBundlePath, caPEM, 0644))

	// Create ETSI registry with the CA bundle
	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
		Name:        "test-etsi",
		Description: "Test ETSI TSL Registry",
		CertBundle:  caBundlePath,
	})
	require.NoError(t, err)

	// Create test server with ETSI registry
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	// Create client
	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: certificate signed by trusted CA should be accepted
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://issuer.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://issuer.example.com",
			Key:  []interface{}{leafB64},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "certificate signed by trusted CA should be trusted")
}

// TestETSIRegistry_UntrustedCertificate tests that certificates not signed
// by a trusted CA are rejected.
func TestETSIRegistry_UntrustedCertificate(t *testing.T) {
	// Generate test certificate chain (CA1)
	_, caPEM, _, _ := generateTestCertChain(t)

	// Generate a different certificate chain (CA2) - leaf not signed by CA1
	_, _, _, untrustedLeafB64 := generateTestCertChain(t)

	// Write CA1 certificate to temp file
	tmpDir := t.TempDir()
	caBundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(caBundlePath, caPEM, 0644))

	// Create ETSI registry with CA1
	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
		Name:        "test-etsi",
		Description: "Test ETSI TSL Registry",
		CertBundle:  caBundlePath,
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: certificate NOT signed by trusted CA should be rejected
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://untrusted-issuer.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://untrusted-issuer.example.com",
			Key:  []interface{}{untrustedLeafB64},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "certificate not signed by trusted CA should not be trusted")
}

// TestETSIRegistry_ExpiredCertificate tests that expired certificates are rejected.
func TestETSIRegistry_ExpiredCertificate(t *testing.T) {
	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CA certificate (valid)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA Root",
		},
		NotBefore:             time.Now().Add(-7 * 24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	caPEM := append([]byte("-----BEGIN CERTIFICATE-----\n"),
		[]byte(base64.StdEncoding.EncodeToString(caCertDER))...)
	caPEM = append(caPEM, []byte("\n-----END CERTIFICATE-----\n")...)

	// Generate leaf key
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create EXPIRED leaf certificate
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
			CommonName:   "Expired Leaf Certificate",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // EXPIRED
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	expiredLeafB64 := base64.StdEncoding.EncodeToString(leafCertDER)

	// Write CA certificate to temp file
	tmpDir := t.TempDir()
	caBundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(caBundlePath, caPEM, 0644))

	// Create ETSI registry
	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
		Name:        "test-etsi",
		Description: "Test ETSI TSL Registry",
		CertBundle:  caBundlePath,
	})
	require.NoError(t, err)

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: expired certificate should be rejected
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://expired-issuer.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://expired-issuer.example.com",
			Key:  []interface{}{expiredLeafB64},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision, "expired certificate should not be trusted")
}

// TestETSIRegistry_CertificateChain tests validation with a full certificate chain.
func TestETSIRegistry_CertificateChain(t *testing.T) {
	// Generate root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Root CA"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err := x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	rootB64 := base64.StdEncoding.EncodeToString(rootCertDER)

	// Generate intermediate CA
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Intermediate CA"},
			CommonName:   "Test Intermediate CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	intermediateCertDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	require.NoError(t, err)

	intermediateCert, err := x509.ParseCertificate(intermediateCertDER)
	require.NoError(t, err)

	intermediateB64 := base64.StdEncoding.EncodeToString(intermediateCertDER)

	// Generate leaf certificate
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"End Entity"},
			CommonName:   "Test Leaf Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)

	leafB64 := base64.StdEncoding.EncodeToString(leafCertDER)

	// Write BOTH root AND intermediate CA certificates to temp file
	// (The ETSI registry needs all trusted CAs in the bundle for chain validation)
	rootPEM := append([]byte("-----BEGIN CERTIFICATE-----\n"),
		[]byte(base64.StdEncoding.EncodeToString(rootCertDER))...)
	rootPEM = append(rootPEM, []byte("\n-----END CERTIFICATE-----\n")...)

	intermediatePEM := append([]byte("-----BEGIN CERTIFICATE-----\n"),
		[]byte(base64.StdEncoding.EncodeToString(intermediateCertDER))...)
	intermediatePEM = append(intermediatePEM, []byte("\n-----END CERTIFICATE-----\n")...)

	caBundlePEM := append(rootPEM, intermediatePEM...)

	tmpDir := t.TempDir()
	caBundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(caBundlePath, caBundlePEM, 0644))

	// Create ETSI registry with both root and intermediate CA
	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
		Name:        "test-etsi-chain",
		Description: "Test ETSI TSL Registry with Chain",
		CertBundle:  caBundlePath,
	})
	require.NoError(t, err)

	// Verify both certs were loaded
	assert.Equal(t, 2, reg.CertificateCount(), "should have loaded 2 CA certificates")

	// Create test server
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	client := authzenclient.New(srv.URL())
	ctx := context.Background()

	// Test: certificate chain should be accepted
	// Note: x5c order is leaf, intermediate(s), root
	resp, err := client.Evaluate(ctx, &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "https://chain-issuer.example.com",
		},
		Resource: authzen.Resource{
			Type: "x5c",
			ID:   "https://chain-issuer.example.com",
			Key:  []interface{}{leafB64, intermediateB64, rootB64},
		},
		Action: &authzen.Action{
			Name: "issuer",
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision, "certificate signed by trusted intermediate CA should be trusted")
}

// TestETSIRegistry_Info tests that registry info is accessible via the API.
func TestETSIRegistry_Info(t *testing.T) {
	// Generate test certificate chain
	_, caPEM, _, _ := generateTestCertChain(t)

	// Write CA certificate to temp file
	tmpDir := t.TempDir()
	caBundlePath := filepath.Join(tmpDir, "ca-bundle.pem")
	require.NoError(t, os.WriteFile(caBundlePath, caPEM, 0644))

	// Create ETSI registry
	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
		Name:        "test-etsi-info",
		Description: "Test ETSI TSL Registry Info",
		CertBundle:  caBundlePath,
	})
	require.NoError(t, err)

	// Verify registry info
	info := reg.Info()
	assert.Equal(t, "test-etsi-info", info.Name)
	assert.Equal(t, "etsi_tsl", info.Type)
	assert.Equal(t, "Test ETSI TSL Registry Info", info.Description)
	assert.True(t, reg.Healthy())
	assert.Equal(t, 1, reg.CertificateCount())
}
