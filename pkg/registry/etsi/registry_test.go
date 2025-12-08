package etsi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/go-trust/pkg/authzen"
)

// generateTestCertificate creates a self-signed test certificate
func generateTestCertificate(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Parse the DER certificate back
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Encode to PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return cert, pemBytes
}

// writeTestCertFile writes a PEM certificate to a temp file
func writeTestCertFile(t *testing.T, dir string, filename string, pemData []byte) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	return path
}

func TestNewTSLRegistry_WithCertBundle(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate and write to file
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	// Create registry
	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "test-registry",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Verify it's healthy
	if !reg.Healthy() {
		t.Error("registry should be healthy")
	}

	// Verify certificate count
	if reg.CertificateCount() != 1 {
		t.Errorf("expected 1 certificate, got %d", reg.CertificateCount())
	}

	// Verify info
	info := reg.Info()
	if info.Name != "test-registry" {
		t.Errorf("expected name 'test-registry', got %q", info.Name)
	}
	if info.Type != "etsi_tsl" {
		t.Errorf("expected type 'etsi_tsl', got %q", info.Type)
	}
}

func TestNewTSLRegistry_NoCertBundle(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name: "empty-registry",
	})
	if err == nil {
		t.Error("expected error when no trust data configured")
	}
}

func TestNewTSLRegistry_MissingFile(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name:       "missing-file",
		CertBundle: "/nonexistent/path/certs.pem",
	})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestNewTSLRegistry_EmptyPEM(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write empty PEM file
	emptyPath := filepath.Join(tmpDir, "empty.pem")
	if err := os.WriteFile(emptyPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	_, err = NewTSLRegistry(TSLConfig{
		Name:       "empty-pem",
		CertBundle: emptyPath,
	})
	if err == nil {
		t.Error("expected error for empty PEM file")
	}
}

func TestNewTSLRegistry_RejectsNetworkURLsInTSLFiles(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"http URL", "http://example.com/tsl.xml"},
		{"https URL", "https://example.com/tsl.xml"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTSLRegistry(TSLConfig{
				Name:     "network-url-test",
				TSLFiles: []string{tc.url},
			})
			if err == nil {
				t.Error("expected error for network URL in TSLFiles")
			}
		})
	}
}

func TestNewTSLRegistry_RejectsNetworkURLsWhenDisabled(t *testing.T) {
	_, err := NewTSLRegistry(TSLConfig{
		Name:               "network-disabled",
		TSLURLs:            []string{"https://example.com/tsl.xml"},
		AllowNetworkAccess: false, // default
	})
	if err == nil {
		t.Error("expected error for network URL when AllowNetworkAccess=false")
	}
}

func TestTSLRegistry_Info(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:        "info-test",
		Description: "Test description",
		CertBundle:  certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	info := reg.Info()

	if info.Name != "info-test" {
		t.Errorf("expected name 'info-test', got %q", info.Name)
	}
	if info.Description != "Test description" {
		t.Errorf("expected description 'Test description', got %q", info.Description)
	}
	if info.Type != "etsi_tsl" {
		t.Errorf("expected type 'etsi_tsl', got %q", info.Type)
	}
	if info.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %q", info.Version)
	}
}

func TestTSLRegistry_SupportedResourceTypes(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "types-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	types := reg.SupportedResourceTypes()
	if len(types) != 2 {
		t.Errorf("expected 2 supported types, got %d", len(types))
	}

	foundX5C := false
	foundJWK := false
	for _, typ := range types {
		if typ == "x5c" {
			foundX5C = true
		}
		if typ == "jwk" {
			foundJWK = true
		}
	}
	if !foundX5C {
		t.Error("expected x5c in supported types")
	}
	if !foundJWK {
		t.Error("expected jwk in supported types")
	}
}

func TestTSLRegistry_SupportsResolutionOnly(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "resolution-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	if reg.SupportsResolutionOnly() {
		t.Error("ETSI TSL registry should not support resolution-only requests")
	}
}

func TestTSLRegistry_EvaluateResolutionOnlyRequest(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "evaluate-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Create a resolution-only request (empty resource.key)
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "x5c",
			Key:  nil, // Empty key = resolution-only
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for resolution-only request")
	}
}

func TestTSLRegistry_EvaluateUnsupportedResourceType(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "unsupported-type-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	// Create request with unsupported resource type
	req := &authzen.EvaluationRequest{
		Resource: authzen.Resource{
			Type: "unsupported",
			Key:  []interface{}{"some-data"},
		},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision {
		t.Error("expected false decision for unsupported resource type")
	}
}

func TestTSLRegistry_Refresh(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "refresh-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	originalLoadedAt := reg.LoadedAt()

	// Wait a bit to ensure timestamp difference
	time.Sleep(10 * time.Millisecond)

	// Refresh
	if err := reg.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	// Verify loadedAt changed
	if !reg.LoadedAt().After(originalLoadedAt) {
		t.Error("expected LoadedAt to be updated after refresh")
	}
}

func TestTSLRegistry_MultipleCertBundles(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate two test certificates
	_, pemData1 := generateTestCertificate(t, "Test CA 1")
	_, pemData2 := generateTestCertificate(t, "Test CA 2")

	// Combine into one PEM file
	combinedPEM := append(pemData1, pemData2...)
	certPath := writeTestCertFile(t, tmpDir, "combined.pem", combinedPEM)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "multi-cert-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	if reg.CertificateCount() != 2 {
		t.Errorf("expected 2 certificates, got %d", reg.CertificateCount())
	}
}

func TestTSLRegistry_CertPool(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tsl-registry-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	_, pemData := generateTestCertificate(t, "Test CA")
	certPath := writeTestCertFile(t, tmpDir, "test-ca.pem", pemData)

	reg, err := NewTSLRegistry(TSLConfig{
		Name:       "certpool-test",
		CertBundle: certPath,
	})
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	pool := reg.CertPool()
	if pool == nil {
		t.Error("CertPool should not be nil")
	}
}
