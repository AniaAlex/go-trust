package trustapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestKeyType_Constants(t *testing.T) {
	// Verify constants match AuthZEN resource types
	if KeyTypeJWK != "jwk" {
		t.Errorf("KeyTypeJWK should be 'jwk', got '%s'", KeyTypeJWK)
	}
	if KeyTypeX5C != "x5c" {
		t.Errorf("KeyTypeX5C should be 'x5c', got '%s'", KeyTypeX5C)
	}
}

func TestRole_Constants(t *testing.T) {
	// Verify role constants
	if RoleIssuer != "issuer" {
		t.Errorf("RoleIssuer should be 'issuer', got '%s'", RoleIssuer)
	}
	if RoleVerifier != "verifier" {
		t.Errorf("RoleVerifier should be 'verifier', got '%s'", RoleVerifier)
	}
	if RoleCredentialIssuer != "credential-issuer" {
		t.Errorf("RoleCredentialIssuer should be 'credential-issuer', got '%s'", RoleCredentialIssuer)
	}
	if RoleAny != "" {
		t.Errorf("RoleAny should be empty string, got '%s'", RoleAny)
	}
}

func TestX5CCertChain(t *testing.T) {
	// Create a simple certificate chain for testing
	cert := createTestCert(t, "CN=Test")
	chain := X5CCertChain{cert}

	t.Run("GetLeafCert", func(t *testing.T) {
		leaf := chain.GetLeafCert()
		if leaf == nil {
			t.Error("expected leaf cert, got nil")
		}
		if leaf.Subject.CommonName != "CN=Test" {
			t.Errorf("expected CN='CN=Test', got CN=%s", leaf.Subject.CommonName)
		}
	})

	t.Run("GetRootCert", func(t *testing.T) {
		root := chain.GetRootCert()
		if root == nil {
			t.Error("expected root cert, got nil")
		}
		// For single-cert chain, leaf == root
		if root != chain.GetLeafCert() {
			t.Error("for single cert chain, root should equal leaf")
		}
	})

	t.Run("GetSubjectID", func(t *testing.T) {
		subjectID := chain.GetSubjectID()
		if subjectID != "CN=Test" {
			t.Errorf("expected SubjectID 'CN=Test', got '%s'", subjectID)
		}
	})

	t.Run("ToBase64Strings", func(t *testing.T) {
		strs := chain.ToBase64Strings()
		if len(strs) != 1 {
			t.Errorf("expected 1 string, got %d", len(strs))
		}
		if strs[0] == "" {
			t.Error("expected non-empty base64 string")
		}
	})

	t.Run("EmptyChain", func(t *testing.T) {
		empty := X5CCertChain{}
		if empty.GetLeafCert() != nil {
			t.Error("expected nil leaf for empty chain")
		}
		if empty.GetRootCert() != nil {
			t.Error("expected nil root for empty chain")
		}
		if empty.GetSubjectID() != "" {
			t.Error("expected empty subject ID for empty chain")
		}
	})
}

func TestTrustOptions(t *testing.T) {
	opts := &TrustOptions{
		IncludeTrustChain:   true,
		IncludeCertificates: true,
		BypassCache:         true,
	}

	if !opts.IncludeTrustChain {
		t.Error("IncludeTrustChain should be true")
	}
	if !opts.IncludeCertificates {
		t.Error("IncludeCertificates should be true")
	}
	if !opts.BypassCache {
		t.Error("BypassCache should be true")
	}
}

func TestEvaluationRequest(t *testing.T) {
	cert := createTestCert(t, "CN=Issuer")

	req := &EvaluationRequest{
		SubjectID:      "https://issuer.example.com",
		KeyType:        KeyTypeX5C,
		Key:            []*x509.Certificate{cert},
		Role:           RoleCredentialIssuer,
		CredentialType: "PID",
		Options: &TrustOptions{
			BypassCache: true,
		},
	}

	if req.SubjectID != "https://issuer.example.com" {
		t.Error("SubjectID mismatch")
	}
	if req.KeyType != KeyTypeX5C {
		t.Error("KeyType mismatch")
	}
	if req.Role != RoleCredentialIssuer {
		t.Error("Role mismatch")
	}
	if req.CredentialType != "PID" {
		t.Error("CredentialType mismatch")
	}
	if req.Options == nil || !req.Options.BypassCache {
		t.Error("Options.BypassCache should be true")
	}
}

func TestTrustDecision(t *testing.T) {
	decision := &TrustDecision{
		Trusted:        true,
		Reason:         "verified against trust anchor",
		TrustFramework: "eudi",
		Metadata:       map[string]any{"source": "tsl"},
	}

	if !decision.Trusted {
		t.Error("expected Trusted=true")
	}
	if decision.TrustFramework != "eudi" {
		t.Error("TrustFramework mismatch")
	}
}

// createTestCert creates a self-signed certificate for testing
func createTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}
