package pipeline_test

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/go-trust/pkg/api"
	"github.com/SUNET/go-trust/pkg/authzen"
	"github.com/SUNET/go-trust/pkg/logging"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestX5CVerificationEndToEnd tests the complete x5c certificate verification process
// using the comprehensive test infrastructure and real HTTP requests
func TestX5CVerificationEndToEnd(t *testing.T) {
	// Setup test server with comprehensive test infrastructure
	server, cleanup := setupTestServer(t)
	defer cleanup()

	// Test cases with different certificate scenarios
	testCases := []struct {
		name           string
		certPath       string
		expectedResult bool
		description    string
	}{
		{
			name:           "Valid_Swedbank_Certificate",
			certPath:       "country-se/providers/swedbank-ca/swedbank-root-ca.pem",
			expectedResult: true,
			description:    "Valid certificate from Swedish trust infrastructure",
		},
		{
			name:           "Valid_Deutsche_Telekom_Certificate",
			certPath:       "country-de/providers/deutsche-telekom/telekom-root-ca.pem",
			expectedResult: true,
			description:    "Valid certificate from German trust infrastructure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Load certificate from test infrastructure
			cert := loadTestCertificate(t, tc.certPath)

			// Create simple AuthZEN request
			request := createSimpleAuthZENRequest(cert)

			// Make HTTP request to verification endpoint
			response := makeVerificationRequest(t, server, request)

			// Verify response
			verifyAuthZENResponse(t, response, tc.expectedResult, tc.description)
		})
	}

	// Test invalid certificate scenarios
	t.Run("Invalid_Certificate_Scenarios", func(t *testing.T) {
		t.Run("Malformed_X5C", func(t *testing.T) {
			request := authzen.EvaluationRequest{
				Subject: authzen.Entity{
					Type: "x509",
					ID:   "malformed-cert",
					Properties: map[string]interface{}{
						"x5c": []string{"invalid-base64-data!!!"},
					},
				},
				Action: struct {
					Name       string                 `json:"name"`
					Properties map[string]interface{} `json:"properties,omitempty"`
				}{
					Name: "verify",
				},
			}

			response := makeVerificationRequest(t, server, request)
			verifyAuthZENResponse(t, response, false, "Malformed x5c should be rejected")
		})

		t.Run("Empty_X5C", func(t *testing.T) {
			request := authzen.EvaluationRequest{
				Subject: authzen.Entity{
					Type: "x509",
					ID:   "empty-cert",
					Properties: map[string]interface{}{
						"x5c": []string{},
					},
				},
				Action: authzen.Entity{
					Name: "verify",
				},
			}

			response := makeVerificationRequest(t, server, request)
			verifyAuthZENResponse(t, response, false, "Empty x5c should be rejected")
		})

		t.Run("Missing_X5C", func(t *testing.T) {
			request := authzen.EvaluationRequest{
				Subject: authzen.Entity{
					Type: "x509",
					ID:   "no-cert",
				},
				Action: authzen.Entity{
					Name: "verify",
				},
			}

			response := makeVerificationRequest(t, server, request)
			verifyAuthZENResponse(t, response, false, "Missing x5c should be rejected")
		})
	})

	// Test certificate chain validation
	t.Run("Certificate_Chain_Validation", func(t *testing.T) {
		// Load certificate and create chain with self-reference for testing
		cert := loadTestCertificate(t, "country-se/providers/swedbank-ca/swedbank-root-ca.pem")
		x5cCert := base64.StdEncoding.EncodeToString(cert.Raw)

		request := authzen.EvaluationRequest{
			Subject: authzen.Entity{
				Type: "x509",
				ID:   "chain-test",
				Properties: map[string]interface{}{
					"x5c": []string{x5cCert, x5cCert}, // Chain with duplicate for testing
				},
			},
			Action: authzen.Entity{
				Name: "verify",
			},
		}

		response := makeVerificationRequest(t, server, request)

		// Should still process successfully (validates first certificate in chain)
		assert.True(t, response.Decision, "Certificate chain should be processed successfully")
		t.Logf("Certificate chain validation completed: decision=%v", response.Decision)
	})
}

// setupTestServer creates a test server with the comprehensive test infrastructure
func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	// Get project root and setup test infrastructure
	projectRoot := getProjectRoot(t)
	sourceDir := filepath.Join(projectRoot, "comprehensive-test", "test-trust-infrastructure")

	// Check if test infrastructure exists
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		t.Skipf("Comprehensive test infrastructure not found at %s", sourceDir)
	}

	// Create temporary directory for test
	testDir := t.TempDir()
	targetDir := filepath.Join(testDir, "test-trust-infrastructure")
	copyTestInfrastructure(t, sourceDir, targetDir)

	// Create pipeline and process TSLs
	logger := logging.NewLogger(logging.InfoLevel)
	mockPipeline := &Pipeline{Logger: logger}
	ctx := &Context{}

	// Generate TSLs from test infrastructure
	var err error
	ctx, err = GenerateTSL(mockPipeline, ctx, filepath.Join(targetDir, "lotl"))
	require.NoError(t, err, "Failed to generate LOTL")

	ctx, err = GenerateTSL(mockPipeline, ctx, filepath.Join(targetDir, "country-se"))
	require.NoError(t, err, "Failed to generate Swedish TSL")

	ctx, err = GenerateTSL(mockPipeline, ctx, filepath.Join(targetDir, "country-de"))
	require.NoError(t, err, "Failed to generate German TSL")

	// Create certificate pool
	ctx, err = SelectCertPool(mockPipeline, ctx)
	require.NoError(t, err, "Failed to create certificate pool")
	require.NotNil(t, ctx.CertPool, "Certificate pool should be created")

	// Setup API server
	serverCtx := api.NewServerContext(logger)
	serverCtx.PipelineContext = ctx

	gin.SetMode(gin.TestMode)
	router := gin.New()
	api.RegisterAPIRoutes(router, serverCtx)

	server := httptest.NewServer(router)

	cleanup := func() {
		server.Close()
	}

	t.Logf("Test server setup complete with %d TSLs and certificate pool", len(ctx.TSLs.ToSlice()))
	return server, cleanup
}

// loadTestCertificate loads a certificate from the test infrastructure
func loadTestCertificate(t *testing.T, relativePath string) *x509.Certificate {
	projectRoot := getProjectRoot(t)
	certPath := filepath.Join(projectRoot, "comprehensive-test", "test-trust-infrastructure", relativePath)

	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err, "Failed to read certificate file: %s", certPath)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "Failed to decode PEM certificate")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse certificate")

	return cert
}

// createSimpleAuthZENRequest creates a simple AuthZEN evaluation request with x5c certificate
func createSimpleAuthZENRequest(cert *x509.Certificate) authzen.EvaluationRequest {
	// Convert certificate to x5c format (base64 DER)
	x5cCert := base64.StdEncoding.EncodeToString(cert.Raw)

	return authzen.EvaluationRequest{
		Subject: authzen.Entity{
			Type: "x509",
			ID:   fmt.Sprintf("cert-%s", cert.SerialNumber.String()),
			Properties: map[string]interface{}{
				"x5c": []string{x5cCert},
			},
		},
		Action: authzen.Entity{
			Name: "verify",
		},
		Resource: authzen.Entity{
			Type: "tsl",
			ID:   "comprehensive-test-tsl",
		},
		Context: map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"test_case": "x5c_verification",
		},
	}
}

// makeVerificationRequest makes an HTTP request to the AuthZEN decision endpoint
func makeVerificationRequest(t *testing.T, server *httptest.Server, request authzen.EvaluationRequest) authzen.EvaluationResponse {
	// Marshal request to JSON
	requestBody, err := json.Marshal(request)
	require.NoError(t, err, "Failed to marshal AuthZEN request")

	// Make HTTP POST request
	resp, err := http.Post(
		fmt.Sprintf("%s/authzen/decision", server.URL),
		"application/json",
		bytes.NewBuffer(requestBody),
	)
	require.NoError(t, err, "Failed to make HTTP request")
	defer resp.Body.Close()

	// Parse response
	var response authzen.EvaluationResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err, "Failed to decode AuthZEN response")

	t.Logf("AuthZEN request for %s: decision=%v", request.Subject.ID, response.Decision)

	return response
}

// verifyAuthZENResponse verifies the AuthZEN evaluation response
func verifyAuthZENResponse(t *testing.T, response authzen.EvaluationResponse, expectedDecision bool, description string) {
	assert.Equal(t, expectedDecision, response.Decision,
		"AuthZEN decision mismatch for %s", description)

	if !expectedDecision {
		// For denial decisions, should have context with reason
		assert.NotNil(t, response.Context, "Denial response should have context")
		if response.Context != nil {
			assert.NotEmpty(t, response.Context.ReasonAdmin, "Should have admin reason for denial")
		}
	}

	t.Logf("✅ %s: decision=%v (expected=%v)", description, response.Decision, expectedDecision)
}

// Helper functions (reused from comprehensive_integration_test.go)

// getProjectRoot finds the project root directory by looking for go.mod
func getProjectRoot(t *testing.T) string {
	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root")
		}
		dir = parent
	}
}

// copyTestInfrastructure copies the test infrastructure directory recursively
func copyTestInfrastructure(t *testing.T, src, dst string) {
	require.NoError(t, os.MkdirAll(dst, 0755))

	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		_, err = dstFile.ReadFrom(srcFile)
		return err
	})
	require.NoError(t, err)
}
