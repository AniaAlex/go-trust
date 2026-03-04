package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRegistry is a mock TrustRegistry for testing
type mockRegistry struct {
	name          string
	healthy       bool
	resourceTypes []string
}

func (m *mockRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{Decision: true}, nil
}

func (m *mockRegistry) Refresh(ctx context.Context) error {
	return nil
}

func (m *mockRegistry) SupportedResourceTypes() []string {
	return m.resourceTypes
}

func (m *mockRegistry) SupportsResolutionOnly() bool {
	return false
}

func (m *mockRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{Name: m.name}
}

func (m *mockRegistry) Healthy() bool {
	return m.healthy
}

// createTestContext creates a ServerContext with the specified number of registries
func createTestContext(registryCount int, healthy bool) *ServerContext {
	logger := logging.DefaultLogger()
	mgr := registry.NewRegistryManager(registry.FirstMatch, 10*time.Second)

	// Add mock registries
	for i := 0; i < registryCount; i++ {
		mgr.Register(&mockRegistry{
			name:          "mock-registry",
			healthy:       healthy,
			resourceTypes: []string{"x5c", "jwk"},
		})
	}

	return &ServerContext{
		RegistryManager: mgr,
		Logger:          logger,
	}
}

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(5, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Health endpoint should return 200 OK")

	var response HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Health response should be valid JSON")
	assert.Equal(t, "ok", response.Status)
	assert.NotZero(t, response.Timestamp, "Timestamp should be present")
}

func TestHealthzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(0, false)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Healthz endpoint should return 200 OK")

	var response HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Healthz response should be valid JSON")
	assert.Equal(t, "ok", response.Status)
}

func TestReadyEndpoint_Ready(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(3, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Ready endpoint should return 200 OK when registries are healthy")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Ready response should be valid JSON")

	assert.Equal(t, "ready", response.Status)
	assert.True(t, response.Ready, "Service should be ready")
	assert.Equal(t, 3, response.RegistryCount)
	assert.Equal(t, 3, response.HealthyCount)
	assert.NotEmpty(t, response.Message, "Should have message when ready")
	assert.Contains(t, response.Message, "ready to accept traffic", "Message should be positive")
}

func TestReadyEndpoint_NotReady_NoTSLs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(0, false)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Ready endpoint should return 503 when no registries configured")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Ready response should be valid JSON")

	assert.Equal(t, "not_ready", response.Status)
	assert.False(t, response.Ready, "Service should not be ready")
	assert.Equal(t, 0, response.RegistryCount)
	assert.NotEmpty(t, response.Message, "Should have message explaining why not ready")
	assert.Contains(t, response.Message, "No registries configured", "Message should mention no registries")
}

func TestReadyEndpoint_NotReady_UnhealthyRegistries(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(5, false) // 5 unhealthy registries

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Ready endpoint should return 503 when registries are unhealthy")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Ready response should be valid JSON")

	assert.Equal(t, "not_ready", response.Status)
	assert.False(t, response.Ready, "Service should not be ready")
	assert.Equal(t, 5, response.RegistryCount)
	assert.Equal(t, 0, response.HealthyCount)
	assert.NotEmpty(t, response.Message, "Should have message explaining why not ready")
	assert.Contains(t, response.Message, "No healthy registries", "Message should mention unhealthy registries")
}

func TestReadinessEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(10, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Readiness endpoint should return 200 OK when ready")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Readiness response should be valid JSON")

	assert.Equal(t, "ready", response.Status)
	assert.True(t, response.Ready)
	assert.Equal(t, 10, response.RegistryCount)
}

func TestRegisterHealthEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(1, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	// Test only current endpoints are registered
	endpoints := []string{"/healthz", "/readyz"}
	for _, endpoint := range endpoints {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusNotFound, w.Code,
			"Endpoint %s should be registered", endpoint)
	}

	// Verify deprecated endpoints are NOT registered
	deprecatedEndpoints := []string{"/health", "/ready", "/readiness"}
	for _, endpoint := range deprecatedEndpoints {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"Deprecated endpoint %s should NOT be registered", endpoint)
	}
}

func TestHealthEndpoint_Concurrent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(5, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	// Make 100 concurrent requests to test thread safety
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestReadyEndpoint_Concurrent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(5, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	// Make 100 concurrent requests to test thread safety
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < 100; i++ {
		<-done
	}
}

func TestHealthResponse_JSONFormat(t *testing.T) {
	ts, err := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	require.NoError(t, err)

	response := HealthResponse{
		Status:    "ok",
		Timestamp: ts,
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	expected := `{"status":"ok","timestamp":"2024-01-15T10:30:00Z"}`
	assert.JSONEq(t, expected, string(data))
}

func TestReadyzEndpoint_Verbose(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(3, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz?verbose=true", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Readyz endpoint should return 200 OK when ready")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Readyz verbose response should be valid JSON")

	assert.Equal(t, "ready", response.Status)
	assert.True(t, response.Ready)
	assert.Equal(t, 3, response.RegistryCount)
	assert.NotNil(t, response.Registries, "Registries field should be populated in verbose mode")
	assert.Len(t, response.Registries, 3, "Should include 3 registry infos in verbose mode")
}

func TestReadyzEndpoint_NonVerbose(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(3, true)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "ready", response.Status)
	assert.True(t, response.Ready)
	assert.Nil(t, response.Registries, "Registries field should be nil/omitted in non-verbose mode")
}

func TestReadinessResponse_JSONFormat(t *testing.T) {
	ts, err := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	require.NoError(t, err)

	response := ReadinessResponse{
		Status:        "ready",
		Timestamp:     ts,
		RegistryCount: 5,
		HealthyCount:  5,
		Ready:         true,
		Message:       "",
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	assert.Contains(t, string(data), `"status":"ready"`)
	assert.Contains(t, string(data), `"registry_count":5`)
	assert.Contains(t, string(data), `"healthy_count":5`)
	assert.Contains(t, string(data), `"ready":true`)
}
