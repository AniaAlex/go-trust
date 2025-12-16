package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/etsi119612"
	"github.com/sirosfoundation/go-trust/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/pipeline"
	"github.com/sirosfoundation/go-trust/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestContext creates a ServerContext with the specified number of TSLs and last processed time
func createTestContext(tslCount int, lastProcessed time.Time) *ServerContext {
	pCtx := pipeline.NewContext()
	pCtx.TSLs = utils.NewStack[*etsi119612.TSL]()

	// Add dummy TSLs
	for i := 0; i < tslCount; i++ {
		pCtx.TSLs.Push(&etsi119612.TSL{})
	}

	return &ServerContext{
		PipelineContext: pCtx,
		LastProcessed:   lastProcessed,
		Logger:          logging.DefaultLogger(),
	}
}

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(5, time.Now().Add(-5*time.Minute))

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

	ctx := createTestContext(0, time.Time{})

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

	now := time.Now()
	ctx := createTestContext(3, now)

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Ready endpoint should return 200 OK when TSLs are loaded")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Ready response should be valid JSON")

	assert.Equal(t, "ready", response.Status)
	assert.True(t, response.Ready, "Service should be ready")
	assert.Equal(t, 3, response.TSLCount)
	assert.Equal(t, now.Format(time.RFC3339), response.LastProcessed)
	assert.NotEmpty(t, response.Message, "Should have message when ready")
	assert.Contains(t, response.Message, "ready to accept traffic", "Message should be positive")
}

func TestReadyEndpoint_NotReady_NoTSLs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(0, time.Time{})

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Ready endpoint should return 503 when no TSLs loaded")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Ready response should be valid JSON")

	assert.Equal(t, "not_ready", response.Status)
	assert.False(t, response.Ready, "Service should not be ready")
	assert.Equal(t, 0, response.TSLCount)
	assert.NotEmpty(t, response.Message, "Should have message explaining why not ready")
	assert.Contains(t, response.Message, "Pipeline has not been processed yet", "Message should mention pipeline not processed")
}

func TestReadyEndpoint_NotReady_NotProcessed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(5, time.Time{}) // Zero time = never processed

	r := gin.New()
	RegisterHealthEndpoints(r, ctx)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "Ready endpoint should return 503 when pipeline not processed")

	var response ReadinessResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err, "Ready response should be valid JSON")

	assert.Equal(t, "not_ready", response.Status)
	assert.False(t, response.Ready, "Service should not be ready")
	assert.Equal(t, 5, response.TSLCount)
	assert.NotEmpty(t, response.Message, "Should have message explaining why not ready")
	assert.Contains(t, response.Message, "Pipeline has not been processed yet", "Message should mention pipeline not processed")
}

func TestReadinessEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(10, time.Now())

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
	assert.Equal(t, 10, response.TSLCount)
}

func TestRegisterHealthEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx := createTestContext(1, time.Now())

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

	ctx := createTestContext(5, time.Now())

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

	ctx := createTestContext(5, time.Now())

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

	now := time.Now()
	ctx := createTestContext(3, now)

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
	assert.Equal(t, 3, response.TSLCount)
	assert.NotNil(t, response.TSLs, "TSLs field should be populated in verbose mode")
	assert.Len(t, response.TSLs, 3, "Should include 3 TSL summaries in verbose mode")
}

func TestReadyzEndpoint_NonVerbose(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now()
	ctx := createTestContext(3, now)

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
	assert.Nil(t, response.TSLs, "TSLs field should be nil/omitted in non-verbose mode")
}

func TestReadinessResponse_JSONFormat(t *testing.T) {
	ts, err := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	require.NoError(t, err)

	response := ReadinessResponse{
		Status:        "ready",
		Timestamp:     ts,
		TSLCount:      5,
		LastProcessed: "2024-01-15T10:25:00Z",
		Ready:         true,
		Message:       "",
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	assert.Contains(t, string(data), `"status":"ready"`)
	assert.Contains(t, string(data), `"tsl_count":5`)
	assert.Contains(t, string(data), `"ready":true`)
}
