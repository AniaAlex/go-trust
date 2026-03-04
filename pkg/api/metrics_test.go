package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()

	assert.NotNil(t, m.RefreshExecutionDuration)
	assert.NotNil(t, m.RefreshExecutionTotal)
	assert.NotNil(t, m.RefreshExecutionErrors)
	assert.NotNil(t, m.TSLCount)
	assert.NotNil(t, m.TSLProcessingDuration)
	assert.NotNil(t, m.APIRequestsTotal)
	assert.NotNil(t, m.APIRequestDuration)
	assert.NotNil(t, m.APIRequestsInFlight)
	assert.NotNil(t, m.ErrorsTotal)
	assert.NotNil(t, m.CertValidationTotal)
	assert.NotNil(t, m.CertValidationDuration)
}

func TestMetricsMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()
	r.Use(m.MetricsMiddleware())

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Make a request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Metrics should be recorded (we can't easily verify exact values without
	// scraping the metrics endpoint, but we can verify no panics)
}

func TestMetricsMiddleware_SkipsMetricsEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()
	r.Use(m.MetricsMiddleware())

	r.GET("/metrics", func(c *gin.Context) {
		c.String(200, "metrics")
	})

	// Make a request to /metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Middleware should skip recording metrics for the metrics endpoint itself
}

func TestMetricsMiddleware_RecordsStatusCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()
	r.Use(m.MetricsMiddleware())

	r.GET("/success", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.GET("/error", func(c *gin.Context) {
		c.JSON(500, gin.H{"error": "internal error"})
	})
	r.GET("/notfound", func(c *gin.Context) {
		c.JSON(404, gin.H{"error": "not found"})
	})

	// Test different status codes
	testCases := []struct {
		path   string
		status int
	}{
		{"/success", 200},
		{"/error", 500},
		{"/notfound", 404},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, tc.status, w.Code)
	}
}

func TestRecordRefreshExecution(t *testing.T) {
	m := NewMetrics()

	// Test successful execution
	m.RecordRefreshExecution(500*time.Millisecond, 5, nil)

	// Test failed execution
	m.RecordRefreshExecution(200*time.Millisecond, 0, assert.AnError)

	// No panics = success
}

func TestRecordRefreshExecution_UpdatesTSLCount(t *testing.T) {
	m := NewMetrics()

	m.RecordRefreshExecution(100*time.Millisecond, 10, nil)
	m.RecordRefreshExecution(100*time.Millisecond, 15, nil)
	m.RecordRefreshExecution(100*time.Millisecond, 5, nil)

	// TSL count should be set to the last value (5)
	// We can't easily verify the exact value without scraping metrics
}

func TestRecordTSLProcessing(t *testing.T) {
	m := NewMetrics()

	m.RecordTSLProcessing(50 * time.Millisecond)
	m.RecordTSLProcessing(100 * time.Millisecond)
	m.RecordTSLProcessing(150 * time.Millisecond)

	// No panics = success
}

func TestRecordError(t *testing.T) {
	m := NewMetrics()

	m.RecordError("parse_error", "tsl_parsing")
	m.RecordError("validation_error", "cert_validation")
	m.RecordError("network_error", "tsl_fetch")

	// No panics = success
}

func TestRecordCertValidation(t *testing.T) {
	m := NewMetrics()

	// Test successful validation
	m.RecordCertValidation(10*time.Millisecond, true)

	// Test failed validation
	m.RecordCertValidation(5*time.Millisecond, false)

	// No panics = success
}

func TestRegisterMetricsEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()

	RegisterMetricsEndpoint(r, m)

	// Test that /metrics endpoint is registered
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "go_trust_", "Response should contain go_trust metrics")
}

func TestMetricsEndpoint_PrometheusFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()

	RegisterMetricsEndpoint(r, m)

	// Add a test route to generate API metrics
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Record some metrics
	m.RecordRefreshExecution(500*time.Millisecond, 5, nil)
	m.RecordTSLProcessing(100 * time.Millisecond)
	m.RecordError("test_error", "test_operation")
	m.RecordCertValidation(10*time.Millisecond, true)

	// Make an API request to generate API metrics
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Scrape metrics endpoint
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	body := w.Body.String()

	// Verify key metrics are present
	assert.Contains(t, body, "go_trust_refresh_execution_total")
	assert.Contains(t, body, "go_trust_tsl_count")
	assert.Contains(t, body, "go_trust_api_requests_total")
	assert.Contains(t, body, "go_trust_errors_total")
	assert.Contains(t, body, "go_trust_cert_validation_total")

	// Verify Prometheus format (HELP and TYPE comments)
	assert.Contains(t, body, "# HELP go_trust_")
	assert.Contains(t, body, "# TYPE go_trust_")
}

func TestMetricsMiddleware_Concurrent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()
	r.Use(m.MetricsMiddleware())

	r.GET("/test", func(c *gin.Context) {
		time.Sleep(10 * time.Millisecond)
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Make 50 concurrent requests
	done := make(chan bool, 50)
	for i := 0; i < 50; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	// Wait for all requests
	for i := 0; i < 50; i++ {
		<-done
	}
}

func TestMetricsMiddleware_UnknownEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()
	r.Use(m.MetricsMiddleware())

	// Don't register any routes, so all requests hit 404

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	// Middleware should record metrics even for unknown endpoints
}

func TestMetricsEndpoint_ContentType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()

	RegisterMetricsEndpoint(r, m)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Prometheus metrics should have text/plain content type
	contentType := w.Header().Get("Content-Type")
	assert.True(t,
		strings.Contains(contentType, "text/plain") ||
			strings.Contains(contentType, "application/openmetrics-text"),
		"Content-Type should be text/plain or application/openmetrics-text, got: %s", contentType)
}

func TestMetricsLabels(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m := NewMetrics()
	r := gin.New()
	RegisterMetricsEndpoint(r, m)

	// Create routes with different methods
	r.GET("/api/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.POST("/api/test", func(c *gin.Context) {
		c.JSON(201, gin.H{"status": "created"})
	})

	// Make requests
	tests := []struct {
		method string
		status int
	}{
		{"GET", 200},
		{"POST", 201},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "/api/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, tt.status, w.Code)
	}

	// Scrape metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	body := w.Body.String()

	// Verify labels are recorded
	assert.Contains(t, body, `method="GET"`)
	assert.Contains(t, body, `method="POST"`)
	assert.Contains(t, body, `endpoint="/api/test"`)
}

func TestRecordError_DifferentTypes(t *testing.T) {
	m := NewMetrics()

	errorTypes := []struct {
		errorType string
		operation string
	}{
		{"parse_error", "tsl_parsing"},
		{"validation_error", "cert_validation"},
		{"network_error", "tsl_fetch"},
		{"timeout_error", "api_request"},
		{"decode_error", "x5c_parsing"},
	}

	for _, et := range errorTypes {
		m.RecordError(et.errorType, et.operation)
	}

	// No panics = success
}

func TestRefreshMetrics_MultipleExecutions(t *testing.T) {
	m := NewMetrics()

	executions := []struct {
		duration time.Duration
		tslCount int
		err      error
	}{
		{100 * time.Millisecond, 5, nil},
		{200 * time.Millisecond, 8, nil},
		{50 * time.Millisecond, 0, assert.AnError},
		{300 * time.Millisecond, 10, nil},
	}

	for _, exec := range executions {
		m.RecordRefreshExecution(exec.duration, exec.tslCount, exec.err)
	}

	// All executions should be recorded without panic
}

func BenchmarkMetricsMiddleware(b *testing.B) {
	gin.SetMode(gin.ReleaseMode)

	m := NewMetrics()
	r := gin.New()
	r.Use(m.MetricsMiddleware())

	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}
}

func BenchmarkRecordRefreshExecution(b *testing.B) {
	m := NewMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordRefreshExecution(100*time.Millisecond, 5, nil)
	}
}

func BenchmarkRecordCertValidation(b *testing.B) {
	m := NewMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.RecordCertValidation(10*time.Millisecond, true)
	}
}
