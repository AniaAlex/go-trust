package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNewRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(100, 10)
	assert.NotNil(t, limiter)
	assert.Equal(t, 100, limiter.rps)
	assert.Equal(t, 10, limiter.burst)
	assert.NotNil(t, limiter.limiters)
}

func TestRateLimiter_GetLimiter(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	// First call should create a new limiter
	limiter1 := rl.getLimiter("192.168.1.1")
	assert.NotNil(t, limiter1)

	// Second call for same IP should return the same limiter (same pointer)
	limiter2 := rl.getLimiter("192.168.1.1")
	assert.Same(t, limiter1, limiter2)

	// Different IP should get a different limiter (different pointer)
	limiter3 := rl.getLimiter("192.168.1.2")
	assert.NotNil(t, limiter3)
	assert.NotSame(t, limiter1, limiter3)
}

func TestRateLimiter_Middleware_AllowsRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter with generous limits
	rl := NewRateLimiter(100, 10)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// Make a request that should be allowed
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "ok")
}

func TestRateLimiter_Middleware_EnforcesLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter with very strict limits
	// 1 request per second with burst of 2
	rl := NewRateLimiter(1, 2)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// First 2 requests should succeed (burst allows 2)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, 200, w.Code, "Request %d should succeed", i+1)
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, 429, w.Code)
	assert.Contains(t, w.Body.String(), "rate limit exceeded")
}

func TestRateLimiter_Middleware_PerIPLimiting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter with very strict limits
	rl := NewRateLimiter(1, 1)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// First IP: make request that uses up its quota
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, 200, w1.Code)

	// First IP: second request should be rate limited
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, 429, w2.Code)

	// Different IP: should still be allowed
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "192.168.1.2:1234"
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	assert.Equal(t, 200, w3.Code)
}

func TestRateLimiter_Middleware_TokenRefill(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create rate limiter with 10 req/sec and burst of 1
	// At this rate, tokens refill every 100ms
	rl := NewRateLimiter(10, 1)

	router := gin.New()
	router.Use(rl.Middleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "ok"})
	})

	// First request should succeed
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:1234"
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, 200, w1.Code)

	// Immediate second request should be rate limited
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, 429, w2.Code)

	// Wait for token to refill (100ms + buffer)
	time.Sleep(150 * time.Millisecond)

	// Third request should succeed after waiting
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "192.168.1.1:1234"
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	assert.Equal(t, 200, w3.Code)
}

func TestRateLimiter_CleanupOldLimiters(t *testing.T) {
	rl := NewRateLimiter(100, 10)

	// Create some limiters
	rl.getLimiter("192.168.1.1")
	rl.getLimiter("192.168.1.2")
	rl.getLimiter("192.168.1.3")

	assert.Equal(t, 3, len(rl.limiters))

	// Cleanup with a long maxAge should keep all limiters
	rl.CleanupOldLimiters(time.Hour)
	assert.Equal(t, 3, len(rl.limiters))

	// Cleanup with zero maxAge should remove all limiters
	rl.CleanupOldLimiters(0)
	assert.Equal(t, 0, len(rl.limiters))
}
