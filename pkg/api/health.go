package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
)

// HealthResponse represents the response from health check endpoints
type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// ReadinessResponse represents the response from the readiness endpoint
type ReadinessResponse struct {
	Status        string                   `json:"status"`
	Timestamp     time.Time                `json:"timestamp"`
	TSLCount      int                      `json:"tsl_count"`
	LastProcessed string                   `json:"last_processed,omitempty"`
	Ready         bool                     `json:"ready"`
	Message       string                   `json:"message,omitempty"`
	TSLs          []map[string]interface{} `json:"tsls,omitempty"` // Only included with ?verbose=true
}

// RegisterHealthEndpoints registers health check endpoints on the given Gin router.
// These endpoints are useful for Kubernetes liveness and readiness probes, load balancers,
// and monitoring systems.
//
// Endpoints:
//
//	GET /healthz      - Liveness probe: returns 200 if the server is running
//	GET /readyz       - Readiness probe: returns 200 if server is ready to accept traffic
//	                    Supports ?verbose=true query parameter for detailed TSL information
//
// The /healthz endpoint always returns 200 OK if the server is running, indicating
// that the process is alive and can handle requests.
//
// The /readyz endpoint checks whether the service has:
//   - Successfully loaded at least one TSL
//   - Refreshed registries at least once
//
// If these conditions are not met, it returns 503 Service Unavailable.
//
// Use ?verbose=true on /readyz to include detailed TSL summaries in the response.
func RegisterHealthEndpoints(r *gin.Engine, serverCtx *ServerContext) {
	r.GET("/healthz", HealthHandler(serverCtx))
	r.GET("/readyz", ReadinessHandler(serverCtx))

	serverCtx.Logger.Info("Health check endpoints registered",
		logging.F("endpoints", []string{"/healthz", "/readyz"}))
}

// HealthHandler godoc
// @Summary Liveness check
// @Description Returns OK if the server is running and able to handle requests
// @Tags Health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /healthz [get]
func HealthHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		serverCtx.Logger.Debug("Health check requested",
			logging.F("remote_ip", c.ClientIP()),
			logging.F("endpoint", c.Request.URL.Path))

		c.JSON(200, HealthResponse{
			Status:    "ok",
			Timestamp: time.Now(),
		})
	}
}

// ReadinessHandler godoc
// @Summary Readiness check
// @Description Returns ready status if registries have been refreshed and are loaded
// @Description
// @Description Query Parameters:
// @Description - verbose=true: Include detailed TSL information in the response
// @Tags Health
// @Produce json
// @Param verbose query bool false "Include detailed TSL information"
// @Success 200 {object} ReadinessResponse "Service is ready"
// @Failure 503 {object} ReadinessResponse "Service is not ready"
// @Router /readyz [get]
func ReadinessHandler(serverCtx *ServerContext) gin.HandlerFunc {
	return func(c *gin.Context) {
		serverCtx.RLock()
		registryCount := 0
		lastProcessed := ""
		hasProcessed := !serverCtx.LastProcessed.IsZero()
		verbose := c.Query("verbose") == "true"

		if serverCtx.RegistryManager != nil {
			registryCount = len(serverCtx.RegistryManager.ListRegistries())
		}

		if hasProcessed {
			lastProcessed = serverCtx.LastProcessed.Format(time.RFC3339)
		}

		// Collect detailed registry information if verbose mode requested
		var registryInfos []map[string]interface{}
		if verbose && serverCtx.RegistryManager != nil {
			for _, info := range serverCtx.RegistryManager.ListRegistries() {
				registryInfos = append(registryInfos, map[string]interface{}{
					"name":            info.Name,
					"resource_types":  info.ResourceTypes,
					"resolution_only": info.ResolutionOnly,
					"healthy":         info.Healthy,
				})
			}
		}
		serverCtx.RUnlock()

		// Service is ready if:
		// 1. Registries have been refreshed at least once
		// 2. At least one registry is available (optional but recommended)
		isReady := hasProcessed && registryCount > 0

		response := ReadinessResponse{
			Timestamp:     time.Now(),
			TSLCount:      registryCount, // Using TSLCount field for backward compat
			LastProcessed: lastProcessed,
			Ready:         isReady,
			TSLs:          registryInfos, // Using TSLs field for backward compat
		}

		if isReady {
			response.Status = "ready"
			response.Message = "Service is ready to accept traffic"

			serverCtx.Logger.Debug("Readiness check passed",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("endpoint", c.Request.URL.Path),
				logging.F("verbose", verbose),
				logging.F("registry_count", registryCount),
				logging.F("last_processed", lastProcessed))

			c.JSON(200, response)
		} else {
			response.Status = "not_ready"
			if !hasProcessed {
				response.Message = "Registries have not been refreshed yet"
			} else if registryCount == 0 {
				response.Message = "No registries configured"
			}

			serverCtx.Logger.Warn("Readiness check failed",
				logging.F("remote_ip", c.ClientIP()),
				logging.F("endpoint", c.Request.URL.Path),
				logging.F("verbose", verbose),
				logging.F("reason", response.Message),
				logging.F("registry_count", registryCount),
				logging.F("has_processed", hasProcessed))

			c.JSON(503, response)
		}
	}
}
