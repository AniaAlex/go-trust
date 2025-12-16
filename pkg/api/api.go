package api

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/pipeline"
)

// parseX5C extracts and parses x5c certificates from a map[string]interface{}.
// DEPRECATED: Use parseX5CFromArray or parseX5CFromJWK for AuthZEN Trust Registry Profile compliance.
func parseX5C(props map[string]interface{}) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	if props == nil {
		return certs, nil
	}
	x5cVal, ok := props["x5c"]
	if !ok {
		return certs, nil
	}
	x5cList, ok := x5cVal.([]interface{})
	if !ok {
		return certs, fmt.Errorf("x5c property is not a list")
	}
	for _, item := range x5cList {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("x5c entry is not a string")
		}
		der, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode x5c entry: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseX5CFromArray parses X.509 certificates from an array of base64-encoded DER certificates.
// This is used when resource.type is "x5c" in the AuthZEN Trust Registry Profile.
// Each element in the array should be a base64-encoded X.509 DER certificate.
func parseX5CFromArray(key []interface{}) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	if len(key) == 0 {
		return nil, fmt.Errorf("resource.key is empty")
	}

	for i, item := range key {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("resource.key[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode resource.key[%d]: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from resource.key[%d]: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseX5CFromJWK parses X.509 certificates from a JWK (JSON Web Key) structure.
// This is used when resource.type is "jwk" in the AuthZEN Trust Registry Profile.
// The JWK may contain an "x5c" claim which is an array of base64-encoded DER certificates.
// The resource.key array should contain a single JWK object as a map[string]interface{}.
func parseX5CFromJWK(key []interface{}) ([]*x509.Certificate, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("resource.key is empty")
	}

	// The first element should be a JWK object
	jwk, ok := key[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("resource.key[0] is not a JWK object (map)")
	}

	// Extract x5c claim from JWK
	x5cVal, ok := jwk["x5c"]
	if !ok {
		return nil, fmt.Errorf("JWK does not contain x5c claim")
	}

	x5cList, ok := x5cVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("JWK x5c claim is not an array")
	}

	var certs []*x509.Certificate
	for i, item := range x5cList {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("JWK x5c[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode JWK x5c[%d]: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from JWK x5c[%d]: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// buildResponse constructs an EvaluationResponse for the AuthZEN API.
// Per the AuthZEN Trust Registry Profile, the response format is not profiled,
// so we use a simplified structure with reason as a general-purpose field.
func buildResponse(decision bool, reason string) authzen.EvaluationResponse {
	if decision {
		return authzen.EvaluationResponse{Decision: true}
	}
	return authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"error": reason},
		},
	}
}

// StartBackgroundUpdater runs the pipeline at regular intervals and updates the server context.
// This function starts a goroutine that processes the pipeline at the specified frequency
// and updates the ServerContext with the new pipeline results. The updated context is then
// used by API handlers to respond to requests with fresh data.
//
// The pipeline is processed immediately upon calling this function, before starting the
// background updates. This ensures TSLs are available as soon as the server starts.
//
// Success and failure events are logged using the ServerContext's structured logger:
// - On success: An info-level message with the update frequency
// - On failure: An error-level message with the error details and frequency
//
// Parameters:
//   - pl: The pipeline to process periodically
//   - serverCtx: The server context to update with pipeline results (must have a valid logger)
//   - freq: The frequency at which to process the pipeline (e.g., 5m for every 5 minutes)
//
// This function is typically called at server startup to ensure TSLs are kept up-to-date.
func StartBackgroundUpdater(pl *pipeline.Pipeline, serverCtx *ServerContext, freq time.Duration) error {
	// Process pipeline immediately to ensure TSLs are loaded without waiting
	start := time.Now()
	newCtx, err := pl.Process(pipeline.NewContext())
	duration := time.Since(start)

	serverCtx.Lock()
	if err == nil && newCtx != nil {
		serverCtx.PipelineContext = newCtx
		serverCtx.LastProcessed = time.Now()
		tslCount := countTSLs(newCtx)
		serverCtx.Logger.Info("Initial pipeline processing successful",
			logging.F("tsl_count", tslCount))

		// Record metrics if available
		if serverCtx.Metrics != nil {
			serverCtx.Metrics.RecordPipelineExecution(duration, tslCount, nil)
		}
	} else if err != nil {
		serverCtx.Logger.Error("Initial pipeline processing failed",
			logging.F("error", err.Error()))

		// Record error metrics if available
		if serverCtx.Metrics != nil {
			serverCtx.Metrics.RecordPipelineExecution(duration, 0, err)
		}
	}
	serverCtx.Unlock()

	// Start background processing
	go func() {
		for {
			time.Sleep(freq)

			start := time.Now()
			newCtx, err := pl.Process(pipeline.NewContext())
			duration := time.Since(start)

			serverCtx.Lock()
			if err == nil && newCtx != nil {
				serverCtx.PipelineContext = newCtx
				serverCtx.LastProcessed = time.Now()
			}
			serverCtx.Unlock()

			if err != nil {
				// ServerContext always has a logger after our improvements
				serverCtx.Logger.Error("Pipeline processing failed",
					logging.F("error", err.Error()),
					logging.F("frequency", freq.String()))

				// Record error metrics if available
				if serverCtx.Metrics != nil {
					serverCtx.Metrics.RecordPipelineExecution(duration, 0, err)
				}
			} else {
				// Log successful update
				tslCount := countTSLs(newCtx)
				serverCtx.Logger.Info("Pipeline processed successfully",
					logging.F("frequency", freq.String()),
					logging.F("tsl_count", tslCount))

				// Record metrics if available
				if serverCtx.Metrics != nil {
					serverCtx.Metrics.RecordPipelineExecution(duration, tslCount, nil)
				}
			}
		}
	}()
	return nil
}

// countTSLs counts the number of TSLs in the pipeline context.
// This is a helper function to provide consistent TSL counting for logging.
func countTSLs(ctx *pipeline.Context) int {
	if ctx == nil || ctx.TSLs == nil {
		return 0
	}
	return ctx.TSLs.Size()
}

// NewServerContext creates a new ServerContext with a configured logger.
// The ServerContext will always have a valid logger - if none is provided,
// it will use the DefaultLogger.
func NewServerContext(logger logging.Logger) *ServerContext {
	// Always ensure a valid logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &ServerContext{
		Logger: logger,
	}
}

// RegisterAPIRoutes sets up all API routes on the given Gin engine.
//
// This function registers the following API endpoints:
//
// AuthZEN Discovery:
//
// GET /.well-known/authzen-configuration - Returns PDP metadata for service discovery (AuthZEN spec Section 9)
//
// AuthZEN Evaluation:
//
// POST /evaluation - Implements the AuthZEN Trust Registry Profile for validating name-to-key bindings
//
//	This endpoint processes AuthZEN EvaluationRequest objects per draft-johansson-authzen-trust,
//	validating that a public key (in resource.key) is correctly bound to a name (in subject.id)
//	according to the trusted certificates in the pipeline context.
//
// TSL Information:
//
// GET /tsls - Returns detailed information about all loaded Trust Status Lists
//
// Deprecated Endpoints (will be removed in v2.0.0):
//
// GET /status - DEPRECATED: Use GET /readyz instead
//
// GET /info - DEPRECATED: Use GET /tsls instead
//
// If a RateLimiter is configured in the ServerContext, it will be applied to all routes.
func RegisterAPIRoutes(r *gin.Engine, serverCtx *ServerContext) {
	// Apply rate limiting middleware if configured
	if serverCtx.RateLimiter != nil {
		r.Use(serverCtx.RateLimiter.Middleware())
		serverCtx.Logger.Info("Rate limiting enabled",
			logging.F("rps", serverCtx.RateLimiter.rps),
			logging.F("burst", serverCtx.RateLimiter.burst))
	}

	// AuthZEN well-known discovery endpoint (Section 9 of base spec)
	r.GET("/.well-known/authzen-configuration", WellKnownHandler(serverCtx.BaseURL))

	// AuthZEN evaluation endpoint
	r.POST("/evaluation", AuthZENDecisionHandler(serverCtx))

	// TSL information endpoint
	r.GET("/tsls", TSLsHandler(serverCtx))

	// Deprecated endpoints (kept for backward compatibility)
	r.GET("/status", StatusHandler(serverCtx))
	r.GET("/info", InfoHandler(serverCtx))

	// Test-mode shutdown endpoint
	// This endpoint is only registered when GO_TRUST_TEST_MODE environment variable is set
	// It allows integration tests to gracefully shutdown the server
	if os.Getenv("GO_TRUST_TEST_MODE") == "1" {
		r.POST("/test/shutdown", TestShutdownHandler(serverCtx))
		serverCtx.Logger.Warn("Test mode enabled: /test/shutdown endpoint is available")
	}
}
