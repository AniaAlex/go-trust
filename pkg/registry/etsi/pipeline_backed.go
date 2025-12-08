// pipeline_backed.go provides a TrustRegistry implementation that wraps a pipeline context.
//
// The PipelineBackedRegistry is designed for use with the go-trust server where
// TSL data is loaded and refreshed by a background pipeline. This registry reads
// trust data (certificates and TSLs) from a PipelineContextProvider interface,
// allowing it to be decoupled from the pipeline package while still benefiting
// from automatic background updates.
//
// # When to Use PipelineBackedRegistry
//
// Use PipelineBackedRegistry when:
//   - Running the go-trust server with background TSL updates
//   - You need automatic refresh of TSL data without manual intervention
//   - Multiple components need to share the same TSL data
//
// For standalone use cases without a pipeline, use TSLRegistry instead.
//
// # Example
//
//	// In go-trust server main.go
//	serverCtx := api.NewServerContext(nil)
//	serverCtx.PipelineContext = &pipeline.Context{}
//
//	// PipelineContext implements PipelineContextProvider
//	tslRegistry := etsi.NewPipelineBackedRegistry(serverCtx.PipelineContext, "ETSI-TSL")
//	registryMgr.Register(tslRegistry)
//
//	// Start background pipeline updates
//	api.StartBackgroundUpdater(pl, serverCtx, 5*time.Minute)
package etsi

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/SUNET/g119612/pkg/etsi119612"
	"github.com/SUNET/go-trust/pkg/authzen"
	"github.com/SUNET/go-trust/pkg/registry"
	"github.com/SUNET/go-trust/pkg/utils/x509util"
)

// PipelineContextProvider is an interface for accessing pipeline-managed TSL data.
// This decouples the registry from the pipeline package while still allowing
// the server to use pipeline-based background updates.
//
// The pipeline.Context type implements this interface, providing:
//   - GetCertPool: Access to the certificate pool built from TSL certificates
//   - GetTSLs: Access to the loaded TSL objects for metadata
//   - GetTSLCount: Count of loaded TSLs for health checks
type PipelineContextProvider interface {
	// GetCertPool returns the current certificate pool
	GetCertPool() *x509.CertPool
	// GetTSLs returns the current TSL collection
	GetTSLs() []*etsi119612.TSL
	// GetTSLCount returns the number of loaded TSLs
	GetTSLCount() int
}

// PipelineBackedRegistry wraps a PipelineContextProvider to implement TrustRegistry.
// Use this when you want the registry to share data with a background pipeline updater.
type PipelineBackedRegistry struct {
	provider    PipelineContextProvider
	name        string
	description string
	mu          sync.RWMutex
}

// NewPipelineBackedRegistry creates a registry that reads from a PipelineContextProvider.
// This is useful for backward compatibility with the existing pipeline-based server.
func NewPipelineBackedRegistry(provider PipelineContextProvider, name string) *PipelineBackedRegistry {
	if name == "" {
		name = "ETSI-TSL-Pipeline"
	}
	return &PipelineBackedRegistry{
		provider:    provider,
		name:        name,
		description: "ETSI TS 119 612 Trust Status List Registry (pipeline-backed)",
	}
}

// Evaluate implements TrustRegistry.Evaluate by validating X.509 certificates against the provider's cert pool.
func (r *PipelineBackedRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "ETSI TSL registry does not support resolution-only requests",
				},
			},
		}, nil
	}

	// Extract certificates from resource.key based on resource.type
	var certs []*x509.Certificate
	var parseErr error

	switch req.Resource.Type {
	case "x5c":
		certs, parseErr = x509util.ParseX5CFromArray(req.Resource.Key)
	case "jwk":
		certs, parseErr = x509util.ParseX5CFromJWK(req.Resource.Key)
	default:
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("unsupported resource type: %s (expected x5c or jwk)", req.Resource.Type),
				},
			},
		}, nil
	}

	if parseErr != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": parseErr.Error(),
				},
			},
		}, nil
	}

	if len(certs) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "no certificates found in resource.key",
				},
			},
		}, nil
	}

	// Get certificate pool from provider
	certPool := r.provider.GetCertPool()
	if certPool == nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "TSL CertPool is not initialized",
				},
			},
		}, nil
	}

	start := time.Now()
	opts := x509.VerifyOptions{
		Roots: certPool,
	}
	chains, err := certs[0].Verify(opts)
	validationDuration := time.Since(start)

	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         err.Error(),
					"validation_ms": validationDuration.Milliseconds(),
				},
			},
		}, nil
	}

	// Success - certificate is trusted
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"tsl_count":     r.provider.GetTSLCount(),
				"validation_ms": validationDuration.Milliseconds(),
				"chain_length":  len(chains),
			},
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *PipelineBackedRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk"}
}

// SupportsResolutionOnly returns false - ETSI TSL requires certificate validation.
func (r *PipelineBackedRegistry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry.
func (r *PipelineBackedRegistry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	trustAnchors := make([]string, 0)
	for _, tsl := range r.provider.GetTSLs() {
		if tsl != nil {
			summary := tsl.Summary()
			if territory, ok := summary["territory"].(string); ok {
				trustAnchors = append(trustAnchors, fmt.Sprintf("TSL:%s", territory))
			}
		}
	}

	return registry.RegistryInfo{
		Name:         r.name,
		Type:         "etsi_tsl",
		Description:  r.description,
		Version:      "1.0.0",
		TrustAnchors: trustAnchors,
	}
}

// Healthy returns true if the registry has a valid certificate pool.
func (r *PipelineBackedRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.provider.GetCertPool() != nil && r.provider.GetTSLCount() > 0
}

// Refresh is a no-op for pipeline-backed registry - refresh is handled by the pipeline.
func (r *PipelineBackedRegistry) Refresh(ctx context.Context) error {
	// Refresh is handled by the pipeline background updater
	return nil
}
