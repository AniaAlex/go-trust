// Package etsi provides a TrustRegistry implementation for ETSI TS 119 612 Trust Status Lists.
//
// This package wraps the existing ETSI TSL pipeline logic to provide a standard
// TrustRegistry interface, allowing ETSI TSLs to be used alongside other trust
// resolution backends in a multi-registry architecture.
package etsi

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/SUNET/go-trust/pkg/authzen"
	"github.com/SUNET/go-trust/pkg/pipeline"
	"github.com/SUNET/go-trust/pkg/registry"
	"github.com/SUNET/go-trust/pkg/utils/x509util"
)

// TSLRegistry implements TrustRegistry for ETSI TS 119 612 Trust Status Lists.
// It wraps the existing pipeline.Context to provide a registry interface.
type TSLRegistry struct {
	pipelineCtx *pipeline.Context
	name        string
	description string
}

// NewTSLRegistry creates a new ETSI TSL registry from a pipeline context
func NewTSLRegistry(ctx *pipeline.Context, name string) *TSLRegistry {
	return &TSLRegistry{
		pipelineCtx: ctx,
		name:        name,
		description: "ETSI TS 119 612 Trust Status List Registry",
	}
}

// Evaluate implements TrustRegistry.Evaluate by validating X.509 certificates against TSL cert pools
func (r *TSLRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Extract certificates from resource.key based on resource.type
	var certs []*x509.Certificate
	var parseErr error

	if req.Resource.Type == "x5c" {
		// resource.key is an array of base64-encoded X.509 certificates
		certs, parseErr = x509util.ParseX5CFromArray(req.Resource.Key)
	} else if req.Resource.Type == "jwk" {
		// resource.type == "jwk" - extract certificate from JWK x5c claim
		certs, parseErr = x509util.ParseX5CFromJWK(req.Resource.Key)
	} else {
		// Unsupported resource type for ETSI TSL
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("unsupported resource type for ETSI TSL: %s", req.Resource.Type),
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

	// Validate certificate chain against TSL certificate pool
	if r.pipelineCtx == nil || r.pipelineCtx.CertPool == nil {
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
		Roots: r.pipelineCtx.CertPool,
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
				"tsl_count":     r.getTSLCount(),
				"validation_ms": validationDuration.Milliseconds(),
				"chain_length":  len(chains),
			},
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle
func (r *TSLRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk"}
}

// SupportsResolutionOnly returns false for ETSI TSL registry.
// ETSI TSL does not support resolution-only requests - it requires
// an X.509 certificate chain to validate against the trust status lists.
func (r *TSLRegistry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry
func (r *TSLRegistry) Info() registry.RegistryInfo {
	trustAnchors := make([]string, 0)
	if r.pipelineCtx != nil && r.pipelineCtx.TSLs != nil {
		for _, tsl := range r.pipelineCtx.TSLs.ToSlice() {
			if tsl != nil {
				summary := tsl.Summary()
				if territory, ok := summary["territory"].(string); ok {
					trustAnchors = append(trustAnchors, fmt.Sprintf("TSL:%s", territory))
				}
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

// Healthy returns true if the registry is operational
func (r *TSLRegistry) Healthy() bool {
	return r.pipelineCtx != nil &&
		r.pipelineCtx.CertPool != nil &&
		r.pipelineCtx.TSLs != nil &&
		r.pipelineCtx.TSLs.Size() > 0
}

// Refresh triggers a pipeline refresh (if supported by the pipeline)
func (r *TSLRegistry) Refresh(ctx context.Context) error {
	// For now, refresh is handled externally by the pipeline scheduler
	// Future: could trigger on-demand refresh here
	return nil
}

// getTSLCount returns the number of loaded TSLs
func (r *TSLRegistry) getTSLCount() int {
	if r.pipelineCtx != nil && r.pipelineCtx.TSLs != nil {
		return r.pipelineCtx.TSLs.Size()
	}
	return 0
}
