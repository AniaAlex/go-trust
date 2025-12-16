package registry

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// ResolutionResult contains the evaluation result plus metadata about which registry resolved it
type ResolutionResult struct {
	Decision     bool
	Registry     string // Which registry resolved this
	Confidence   float64
	Response     *authzen.EvaluationResponse
	ResolutionMS int64
}

// evaluateFirstMatch queries registries in parallel and returns first positive match.
// This is the default and fastest strategy for most use cases.
func (m *RegistryManager) evaluateFirstMatch(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistries(req)
	m.mu.RUnlock()

	if len(registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         "no applicable registries for resource type",
					"resource_type": req.Resource.Type,
				},
			},
		}, nil
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// Channel for results
	results := make(chan *ResolutionResult, len(registries))

	// Query all registries in parallel
	var wg sync.WaitGroup
	for _, reg := range registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()

			info := registry.Info()

			// Check circuit breaker
			if !m.circuitBreakers[info.Name].CanAttempt() {
				return
			}

			startTime := time.Now()
			resp, err := registry.Evaluate(timeoutCtx, req)
			resolutionMS := time.Since(startTime).Milliseconds()

			if err != nil {
				m.circuitBreakers[info.Name].RecordFailure()
				return
			}

			m.circuitBreakers[info.Name].RecordSuccess()

			// Send result if decision is true
			if resp != nil && resp.Decision {
				results <- &ResolutionResult{
					Decision:     true,
					Registry:     info.Name,
					Confidence:   1.0,
					Response:     resp,
					ResolutionMS: resolutionMS,
				}
			}
		}(reg)
	}

	// Wait for results in separate goroutine
	go func() {
		wg.Wait()
		close(results)
	}()

	// Return first positive result
	select {
	case result := <-results:
		if result != nil {
			// Add resolution metadata to response context
			if result.Response.Context == nil {
				result.Response.Context = &authzen.EvaluationResponseContext{}
			}
			if result.Response.Context.Reason == nil {
				result.Response.Context.Reason = make(map[string]interface{})
			}
			result.Response.Context.Reason["registry"] = result.Registry
			result.Response.Context.Reason["resolution_ms"] = result.ResolutionMS

			return result.Response, nil
		}
	case <-timeoutCtx.Done():
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "timeout waiting for registry responses",
				},
			},
		}, nil
	}

	// No positive results
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"error":              "no registry returned positive match",
				"registries_queried": len(registries),
			},
		},
	}, nil
}

// evaluateAll queries all applicable registries and aggregates results.
// This strategy is useful for auditing or when you need to know which
// registries matched.
func (m *RegistryManager) evaluateAll(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistries(req)
	m.mu.RUnlock()

	if len(registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         "no applicable registries",
					"resource_type": req.Resource.Type,
				},
			},
		}, nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	type result struct {
		registry string
		response *authzen.EvaluationResponse
		err      error
		duration int64
	}

	results := make(chan result, len(registries))
	var wg sync.WaitGroup

	for _, reg := range registries {
		wg.Add(1)
		go func(registry TrustRegistry) {
			defer wg.Done()

			info := registry.Info()
			startTime := time.Now()

			if !m.circuitBreakers[info.Name].CanAttempt() {
				return
			}

			resp, err := registry.Evaluate(timeoutCtx, req)
			duration := time.Since(startTime).Milliseconds()

			if err != nil {
				m.circuitBreakers[info.Name].RecordFailure()
			} else {
				m.circuitBreakers[info.Name].RecordSuccess()
			}

			results <- result{
				registry: info.Name,
				response: resp,
				err:      err,
				duration: duration,
			}
		}(reg)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	var allResults []map[string]interface{}
	decision := false
	registriesMatched := []string{}

	for r := range results {
		resultInfo := map[string]interface{}{
			"registry":    r.registry,
			"duration_ms": r.duration,
		}

		if r.err != nil {
			resultInfo["error"] = r.err.Error()
		} else if r.response != nil {
			resultInfo["decision"] = r.response.Decision
			if r.response.Decision {
				decision = true
				registriesMatched = append(registriesMatched, r.registry)
			}
		}

		allResults = append(allResults, resultInfo)
	}

	return &authzen.EvaluationResponse{
		Decision: decision,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registries_queried": len(registries),
				"registries_matched": registriesMatched,
				"all_results":        allResults,
			},
		},
	}, nil
}

// evaluateBestMatch queries all registries and returns the one with highest confidence.
// Currently uses first match as a fallback; confidence scoring could be enhanced
// by examining response context.
func (m *RegistryManager) evaluateBestMatch(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// For now, delegate to evaluateAll and pick first positive match
	// In future, could extract confidence scores from response context
	resp, err := m.evaluateAll(ctx, req)
	if err != nil {
		return resp, err
	}

	// Transform aggregated result to single best match
	if resp.Decision && resp.Context != nil && resp.Context.Reason != nil {
		if matched, ok := resp.Context.Reason["registries_matched"].([]string); ok && len(matched) > 0 {
			resp.Context.Reason["registry"] = matched[0]
			resp.Context.Reason["strategy"] = "best_match"
			// Remove aggregation details
			delete(resp.Context.Reason, "all_results")
		}
	}

	return resp, nil
}

// evaluateSequential tries registries in registration order until one returns true.
// This strategy is useful when you have preferred registries or want to minimize
// load on rate-limited APIs.
func (m *RegistryManager) evaluateSequential(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	m.mu.RLock()
	registries := m.getApplicableRegistries(req)
	m.mu.RUnlock()

	if len(registries) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         "no applicable registries",
					"resource_type": req.Resource.Type,
				},
			},
		}, nil
	}

	attempted := []string{}

	for _, reg := range registries {
		info := reg.Info()

		if !m.circuitBreakers[info.Name].CanAttempt() {
			attempted = append(attempted, info.Name+" (circuit open)")
			continue
		}

		startTime := time.Now()
		resp, err := reg.Evaluate(ctx, req)
		resolutionMS := time.Since(startTime).Milliseconds()

		if err != nil {
			m.circuitBreakers[info.Name].RecordFailure()
			attempted = append(attempted, info.Name+" (error)")
			continue
		}

		m.circuitBreakers[info.Name].RecordSuccess()
		attempted = append(attempted, info.Name)

		if resp != nil && resp.Decision {
			if resp.Context == nil {
				resp.Context = &authzen.EvaluationResponseContext{}
			}
			if resp.Context.Reason == nil {
				resp.Context.Reason = make(map[string]interface{})
			}
			resp.Context.Reason["registry"] = info.Name
			resp.Context.Reason["resolution_ms"] = resolutionMS
			resp.Context.Reason["registries_attempted"] = attempted
			return resp, nil
		}
	}

	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"error":                "no registry returned positive match",
				"registries_attempted": attempted,
			},
		},
	}, nil
}
