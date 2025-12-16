# Multi-Registry Trust Resolution Architecture

## Overview

This document describes the architecture for supporting multiple trust registries in parallel within go-trust, building on the base TrustRegistry interface design.

## Key Principle: Parallel Resolution with First-Match

In practical deployments, entities (represented by key pairs) often appear in **multiple trust registries**:

- An X.509 certificate may be in both an ETSI 119 612 TSL and an OpenID Federation
- A DID may be registered across multiple DID methods and federations
- Organizations often participate in multiple trust frameworks simultaneously

The RegistryManager must support:
1. **Parallel queries** to multiple registries for performance
2. **First-match semantics** to return quickly
3. **Aggregation strategies** when multiple results are desired
4. **Circuit breaking** to handle registry failures gracefully

## Architecture

### 1. Enhanced RegistryManager Interface

```go
package registry

import (
    "context"
    "sync"
    "time"

    "github.com/sirosfoundation/go-trust/pkg/authzen"
)

// RegistryManager coordinates multiple TrustRegistry implementations
type RegistryManager struct {
    registries []TrustRegistry
    strategy   ResolutionStrategy
    timeout    time.Duration

    // Circuit breaker state per registry
    circuitBreakers map[string]*CircuitBreaker
    mu              sync.RWMutex
}

// ResolutionStrategy defines how to aggregate results from multiple registries
type ResolutionStrategy string

const (
    // FirstMatch returns as soon as any registry returns decision=true
    FirstMatch ResolutionStrategy = "first_match"

    // AllRegistries queries all registries and aggregates results
    AllRegistries ResolutionStrategy = "all"

    // BestMatch queries all registries and returns the one with highest confidence
    BestMatch ResolutionStrategy = "best_match"

    // Sequential tries registries in order until one succeeds
    Sequential ResolutionStrategy = "sequential"
)

// ResolutionResult contains the evaluation result plus metadata about which registry resolved it
type ResolutionResult struct {
    Decision     bool
    Registry     string // Which registry resolved this
    Confidence   float64 // 0.0-1.0, registry-specific confidence
    Response     *authzen.EvaluationResponse
    ResolutionMS int64 // Time taken to resolve
}

// NewRegistryManager creates a manager with the given strategy
func NewRegistryManager(strategy ResolutionStrategy, timeout time.Duration) *RegistryManager {
    return &RegistryManager{
        registries:      make([]TrustRegistry, 0),
        strategy:        strategy,
        timeout:         timeout,
        circuitBreakers: make(map[string]*CircuitBreaker),
    }
}

// Register adds a trust registry to the manager
func (m *RegistryManager) Register(registry TrustRegistry) {
    m.mu.Lock()
    defer m.mu.Unlock()

    m.registries = append(m.registries, registry)
    info := registry.Info()
    m.circuitBreakers[info.Name] = NewCircuitBreaker(5, 30*time.Second)
}

// Evaluate implements the TrustRegistry interface by delegating to registered registries
func (m *RegistryManager) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    switch m.strategy {
    case FirstMatch:
        return m.evaluateFirstMatch(ctx, req)
    case AllRegistries:
        return m.evaluateAll(ctx, req)
    case BestMatch:
        return m.evaluateBestMatch(ctx, req)
    case Sequential:
        return m.evaluateSequential(ctx, req)
    default:
        return m.evaluateFirstMatch(ctx, req)
    }
}

// evaluateFirstMatch queries registries in parallel and returns first positive match
func (m *RegistryManager) evaluateFirstMatch(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    m.mu.RLock()
    registries := m.getApplicableRegistries(req)
    m.mu.RUnlock()

    if len(registries) == 0 {
        return &authzen.EvaluationResponse{
            Decision: false,
            Context: &authzen.EvaluationResponseContext{
                Reason: map[string]interface{}{
                    "error": "no applicable registries for resource type",
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
            if resp.Decision {
                results <- &ResolutionResult{
                    Decision:     true,
                    Registry:     info.Name,
                    Confidence:   1.0, // Registry-specific confidence could be extracted from context
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
                "error": "no registry returned positive match",
                "registries_queried": len(registries),
            },
        },
    }, nil
}

// evaluateAll queries all registries and returns aggregated results
func (m *RegistryManager) evaluateAll(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    m.mu.RLock()
    registries := m.getApplicableRegistries(req)
    m.mu.RUnlock()

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
    var allResults []result
    for r := range results {
        allResults = append(allResults, r)
    }

    // Aggregate decisions (any true = true)
    decision := false
    registriesMatched := []string{}

    for _, r := range allResults {
        if r.err == nil && r.response != nil && r.response.Decision {
            decision = true
            registriesMatched = append(registriesMatched, r.registry)
        }
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

// evaluateSequential tries registries in order until one returns true
func (m *RegistryManager) evaluateSequential(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
    m.mu.RLock()
    registries := m.getApplicableRegistries(req)
    m.mu.RUnlock()

    for _, reg := range registries {
        info := reg.Info()

        if !m.circuitBreakers[info.Name].CanAttempt() {
            continue
        }

        resp, err := reg.Evaluate(ctx, req)
        if err != nil {
            m.circuitBreakers[info.Name].RecordFailure()
            continue
        }

        m.circuitBreakers[info.Name].RecordSuccess()

        if resp.Decision {
            if resp.Context == nil {
                resp.Context = &authzen.EvaluationResponseContext{}
            }
            if resp.Context.Reason == nil {
                resp.Context.Reason = make(map[string]interface{})
            }
            resp.Context.Reason["registry"] = info.Name
            return resp, nil
        }
    }

    return &authzen.EvaluationResponse{
        Decision: false,
        Context: &authzen.EvaluationResponseContext{
            Reason: map[string]interface{}{
                "error": "no registry returned positive match",
            },
        },
    }, nil
}

// getApplicableRegistries filters registries that support the resource type
func (m *RegistryManager) getApplicableRegistries(req *authzen.EvaluationRequest) []TrustRegistry {
    applicable := make([]TrustRegistry, 0)

    for _, reg := range m.registries {
        supported := reg.SupportedResourceTypes()
        for _, rt := range supported {
            if rt == req.Resource.Type || rt == "*" {
                applicable = append(applicable, reg)
                break
            }
        }
    }

    return applicable
}

// CircuitBreaker implements a simple circuit breaker pattern
type CircuitBreaker struct {
    maxFailures   int
    resetTimeout  time.Duration
    failures      int
    lastFailure   time.Time
    state         CircuitState
    mu            sync.RWMutex
}

type CircuitState string

const (
    CircuitClosed   CircuitState = "closed"    // Normal operation
    CircuitOpen     CircuitState = "open"      // Failures exceeded, rejecting requests
    CircuitHalfOpen CircuitState = "half_open" // Testing if service recovered
)

func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
    return &CircuitBreaker{
        maxFailures:  maxFailures,
        resetTimeout: resetTimeout,
        state:        CircuitClosed,
    }
}

func (cb *CircuitBreaker) CanAttempt() bool {
    cb.mu.RLock()
    defer cb.mu.RUnlock()

    switch cb.state {
    case CircuitClosed:
        return true
    case CircuitOpen:
        // Check if we should transition to half-open
        if time.Since(cb.lastFailure) > cb.resetTimeout {
            return true // Will transition to half-open on next attempt
        }
        return false
    case CircuitHalfOpen:
        return true
    default:
        return false
    }
}

func (cb *CircuitBreaker) RecordSuccess() {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    cb.failures = 0
    cb.state = CircuitClosed
}

func (cb *CircuitBreaker) RecordFailure() {
    cb.mu.Lock()
    defer cb.mu.Unlock()

    cb.failures++
    cb.lastFailure = time.Now()

    if cb.failures >= cb.maxFailures {
        cb.state = CircuitOpen
    }
}
```

### 2. Configuration Example

```yaml
# go-trust configuration with multiple registries
registries:
  - name: "ETSI TSL Registry"
    type: "etsi_tsl"
    enabled: true
    priority: 1
    config:
      pipelines:
        - name: "EU Trust List"
          url: "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
        - name: "Sweden"
          url: "https://tillitslista.se/SE-TL.xml"

  - name: "OpenID Federation"
    type: "openid_federation"
    enabled: true
    priority: 2
    config:
      trust_anchors:
        - entity_id: "https://edugain.geant.org"
          jwks_url: "https://edugain.geant.org/.well-known/openid-federation"
        - entity_id: "https://swamid.se"
          jwks_url: "https://swamid.se/.well-known/openid-federation"

  - name: "DID:Web Registry"
    type: "did_web"
    enabled: true
    priority: 3
    config:
      allowed_domains:
        - "*.example.edu"
        - "*.example.org"

resolution:
  strategy: "first_match"  # first_match | all | best_match | sequential
  timeout: "5s"
  circuit_breaker:
    max_failures: 5
    reset_timeout: "30s"
```

### 3. Handler Integration

```go
// pkg/api/handlers.go
func (s *ServerContext) AuthZENDecisionHandler(w http.ResponseWriter, r *http.Request) {
    var req authzen.EvaluationRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    if err := req.Validate(); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Use RegistryManager instead of direct CertPool validation
    resp, err := s.RegistryManager.Evaluate(r.Context(), &req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}
```

### 4. Observability & Metrics

```go
// pkg/registry/metrics.go
type RegistryMetrics struct {
    EvaluationsTotal     *prometheus.CounterVec   // by registry, result
    EvaluationDuration   *prometheus.HistogramVec // by registry
    CircuitBreakerState  *prometheus.GaugeVec     // by registry
    ParallelQueries      prometheus.Histogram
}

func (m *RegistryManager) recordMetrics(registry string, duration time.Duration, decision bool) {
    m.metrics.EvaluationsTotal.WithLabelValues(registry, fmt.Sprintf("%t", decision)).Inc()
    m.metrics.EvaluationDuration.WithLabelValues(registry).Observe(duration.Seconds())
}
```

## Use Cases

### Use Case 1: X.509 Certificate in Multiple TSLs

An entity has certificates in both EU TSL and Swedish national TSL:

```
Request: subject.id="CN=Example Org,O=Example", resource.type="x5c"

Parallel Query:
  - ETSI TSL (EU) → checks EU list → MATCH (50ms)
  - ETSI TSL (SE) → checks SE list → MATCH (40ms)

Result: First match from SE TSL returns after 40ms
```

### Use Case 2: Entity in OpenID Federation AND TSL

An OpenID Provider is registered in both OpenID Federation and has certificates in TSL:

```
Request: subject.id="https://op.example.com", resource.type="entity_configuration"

Parallel Query:
  - OpenID Federation → resolves trust chain → MATCH (200ms)
  - ETSI TSL → N/A (doesn't support entity_configuration)

Result: OpenID Federation match returns
```

### Use Case 3: DID with Multiple Methods

A DID that could resolve via multiple methods:

```
Request: subject.id="did:web:example.org", resource.type="jwk"

Parallel Query:
  - DID:Web Registry → resolves DID document → MATCH (100ms)
  - OpenID Federation → checks if example.org has entity config → NO MATCH
  - ETSI TSL → N/A

Result: DID:Web match returns
```

## Benefits

1. **Performance**: Parallel queries minimize total resolution time
2. **Resilience**: Circuit breakers prevent cascade failures
3. **Flexibility**: Different strategies for different use cases
4. **Observability**: Metrics show which registries are being used
5. **Gradual Migration**: Add new registries without disrupting existing ones

## Migration Path

### Phase 1: Extract ETSI Implementation
- Move current ETSI logic to `pkg/registry/etsi/`
- Implement `TrustRegistry` interface
- Keep backward compatibility

### Phase 2: Add RegistryManager
- Implement parallel resolution logic
- Add circuit breaker support
- Update handlers to use manager

### Phase 3: Add New Registries
- Implement OpenID Federation registry
- Implement DID:Web registry
- Configure multiple pipelines

### Phase 4: Optimize
- Add caching layers
- Tune circuit breaker parameters
- Add advanced strategies (weighted, machine learning-based)

## Future Enhancements

1. **Weighted Routing**: Prefer certain registries based on historical success rates
2. **Caching**: Shared cache across registries for resolved entities
3. **Policy-Based Routing**: Route to specific registries based on subject.id patterns
4. **Health Checks**: Periodic background health checks for registries
5. **Adaptive Timeouts**: Adjust timeouts based on registry performance
6. **Result Aggregation**: Combine confidence scores from multiple registries
