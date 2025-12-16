package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// RegistryManager coordinates multiple TrustRegistry implementations.
// It routes evaluation requests to applicable registries based on their
// SupportedResourceTypes and executes queries according to the configured
// ResolutionStrategy.
type RegistryManager struct {
	registries      []TrustRegistry
	strategy        ResolutionStrategy
	timeout         time.Duration
	circuitBreakers map[string]*CircuitBreaker
	mu              sync.RWMutex
}

// NewRegistryManager creates a new RegistryManager with the specified strategy and timeout.
//
// strategy: How to aggregate results from multiple registries
// timeout: Maximum time to wait for registry responses
func NewRegistryManager(strategy ResolutionStrategy, timeout time.Duration) *RegistryManager {
	return &RegistryManager{
		registries:      make([]TrustRegistry, 0),
		strategy:        strategy,
		timeout:         timeout,
		circuitBreakers: make(map[string]*CircuitBreaker),
	}
}

// Register adds a TrustRegistry to the manager. Registries are queried in the
// order they are registered when using Sequential strategy.
func (m *RegistryManager) Register(registry TrustRegistry) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.registries = append(m.registries, registry)

	// Create circuit breaker for this registry
	info := registry.Info()
	m.circuitBreakers[info.Name] = NewCircuitBreaker(5, 30*time.Second)
}

// Evaluate implements the TrustRegistry interface by delegating to registered registries
// according to the configured strategy.
func (m *RegistryManager) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Validate request first
	if err := req.Validate(); err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("invalid request: %v", err),
				},
			},
		}, nil
	}

	// Route to appropriate strategy
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

// SupportedResourceTypes returns the union of all resource types supported by registered registries
func (m *RegistryManager) SupportedResourceTypes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	typeSet := make(map[string]bool)
	for _, reg := range m.registries {
		for _, rt := range reg.SupportedResourceTypes() {
			typeSet[rt] = true
		}
	}

	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}
	return types
}

// Info returns metadata about the RegistryManager
func (m *RegistryManager) Info() RegistryInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	anchors := make([]string, 0)
	for _, reg := range m.registries {
		info := reg.Info()
		anchors = append(anchors, info.TrustAnchors...)
	}

	return RegistryInfo{
		Name:         "Registry Manager",
		Type:         "manager",
		Description:  fmt.Sprintf("Manages %d trust registries with %s strategy", len(m.registries), m.strategy),
		Version:      "1.0.0",
		TrustAnchors: anchors,
	}
}

// Healthy returns true if at least one registry is healthy
func (m *RegistryManager) Healthy() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, reg := range m.registries {
		if reg.Healthy() {
			return true
		}
	}
	return len(m.registries) == 0 // No registries = healthy (for startup)
}

// Refresh refreshes all registered registries
func (m *RegistryManager) Refresh(ctx context.Context) error {
	m.mu.RLock()
	registries := make([]TrustRegistry, len(m.registries))
	copy(registries, m.registries)
	m.mu.RUnlock()

	var errs []error
	for _, reg := range registries {
		if err := reg.Refresh(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", reg.Info().Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("refresh errors: %v", errs)
	}
	return nil
}

// getApplicableRegistries filters registries that support the requested resource type
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
