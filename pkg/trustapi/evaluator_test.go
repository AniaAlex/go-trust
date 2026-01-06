package trustapi

import (
	"context"
	"crypto"
	"testing"
)

// mockEvaluator is a test implementation of TrustEvaluator
type mockEvaluator struct {
	name     string
	healthy  bool
	decision *TrustDecision
	keyTypes []KeyType
}

func (m *mockEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error) {
	if m.decision != nil {
		return m.decision, nil
	}
	return &TrustDecision{Trusted: true}, nil
}

func (m *mockEvaluator) SupportsKeyType(kt KeyType) bool {
	for _, supported := range m.keyTypes {
		if kt == supported {
			return true
		}
	}
	return len(m.keyTypes) == 0 // empty means all types supported
}

func (m *mockEvaluator) Name() string {
	if m.name != "" {
		return m.name
	}
	return "mock"
}

func (m *mockEvaluator) Healthy() bool {
	return m.healthy
}

// mockResolver is a test implementation of KeyResolver
type mockResolver struct {
	key crypto.PublicKey
	err error
}

func (m *mockResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.key, nil
}

// Verify interface compliance at compile time
var _ TrustEvaluator = (*mockEvaluator)(nil)
var _ KeyResolver = (*mockResolver)(nil)

func TestTrustEvaluator_Interface(t *testing.T) {
	eval := &mockEvaluator{
		name:     "test-evaluator",
		healthy:  true,
		keyTypes: []KeyType{KeyTypeX5C},
		decision: &TrustDecision{
			Trusted: true,
			Reason:  "test",
		},
	}

	t.Run("Name", func(t *testing.T) {
		if eval.Name() != "test-evaluator" {
			t.Errorf("expected name 'test-evaluator', got '%s'", eval.Name())
		}
	})

	t.Run("Healthy", func(t *testing.T) {
		if !eval.Healthy() {
			t.Error("expected healthy=true")
		}
	})

	t.Run("SupportsKeyType", func(t *testing.T) {
		if !eval.SupportsKeyType(KeyTypeX5C) {
			t.Error("expected X5C to be supported")
		}
		if eval.SupportsKeyType(KeyTypeJWK) {
			t.Error("expected JWK to NOT be supported")
		}
	})

	t.Run("Evaluate", func(t *testing.T) {
		req := &EvaluationRequest{
			SubjectID: "test",
			KeyType:   KeyTypeX5C,
		}
		decision, err := eval.Evaluate(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !decision.Trusted {
			t.Error("expected Trusted=true")
		}
	})
}

func TestKeyResolver_Interface(t *testing.T) {
	resolver := &mockResolver{}

	t.Run("ResolveKey", func(t *testing.T) {
		key, err := resolver.ResolveKey(context.Background(), "did:web:example.com#key-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Key is nil in our mock, but method works
		_ = key
	})
}

func TestCombinedTrustService_Interface(t *testing.T) {
	// Verify that a type can implement CombinedTrustService
	type combined struct {
		mockEvaluator
		mockResolver
	}

	c := &combined{
		mockEvaluator: mockEvaluator{healthy: true},
	}

	// Should satisfy both interfaces
	var _ TrustEvaluator = c
	var _ KeyResolver = c
	var _ CombinedTrustService = c
}
