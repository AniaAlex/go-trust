package static

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

func TestWhitelistRegistry_Evaluate(t *testing.T) {
	tests := []struct {
		name     string
		config   WhitelistConfig
		request  *authzen.EvaluationRequest
		decision bool
	}{
		{
			name: "issuer in whitelist",
			config: WhitelistConfig{
				Issuers: []string{"https://issuer.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://issuer.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "issuer not in whitelist",
			config: WhitelistConfig{
				Issuers: []string{"https://other.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://issuer.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: false,
		},
		{
			name: "verifier in whitelist",
			config: WhitelistConfig{
				Verifiers: []string{"https://verifier.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://verifier.example.com"},
				Action:  &authzen.Action{Name: "verifier"},
			},
			decision: true,
		},
		{
			name: "wildcard prefix match",
			config: WhitelistConfig{
				Issuers: []string{"https://example.com/*"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://example.com/issuer1"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "trusted_subjects fallback",
			config: WhitelistConfig{
				TrustedSubjects: []string{"https://trusted.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://trusted.example.com"},
				Action:  &authzen.Action{Name: "custom-role"},
			},
			decision: true,
		},
		{
			name: "global wildcard",
			config: WhitelistConfig{
				Issuers: []string{"*"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://any.example.com"},
				Action:  &authzen.Action{Name: "issuer"},
			},
			decision: true,
		},
		{
			name: "credential-issuer role matches issuers list",
			config: WhitelistConfig{
				Issuers: []string{"https://pid.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://pid.example.com"},
				Action:  &authzen.Action{Name: "credential-issuer"},
			},
			decision: true,
		},
		{
			name: "credential-verifier role matches verifiers list",
			config: WhitelistConfig{
				Verifiers: []string{"https://rp.example.com"},
			},
			request: &authzen.EvaluationRequest{
				Subject: authzen.Subject{ID: "https://rp.example.com"},
				Action:  &authzen.Action{Name: "credential-verifier"},
			},
			decision: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewWhitelistRegistry(WithWhitelistConfig(tt.config))

			resp, err := reg.Evaluate(context.Background(), tt.request)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != tt.decision {
				t.Errorf("expected decision=%v, got %v", tt.decision, resp.Decision)
			}
		})
	}
}

func TestWhitelistRegistry_FromFile(t *testing.T) {
	// Create temp YAML config
	yamlContent := `
issuers:
  - https://issuer1.example.com
  - https://issuer2.example.com
verifiers:
  - https://verifier.example.com
`

	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "whitelist.yaml")
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	reg, err := NewWhitelistRegistryFromFile(yamlPath, false)
	if err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}

	// Test that config was loaded
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer1.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected issuer to be trusted")
	}
}

func TestWhitelistRegistry_FileWatch(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "whitelist.yaml")

	// Initial config - only issuer1 trusted
	initialConfig := `
issuers:
  - https://issuer1.example.com
`
	if err := os.WriteFile(yamlPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	// Create registry with file watching enabled
	reg, err := NewWhitelistRegistryFromFile(yamlPath, true)
	if err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}
	defer reg.Close()

	// Verify initial config
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer2.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}
	resp, _ := reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Error("issuer2 should NOT be trusted initially")
	}

	// Update config - add issuer2
	updatedConfig := `
issuers:
  - https://issuer1.example.com
  - https://issuer2.example.com
`
	if err := os.WriteFile(yamlPath, []byte(updatedConfig), 0644); err != nil {
		t.Fatalf("failed to update yaml file: %v", err)
	}

	// Wait for file watcher to pick up the change
	time.Sleep(200 * time.Millisecond)

	// Verify config was reloaded
	resp, _ = reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Error("issuer2 should be trusted after config reload")
	}
}

func TestWhitelistRegistry_RuntimeUpdates(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Initially empty - should deny
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, _ := reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Error("expected deny for empty whitelist")
	}

	// Add issuer at runtime
	reg.AddIssuer("https://issuer.example.com")

	resp, _ = reg.Evaluate(context.Background(), req)
	if !resp.Decision {
		t.Error("expected allow after adding issuer")
	}

	// Remove issuer
	reg.RemoveIssuer("https://issuer.example.com")

	resp, _ = reg.Evaluate(context.Background(), req)
	if resp.Decision {
		t.Error("expected deny after removing issuer")
	}
}

func TestWhitelistRegistry_Info(t *testing.T) {
	reg := NewWhitelistRegistry(
		WithWhitelistName("my-whitelist"),
		WithWhitelistDescription("Test whitelist"),
	)

	info := reg.Info()

	if info.Name != "my-whitelist" {
		t.Errorf("expected name 'my-whitelist', got %q", info.Name)
	}
	if info.Type != "static_whitelist" {
		t.Errorf("expected type 'static_whitelist', got %q", info.Type)
	}
	if !info.ResolutionOnly {
		t.Error("expected ResolutionOnly=true")
	}
	if !info.Healthy {
		t.Error("expected Healthy=true")
	}
}

func TestWhitelistRegistry_AddRemoveVerifier(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Add verifier
	reg.AddVerifier("https://verifier.example.com")

	cfg := reg.GetConfig()
	if len(cfg.Verifiers) != 1 || cfg.Verifiers[0] != "https://verifier.example.com" {
		t.Errorf("unexpected verifiers: %v", cfg.Verifiers)
	}

	// Add duplicate - should be ignored
	reg.AddVerifier("https://verifier.example.com")
	cfg = reg.GetConfig()
	if len(cfg.Verifiers) != 1 {
		t.Errorf("expected 1 verifier after duplicate add, got %d", len(cfg.Verifiers))
	}

	// Remove
	reg.RemoveVerifier("https://verifier.example.com")
	cfg = reg.GetConfig()
	if len(cfg.Verifiers) != 0 {
		t.Errorf("expected 0 verifiers after remove, got %d", len(cfg.Verifiers))
	}
}

func TestWhitelistRegistry_JSONConfig(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "whitelist.json")

	jsonContent := `{
"issuers": ["https://issuer.example.com"],
"verifiers": ["https://verifier.example.com"]
}`
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		t.Fatalf("failed to write json file: %v", err)
	}

	reg, err := NewWhitelistRegistryFromFile(jsonPath, false)
	if err != nil {
		t.Fatalf("failed to load from file: %v", err)
	}

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://issuer.example.com"},
		Action:  &authzen.Action{Name: "issuer"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected issuer to be trusted")
	}
}

func TestWhitelistRegistry_InterfaceMethods(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Test SupportedResourceTypes
	types := reg.SupportedResourceTypes()
	if len(types) != 1 || types[0] != "*" {
		t.Errorf("expected [*], got %v", types)
	}

	// Test SupportsResolutionOnly
	if !reg.SupportsResolutionOnly() {
		t.Error("expected SupportsResolutionOnly to return true")
	}

	// Test Healthy
	if !reg.Healthy() {
		t.Error("expected Healthy to return true")
	}

	// Test Refresh (no-op)
	if err := reg.Refresh(context.Background()); err != nil {
		t.Errorf("expected Refresh to succeed, got %v", err)
	}
}

func TestWhitelistRegistry_SetConfig(t *testing.T) {
	reg := NewWhitelistRegistry()

	newCfg := WhitelistConfig{
		Issuers:   []string{"https://new-issuer.example.com"},
		Verifiers: []string{"https://new-verifier.example.com"},
	}
	reg.SetConfig(newCfg)

	cfg := reg.GetConfig()
	if len(cfg.Issuers) != 1 || cfg.Issuers[0] != "https://new-issuer.example.com" {
		t.Errorf("SetConfig did not update issuers: %v", cfg.Issuers)
	}
}

func TestWhitelistRegistry_WithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	reg := NewWhitelistRegistry(WithWhitelistLogger(logger))

	if reg.logger != logger {
		t.Error("expected custom logger to be set")
	}
}

func TestWhitelistRegistry_NilAction(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		TrustedSubjects: []string{"https://subject.example.com"},
	}))

	// Request without action
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://subject.example.com"},
		Action:  nil,
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected subject in trusted_subjects to be trusted even with nil action")
	}
}

func TestWhitelistRegistry_AddIssuerDuplicate(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Add issuer
	reg.AddIssuer("https://issuer.example.com")

	// Add same issuer again (duplicate)
	reg.AddIssuer("https://issuer.example.com")

	cfg := reg.GetConfig()
	if len(cfg.Issuers) != 1 {
		t.Errorf("expected 1 issuer after duplicate add, got %d", len(cfg.Issuers))
	}
}

func TestWhitelistRegistry_RemoveNonexistent(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Try to remove issuer that doesn't exist
	reg.RemoveIssuer("https://nonexistent.example.com")
	// Should not panic or error

	// Try to remove verifier that doesn't exist
	reg.RemoveVerifier("https://nonexistent.example.com")
	// Should not panic or error
}

func TestWhitelistRegistry_FileNotFound(t *testing.T) {
	_, err := NewWhitelistRegistryFromFile("/nonexistent/path/whitelist.yaml", false)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestWhitelistRegistry_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "invalid.yaml")

	if err := os.WriteFile(yamlPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("failed to write invalid yaml: %v", err)
	}

	_, err := NewWhitelistRegistryFromFile(yamlPath, false)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestWhitelistRegistry_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "invalid.json")

	if err := os.WriteFile(jsonPath, []byte("{invalid json"), 0644); err != nil {
		t.Fatalf("failed to write invalid json: %v", err)
	}

	_, err := NewWhitelistRegistryFromFile(jsonPath, false)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestWhitelistRegistry_CloseWithoutWatcher(t *testing.T) {
	reg := NewWhitelistRegistry()

	// Close should not panic when watcher was never started
	err := reg.Close()
	if err != nil {
		t.Errorf("Close should not error without watcher: %v", err)
	}
}

func TestWhitelistRegistry_PidProviderRole(t *testing.T) {
	reg := NewWhitelistRegistry(WithWhitelistConfig(WhitelistConfig{
		Issuers: []string{"https://pid-provider.example.com"},
	}))

	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{ID: "https://pid-provider.example.com"},
		Action:  &authzen.Action{Name: "pid-provider"},
	}

	resp, err := reg.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected pid-provider to match issuers list")
	}
}
