// Package static provides simple static trust registries.
package static

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// WhitelistRegistry is a TrustRegistry that maintains a whitelist of trusted subjects.
//
// This is the simplest trust model: if a subject URL is in the whitelist, it's trusted.
// For more sophisticated trust evaluation (certificate validation, key binding, etc.),
// use ETSI, OpenID Federation, or other registries.
type WhitelistRegistry struct {
	name        string
	description string

	mu     sync.RWMutex
	config WhitelistConfig

	// File watching
	configPath string
	watcher    *fsnotify.Watcher
	stopCh     chan struct{}
	logger     *slog.Logger
}

// WhitelistConfig holds the whitelist configuration.
type WhitelistConfig struct {
	// Issuers is a list of trusted credential issuer URLs/identifiers.
	Issuers []string `json:"issuers" yaml:"issuers"`

	// Verifiers is a list of trusted verifier URLs/identifiers.
	Verifiers []string `json:"verifiers" yaml:"verifiers"`

	// TrustedSubjects is a catch-all for subjects that should be trusted
	// regardless of role. This is checked if role-specific lists don't match.
	TrustedSubjects []string `json:"trusted_subjects" yaml:"trusted_subjects"`
}

// WhitelistOption is a functional option for configuring WhitelistRegistry.
type WhitelistOption func(*WhitelistRegistry)

// WithWhitelistName sets the registry name.
func WithWhitelistName(name string) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.name = name
	}
}

// WithWhitelistDescription sets the registry description.
func WithWhitelistDescription(desc string) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.description = desc
	}
}

// WithWhitelistConfig sets the initial configuration.
func WithWhitelistConfig(cfg WhitelistConfig) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.config = cfg
	}
}

// WithWhitelistLogger sets the logger for file watch events.
func WithWhitelistLogger(logger *slog.Logger) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.logger = logger
	}
}

// NewWhitelistRegistry creates a new whitelist registry.
func NewWhitelistRegistry(opts ...WhitelistOption) *WhitelistRegistry {
	r := &WhitelistRegistry{
		name:        "whitelist",
		description: "Simple URL whitelist for trusted issuers and verifiers",
		config:      WhitelistConfig{},
		logger:      slog.Default(),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// NewWhitelistRegistryFromFile creates a whitelist registry from a config file.
// Supports JSON and YAML formats (detected by file extension).
// If watch is true, the registry will monitor the file for changes and reload automatically.
func NewWhitelistRegistryFromFile(path string, watch bool, opts ...WhitelistOption) (*WhitelistRegistry, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	cfg, err := loadWhitelistConfig(absPath)
	if err != nil {
		return nil, err
	}

	opts = append(opts, WithWhitelistConfig(cfg))
	r := NewWhitelistRegistry(opts...)
	r.configPath = absPath

	if watch {
		if err := r.startWatching(); err != nil {
			return nil, fmt.Errorf("starting file watcher: %w", err)
		}
	}

	return r, nil
}

// loadWhitelistConfig loads configuration from a file.
func loadWhitelistConfig(path string) (WhitelistConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return WhitelistConfig{}, fmt.Errorf("reading whitelist config: %w", err)
	}

	var cfg WhitelistConfig
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return WhitelistConfig{}, fmt.Errorf("parsing YAML config: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return WhitelistConfig{}, fmt.Errorf("parsing JSON config: %w", err)
		}
	}

	return cfg, nil
}

// startWatching begins monitoring the config file for changes.
func (r *WhitelistRegistry) startWatching() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}

	// Watch the directory containing the config file (handles atomic renames)
	dir := filepath.Dir(r.configPath)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close() // Best effort cleanup on error path
		return fmt.Errorf("watching directory %s: %w", dir, err)
	}

	r.watcher = watcher
	r.stopCh = make(chan struct{})

	go r.watchLoop()

	r.logger.Info("started watching config file", "path", r.configPath)
	return nil
}

// watchLoop handles file system events.
func (r *WhitelistRegistry) watchLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			// Check if this event is for our config file
			if filepath.Clean(event.Name) != r.configPath {
				continue
			}
			// Reload on write or create (create handles atomic replace via rename)
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				r.logger.Info("config file changed, reloading", "path", r.configPath, "op", event.Op.String())
				if err := r.reloadConfig(); err != nil {
					r.logger.Error("failed to reload config", "error", err)
				}
			}
		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.Error("file watcher error", "error", err)
		}
	}
}

// reloadConfig reloads the configuration from the file.
func (r *WhitelistRegistry) reloadConfig() error {
	cfg, err := loadWhitelistConfig(r.configPath)
	if err != nil {
		return err
	}

	r.mu.Lock()
	r.config = cfg
	r.mu.Unlock()

	r.logger.Info("config reloaded",
		"issuers", len(cfg.Issuers),
		"verifiers", len(cfg.Verifiers),
		"trusted_subjects", len(cfg.TrustedSubjects))
	return nil
}

// Close stops the file watcher and releases resources.
func (r *WhitelistRegistry) Close() error {
	if r.stopCh != nil {
		close(r.stopCh)
	}
	if r.watcher != nil {
		return r.watcher.Close()
	}
	return nil
}

// Evaluate checks if the subject is in the whitelist.
func (r *WhitelistRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	subjectID := req.Subject.ID

	// Determine role from action
	role := r.extractRole(req)

	// Check role-specific lists first
	switch role {
	case "issuer", "credential-issuer", "pid-provider":
		if r.matchesList(subjectID, r.config.Issuers) {
			return r.allow(subjectID, role, "issuers")
		}
	case "verifier", "credential-verifier":
		if r.matchesList(subjectID, r.config.Verifiers) {
			return r.allow(subjectID, role, "verifiers")
		}
	}

	// Check catch-all trusted subjects
	if r.matchesList(subjectID, r.config.TrustedSubjects) {
		return r.allow(subjectID, role, "trusted_subjects")
	}

	return r.deny(subjectID, fmt.Sprintf("subject not in whitelist for role '%s'", role))
}

// extractRole extracts the role from the request action.
func (r *WhitelistRegistry) extractRole(req *authzen.EvaluationRequest) string {
	if req.Action != nil && req.Action.Name != "" {
		return strings.ToLower(req.Action.Name)
	}
	return "any"
}

// matchesList checks if subject matches any entry in the list.
// Supports exact match and prefix match (entries ending with *).
func (r *WhitelistRegistry) matchesList(subject string, list []string) bool {
	for _, entry := range list {
		if entry == "*" {
			return true // Wildcard matches all
		}
		if strings.HasSuffix(entry, "*") {
			prefix := strings.TrimSuffix(entry, "*")
			if strings.HasPrefix(subject, prefix) {
				return true
			}
		} else if entry == subject {
			return true
		}
	}
	return false
}

func (r *WhitelistRegistry) allow(subject, role, matchedList string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry":     r.name,
				"type":         "whitelist",
				"role":         role,
				"matched_list": matchedList,
			},
		},
	}, nil
}

func (r *WhitelistRegistry) deny(subject, reason string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry": r.name,
				"type":     "whitelist",
				"error":    reason,
			},
		},
	}, nil
}

// SupportedResourceTypes returns all types since whitelist doesn't validate keys.
func (r *WhitelistRegistry) SupportedResourceTypes() []string {
	return []string{"*"}
}

// SupportsResolutionOnly returns true since whitelist doesn't require key material.
func (r *WhitelistRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *WhitelistRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:           r.name,
		Type:           "static_whitelist",
		Description:    r.description,
		Version:        "1.0.0",
		ResourceTypes:  []string{"*"},
		ResolutionOnly: true,
		Healthy:        true,
	}
}

// Healthy always returns true.
func (r *WhitelistRegistry) Healthy() bool {
	return true
}

// Refresh reloads the configuration (no-op for in-memory config).
func (r *WhitelistRegistry) Refresh(ctx context.Context) error {
	return nil
}

// --- Runtime configuration methods ---

// GetConfig returns a copy of the current configuration.
func (r *WhitelistRegistry) GetConfig() WhitelistConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return WhitelistConfig{
		Issuers:         append([]string{}, r.config.Issuers...),
		Verifiers:       append([]string{}, r.config.Verifiers...),
		TrustedSubjects: append([]string{}, r.config.TrustedSubjects...),
	}
}

// SetConfig replaces the entire configuration.
func (r *WhitelistRegistry) SetConfig(cfg WhitelistConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config = cfg
}

// AddIssuer adds an issuer to the whitelist.
func (r *WhitelistRegistry) AddIssuer(issuer string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Avoid duplicates
	for _, existing := range r.config.Issuers {
		if existing == issuer {
			return
		}
	}
	r.config.Issuers = append(r.config.Issuers, issuer)
}

// RemoveIssuer removes an issuer from the whitelist.
func (r *WhitelistRegistry) RemoveIssuer(issuer string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.config.Issuers {
		if existing == issuer {
			r.config.Issuers = append(r.config.Issuers[:i], r.config.Issuers[i+1:]...)
			return
		}
	}
}

// AddVerifier adds a verifier to the whitelist.
func (r *WhitelistRegistry) AddVerifier(verifier string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Avoid duplicates
	for _, existing := range r.config.Verifiers {
		if existing == verifier {
			return
		}
	}
	r.config.Verifiers = append(r.config.Verifiers, verifier)
}

// RemoveVerifier removes a verifier from the whitelist.
func (r *WhitelistRegistry) RemoveVerifier(verifier string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.config.Verifiers {
		if existing == verifier {
			r.config.Verifiers = append(r.config.Verifiers[:i], r.config.Verifiers[i+1:]...)
			return
		}
	}
}

// Compile-time check that WhitelistRegistry implements TrustRegistry
var _ registry.TrustRegistry = (*WhitelistRegistry)(nil)
