// Package static provides simple static trust registries.
package static

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// WhitelistRegistry is a TrustRegistry that maintains a whitelist of trusted subjects
// and validates name-to-key bindings by fetching and caching entity JWKS.
//
// Unlike simple URL-based whitelisting, this registry:
// 1. Resolves each whitelisted entity's JWKS endpoint
// 2. Extracts and normalizes public keys
// 3. Computes SHA-256 fingerprints for each key
// 4. Validates that incoming request keys match a whitelisted entity's keys
type WhitelistRegistry struct {
	name        string
	description string

	mu     sync.RWMutex
	config WhitelistConfig

	// keyHashes maps entity ID to a set of allowed key fingerprints.
	// Each entity can have multiple keys (key rotation, different purposes).
	keyHashes map[string]map[string]bool

	// HTTP client for fetching JWKS
	httpClient *http.Client

	// File watching
	configPath string
	watcher    *fsnotify.Watcher
	stopCh     chan struct{}
	logger     *slog.Logger

	// Track if keys have been loaded
	keysLoaded  bool
	lastRefresh time.Time

	// Background refresh
	refreshInterval time.Duration
	refreshStopCh   chan struct{}
}

// WhitelistConfig holds the whitelist configuration.
type WhitelistConfig struct {
	// Issuers is a list of trusted credential issuer URLs/identifiers.
	// The registry will fetch JWKS from each issuer's well-known endpoint.
	Issuers []string `json:"issuers" yaml:"issuers"`

	// Verifiers is a list of trusted verifier URLs/identifiers.
	// The registry will fetch JWKS from each verifier's well-known endpoint.
	Verifiers []string `json:"verifiers" yaml:"verifiers"`

	// TrustedSubjects is a catch-all for subjects that should be trusted
	// regardless of role. This is checked if role-specific lists don't match.
	TrustedSubjects []string `json:"trusted_subjects" yaml:"trusted_subjects"`

	// JWKSEndpointPattern specifies the URL pattern for fetching JWKS.
	// Default: "{entity}/.well-known/jwks.json"
	// Use {entity} as placeholder for the entity URL.
	JWKSEndpointPattern string `json:"jwks_endpoint_pattern,omitempty" yaml:"jwks_endpoint_pattern,omitempty"`

	// FetchTimeout is the timeout for fetching JWKS (default: 30s).
	FetchTimeout string `json:"fetch_timeout,omitempty" yaml:"fetch_timeout,omitempty"`

	// AllowHTTP allows fetching JWKS over HTTP (default: false, requires HTTPS).
	AllowHTTP bool `json:"allow_http,omitempty" yaml:"allow_http,omitempty"`

	// RefreshInterval specifies how often to refresh JWKS keys (default: 0 = no refresh).
	// Example: "5m", "1h", "30s"
	RefreshInterval string `json:"refresh_interval,omitempty" yaml:"refresh_interval,omitempty"`
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

// WithHTTPClient sets a custom HTTP client for JWKS fetching.
func WithHTTPClient(client *http.Client) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.httpClient = client
	}
}

// WithRefreshInterval sets the background refresh interval for JWKS keys.
// If set to 0 (default), no background refresh is performed.
func WithRefreshInterval(interval time.Duration) WhitelistOption {
	return func(r *WhitelistRegistry) {
		r.refreshInterval = interval
	}
}

// NewWhitelistRegistry creates a new whitelist registry.
func NewWhitelistRegistry(opts ...WhitelistOption) *WhitelistRegistry {
	r := &WhitelistRegistry{
		name:        "whitelist",
		description: "Key-binding whitelist for trusted issuers and verifiers",
		config:      WhitelistConfig{},
		logger:      slog.Default(),
		keyHashes:   make(map[string]map[string]bool),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
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

// Close stops the file watcher, refresh loop, and releases resources.
func (r *WhitelistRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Stop file watcher (only once)
	if r.stopCh != nil {
		close(r.stopCh)
		r.stopCh = nil
	}
	// Stop refresh loop (only once)
	if r.refreshStopCh != nil {
		close(r.refreshStopCh)
		r.refreshStopCh = nil
	}
	if r.watcher != nil {
		err := r.watcher.Close()
		r.watcher = nil
		return err
	}
	return nil
}

// StartRefreshLoop starts a background goroutine that periodically refreshes JWKS keys.
// This should be called after creation if background refresh is desired.
// The loop runs until Close() is called.
func (r *WhitelistRegistry) StartRefreshLoop(ctx context.Context) error {
	// Parse refresh interval from config if not set via option
	if r.refreshInterval == 0 && r.config.RefreshInterval != "" {
		duration, err := time.ParseDuration(r.config.RefreshInterval)
		if err != nil {
			return fmt.Errorf("invalid refresh_interval %q: %w", r.config.RefreshInterval, err)
		}
		r.refreshInterval = duration
	}

	if r.refreshInterval <= 0 {
		r.logger.Debug("refresh interval not set, skipping refresh loop")
		return nil
	}

	// Perform initial refresh
	if err := r.Refresh(ctx); err != nil {
		r.logger.Warn("initial refresh failed", "error", err)
		// Continue anyway - we'll retry on the next interval
	}

	// Start background loop
	r.refreshStopCh = make(chan struct{})
	go r.refreshLoop()

	r.logger.Info("started JWKS refresh loop", "interval", r.refreshInterval)
	return nil
}

// refreshLoop periodically refreshes JWKS keys.
func (r *WhitelistRegistry) refreshLoop() {
	ticker := time.NewTicker(r.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.refreshStopCh:
			r.logger.Info("stopping JWKS refresh loop")
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			if err := r.Refresh(ctx); err != nil {
				r.logger.Warn("scheduled refresh failed", "error", err)
			} else {
				r.logger.Debug("scheduled refresh completed",
					"entities", len(r.keyHashes),
					"total_keys", r.countTotalKeys())
			}
			cancel()
		}
	}
}

// Evaluate checks if the name-to-key binding is trusted.
// The subject ID must be in the whitelist AND the provided key must match
// one of the entity's registered keys (fetched from their JWKS endpoint).
func (r *WhitelistRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	subjectID := req.Subject.ID
	role := r.extractRole(req)

	// First check if subject is in whitelist
	var matchedList string
	var inWhitelist bool

	switch role {
	case "issuer", "credential-issuer", "pid-provider":
		if r.matchesList(subjectID, r.config.Issuers) {
			inWhitelist = true
			matchedList = "issuers"
		}
	case "verifier", "credential-verifier":
		if r.matchesList(subjectID, r.config.Verifiers) {
			inWhitelist = true
			matchedList = "verifiers"
		}
	}

	// Check catch-all trusted subjects
	if !inWhitelist && r.matchesList(subjectID, r.config.TrustedSubjects) {
		inWhitelist = true
		matchedList = "trusted_subjects"
	}

	if !inWhitelist {
		return r.deny(subjectID, fmt.Sprintf("subject not in whitelist for role '%s'", role))
	}

	// If this is a resolution-only request (no key provided), allow based on whitelist membership
	if req.IsResolutionOnlyRequest() {
		return r.allowResolutionOnly(subjectID, role, matchedList)
	}

	// Verify key binding: extract the key from the request and check against cached hashes
	keyFingerprint, err := r.extractKeyFingerprint(req)
	if err != nil {
		return r.deny(subjectID, fmt.Sprintf("failed to extract key: %s", err))
	}

	// Check if the key fingerprint matches any of the entity's registered keys
	allowedKeys, hasKeys := r.keyHashes[subjectID]
	if !hasKeys || len(allowedKeys) == 0 {
		// No keys cached for this entity - need to refresh
		return r.deny(subjectID, "no keys cached for entity; call Refresh() to load keys")
	}

	if allowedKeys[keyFingerprint] {
		return r.allowWithKey(subjectID, role, matchedList, keyFingerprint)
	}

	return r.deny(subjectID, "key fingerprint does not match any registered keys for this entity")
}

// extractKeyFingerprint extracts and computes fingerprint of the key from the request.
func (r *WhitelistRegistry) extractKeyFingerprint(req *authzen.EvaluationRequest) (string, error) {
	pubKey, err := ExtractPublicKeyFromRequest(req.Resource.Type, req.Resource.Key)
	if err != nil {
		return "", fmt.Errorf("extracting public key: %w", err)
	}

	fingerprint, err := KeyFingerprint(pubKey)
	if err != nil {
		return "", fmt.Errorf("computing fingerprint: %w", err)
	}

	return fingerprint, nil
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

func (r *WhitelistRegistry) allowWithKey(subject, role, matchedList, keyFingerprint string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry":        r.name,
				"type":            "whitelist",
				"role":            role,
				"matched_list":    matchedList,
				"key_fingerprint": keyFingerprint,
			},
		},
	}, nil
}

func (r *WhitelistRegistry) allowResolutionOnly(subject, role, matchedList string) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry":        r.name,
				"type":            "whitelist",
				"role":            role,
				"matched_list":    matchedList,
				"resolution_only": true,
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

// SupportedResourceTypes returns the resource types this registry can validate.
func (r *WhitelistRegistry) SupportedResourceTypes() []string {
	return []string{"jwk", "x5c"}
}

// SupportsResolutionOnly returns true since whitelist supports resolution-only requests
// (checking if entity is whitelisted without validating a specific key).
func (r *WhitelistRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *WhitelistRegistry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return registry.RegistryInfo{
		Name:           r.name,
		Type:           "static_whitelist",
		Description:    r.description,
		Version:        "2.0.0",
		ResourceTypes:  []string{"jwk", "x5c"},
		ResolutionOnly: true,
		Healthy:        r.keysLoaded,
	}
}

// Healthy returns true if keys have been loaded for whitelisted entities.
func (r *WhitelistRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.keysLoaded
}

// Refresh fetches JWKS for all whitelisted entities and caches their key fingerprints.
func (r *WhitelistRegistry) Refresh(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Collect all unique entities
	entities := make(map[string]bool)
	for _, issuer := range r.config.Issuers {
		if issuer != "*" && !strings.HasSuffix(issuer, "*") {
			entities[issuer] = true
		}
	}
	for _, verifier := range r.config.Verifiers {
		if verifier != "*" && !strings.HasSuffix(verifier, "*") {
			entities[verifier] = true
		}
	}
	for _, subject := range r.config.TrustedSubjects {
		if subject != "*" && !strings.HasSuffix(subject, "*") {
			entities[subject] = true
		}
	}

	// Clear existing key hashes
	r.keyHashes = make(map[string]map[string]bool)

	// Fetch JWKS for each entity
	var errors []string
	for entity := range entities {
		keys, err := r.fetchEntityKeys(ctx, entity)
		if err != nil {
			r.logger.Warn("failed to fetch keys for entity",
				"entity", entity,
				"error", err)
			errors = append(errors, fmt.Sprintf("%s: %s", entity, err))
			continue
		}

		keySet := make(map[string]bool)
		for _, key := range keys {
			fingerprint, err := KeyFingerprint(key)
			if err != nil {
				r.logger.Warn("failed to compute key fingerprint",
					"entity", entity,
					"error", err)
				continue
			}
			keySet[fingerprint] = true
		}

		if len(keySet) > 0 {
			r.keyHashes[entity] = keySet
			r.logger.Info("loaded keys for entity",
				"entity", entity,
				"key_count", len(keySet))
		}
	}

	r.keysLoaded = len(r.keyHashes) > 0 || len(entities) == 0
	r.lastRefresh = time.Now()

	if len(errors) > 0 {
		return fmt.Errorf("failed to fetch keys for %d entities", len(errors))
	}

	r.logger.Info("whitelist keys refreshed",
		"entities", len(r.keyHashes),
		"total_keys", r.countTotalKeys())
	return nil
}

// countTotalKeys returns the total number of cached key fingerprints.
func (r *WhitelistRegistry) countTotalKeys() int {
	count := 0
	for _, keys := range r.keyHashes {
		count += len(keys)
	}
	return count
}

// fetchEntityKeys fetches JWKS from an entity's well-known endpoint.
func (r *WhitelistRegistry) fetchEntityKeys(ctx context.Context, entity string) ([]crypto.PublicKey, error) {
	// Determine JWKS URL
	jwksURL := r.buildJWKSURL(entity)

	// Validate URL scheme
	if !r.config.AllowHTTP && !strings.HasPrefix(jwksURL, "https://") {
		return nil, fmt.Errorf("HTTPS required for JWKS fetch (got %s)", jwksURL)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	// Fetch JWKS
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var jwks map[string]interface{}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	return ExtractPublicKeysFromJWKS(jwks)
}

// buildJWKSURL constructs the JWKS URL for an entity.
func (r *WhitelistRegistry) buildJWKSURL(entity string) string {
	pattern := r.config.JWKSEndpointPattern
	if pattern == "" {
		pattern = "{entity}/.well-known/jwks.json"
	}

	// Ensure entity has no trailing slash
	entity = strings.TrimSuffix(entity, "/")

	// Replace placeholder
	return strings.ReplaceAll(pattern, "{entity}", entity)
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
