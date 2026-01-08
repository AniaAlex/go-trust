// Package etsi provides a TrustRegistry implementation for ETSI TS 119 612 Trust Status Lists.
//
// This package provides a unified TSLRegistry that can load trust data from:
//   - Local PEM certificate bundles
//   - Local TSL XML files
//   - Remote TSL URLs (with optional reference following)
//
// The registry uses etsi119612.FetchTSLWithOptions directly without any pipeline dependency.
//
// # Usage Examples
//
//	// Load from local PEM bundle (recommended for production)
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:       "EU-TSL",
//	    CertBundle: "/var/lib/go-trust/eu-trusted-certs.pem",
//	})
//
//	// Load from local TSL XML files
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:     "EU-TSL",
//	    TSLFiles: []string{"/var/lib/go-trust/eu-lotl.xml"},
//	})
//
//	// Load from remote URL with reference following
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:         "EU-LOTL",
//	    TSLURLs:      []string{"https://ec.europa.eu/tools/lotl/eu-lotl.xml"},
//	    FollowRefs:   true,
//	    MaxRefDepth:  3,
//	})
package etsi

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
	"github.com/sirosfoundation/g119612/pkg/utils/x509util"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// TSLConfig configures an ETSI TSL registry.
type TSLConfig struct {
	// Name is a human-readable identifier for this registry
	Name string

	// Description provides additional context about this registry
	Description string

	// CertBundle is the path to a PEM file containing trusted CA certificates.
	// This is the recommended way to load trust data for production use.
	CertBundle string

	// TSLFiles is a list of paths to local TSL XML files.
	// These files must already exist locally.
	TSLFiles []string

	// TSLURLs is a list of URLs to fetch TSL XML from.
	// Can be file:// URLs for local files or http(s):// URLs for remote.
	TSLURLs []string

	// FollowRefs controls whether to follow TSL references (pointers to other TSLs).
	// Only applicable when loading from TSLURLs.
	// Default: false (don't follow references)
	FollowRefs bool

	// MaxRefDepth controls how deep to follow TSL references.
	// Only used when FollowRefs is true.
	// Default: 3
	MaxRefDepth int

	// FetchTimeout is the timeout for HTTP requests when fetching remote TSLs.
	// Default: 30 seconds
	FetchTimeout time.Duration

	// UserAgent is the User-Agent header for HTTP requests.
	// Default: "Go-Trust/1.0 TSL Registry"
	UserAgent string

	// AllowNetworkAccess controls whether network URLs are permitted.
	// Set to false for production servers that should only use local files.
	// Default: false
	AllowNetworkAccess bool
}

// TSLRegistry implements TrustRegistry for ETSI TS 119 612 Trust Status Lists.
// It loads TSL data directly using etsi119612.FetchTSLWithOptions without pipeline dependency.
type TSLRegistry struct {
	config      TSLConfig
	certPool    *x509.CertPool
	certCount   int
	tsls        []*etsi119612.TSL
	loadedAt    time.Time
	sourceFiles []string
	mu          sync.RWMutex
	healthy     bool
	lastError   error
}

// NewTSLRegistry creates a new ETSI TSL registry.
// It loads trust data from the configured sources (cert bundles, local files, or URLs).
func NewTSLRegistry(cfg TSLConfig) (*TSLRegistry, error) {
	if cfg.Name == "" {
		cfg.Name = "ETSI-TSL"
	}
	if cfg.Description == "" {
		cfg.Description = "ETSI TS 119 612 Trust Status List Registry"
	}
	if cfg.MaxRefDepth == 0 {
		cfg.MaxRefDepth = 3
	}
	if cfg.FetchTimeout == 0 {
		cfg.FetchTimeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Go-Trust/1.0 TSL Registry (+https://github.com/sirosfoundation/go-trust)"
	}

	r := &TSLRegistry{
		config: cfg,
	}

	if err := r.load(); err != nil {
		return nil, fmt.Errorf("failed to load trust data: %w", err)
	}

	return r, nil
}

// load reads trust data from configured sources.
func (r *TSLRegistry) load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var pool *x509.CertPool
	var certCount int
	var tsls []*etsi119612.TSL
	var sourceFiles []string

	// Load from PEM certificate bundle
	if r.config.CertBundle != "" {
		p, count, err := r.loadCertBundle(r.config.CertBundle)
		if err != nil {
			r.lastError = err
			r.healthy = false
			return err
		}
		pool = p
		certCount = count
		absPath, _ := filepath.Abs(r.config.CertBundle)
		sourceFiles = append(sourceFiles, absPath)
	}

	// Load from local TSL XML files
	for _, tslPath := range r.config.TSLFiles {
		// Reject network URLs in TSLFiles
		if strings.HasPrefix(tslPath, "http://") || strings.HasPrefix(tslPath, "https://") {
			r.lastError = fmt.Errorf("network URLs not allowed in TSLFiles: %s", tslPath)
			r.healthy = false
			return r.lastError
		}

		tsl, certs, err := r.loadLocalTSL(tslPath)
		if err != nil {
			r.lastError = err
			r.healthy = false
			return err
		}

		tsls = append(tsls, tsl)
		absPath, _ := filepath.Abs(tslPath)
		sourceFiles = append(sourceFiles, absPath)

		if pool == nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range certs {
			pool.AddCert(cert)
			certCount++
		}
	}

	// Load from TSL URLs (local file:// or remote http(s)://)
	for _, tslURL := range r.config.TSLURLs {
		// Check if network access is allowed
		if !r.config.AllowNetworkAccess {
			if strings.HasPrefix(tslURL, "http://") || strings.HasPrefix(tslURL, "https://") {
				r.lastError = fmt.Errorf("network URL not allowed (AllowNetworkAccess=false): %s", tslURL)
				r.healthy = false
				return r.lastError
			}
		}

		loadedTSLs, certs, err := r.loadTSLFromURL(tslURL)
		if err != nil {
			r.lastError = err
			r.healthy = false
			return err
		}

		tsls = append(tsls, loadedTSLs...)
		sourceFiles = append(sourceFiles, tslURL)

		if pool == nil {
			pool = x509.NewCertPool()
		}
		for _, cert := range certs {
			pool.AddCert(cert)
			certCount++
		}
	}

	// Verify we have some trust data
	if pool == nil || certCount == 0 {
		r.lastError = fmt.Errorf("no trust data loaded")
		r.healthy = false
		return fmt.Errorf("no trust data loaded - configure CertBundle, TSLFiles, or TSLURLs")
	}

	r.certPool = pool
	r.certCount = certCount
	r.tsls = tsls
	r.sourceFiles = sourceFiles
	r.loadedAt = time.Now()
	r.healthy = true
	r.lastError = nil

	return nil
}

// loadCertBundle reads certificates from a PEM file.
func (r *TSLRegistry) loadCertBundle(path string) (*x509.CertPool, int, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid cert bundle path: %w", err)
	}

	pemData, err := os.ReadFile(absPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read cert bundle %s: %w", absPath, err)
	}

	pool := x509.NewCertPool()
	var certCount int
	var block *pem.Block
	rest := pemData
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// Log warning but continue - one bad cert shouldn't fail the whole bundle
				continue
			}
			pool.AddCert(cert)
			certCount++
		}
	}

	if certCount == 0 {
		return nil, 0, fmt.Errorf("no valid certificates found in %s", absPath)
	}

	return pool, certCount, nil
}

// loadLocalTSL loads a TSL from a local file path.
func (r *TSLRegistry) loadLocalTSL(path string) (*etsi119612.TSL, []*x509.Certificate, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid TSL path %s: %w", path, err)
	}

	// Verify file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("TSL file does not exist: %s", absPath)
	}

	// Use file:// URL for FetchTSLWithOptions
	fileURL := "file://" + absPath

	opts := etsi119612.TSLFetchOptions{
		UserAgent:           r.config.UserAgent,
		Timeout:             r.config.FetchTimeout,
		MaxDereferenceDepth: 0, // Don't follow references for local files
	}

	tsl, err := etsi119612.FetchTSLWithOptions(fileURL, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSL from %s: %w", absPath, err)
	}

	// Extract certificates from TSL
	certs := extractCertsFromTSL(tsl)

	return tsl, certs, nil
}

// loadTSLFromURL loads a TSL from a URL (file:// or http(s)://).
func (r *TSLRegistry) loadTSLFromURL(url string) ([]*etsi119612.TSL, []*x509.Certificate, error) {
	// Convert local paths to file:// URLs
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "file://") {
		absPath, err := filepath.Abs(url)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid path %s: %w", url, err)
		}
		url = "file://" + absPath
	}

	opts := etsi119612.TSLFetchOptions{
		UserAgent:     r.config.UserAgent,
		Timeout:       r.config.FetchTimeout,
		AcceptHeaders: []string{"application/xml", "text/xml", "application/xhtml+xml", "text/html;q=0.9", "*/*;q=0.8"},
	}

	var tsls []*etsi119612.TSL
	var err error

	if r.config.FollowRefs {
		opts.MaxDereferenceDepth = r.config.MaxRefDepth
		tsls, err = etsi119612.FetchTSLWithReferencesAndOptions(url, opts)
	} else {
		opts.MaxDereferenceDepth = 0
		var tsl *etsi119612.TSL
		tsl, err = etsi119612.FetchTSLWithOptions(url, opts)
		if tsl != nil {
			tsls = []*etsi119612.TSL{tsl}
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TSL from %s: %w", url, err)
	}

	// Extract certificates from all loaded TSLs
	var allCerts []*x509.Certificate
	for _, tsl := range tsls {
		certs := extractCertsFromTSL(tsl)
		allCerts = append(allCerts, certs...)
	}

	return tsls, allCerts, nil
}

// extractCertsFromTSL extracts all X.509 certificates from a TSL.
func extractCertsFromTSL(tsl *etsi119612.TSL) []*x509.Certificate {
	var certs []*x509.Certificate

	if tsl == nil || tsl.StatusList.TslTrustServiceProviderList == nil {
		return certs
	}

	for _, provider := range tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider {
		if provider == nil || provider.TslTSPServices == nil {
			continue
		}
		for _, service := range provider.TslTSPServices.TslTSPService {
			if service == nil || service.TslServiceInformation == nil {
				continue
			}
			serviceCerts := extractCertsFromService(service)
			certs = append(certs, serviceCerts...)
		}
	}

	return certs
}

// extractCertsFromService extracts X.509 certificates from a TSL service entry.
func extractCertsFromService(service *etsi119612.TSPServiceType) []*x509.Certificate {
	var certs []*x509.Certificate

	if service.TslServiceInformation == nil ||
		service.TslServiceInformation.TslServiceDigitalIdentity == nil {
		return certs
	}

	for _, digitalId := range service.TslServiceInformation.TslServiceDigitalIdentity.DigitalId {
		if digitalId == nil || digitalId.X509Certificate == "" {
			continue
		}
		// The certificate is base64 encoded in the XML - decode it
		certBytes, err := base64Decode(digitalId.X509Certificate)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}

// base64Decode decodes a base64 string, handling both standard and URL-safe encodings.
func base64Decode(s string) ([]byte, error) {
	// Remove any whitespace
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")

	// Try standard base64 first
	data, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return data, nil
	}

	// Try URL-safe base64
	return base64.URLEncoding.DecodeString(s)
}

// Evaluate implements TrustRegistry.Evaluate by validating X.509 certificates
// against the loaded certificate pool.
func (r *TSLRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
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

	// Validate certificate chain against cert pool
	if r.certPool == nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": "certificate pool not initialized",
				},
			},
		}, nil
	}

	start := time.Now()
	opts := x509.VerifyOptions{
		Roots: r.certPool,
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
				"tsl_count":     len(r.tsls),
				"trusted_certs": r.certCount,
				"validation_ms": validationDuration.Milliseconds(),
				"chain_length":  len(chains),
				"data_loaded":   r.loadedAt.Format(time.RFC3339),
			},
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *TSLRegistry) SupportedResourceTypes() []string {
	return []string{"x5c", "jwk"}
}

// SupportsResolutionOnly returns false - ETSI TSL requires certificate validation.
func (r *TSLRegistry) SupportsResolutionOnly() bool {
	return false
}

// Info returns metadata about this registry.
func (r *TSLRegistry) Info() registry.RegistryInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	trustAnchors := make([]string, 0, len(r.tsls))
	for _, tsl := range r.tsls {
		if tsl != nil {
			summary := tsl.Summary()
			if territory, ok := summary["territory"].(string); ok {
				trustAnchors = append(trustAnchors, fmt.Sprintf("TSL:%s", territory))
			}
		}
	}
	// Add source files as trust anchors if no TSL territories
	if len(trustAnchors) == 0 {
		for _, f := range r.sourceFiles {
			trustAnchors = append(trustAnchors, f)
		}
	}

	return registry.RegistryInfo{
		Name:         r.config.Name,
		Type:         "etsi_tsl",
		Description:  r.config.Description,
		Version:      "1.0.0",
		TrustAnchors: trustAnchors,
	}
}

// Healthy returns true if the registry has loaded trust data successfully.
func (r *TSLRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy && r.certPool != nil && r.certCount > 0
}

// Refresh reloads trust data from the configured sources.
func (r *TSLRegistry) Refresh(ctx context.Context) error {
	return r.load()
}

// CertificateCount returns the number of trusted certificates loaded.
func (r *TSLRegistry) CertificateCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.certCount
}

// TSLCount returns the number of loaded TSLs.
func (r *TSLRegistry) TSLCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tsls)
}

// LoadedAt returns when the trust data was last loaded.
func (r *TSLRegistry) LoadedAt() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadedAt
}

// LastError returns the last error encountered during loading.
func (r *TSLRegistry) LastError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastError
}

// TSLs returns the loaded TSL objects.
func (r *TSLRegistry) TSLs() []*etsi119612.TSL {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tsls
}

// CertPool returns the loaded certificate pool.
func (r *TSLRegistry) CertPool() *x509.CertPool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.certPool
}
