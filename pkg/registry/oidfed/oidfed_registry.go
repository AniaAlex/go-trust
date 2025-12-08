// Package oidfed implements a TrustRegistry using OpenID Federation for trust chain validation.
package oidfed

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/SUNET/go-trust/pkg/authzen"
	"github.com/SUNET/go-trust/pkg/registry"
	oidfed "github.com/go-oidfed/lib"
	oidfedjwx "github.com/go-oidfed/lib/jwx"
)

// OIDFedRegistry implements a trust registry using OpenID Federation.
// It resolves trust chains from entities to configured trust anchors and
// evaluates them against AuthZEN access evaluation requests.
type OIDFedRegistry struct {
	trustAnchors       oidfed.TrustAnchors
	requiredTrustMarks []string // Optional: require specific trust mark types
	entityTypes        []string // Optional: filter by entity types (e.g., "openid_provider")
	description        string
}

// Config holds configuration for creating an OIDFedRegistry.
type Config struct {
	// TrustAnchors defines the federation trust anchors
	TrustAnchors []TrustAnchorConfig `json:"trust_anchors"`

	// RequiredTrustMarks is an optional list of trust mark types that must be present
	RequiredTrustMarks []string `json:"required_trust_marks,omitempty"`

	// EntityTypes filters entities by type (e.g., "openid_provider", "openid_relying_party")
	EntityTypes []string `json:"entity_types,omitempty"`

	// Description of this registry instance
	Description string `json:"description,omitempty"`
}

// TrustAnchorConfig defines a single trust anchor.
type TrustAnchorConfig struct {
	// EntityID is the entity identifier (URL) of the trust anchor
	EntityID string `json:"entity_id"`

	// JWKS is an optional explicit JWKS for the trust anchor
	// If not provided, it will be fetched from the entity configuration
	JWKS *oidfedjwx.JWKS `json:"jwks,omitempty"`
}

// NewOIDFedRegistry creates a new OpenID Federation trust registry.
func NewOIDFedRegistry(config Config) (*OIDFedRegistry, error) {
	if len(config.TrustAnchors) == 0 {
		return nil, fmt.Errorf("at least one trust anchor must be configured")
	}

	trustAnchors := make(oidfed.TrustAnchors, len(config.TrustAnchors))
	for i, ta := range config.TrustAnchors {
		if ta.EntityID == "" {
			return nil, fmt.Errorf("trust anchor %d: entity_id is required", i)
		}

		anchor := oidfed.TrustAnchor{
			EntityID: ta.EntityID,
		}
		if ta.JWKS != nil {
			anchor.JWKS = *ta.JWKS
		}
		trustAnchors[i] = anchor
	}

	description := config.Description
	if description == "" {
		description = fmt.Sprintf("OpenID Federation Registry with %d trust anchor(s)", len(trustAnchors))
	}

	return &OIDFedRegistry{
		trustAnchors:       trustAnchors,
		requiredTrustMarks: config.RequiredTrustMarks,
		entityTypes:        config.EntityTypes,
		description:        description,
	}, nil
}

// Name returns the registry name.
func (r *OIDFedRegistry) Name() string {
	return "oidfed-registry"
}

// Description returns a human-readable description.
func (r *OIDFedRegistry) Description() string {
	return r.description
}

// SupportedResourceTypes returns the resource types this registry can evaluate.
// OpenID Federation works with entity identifiers (URLs), so we look for
// entity_id in the resource or subject properties.
func (r *OIDFedRegistry) SupportedResourceTypes() []string {
	// OpenID Federation can work with various resource types
	// as long as they can be mapped to entity identifiers
	return []string{
		"entity",
		"openid_provider",
		"relying_party",
		"oauth_client",
		"oauth_server",
		"federation_entity",
	}
}

// SupportsResolutionOnly returns true for OpenID Federation registry.
// The registry supports resolution-only requests where clients can
// retrieve entity configurations and trust chain metadata without
// validating a specific key binding.
func (r *OIDFedRegistry) SupportsResolutionOnly() bool {
	return true
}

// Evaluate performs an AuthZEN access evaluation using OpenID Federation trust chains.
// For resolution-only requests (where IsResolutionOnlyRequest() returns true), the method
// returns decision=true with the entity configuration in trust_metadata, without validating
// a specific key binding.
func (r *OIDFedRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	// Extract entity ID from the request
	entityID, err := r.extractEntityID(req)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"message": "unable to extract entity ID from request",
					"error":   err.Error(),
				},
			},
		}, nil
	}

	// Build and validate trust chains
	resolver := &oidfed.TrustResolver{
		StartingEntity: entityID,
		TrustAnchors:   r.trustAnchors,
		Types:          r.entityTypes,
	}

	// Resolve and verify trust chains
	chains := resolver.ResolveToValidChains()
	if len(chains) == 0 {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"message":   "no valid trust chain found",
					"entity_id": entityID,
				},
			},
		}, nil
	}

	// Select the best chain (first valid chain for now)
	chain := chains[0]

	// Check required trust marks if configured
	if len(r.requiredTrustMarks) > 0 {
		if !r.checkTrustMarks(chain) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"message":              "required trust marks not present",
						"entity_id":            entityID,
						"required_trust_marks": r.requiredTrustMarks,
					},
				},
			}, nil
		}
	}

	// Extract metadata and build decision
	metadata := r.extractMetadata(chain)

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		return r.buildResolutionOnlyResponse(entityID, chain, metadata), nil
	}

	// Extract certificates from JWKS if requested
	var certificates []*x509.Certificate
	if req.Context != nil {
		if includeCerts, ok := req.Context["include_certificates"].(bool); ok && includeCerts {
			certificates = r.extractCertificates(chain)
		}
	}

	reasonData := map[string]interface{}{
		"entity_id":          entityID,
		"trust_chain_length": len(chain),
		"trust_anchor":       r.getTrustAnchorID(chain),
		"metadata":           metadata,
	}

	if len(certificates) > 0 {
		reasonData["certificates_count"] = len(certificates)
		// Note: Full certificate details could be added here if needed
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason:        reasonData,
			TrustMetadata: r.chainToTrustMetadata(chain, metadata),
		},
	}, nil
}

// Info returns registry information.
func (r *OIDFedRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:         r.Name(),
		Type:         "openid_federation",
		Description:  r.description,
		TrustAnchors: r.getTrustAnchorEntityIDs(),
	}
}

// Healthy returns true if the registry is operational.
func (r *OIDFedRegistry) Healthy() bool {
	// OpenID Federation registry is healthy as long as it's configured
	return len(r.trustAnchors) > 0
}

// Refresh triggers an update of cached data.
// For OpenID Federation, the go-oidfed/lib handles caching internally.
func (r *OIDFedRegistry) Refresh(ctx context.Context) error {
	// The go-oidfed/lib library handles caching and refreshing internally
	// Nothing specific to do here
	return nil
}

// extractEntityID extracts the entity identifier from the request.
// It checks subject.entity_id, resource.entity_id, subject.id, or resource.id.
func (r *OIDFedRegistry) extractEntityID(req *authzen.EvaluationRequest) (string, error) {
	// Try subject.entity_id or subject.id first
	if req.Subject.Type == "key" && req.Subject.ID != "" {
		// Check if ID looks like a URL (entity identifier)
		if strings.HasPrefix(req.Subject.ID, "http://") || strings.HasPrefix(req.Subject.ID, "https://") {
			return req.Subject.ID, nil
		}
	}

	// Try resource.entity_id or resource.id
	if req.Resource.ID != "" {
		if strings.HasPrefix(req.Resource.ID, "http://") || strings.HasPrefix(req.Resource.ID, "https://") {
			return req.Resource.ID, nil
		}
	}

	return "", fmt.Errorf("no entity_id found in request subject or resource")
}

// checkTrustMarks verifies that all required trust marks are present in the trust chain.
func (r *OIDFedRegistry) checkTrustMarks(chain oidfed.TrustChain) bool {
	if len(r.requiredTrustMarks) == 0 {
		return true
	}

	// Get trust marks from the leaf entity (first in chain)
	if len(chain) == 0 || chain[0].TrustMarks == nil {
		return false
	}

	trustMarks := chain[0].TrustMarks
	foundMarks := make(map[string]bool)

	for _, tm := range trustMarks {
		foundMarks[tm.TrustMarkType] = true
	}

	// Check all required marks are present
	for _, required := range r.requiredTrustMarks {
		if !foundMarks[required] {
			return false
		}
	}

	return true
}

// extractMetadata extracts useful metadata from the trust chain.
func (r *OIDFedRegistry) extractMetadata(chain oidfed.TrustChain) map[string]interface{} {
	metadata := make(map[string]interface{})

	if len(chain) == 0 {
		return metadata
	}

	leaf := chain[0]

	// Add entity types if metadata is present
	if leaf.Metadata != nil {
		entityTypes := leaf.Metadata.GuessEntityTypes()
		if len(entityTypes) > 0 {
			metadata["entity_types"] = entityTypes
		}
	}

	// Add trust marks
	if len(leaf.TrustMarks) > 0 {
		trustMarkTypes := make([]string, len(leaf.TrustMarks))
		for i, tm := range leaf.TrustMarks {
			trustMarkTypes[i] = tm.TrustMarkType
		}
		metadata["trust_marks"] = trustMarkTypes
	}

	// Add issuer and subject
	metadata["issuer"] = leaf.Issuer
	metadata["subject"] = leaf.Subject

	// Add expiration time
	metadata["expires_at"] = leaf.ExpiresAt.Time.Format(time.RFC3339)

	return metadata
}

// extractCertificates extracts X.509 certificates from the JWKS in the trust chain.
func (r *OIDFedRegistry) extractCertificates(chain oidfed.TrustChain) []*x509.Certificate {
	var certificates []*x509.Certificate

	for _, stmt := range chain {
		if stmt.JWKS.Set == nil {
			continue
		}

		// Iterate through keys in the JWKS
		for i := 0; i < stmt.JWKS.Set.Len(); i++ {
			key, ok := stmt.JWKS.Set.Key(i)
			if !ok {
				continue
			}

			// Extract x5c chain if present (returns [][]byte)
			certChain, ok := key.X509CertChain()
			if !ok {
				continue
			}
			for j := 0; j < certChain.Len(); j++ {
				certBytes, ok := certChain.Get(j)
				if !ok {
					continue
				}
				// Parse the DER-encoded certificate
				cert, err := x509.ParseCertificate(certBytes)
				if err == nil && cert != nil {
					certificates = append(certificates, cert)
				}
			}
		}
	}

	return certificates
}

// getTrustAnchorID returns the entity ID of the trust anchor for this chain.
func (r *OIDFedRegistry) getTrustAnchorID(chain oidfed.TrustChain) string {
	if len(chain) == 0 {
		return ""
	}

	// The last entity in the chain is the trust anchor
	return chain[len(chain)-1].Subject
}

// buildResolutionOnlyResponse creates an EvaluationResponse for resolution-only requests.
// The response includes decision=true and the entity configuration in trust_metadata.
func (r *OIDFedRegistry) buildResolutionOnlyResponse(entityID string, chain oidfed.TrustChain, metadata map[string]interface{}) *authzen.EvaluationResponse {
	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"entity_id":          entityID,
				"resolution_only":    true,
				"trust_chain_length": len(chain),
				"trust_anchor":       r.getTrustAnchorID(chain),
			},
			TrustMetadata: r.chainToTrustMetadata(chain, metadata),
		},
	}
}

// chainToTrustMetadata converts a trust chain and metadata to the trust_metadata format.
// This returns an OpenID Federation entity configuration structure.
func (r *OIDFedRegistry) chainToTrustMetadata(chain oidfed.TrustChain, metadata map[string]interface{}) map[string]interface{} {
	if len(chain) == 0 {
		return nil
	}

	// The first statement in the chain is the leaf entity's configuration
	leafStatement := chain[0]

	trustMeta := map[string]interface{}{
		"iss":          leafStatement.Issuer,
		"sub":          leafStatement.Subject,
		"metadata":     metadata,
		"trust_chain":  r.buildTrustChainArray(chain),
		"trust_anchor": r.getTrustAnchorID(chain),
	}

	// Include issued_at and expires_at
	if !leafStatement.IssuedAt.Time.IsZero() {
		trustMeta["iat"] = leafStatement.IssuedAt.Time.Unix()
	}
	if !leafStatement.ExpiresAt.Time.IsZero() {
		trustMeta["exp"] = leafStatement.ExpiresAt.Time.Unix()
	}

	// Include JWKS keys summary if available
	if leafStatement.JWKS.Set != nil && leafStatement.JWKS.Set.Len() > 0 {
		trustMeta["jwks"] = r.jwksToMap(leafStatement.JWKS)
	}

	return trustMeta
}

// buildTrustChainArray converts the trust chain to an array of entity statements.
func (r *OIDFedRegistry) buildTrustChainArray(chain oidfed.TrustChain) []map[string]interface{} {
	chainArray := make([]map[string]interface{}, len(chain))
	for i, stmt := range chain {
		stmtMap := map[string]interface{}{
			"iss": stmt.Issuer,
			"sub": stmt.Subject,
		}
		if !stmt.IssuedAt.Time.IsZero() {
			stmtMap["iat"] = stmt.IssuedAt.Time.Unix()
		}
		if !stmt.ExpiresAt.Time.IsZero() {
			stmtMap["exp"] = stmt.ExpiresAt.Time.Unix()
		}
		chainArray[i] = stmtMap
	}
	return chainArray
}

// jwksToMap converts a JWKS to a map representation.
func (r *OIDFedRegistry) jwksToMap(jwks oidfedjwx.JWKS) map[string]interface{} {
	if jwks.Set == nil {
		return nil
	}

	keys := make([]map[string]interface{}, 0)
	for i := 0; i < jwks.Set.Len(); i++ {
		key, ok := jwks.Set.Key(i)
		if !ok {
			continue
		}

		keyMap := map[string]interface{}{
			"kty": key.KeyType().String(),
		}

		// Add key ID if present
		if kid, ok := key.KeyID(); ok && kid != "" {
			keyMap["kid"] = kid
		}

		// Add algorithm if present
		if alg, ok := key.Algorithm(); ok && alg.String() != "" {
			keyMap["alg"] = alg.String()
		}

		// Add use if present
		if use, ok := key.KeyUsage(); ok && use != "" {
			keyMap["use"] = use
		}

		keys = append(keys, keyMap)
	}

	return map[string]interface{}{
		"keys": keys,
	}
}

// getTrustAnchorEntityIDs returns a list of configured trust anchor entity IDs.
func (r *OIDFedRegistry) getTrustAnchorEntityIDs() []string {
	ids := make([]string, len(r.trustAnchors))
	for i, ta := range r.trustAnchors {
		ids[i] = ta.EntityID
	}
	return ids
}
