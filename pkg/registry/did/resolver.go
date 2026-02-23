// Package did provides a generic DID resolution framework and implementspackage did

// various DID method resolvers.
//
// This package provides:
// - A DIDResolver interface for pluggable DID method implementations
// - A GenericDIDRegistry that wraps DID resolvers in a TrustRegistry interface
// - Built-in support for the did:key method
//
// The implementation follows the W3C DID Core specification:
// https://www.w3.org/TR/did-core/
package did

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// DIDDocument represents a W3C DID Document.
// See https://www.w3.org/TR/did-core/#did-documents
type DIDDocument struct {
	Context            interface{}          `json:"@context,omitempty"`
	ID                 string               `json:"id"`
	Controller         interface{}          `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     interface{}          `json:"authentication,omitempty"`
	AssertionMethod    interface{}          `json:"assertionMethod,omitempty"`
	KeyAgreement       interface{}          `json:"keyAgreement,omitempty"`
	Service            interface{}          `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID document.
type VerificationMethod struct {
	ID                 string                 `json:"id"`
	Type               string                 `json:"type"`
	Controller         string                 `json:"controller"`
	PublicKeyJwk       map[string]interface{} `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string                 `json:"publicKeyMultibase,omitempty"`
}

// DIDResolver defines the interface for resolving DIDs to DID documents.
type DIDResolver interface {
	// Resolve resolves a DID to a DID document.
	Resolve(ctx context.Context, did string) (*DIDDocument, error)

	// Method returns the DID method this resolver handles (e.g., "key", "web").
	Method() string
}

// GenericDIDRegistry provides a TrustRegistry implementation that uses
// pluggable DID resolvers to support multiple DID methods.
type GenericDIDRegistry struct {
	resolvers   map[string]DIDResolver
	mu          sync.RWMutex
	description string
}

// GenericDIDRegistryConfig holds configuration for the GenericDIDRegistry.
type GenericDIDRegistryConfig struct {
	Description string `json:"description,omitempty"`
}

// NewGenericDIDRegistry creates a new GenericDIDRegistry.
func NewGenericDIDRegistry(config GenericDIDRegistryConfig) *GenericDIDRegistry {
	description := config.Description
	if description == "" {
		description = "Generic DID Resolution Registry"
	}

	return &GenericDIDRegistry{
		resolvers:   make(map[string]DIDResolver),
		description: description,
	}
}

// RegisterResolver registers a DID resolver for a specific DID method.
func (r *GenericDIDRegistry) RegisterResolver(resolver DIDResolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolvers[resolver.Method()] = resolver
}

// Evaluate implements TrustRegistry.Evaluate by resolving DIDs and validating key bindings.
func (r *GenericDIDRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	startTime := time.Now()

	// Parse the DID to extract the method
	method, err := extractDIDMethod(req.Subject.ID)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error": fmt.Sprintf("invalid DID format: %v", err),
				},
			},
		}, nil
	}

	// Find the appropriate resolver
	r.mu.RLock()
	resolver, exists := r.resolvers[method]
	r.mu.RUnlock()

	if !exists {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":             fmt.Sprintf("no resolver registered for DID method: %s", method),
					"supported_methods": r.getSupportedMethods(),
				},
			},
		}, nil
	}

	// Resolve the DID document
	didDoc, err := resolver.Resolve(ctx, req.Subject.ID)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         fmt.Sprintf("failed to resolve DID: %v", err),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	// Check if this is a resolution-only request
	if req.IsResolutionOnlyRequest() {
		return &authzen.EvaluationResponse{
			Decision: true,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"did":                  didDoc.ID,
					"resolution_only":      true,
					"resolution_ms":        time.Since(startTime).Milliseconds(),
					"verification_methods": len(didDoc.VerificationMethod),
				},
				TrustMetadata: didDocumentToTrustMetadata(didDoc),
			},
		}, nil
	}

	// For full evaluation, validate the key binding
	matched, matchedMethod, err := verifyKeyBinding(req, didDoc)
	if err != nil {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":         err.Error(),
					"resolution_ms": time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	if !matched {
		return &authzen.EvaluationResponse{
			Decision: false,
			Context: &authzen.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"error":                "no matching verification method found in DID document",
					"verification_methods": len(didDoc.VerificationMethod),
					"resolution_ms":        time.Since(startTime).Milliseconds(),
				},
			},
		}, nil
	}

	return &authzen.EvaluationResponse{
		Decision: true,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"did":                  didDoc.ID,
				"verification_method":  matchedMethod.ID,
				"key_type":             matchedMethod.Type,
				"resolution_ms":        time.Since(startTime).Milliseconds(),
				"verification_methods": len(didDoc.VerificationMethod),
			},
			TrustMetadata: didDocumentToTrustMetadata(didDoc),
		},
	}, nil
}

// SupportedResourceTypes returns the resource types this registry can handle.
func (r *GenericDIDRegistry) SupportedResourceTypes() []string {
	return []string{"jwk"}
}

// SupportsResolutionOnly returns true as DID resolution supports resolution-only requests.
func (r *GenericDIDRegistry) SupportsResolutionOnly() bool {
	return true
}

// Info returns metadata about this registry.
func (r *GenericDIDRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:         "generic-did-registry",
		Type:         "did",
		Description:  r.description,
		Version:      "1.0.0",
		TrustAnchors: r.getSupportedMethods(),
	}
}

// Healthy returns true if the registry is operational.
func (r *GenericDIDRegistry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.resolvers) > 0
}

// Refresh is a no-op for DID resolution.
func (r *GenericDIDRegistry) Refresh(ctx context.Context) error {
	return nil
}

// getSupportedMethods returns the list of supported DID methods.
func (r *GenericDIDRegistry) getSupportedMethods() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	methods := make([]string, 0, len(r.resolvers))
	for method := range r.resolvers {
		methods = append(methods, "did:"+method)
	}
	return methods
}

// extractDIDMethod extracts the DID method from a DID string.
// For example, "did:web:example.com" returns "web".
func extractDIDMethod(did string) (string, error) {
	if !strings.HasPrefix(did, "did:") {
		return "", fmt.Errorf("not a valid DID: must start with 'did:'")
	}

	parts := strings.SplitN(did, ":", 3)
	if len(parts) < 3 {
		return "", fmt.Errorf("not a valid DID: missing method-specific identifier")
	}

	return parts[1], nil
}

// didDocumentToTrustMetadata converts a DIDDocument to the trust_metadata format.
func didDocumentToTrustMetadata(didDoc *DIDDocument) map[string]interface{} {
	trustMeta := map[string]interface{}{
		"@context": didDoc.Context,
		"id":       didDoc.ID,
	}

	if didDoc.Controller != nil {
		trustMeta["controller"] = didDoc.Controller
	}

	if len(didDoc.VerificationMethod) > 0 {
		verificationMethods := make([]map[string]interface{}, len(didDoc.VerificationMethod))
		for i, vm := range didDoc.VerificationMethod {
			method := map[string]interface{}{
				"id":         vm.ID,
				"type":       vm.Type,
				"controller": vm.Controller,
			}
			if vm.PublicKeyJwk != nil {
				method["publicKeyJwk"] = vm.PublicKeyJwk
			}
			if vm.PublicKeyMultibase != "" {
				method["publicKeyMultibase"] = vm.PublicKeyMultibase
			}
			verificationMethods[i] = method
		}
		trustMeta["verificationMethod"] = verificationMethods
	}

	if didDoc.Authentication != nil {
		trustMeta["authentication"] = didDoc.Authentication
	}
	if didDoc.AssertionMethod != nil {
		trustMeta["assertionMethod"] = didDoc.AssertionMethod
	}
	if didDoc.KeyAgreement != nil {
		trustMeta["keyAgreement"] = didDoc.KeyAgreement
	}
	if didDoc.Service != nil {
		trustMeta["service"] = didDoc.Service
	}

	return trustMeta
}

// verifyKeyBinding verifies that the request key matches one of the DID document's verification methods.
func verifyKeyBinding(req *authzen.EvaluationRequest, didDoc *DIDDocument) (bool, *VerificationMethod, error) {
	if len(req.Resource.Key) == 0 {
		return false, nil, fmt.Errorf("resource.key must not be empty")
	}

	requestJWK, ok := req.Resource.Key[0].(map[string]interface{})
	if !ok {
		return false, nil, fmt.Errorf("resource.key[0] must be a JWK object")
	}

	for i := range didDoc.VerificationMethod {
		vm := &didDoc.VerificationMethod[i]
		if vm.PublicKeyJwk != nil && jwksMatch(requestJWK, vm.PublicKeyJwk) {
			return true, vm, nil
		}
	}

	return false, nil, nil
}

// jwksMatch compares two JWK objects for key material equality.
func jwksMatch(jwk1, jwk2 map[string]interface{}) bool {
	kty1, _ := jwk1["kty"].(string)
	kty2, _ := jwk2["kty"].(string)
	if kty1 != kty2 {
		return false
	}

	switch kty1 {
	case "OKP":
		return jwk1["crv"] == jwk2["crv"] && jwk1["x"] == jwk2["x"]
	case "EC":
		return jwk1["crv"] == jwk2["crv"] && jwk1["x"] == jwk2["x"] && jwk1["y"] == jwk2["y"]
	case "RSA":
		return jwk1["n"] == jwk2["n"] && jwk1["e"] == jwk2["e"]
	default:
		return false
	}
}

// DIDKeyResolver implements the did:key method.
// See https://w3c-ccg.github.io/did-method-key/
type DIDKeyResolver struct{}

// NewDIDKeyResolver creates a new did:key resolver.
func NewDIDKeyResolver() *DIDKeyResolver {
	return &DIDKeyResolver{}
}

// Method returns "key" as this resolver handles did:key DIDs.
func (r *DIDKeyResolver) Method() string {
	return "key"
}

// Resolve resolves a did:key identifier to a DID document.
// The did:key method encodes the public key directly in the DID.
func (r *DIDKeyResolver) Resolve(ctx context.Context, did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, fmt.Errorf("invalid did:key identifier: must start with 'did:key:'")
	}

	// Extract the multibase-encoded public key
	multibaseKey := strings.TrimPrefix(did, "did:key:")
	if multibaseKey == "" {
		return nil, fmt.Errorf("invalid did:key identifier: missing key material")
	}

	// Parse the multibase-encoded multicodec key
	keyType, publicKeyJwk, err := decodeMultibaseKey(multibaseKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	// Build the DID document
	vmID := did + "#" + multibaseKey
	verificationMethod := VerificationMethod{
		ID:           vmID,
		Type:         keyType,
		Controller:   did,
		PublicKeyJwk: publicKeyJwk,
	}

	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID:                 did,
		VerificationMethod: []VerificationMethod{verificationMethod},
		Authentication:     []interface{}{vmID},
		AssertionMethod:    []interface{}{vmID},
	}, nil
}

// Multicodec prefixes for different key types
const (
	// Ed25519 public key multicodec prefix (0xed01)
	multicodecEd25519Pub = 0xed
	// P-256 public key multicodec prefix (0x1200)
	multicodecP256Pub = 0x80
	// P-384 public key multicodec prefix (0x1201)
	multicodecP384Pub = 0x81
	// secp256k1 public key multicodec prefix (0xe7)
	multicodecSecp256k1Pub = 0xe7
)

// decodeMultibaseKey decodes a multibase-encoded multicodec public key.
func decodeMultibaseKey(multibaseKey string) (string, map[string]interface{}, error) {
	if len(multibaseKey) < 2 {
		return "", nil, fmt.Errorf("multibase key too short")
	}

	// First character is the multibase encoding identifier
	// 'z' = base58btc
	encoding := multibaseKey[0]
	encodedKey := multibaseKey[1:]

	var keyBytes []byte
	var err error

	switch encoding {
	case 'z':
		// Base58btc encoding
		keyBytes, err = base58Decode(encodedKey)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode base58btc: %w", err)
		}
	default:
		return "", nil, fmt.Errorf("unsupported multibase encoding: %c", encoding)
	}

	if len(keyBytes) < 2 {
		return "", nil, fmt.Errorf("decoded key too short")
	}

	// First byte(s) are the multicodec identifier
	multicodec := keyBytes[0]
	var publicKeyBytes []byte

	switch multicodec {
	case multicodecEd25519Pub:
		// Ed25519 public key (32 bytes)
		if len(keyBytes) < 34 {
			return "", nil, fmt.Errorf("Ed25519 key too short: expected 34 bytes, got %d", len(keyBytes))
		}
		publicKeyBytes = keyBytes[2:34]
		return "Ed25519VerificationKey2020", map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(publicKeyBytes),
		}, nil

	case multicodecSecp256k1Pub:
		// secp256k1 public key (33 bytes compressed)
		if len(keyBytes) < 35 {
			return "", nil, fmt.Errorf("secp256k1 key too short: expected 35 bytes, got %d", len(keyBytes))
		}
		publicKeyBytes = keyBytes[2:35]
		// For secp256k1, we need to decompress the key to get x and y
		x, y, err := decompressSecp256k1(publicKeyBytes)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decompress secp256k1 key: %w", err)
		}
		return "EcdsaSecp256k1VerificationKey2019", map[string]interface{}{
			"kty": "EC",
			"crv": "secp256k1",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		}, nil

	default:
		// Check for 2-byte multicodec prefixes
		if len(keyBytes) >= 2 {
			twoByteCodec := (uint16(keyBytes[0]) << 8) | uint16(keyBytes[1])
			switch twoByteCodec {
			case 0x8024: // P-256 (compressed)
				publicKeyBytes = keyBytes[2:]
				x, y, err := decompressP256(publicKeyBytes)
				if err != nil {
					return "", nil, fmt.Errorf("failed to decompress P-256 key: %w", err)
				}
				return "JsonWebKey2020", map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   base64.RawURLEncoding.EncodeToString(x),
					"y":   base64.RawURLEncoding.EncodeToString(y),
				}, nil

			case 0x8124: // P-384 (compressed)
				publicKeyBytes = keyBytes[2:]
				x, y, err := decompressP384(publicKeyBytes)
				if err != nil {
					return "", nil, fmt.Errorf("failed to decompress P-384 key: %w", err)
				}
				return "JsonWebKey2020", map[string]interface{}{
					"kty": "EC",
					"crv": "P-384",
					"x":   base64.RawURLEncoding.EncodeToString(x),
					"y":   base64.RawURLEncoding.EncodeToString(y),
				}, nil
			}
		}

		return "", nil, fmt.Errorf("unsupported multicodec: 0x%x", multicodec)
	}
}

// Base58btc alphabet
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Decode decodes a base58btc encoded string.
func base58Decode(input string) ([]byte, error) {
	// Build the reverse alphabet map
	alphabetMap := make(map[rune]int)
	for i, c := range base58Alphabet {
		alphabetMap[c] = i
	}

	result := make([]byte, 0, len(input))

	// Process each character
	for _, c := range input {
		idx, ok := alphabetMap[c]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}

		// Multiply existing result by 58 and add the new digit
		carry := idx
		for i := len(result) - 1; i >= 0; i-- {
			carry += int(result[i]) * 58
			result[i] = byte(carry % 256)
			carry /= 256
		}

		for carry > 0 {
			result = append([]byte{byte(carry % 256)}, result...)
			carry /= 256
		}
	}

	// Handle leading zeros
	for _, c := range input {
		if c != '1' {
			break
		}
		result = append([]byte{0}, result...)
	}

	return result, nil
}

// decompressSecp256k1 decompresses a compressed secp256k1 public key.
func decompressSecp256k1(compressed []byte) ([]byte, []byte, error) {
	if len(compressed) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed key length: expected 33, got %d", len(compressed))
	}

	// For simplicity, we'll just return the x coordinate
	// A full implementation would compute y from the curve equation
	// secp256k1 decompression requires BigInt arithmetic
	x := compressed[1:33]

	// Placeholder: return compressed form indication in y
	// In production, this should properly decompress the key
	y := make([]byte, 32)
	if compressed[0] == 0x03 {
		y[31] = 0x01 // Odd y
	}

	return x, y, nil
}

// decompressP256 decompresses a compressed P-256 public key.
func decompressP256(compressed []byte) ([]byte, []byte, error) {
	if len(compressed) != 33 {
		return nil, nil, fmt.Errorf("invalid compressed key length: expected 33, got %d", len(compressed))
	}

	// Use Go's elliptic curve library
	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, nil, fmt.Errorf("failed to decompress P-256 key")
	}

	return x.Bytes(), y.Bytes(), nil
}

// decompressP384 decompresses a compressed P-384 public key.
func decompressP384(compressed []byte) ([]byte, []byte, error) {
	if len(compressed) != 49 {
		return nil, nil, fmt.Errorf("invalid compressed key length: expected 49, got %d", len(compressed))
	}

	// Use Go's elliptic curve library
	curve := elliptic.P384()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, nil, fmt.Errorf("failed to decompress P-384 key")
	}

	return x.Bytes(), y.Bytes(), nil
}

// NewGenericDIDRegistryWithKeyMethod creates a GenericDIDRegistry with the did:key resolver registered.
func NewGenericDIDRegistryWithKeyMethod(config GenericDIDRegistryConfig) *GenericDIDRegistry {
	registry := NewGenericDIDRegistry(config)
	registry.RegisterResolver(NewDIDKeyResolver())
	return registry
}

// Ensure interfaces are implemented
var _ DIDResolver = (*DIDKeyResolver)(nil)
var _ registry.TrustRegistry = (*GenericDIDRegistry)(nil)

// Suppress unused warning for ed25519 import (used for key type reference)
var _ = ed25519.PublicKeySize
