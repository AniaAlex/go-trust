// Package main demonstrates using the did:web registry with go-trustpackage example

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/didweb"
)

func main() {
	// Example 1: Basic did:web registry usage
	basicExample()

	// Example 2: Using did:web in a multi-registry setup
	multiRegistryExample()
}

func basicExample() {
	fmt.Println("=== Basic did:web Registry Example ===")
	fmt.Println()

	// Create a did:web registry
	didRegistry, err := didweb.NewDIDWebRegistry(didweb.Config{
		Timeout:     30 * time.Second,
		Description: "Production DID Web Resolver",
		// InsecureSkipVerify: false, // Always verify TLS in production
	})
	if err != nil {
		log.Fatalf("Failed to create did:web registry: %v", err)
	}

	// Create an AuthZEN evaluation request
	// This validates that a specific JWK is published in a DID document
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:example.com",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "did:web:example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
				},
			},
		},
		Action: &authzen.Action{
			Name: "authenticate",
		},
	}

	// Evaluate the request
	resp, err := didRegistry.Evaluate(context.Background(), req)
	if err != nil {
		log.Fatalf("Evaluation failed: %v", err)
	}

	// Print the response
	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Printf("Response:\n%s\n\n", respJSON)

	if resp.Decision {
		fmt.Println("✅ Key binding validated successfully!")
	} else {
		fmt.Println("❌ Key binding validation failed")
		if resp.Context != nil && resp.Context.Reason != nil {
			fmt.Printf("Reason: %v\n", resp.Context.Reason)
		}
	}
	fmt.Println()
}

func multiRegistryExample() {
	fmt.Println("=== Multi-Registry Example with did:web ===")
	fmt.Println()

	// Create a did:web registry
	didRegistry, err := didweb.NewDIDWebRegistry(didweb.Config{
		Timeout:     30 * time.Second,
		Description: "DID Web Resolver",
	})
	if err != nil {
		log.Fatalf("Failed to create did:web registry: %v", err)
	}

	// Create a RegistryManager with FirstMatch strategy
	// This will query did:web (and potentially other registries) in parallel
	manager := registry.NewRegistryManager(
		registry.FirstMatch, // Return first positive match
		30*time.Second,      // Timeout for registry queries
	)

	// Register the did:web registry
	manager.Register(didRegistry)

	// In a real application, you would also register other registries:
	// manager.Register(etsiRegistry)     // For X.509 certificates
	// manager.Register(oidfedRegistry)   // For OpenID Federation

	// Show registry info
	info := manager.Info()
	fmt.Printf("Registry Manager: %s\n", info.Name)
	fmt.Printf("Type: %s\n", info.Type)
	fmt.Printf("Supported Resource Types: %v\n\n", manager.SupportedResourceTypes())

	// Example request with did:web identifier
	req := &authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   "did:web:w3c-ccg.github.io:user:alice",
		},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "did:web:w3c-ccg.github.io:user:alice",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
					"y":   "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4",
				},
			},
		},
	}

	// The manager will automatically route to the did:web registry
	// because it supports the "jwk" resource type
	resp, err := manager.Evaluate(context.Background(), req)
	if err != nil {
		log.Fatalf("Evaluation failed: %v", err)
	}

	respJSON, _ := json.MarshalIndent(resp, "", "  ")
	fmt.Printf("Response:\n%s\n\n", respJSON)
}

// Example DID Document that would be hosted at https://example.com/.well-known/did.json
/*
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "id": "did:web:example.com#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
      }
    },
    {
      "id": "did:web:example.com#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "38M1FDts7Oea7urmseiugGW7tWc3mLpJh6rKe7xINZ8",
        "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
      }
    }
  ],
  "authentication": [
    "did:web:example.com#key-1"
  ],
  "assertionMethod": [
    "did:web:example.com#key-1",
    "did:web:example.com#key-2"
  ]
}
*/
