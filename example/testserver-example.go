//go:build ignore
// +build ignore

// Example: Using the testserver package for integration testing
//
// This example demonstrates how to use the embedded test server
// for testing applications that depend on go-trust.
//
// Run with: go run example/testserver-example.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
)

func main() {
	fmt.Println("=== Go-Trust TestServer Example ===\n")

	// Example 1: Simple accept-all server
	example1AcceptAll()

	// Example 2: Reject-all server
	example2RejectAll()

	// Example 3: Dynamic decision callback
	example3DynamicCallback()

	// Example 4: Discovery endpoint
	example4Discovery()

	fmt.Println("\n=== All examples completed ===")
}

func example1AcceptAll() {
	fmt.Println("Example 1: Accept-All Server")
	fmt.Println("-----------------------------")

	// Create a test server that accepts all requests
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	fmt.Printf("Server running at: %s\n", srv.URL())

	// Make a trust evaluation request
	resp, err := makeEvaluationRequest(srv.URL(), "test-subject", "x5c")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	fmt.Printf("Decision: %v\n\n", resp.Decision)
}

func example2RejectAll() {
	fmt.Println("Example 2: Reject-All Server")
	fmt.Println("----------------------------")

	// Create a test server that rejects all requests
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	fmt.Printf("Server running at: %s\n", srv.URL())

	// Make a trust evaluation request
	resp, err := makeEvaluationRequest(srv.URL(), "test-subject", "x5c")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	fmt.Printf("Decision: %v\n\n", resp.Decision)
}

func example3DynamicCallback() {
	fmt.Println("Example 3: Dynamic Decision Callback")
	fmt.Println("-------------------------------------")

	// Create a test server with custom logic
	srv := testserver.New(
		testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			// Accept subjects with "trusted" prefix
			if strings.HasPrefix(req.Subject.ID, "trusted-") {
				return &authzen.EvaluationResponse{
					Decision: true,
					Context: &authzen.EvaluationResponseContext{
						Reason: map[string]interface{}{
							"message": "Subject is in trusted prefix list",
						},
					},
				}, nil
			}
			// Reject everything else
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"message": "Subject not in trusted prefix list",
					},
				},
			}, nil
		}),
	)
	defer srv.Close()

	fmt.Printf("Server running at: %s\n", srv.URL())

	// Test with trusted subject
	resp1, _ := makeEvaluationRequest(srv.URL(), "trusted-issuer", "x5c")
	fmt.Printf("Subject 'trusted-issuer': Decision=%v\n", resp1.Decision)

	// Test with untrusted subject
	resp2, _ := makeEvaluationRequest(srv.URL(), "untrusted-issuer", "x5c")
	fmt.Printf("Subject 'untrusted-issuer': Decision=%v\n\n", resp2.Decision)
}

func example4Discovery() {
	fmt.Println("Example 4: AuthZEN Discovery")
	fmt.Println("----------------------------")

	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	fmt.Printf("Server running at: %s\n", srv.URL())

	// Fetch the discovery document
	resp, err := http.Get(srv.URL() + "/.well-known/authzen-configuration")
	if err != nil {
		log.Fatalf("Discovery request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Discovery document:\n%s\n", body)
}

// makeEvaluationRequest sends a trust evaluation request to the server
func makeEvaluationRequest(baseURL, subjectID, resourceType string) (*authzen.EvaluationResponse, error) {
	ctx := context.Background()

	// Resolution-only request (no resource.key) - tests if the subject is trusted
	req := authzen.EvaluationRequest{
		Subject: authzen.Subject{
			Type: "key",
			ID:   subjectID,
		},
		Resource: authzen.Resource{
			Type: "", // Empty for resolution-only request
		},
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/evaluation", strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", httpResp.StatusCode, string(body))
	}

	var resp authzen.EvaluationResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response (body=%s): %w", string(body), err)
	}

	return &resp, nil
}
