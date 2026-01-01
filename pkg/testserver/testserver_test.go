package testserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("creates server with default accept-all", func(t *testing.T) {
		srv := New()
		defer srv.Close()

		assert.NotEmpty(t, srv.URL())
	})

	t.Run("creates server with WithAcceptAll", func(t *testing.T) {
		srv := New(WithAcceptAll())
		defer srv.Close()

		client := authzenclient.New(srv.URL())
		resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "test-subject"},
			Resource: authzen.Resource{
				Type: "x5c",
				ID:   "test-subject",
				Key:  []interface{}{"cert"},
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Decision)
	})

	t.Run("creates server with WithRejectAll", func(t *testing.T) {
		srv := New(WithRejectAll())
		defer srv.Close()

		client := authzenclient.New(srv.URL())
		resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "test-subject"},
			Resource: authzen.Resource{
				Type: "x5c",
				ID:   "test-subject",
				Key:  []interface{}{"cert"},
			},
		})

		require.NoError(t, err)
		assert.False(t, resp.Decision)
	})

	t.Run("creates server with custom mock registry", func(t *testing.T) {
		srv := New(WithMockRegistry("test-registry", true, []string{"jwk"}))
		defer srv.Close()

		client := authzenclient.New(srv.URL())
		resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject: authzen.Subject{Type: "key", ID: "did:web:example.com"},
			Resource: authzen.Resource{
				Type: "jwk",
				ID:   "did:web:example.com",
				Key:  []interface{}{map[string]interface{}{"kty": "EC"}},
			},
		})

		require.NoError(t, err)
		assert.True(t, resp.Decision)
	})

	t.Run("creates server with decision callback", func(t *testing.T) {
		srv := New(WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			if req.Subject.ID == "trusted" {
				return &authzen.EvaluationResponse{Decision: true}, nil
			}
			return &authzen.EvaluationResponse{Decision: false}, nil
		}))
		defer srv.Close()

		client := authzenclient.New(srv.URL())

		// Test trusted subject
		resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "trusted"},
			Resource: authzen.Resource{Type: "x5c", ID: "trusted", Key: []interface{}{"cert"}},
		})
		require.NoError(t, err)
		assert.True(t, resp.Decision)

		// Test untrusted subject
		resp, err = client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "untrusted"},
			Resource: authzen.Resource{Type: "x5c", ID: "untrusted", Key: []interface{}{"cert"}},
		})
		require.NoError(t, err)
		assert.False(t, resp.Decision)
	})
}

func TestServer_URL(t *testing.T) {
	srv := New()
	defer srv.Close()

	url := srv.URL()
	assert.Contains(t, url, "http://")
}

func TestServer_Client(t *testing.T) {
	srv := New()
	defer srv.Close()

	client := srv.Client()
	assert.NotNil(t, client)
}

func TestNewHandler(t *testing.T) {
	t.Run("creates handler for custom httptest server", func(t *testing.T) {
		handler := NewHandler(WithAcceptAll())
		srv := httptest.NewServer(handler)
		defer srv.Close()

		client := authzenclient.New(srv.URL)
		resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: "test"},
			Resource: authzen.Resource{Type: "x5c", ID: "test", Key: []interface{}{"cert"}},
		})

		require.NoError(t, err)
		assert.True(t, resp.Decision)
	})
}

func TestHealthEndpoints(t *testing.T) {
	srv := New()
	defer srv.Close()

	t.Run("healthz returns 200", func(t *testing.T) {
		resp, err := http.Get(srv.URL() + "/healthz")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.Equal(t, "ok", body["status"])
	})

	t.Run("readyz returns status", func(t *testing.T) {
		resp, err := http.Get(srv.URL() + "/readyz")
		require.NoError(t, err)
		defer resp.Body.Close()

		// Will return 503 since no pipeline is loaded, but that's expected
		var body map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)
		assert.Contains(t, body, "status")
	})
}

func TestWellKnownEndpoint(t *testing.T) {
	srv := New(WithBaseURL("https://pdp.example.com"))
	defer srv.Close()

	resp, err := http.Get(srv.URL() + "/.well-known/authzen-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var metadata authzen.PDPMetadata
	err = json.NewDecoder(resp.Body).Decode(&metadata)
	require.NoError(t, err)
	assert.Equal(t, "https://pdp.example.com", metadata.PolicyDecisionPoint)
}

func TestDiscoveryWorkflow(t *testing.T) {
	srv := New(WithAcceptAll())
	defer srv.Close()

	// Test discovery + evaluation workflow
	client, err := authzenclient.Discover(context.Background(), srv.URL())
	require.NoError(t, err)
	assert.NotNil(t, client.Metadata)

	resp, err := client.EvaluateRaw(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "did:web:example.com"},
		Resource: authzen.Resource{Type: "jwk", ID: "did:web:example.com", Key: []interface{}{map[string]interface{}{"kty": "EC"}}},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}
