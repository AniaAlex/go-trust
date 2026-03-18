package lote

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeLoTE(t *testing.T, dir, name string, lote *etsi119602.ListOfTrustedEntities) string {
	t.Helper()
	data, err := json.Marshal(lote)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0644))
	return path
}

func testLoTE() *etsi119602.ListOfTrustedEntities {
	return &etsi119602.ListOfTrustedEntities{
		Version: "1.0",
		SchemeInformation: etsi119602.SchemeInformation{
			Territory: "SE",
			SchemeOperator: etsi119602.NameSet{
				{Language: "en", Value: "Test Operator"},
			},
		},
		TrustedEntities: []etsi119602.TrustedEntity{
			{
				EntityID:     "https://issuer.example.com",
				EntityStatus: etsi119602.StatusGranted,
				EntityName: etsi119602.NameSet{
					{Language: "en", Value: "Test Issuer"},
				},
				DigitalIdentities: []etsi119602.DigitalIdentity{
					{
						Type: "jwk",
						JWK: map[string]interface{}{
							"kty": "EC",
							"crv": "P-256",
							"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
							"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
						},
					},
				},
			},
			{
				EntityID:     "https://withdrawn.example.com",
				EntityStatus: etsi119602.StatusWithdrawn,
				EntityName: etsi119602.NameSet{
					{Language: "en", Value: "Withdrawn Entity"},
				},
			},
		},
	}
}

func TestNew_Basic(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.True(t, reg.Healthy())

	info := reg.Info()
	assert.Equal(t, "LoTE", info.Name)
	assert.Equal(t, "lote", info.Type)
	assert.True(t, info.Healthy)
}

func TestNew_NoSources(t *testing.T) {
	_, err := New(Config{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one source")
}

func TestNew_BadSource(t *testing.T) {
	_, err := New(Config{Sources: []string{"/nonexistent/path.json"}})
	assert.Error(t, err)
}

func TestEvaluate_GrantedEntity_JWKMatch(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
					"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestEvaluate_WithdrawnEntity(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://withdrawn.example.com"},
		Resource: authzen.Resource{Type: "jwk", ID: "https://withdrawn.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "withdrawn")
}

func TestEvaluate_UnknownEntity(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://unknown.example.com"},
		Resource: authzen.Resource{Type: "jwk", ID: "https://unknown.example.com"},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "not found")
}

func TestEvaluate_ResolutionOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Resolution only: no resource type or key
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{ID: "https://issuer.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
	assert.NotNil(t, resp.Context.TrustMetadata)
}

func TestEvaluate_KeyMismatch(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject: authzen.Subject{Type: "key", ID: "https://issuer.example.com"},
		Resource: authzen.Resource{
			Type: "jwk",
			ID:   "https://issuer.example.com",
			Key: []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					"y":   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
				},
			},
		},
	})
	require.NoError(t, err)
	assert.False(t, resp.Decision)
	assert.Contains(t, resp.Context.Reason["admin"].(string), "does not match")
}

func TestSupportedResourceTypes(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	types := reg.SupportedResourceTypes()
	assert.Contains(t, types, "jwk")
	assert.Contains(t, types, "x5c")
}

func TestSupportsResolutionOnly(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)
	assert.True(t, reg.SupportsResolutionOnly())
}

func TestRefresh(t *testing.T) {
	dir := t.TempDir()
	path := writeLoTE(t, dir, "lote.json", testLoTE())

	reg, err := New(Config{Sources: []string{path}})
	require.NoError(t, err)

	// Update the file with an additional entity
	updated := testLoTE()
	updated.TrustedEntities = append(updated.TrustedEntities, etsi119602.TrustedEntity{
		EntityID:     "https://new.example.com",
		EntityStatus: etsi119602.StatusGranted,
	})
	data, err := json.Marshal(updated)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0644))

	// Refresh
	require.NoError(t, reg.Refresh(context.Background()))

	// Should now find the new entity
	resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
		Subject:  authzen.Subject{Type: "key", ID: "https://new.example.com"},
		Resource: authzen.Resource{ID: "https://new.example.com"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Decision)
}

func TestMultipleSources(t *testing.T) {
	dir := t.TempDir()

	lote1 := &etsi119602.ListOfTrustedEntities{
		Version: "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "SE"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{EntityID: "https://se.example.com", EntityStatus: etsi119602.StatusGranted},
		},
	}
	lote2 := &etsi119602.ListOfTrustedEntities{
		Version: "1.0",
		SchemeInformation: etsi119602.SchemeInformation{Territory: "NO"},
		TrustedEntities: []etsi119602.TrustedEntity{
			{EntityID: "https://no.example.com", EntityStatus: etsi119602.StatusGranted},
		},
	}

	path1 := writeLoTE(t, dir, "se.json", lote1)
	path2 := writeLoTE(t, dir, "no.json", lote2)

	reg, err := New(Config{Sources: []string{path1, path2}})
	require.NoError(t, err)

	// Both entities should be findable
	for _, id := range []string{"https://se.example.com", "https://no.example.com"} {
		resp, err := reg.Evaluate(context.Background(), &authzen.EvaluationRequest{
			Subject:  authzen.Subject{Type: "key", ID: id},
			Resource: authzen.Resource{ID: id},
		})
		require.NoError(t, err)
		assert.True(t, resp.Decision, "should find %s", id)
	}
}
