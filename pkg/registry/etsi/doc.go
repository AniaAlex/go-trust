// Package etsi provides TrustRegistry implementations for ETSI TS 119 612 Trust Status Lists.
//
// This package provides two registry implementations for validating X.509 certificates
// against ETSI Trust Status Lists:
//
// # TSLRegistry (Standalone Mode)
//
// TSLRegistry loads trust data directly from files or URLs without any pipeline dependency.
// Use this for standalone applications, CLI tools, or when you don't need automatic
// background updates.
//
// Data sources supported:
//   - PEM certificate bundles (recommended for production)
//   - Local TSL XML files
//   - Remote TSL URLs (when AllowNetworkAccess is enabled)
//
// Example usage:
//
//	// Load from PEM bundle
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:       "EU-TSL",
//	    CertBundle: "/var/lib/go-trust/eu-certs.pem",
//	})
//
//	// Load from local TSL files
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:     "EU-TSL",
//	    TSLFiles: []string{"/data/eu-lotl.xml"},
//	})
//
//	// Load from remote URL (for tools that fetch TSLs)
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    Name:               "EU-LOTL",
//	    TSLURLs:            []string{"https://ec.europa.eu/tools/lotl/eu-lotl.xml"},
//	    AllowNetworkAccess: true,
//	    FollowRefs:         true,
//	    MaxRefDepth:        3,
//	})
//
// # PipelineBackedRegistry (Server Mode)
//
// PipelineBackedRegistry reads trust data from a PipelineContextProvider interface,
// which is implemented by pipeline.Context. Use this when running the go-trust server
// with background TSL updates managed by the pipeline system.
//
// Example usage:
//
//	// Create server context with pipeline
//	serverCtx := api.NewServerContext(nil)
//	serverCtx.PipelineContext = &pipeline.Context{}
//
//	// Pipeline context implements PipelineContextProvider
//	tslRegistry := etsi.NewPipelineBackedRegistry(serverCtx.PipelineContext, "ETSI-TSL")
//	registryMgr.Register(tslRegistry)
//
//	// Background pipeline keeps the context updated
//	api.StartBackgroundUpdater(pl, serverCtx, 5*time.Minute)
//
// # AuthZEN Integration
//
// Both registry implementations support the same resource types:
//   - "x5c": Base64-encoded X.509 certificate chain
//   - "jwk": JSON Web Key with x5c claim
//
// The registry validates certificates against the loaded trust anchors and returns
// an evaluation response indicating whether the certificate chain is trusted.
//
// # Network Access Control
//
// For production servers that should not perform network I/O during certificate
// validation, use TSLRegistry with AllowNetworkAccess=false (the default). This
// ensures all trust data is loaded from local files only.
//
// For tools that need to fetch TSLs from remote URLs, set AllowNetworkAccess=true
// and configure the TSLURLs field.
//
// # Reference Following
//
// When loading from TSLURLs, the registry can optionally follow TSL references
// (pointers to other TSLs) to build a complete trust hierarchy:
//
//	reg, err := etsi.NewTSLRegistry(etsi.TSLConfig{
//	    TSLURLs:            []string{"https://example.com/lotl.xml"},
//	    AllowNetworkAccess: true,
//	    FollowRefs:         true,   // Follow TSL references
//	    MaxRefDepth:        3,      // Maximum depth (default: 3)
//	})
//
// Note: TSLFiles always have FollowRefs disabled to prevent unexpected network access.
package etsi
