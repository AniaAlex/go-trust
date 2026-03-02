// Package static provides simple TrustRegistry implementations for testing
// and basic use cases that don't require complex trust frameworks like ETSI TSL
// or OpenID Federation.
//
// This package provides four registry types:
//
//   - AlwaysTrustedRegistry: Always returns decision=true (useful for testing
//     or development environments where trust evaluation is not needed)
//
//   - NeverTrustedRegistry: Always returns decision=false (useful for testing
//     denial scenarios or as a fallback registry)
//
//   - SystemCertPoolRegistry: Validates X.509 certificates against the
//     operating system's root certificate pool (useful for simple deployments
//     that trust the system's CA bundle without custom trust lists)
//
//   - WhitelistRegistry: Maintains a simple whitelist of trusted issuer and
//     verifier URLs. Supports configuration from YAML/JSON files with automatic
//     reload on file changes. This is the simplest trust model for scenarios
//     where URL-based allowlisting is sufficient.
//
// # Usage Examples
//
//	// For testing - always trust
//	reg := static.NewAlwaysTrustedRegistry("test-allow-all")
//
//	// For testing - always deny
//	reg := static.NewNeverTrustedRegistry("test-deny-all")
//
//	// For production - trust system CA bundle
//	reg, err := static.NewSystemCertPoolRegistry(static.SystemCertPoolConfig{
//	    Name:        "system-trust",
//	    Description: "OS-provided CA certificates",
//	})
//
//	// For simple URL whitelisting with file watching
//	reg, err := static.NewWhitelistRegistryFromFile("/etc/go-trust/whitelist.yaml", true)
//	defer reg.Close()
//
//	// Or programmatically
//	reg := static.NewWhitelistRegistry()
//	reg.AddIssuer("https://issuer.example.com")
//	reg.AddVerifier("https://verifier.example.com")
//
// # Security Considerations
//
// AlwaysTrustedRegistry should NEVER be used in production environments as it
// bypasses all trust evaluation. It exists solely for testing purposes.
//
// SystemCertPoolRegistry provides basic X.509 validation but does not check
// certificate revocation (CRL/OCSP) or enforce specific trust frameworks.
// For production deployments requiring higher assurance, consider using the
// ETSI TSL registry or OpenID Federation registry instead.
//
// WhitelistRegistry provides simple URL-based trust without cryptographic
// verification. It should only be used in conjunction with signature verification
// at the application layer (e.g., wallet-backend verifies signatures, then asks
// go-trust if the issuer/verifier URL is allowed). For more sophisticated trust
// evaluation involving certificate chains, key binding, or revocation checking,
// use ETSI TSL, OpenID Federation, or other advanced registries.
package static
