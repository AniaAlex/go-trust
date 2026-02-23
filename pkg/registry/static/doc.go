// Package static provides simple TrustRegistry implementations for testing
// and basic use cases that don't require complex trust frameworks like ETSI TSL
// or OpenID Federation.
//
// This package provides three registry types:
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
// # Security Considerations
//
// AlwaysTrustedRegistry should NEVER be used in production environments as it
// bypasses all trust evaluation. It exists solely for testing purposes.
//
// SystemCertPoolRegistry provides basic X.509 validation but does not check
// certificate revocation (CRL/OCSP) or enforce specific trust frameworks.
// For production deployments requiring higher assurance, consider using the
// ETSI TSL registry or OpenID Federation registry instead.
package static
