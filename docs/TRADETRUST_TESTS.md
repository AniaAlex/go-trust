# TradeTrust-Inspired Test Suite

This document describes the additional test coverage added based on real-world DID document structures from Singapore's TradeTrust implementation.

## Background

TradeTrust (https://www.tradetrust.io/) is a Singapore government-backed initiative for digital trade documents. Their DID implementation (`did:web:trustvc.github.io:did:1`) uses modern W3C standards with multiple verification method types.

## Test Coverage Added

### 1. TestTradeTrustMultikeyMatching

Tests JWK matching against DID documents with multiple modern key types, mirroring the structure used in production TradeTrust systems.

**DID Document Structure:**
- Multiple @context entries for different cryptographic suites:
  - `https://www.w3.org/ns/did/v1` (base DID context)
  - `https://w3id.org/security/suites/bls12381-2020/v1` (BLS signatures)
  - `https://w3id.org/security/multikey/v1` (modern Multikey)

**Verification Methods Tested:**
1. **Ed25519 Multikey**: OKP key type with Ed25519 curve
   - Commonly used for document signing
   - Fast verification, small signatures
   
2. **P-384 Multikey**: EC key type with NIST P-384 curve
   - Higher security level (192-bit security)
   - Larger key size for sensitive applications

3. **P-256 Multikey**: EC key type with NIST P-256 curve
   - Standard elliptic curve (128-bit security)
   - Wide compatibility

**Test Cases:**
- ✅ Matching Ed25519 key verification
- ✅ Matching P-384 key verification  
- ✅ Matching P-256 key verification
- ✅ Non-matching Ed25519 key (negative test)
- ✅ Non-matching P-384 key (negative test)

### 2. TestOpenAttestationKeyTypes

Tests secp256k1 keys as used by OpenAttestation for Ethereum-based document verification.

**DID Document Structure:**
- @context includes `https://w3id.org/security/suites/secp256k1recovery-2020/v2`
- Verification method type: `EcdsaSecp256k1RecoveryMethod2020`

**Key Type:**
- **secp256k1**: EC curve used by Bitcoin/Ethereum
  - Enables blockchain-based verification
  - Recovery of public key from signature

**Test Cases:**
- ✅ Matching secp256k1 key verification
- ✅ Non-matching secp256k1 key (negative test)

## Test Methodology

These tests focus on **unit testing the key matching logic** rather than end-to-end DID resolution:

1. Create DID document structures matching real-world production systems
2. Test the `matchJWK()` function directly
3. Verify correct identification of matching verification methods
4. Ensure non-matching keys are properly rejected

This approach allows testing of complex key structures without requiring network access or mock HTTP servers for DID resolution.

## Coverage Improvement

- **Before**: 52.7% statement coverage
- **After**: 61.6% statement coverage
- **Improvement**: +8.9 percentage points

## Real-World Validation

These tests are based on actual production DID documents from:
- **TrustVC GitHub Repository**: https://github.com/TrustVC/trustvc
  - Production DID: `did:web:trustvc.github.io:did:1`
  - Contains 3 verification methods with different key types
  
- **OpenAttestation**: Ethereum-based document verification
  - Uses secp256k1 for blockchain integration

## Key Insights

1. **Multiple Key Types**: Production systems use multiple verification methods in a single DID document for different purposes (signing, encryption, blockchain anchoring)

2. **Modern Standards**: TradeTrust uses latest W3C standards (Multikey, multiple @context entries)

3. **Practical Compatibility**: Mix of Ed25519 (speed), P-384 (security), and P-256 (compatibility) provides flexibility for different use cases

4. **Blockchain Integration**: OpenAttestation shows how DID:web can integrate with Ethereum using secp256k1

## Future Enhancements

Potential areas for expansion:
- BLS12-381 key matching (currently in TradeTrust but not yet tested)
- publicKeyMultibase format support (alternative to PublicKeyJwk)
- RSA key variants
- Key rotation scenarios with multiple time-stamped keys
