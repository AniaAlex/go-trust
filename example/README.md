# Go-Trust Examples

This directory contains configuration examples for running go-trust as an AuthZEN PDP server.

## Configuration Examples

| File | Description |
|------|-------------|
| `config.yaml` | Comprehensive server configuration with all registry types documented |
| `docker-compose.yaml` | Docker Compose deployment |
| `kubernetes.yaml` | Kubernetes deployment with Ingress and ServiceMonitor |
| `prometheus.yml` | Prometheus scrape configuration |

## Registry Examples

The `config.yaml` documents all supported registry types:

| Registry | Resource Types | Resolution-Only | Description |
|----------|---------------|-----------------|-------------|
| ETSI TSL | `x5c` | No | X.509 trust via ETSI TS 119612 Trust Status Lists |
| OpenID Federation | `entity_configuration`, `jwk` | Yes | Entity trust chain validation |
| DID Web | `did_document`, `jwk`, `verification_method` | Yes | W3C did:web method |
| DID Web VH | `did_document`, `jwk`, `verification_method` | Yes | did:webvh with verifiable history |
| mDOC IACA | `x5c` | No | Dynamic IACA validation for mDOC/mDL |
| Whitelist | URL-based | No | Simple URL-based trust (testing only) |

## Testing Examples

The `testing/` subdirectory contains Go code examples for integration testing:
- `testing/didweb-registry-example.go` - Using the did:web registry programmatically
- `testing/testserver-example.go` - Embedded test server for testing AuthZEN clients

## Quick Start

### Running Locally

```bash
# Build the binary
make build

# Run with ETSI certificate bundle
./gt --etsi-cert-bundle /path/to/trusted-certs.pem

# Run with multiple TSL files
./gt --etsi-tsl-files /path/to/eu-lotl.xml,/path/to/se-tsl.xml

# Run with logging configuration
./gt --etsi-cert-bundle certs.pem --log-level debug --log-format json

# Run with external URL (for .well-known discovery)
./gt --etsi-cert-bundle certs.pem --external-url https://pdp.example.com
```

### CLI Options Reference

```
Server options:
  --host string          API server hostname (default: 127.0.0.1)
  --port string          API server port (default: 6001)
  --external-url string  External URL for PDP discovery

ETSI TSL options:
  --etsi-cert-bundle string  Path to PEM file with trusted CA certificates
  --etsi-tsl-files string    Comma-separated list of local TSL XML files

Logging options:
  --log-level string   debug, info, warn, error (default: info)
  --log-format string  text or json (default: text)

Other:
  --config string  Configuration file path (YAML format) - partial support
  --help           Show help message
  --version        Show version information
```

### Running with Docker

```bash
# Ensure you have a certificate bundle
# (generate with tsl-tool from g119612)

# Start services
docker-compose -f example/docker-compose.yaml up -d
```

### Running on Kubernetes

```bash
# Apply the manifests
kubectl apply -f example/kubernetes.yaml

# Check status
kubectl -n go-trust get pods
```

## TSL Processing

For TSL processing (load, transform, sign, publish), use `tsl-tool` from [g119612](https://github.com/sirosfoundation/g119612):

```bash
# Process TSLs and generate certificate bundle
tsl-tool --output trusted-certs.pem pipeline.yaml

# Then run go-trust with the generated bundle
./gt --etsi-cert-bundle trusted-certs.pem
```

## Programmatic Registry Usage

See the testing examples or the main [README](../README.md) for examples of using each registry type programmatically:

```go
// ETSI TSL
reg, _ := etsi.NewTSLRegistry(etsi.TSLConfig{
    Name:       "ETSI-TSL",
    CertBundle: "/path/to/certs.pem",
})

// OpenID Federation
reg, _ := oidfed.NewOIDFedRegistry(oidfed.Config{
    Description: "OIDF Registry",
    TrustAnchors: []oidfed.TrustAnchorConfig{
        {EntityID: "https://federation.example.com"},
    },
})

// DID Web
reg, _ := didweb.NewDIDWebRegistry(didweb.Config{
    Timeout:     30 * time.Second,
    Description: "DID Web Registry",
})

// DID Web VH
reg, _ := didwebvh.NewDIDWebVHRegistry(didwebvh.Config{
    Timeout:     30 * time.Second,
    Description: "DID Web VH Registry",
})

// mDOC IACA
reg, _ := mdociaca.New(&mdociaca.Config{
    Name:            "mDOC-IACA",
    IssuerAllowlist: []string{"https://issuer.example.com"},
    CacheTTL:        time.Hour,
})

// Whitelist
reg, _ := static.NewWhitelistRegistryFromFile("/etc/go-trust/whitelist.yaml", true)
defer reg.Close()
```

See the main [README](../README.md) for complete documentation.
