# Go-Trust Examples

This directory contains example code and configurations for go-trust, the AuthZEN Trust Decision Point (PDP) server.

## Overview

Go-trust is a multi-framework trust decision engine that evaluates trust across:
- **ETSI TS 119612** - Trust Status Lists (X.509 certificates)
- **OpenID Federation** - Entity trust chains  
- **DID Web** - Decentralized Identifiers

> **Note:** For TSL processing (load, transform, sign, publish), use `tsl-tool` from the [g119612](https://github.com/sirosfoundation/g119612) package. Go-trust consumes pre-processed TSL data.

## Quick Start

### Running the Server

```bash
# Basic server with ETSI certificate bundle
go-trust --etsi-cert-bundle /path/to/trusted-certs.pem

# With TSL files directly
go-trust --etsi-tsl-files eu-lotl.xml,se-tsl.xml

# With external URL for discovery
go-trust --external-url https://pdp.example.com --etsi-cert-bundle certs.pem

# Full options
go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /etc/go-trust/trusted-certs.pem \
  --external-url https://pdp.example.com \
  --log-level info \
  --log-format json
```

### Server Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /evaluation` | AuthZEN trust evaluation |
| `GET /.well-known/authzen-configuration` | PDP discovery document |
| `GET /status` | Server status |
| `GET /info` | Registry information |
| `GET /health` | Kubernetes health check |
| `GET /ready` | Kubernetes readiness check |
| `GET /metrics` | Prometheus metrics |
| `GET /swagger/index.html` | API documentation |

## Example Files

| File | Description |
|------|-------------|
| `didweb-registry-example.go` | Programmatic did:web registry usage |
| `testserver-example.go` | Embedded test server for integration testing |

## Workflow: TSL Processing + PDP Server

For production deployment, use `tsl-tool` (from g119612) to process TSLs and generate certificate bundles:

```bash
# 1. Process TSLs with tsl-tool (in g119612)
tsl-tool --output trusted-certs.pem pipeline.yaml

# 2. Run go-trust with the generated certificate bundle
go-trust --etsi-cert-bundle trusted-certs.pem
```

Example `pipeline.yaml` for tsl-tool:

```yaml
- set-fetch-options:
    - timeout:60s
    - user-agent:TSL-Tool/1.0
- load:
    - https://ec.europa.eu/tools/lotl/eu-lotl.xml
- select:
    - reference-depth:2
```

## did:web Registry Example

The `didweb-registry-example.go` demonstrates programmatic use of the did:web registry:

```go
package main

import (
    "context"
    "time"
    
    "github.com/sirosfoundation/go-trust/pkg/authzen"
    "github.com/sirosfoundation/go-trust/pkg/registry/didweb"
)

func main() {
    // Create a did:web registry
    registry, _ := didweb.NewDIDWebRegistry(didweb.Config{
        Timeout:     30 * time.Second,
        Description: "DID Web Resolver",
    })

    // Evaluate an AuthZEN request
    resp, _ := registry.Evaluate(context.Background(), &authzen.EvaluationRequest{
        Subject: authzen.Subject{
            Type: "key",
            ID:   "did:web:example.com",
        },
        Resource: authzen.Resource{
            Type: "jwk",
            ID:   "did:web:example.com",
            Key:  []interface{}{jwkData}, // JWK to verify
        },
    })
    
    if resp.Decision {
        // Key binding verified
    }
}
```

## Test Server Example

The `testserver-example.go` demonstrates using the embedded test server for integration testing:

```go
package main

import (
    "github.com/sirosfoundation/go-trust/pkg/testserver"
)

func main() {
    // Create a test server that accepts all requests
    srv := testserver.NewAcceptAllServer()
    defer srv.Close()
    
    // Use srv.URL() to get the server address
    // Send AuthZEN requests to the server
}
```

## Configuration Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--host` | - | Listen address | `127.0.0.1` |
| `--port` | - | Listen port | `6001` |
| `--external-url` | `GO_TRUST_EXTERNAL_URL` | External URL for discovery | auto-detect |
| `--etsi-cert-bundle` | - | PEM file with trusted CA certs | - |
| `--etsi-tsl-files` | - | Comma-separated TSL XML files | - |
| `--log-level` | - | Log level: debug, info, warn, error | `info` |
| `--log-format` | - | Log format: text, json | `text` |

## AuthZEN Evaluation Request Format

```json
{
  "subject": {
    "type": "key",
    "id": "did:web:example.com"
  },
  "resource": {
    "type": "x5c",
    "id": "did:web:example.com",
    "key": ["<base64-encoded-certificate>"]
  },
  "action": {
    "name": "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
  }
}
```

### Resource Types

| Type | Description | Key Format |
|------|-------------|------------|
| `x5c` | X.509 certificate chain | Array of base64-encoded DER certificates |
| `jwk` | JSON Web Key | Array of JWK objects with x5c claim |
| `entity` | OpenID Federation entity | Entity ID URL |

## Related Projects

- [g119612](https://github.com/sirosfoundation/g119612) - ETSI TSL processing library and `tsl-tool` CLI
- [go-oidfed/lib](https://github.com/go-oidfed/lib) - OpenID Federation library
