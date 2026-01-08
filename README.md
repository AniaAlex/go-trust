# Go-Trust

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-trust.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-trust)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-trust)](https://goreportcard.com/report/github.com/sirosfoundation/go-trust)
[![Coverage](https://raw.githubusercontent.com/sirosfoundation/go-trust/badges/.badges/main/coverage.svg)](https://github.com/sirosfoundation/go-trust/actions/workflows/go.yml)
[![Go Compatibility](https://raw.githubusercontent.com/sirosfoundation/go-trust/badges/.badges/main/golang.svg)](https://go.dev/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/sirosfoundation/go-trust/go.yml?branch=main)](https://github.com/sirosfoundation/go-trust/actions)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Latest Release](https://img.shields.io/github/v/release/sirosfoundation/go-trust?include_prereleases)](https://github.com/sirosfoundation/go-trust/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-trust)](https://go.dev/)

[![Issues](https://img.shields.io/github/issues/sirosfoundation/go-trust)](https://github.com/sirosfoundation/go-trust/issues)
[![Last Commit](https://img.shields.io/github/last-commit/sirosfoundation/go-trust)](https://github.com/sirosfoundation/go-trust/commits/main)
[![CodeQL](https://github.com/sirosfoundation/go-trust/actions/workflows/codeql.yml/badge.svg)](https://github.com/sirosfoundation/go-trust/actions/workflows/codeql.yml)
[![Dependency Status](https://img.shields.io/librariesio/github/sirosfoundation/go-trust)](https://libraries.io/github/sirosfoundation/go-trust)

</div>

## Overview

Go-Trust is a multi-framework AuthZEN Trust Decision Point (PDP) server. It evaluates trust decisions across multiple trust registries including ETSI TS 119 612 Trust Status Lists (TSLs), OpenID Federation, and DID Web.

Go-Trust is designed to run inside the same trust domain as the entity that relies on trust evaluation (for instance a wallet unit or an issuer). It promotes interoperability across implementations that rely on ETSI trust status lists such as the EUDI wallet.

> **Note:** For TSL processing (load, transform, sign, publish), use `tsl-tool` from [g119612](https://github.com/sirosfoundation/g119612). Go-trust consumes pre-processed TSL data.

## Features

- **AuthZEN Compliant**: Implements the OASIS AuthZEN Trust Registry Profile for policy decisions
- **Multi-Registry Architecture**: Parallel evaluation across ETSI TSL, OpenID Federation, and DID Web
- **Flexible Resolution Strategies**: First-match, all-registries, best-match, or sequential
- **Circuit Breaking**: Graceful handling of registry failures
- **Rate Limiting**: Per-IP rate limiting for API protection
- **Prometheus Metrics**: Comprehensive observability support
- **Kubernetes Native**: Liveness and readiness probes, ConfigMap support
- **Test Server**: Embedded test server for integration testing
- **High Quality**: >80% test coverage, comprehensive linting, security scanning

## Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/sirosfoundation/go-trust.git
cd go-trust
make build

# Or install directly
go install github.com/sirosfoundation/go-trust/cmd/gt@latest
```

### Running the Server

```bash
# With a PEM certificate bundle (recommended for production)
gt --etsi-cert-bundle /path/to/trusted-certs.pem

# With TSL XML files directly
gt --etsi-tsl-files eu-lotl.xml,se-tsl.xml

# With external URL for discovery (behind reverse proxy)
gt --external-url https://pdp.example.com --etsi-cert-bundle certs.pem

# Full configuration
gt \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /etc/go-trust/trusted-certs.pem \
  --external-url https://pdp.example.com \
  --log-level info \
  --log-format json
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Listen address | `127.0.0.1` |
| `--port` | Listen port | `6001` |
| `--external-url` | External URL for discovery | auto-detect |
| `--etsi-cert-bundle` | PEM file with trusted CA certs | - |
| `--etsi-tsl-files` | Comma-separated TSL XML files | - |
| `--log-level` | Log level: debug, info, warn, error | `info` |
| `--log-format` | Log format: text, json | `text` |
| `--config` | Configuration file (YAML) | - |

Environment variable: `GO_TRUST_EXTERNAL_URL` for external URL.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /evaluation` | AuthZEN trust evaluation |
| `GET /.well-known/authzen-configuration` | PDP discovery document |
| `GET /healthz` | Kubernetes liveness probe |
| `GET /readyz` | Kubernetes readiness probe (503 until TSLs loaded) |
| `GET /readyz?verbose=true` | Readiness with detailed TSL info |
| `GET /metrics` | Prometheus metrics |
| `GET /tsls` | List loaded Trust Status Lists |

### AuthZEN Evaluation Request

```json
{
  "subject": {
    "type": "x509_certificate",
    "id": "subject-123",
    "properties": {
      "x5c": ["MIIDQjCCAiqgAwIBAgIUJlq+zz4..."]
    }
  },
  "resource": {
    "type": "service",
    "id": "resource-123"
  },
  "action": {
    "name": "trust"
  }
}
```

### AuthZEN Evaluation Response

```json
{
  "decision": true,
  "context": {
    "reason": {
      "registry": "etsi-tsl",
      "resolution_ms": 12,
      "service_type": "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    }
  }
}
```

## Architecture

### Multi-Registry Design

Go-Trust implements a flexible multi-registry architecture that allows multiple trust frameworks to be queried simultaneously.

```
┌─────────────────┐     ┌─────────────────┐
│  AuthZEN Client │────▶│   Go-Trust PDP  │
└─────────────────┘     └────────┬────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  ETSI TSL       │     │  OpenID Fed     │     │   DID Web       │
│  Registry       │     │  Registry       │     │   Registry      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### TrustRegistry Interface

All trust registries implement the same interface:

```go
type TrustRegistry interface {
    Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)
    SupportedResourceTypes() []string
    Info() RegistryInfo
    Healthy() bool
    Refresh(ctx context.Context) error
}
```

### Resolution Strategies

| Strategy | Description |
|----------|-------------|
| `FirstMatch` | Returns as soon as any registry returns `decision=true` |
| `AllRegistries` | Queries all registries and aggregates results |
| `BestMatch` | Returns the result with highest confidence |
| `Sequential` | Tries registries in order until one succeeds |

### Supported Registry Types

#### ETSI TSL Registry

Evaluates X.509 certificates against ETSI TS 119 612 Trust Status Lists.

**Input sources:**
- `--etsi-cert-bundle`: PEM file with trusted CA certificates (processed by tsl-tool)
- `--etsi-tsl-files`: Raw TSL XML files

**Supported resource types:** `x509_certificate`, `x5c`

#### OpenID Federation Registry

Evaluates trust chains in OpenID Federation ecosystems.

**Supported resource types:** `entity`, `openid_federation`

#### DID Web Registry

Resolves and validates DID Web identifiers per W3C DID specification.

**DID Web URL Mapping:**
- `did:web:example.com` → `https://example.com/.well-known/did.json`
- `did:web:example.com:users:alice` → `https://example.com/users/alice/did.json`
- `did:web:example.com%3A3000` → `https://example.com:3000/.well-known/did.json`

**Supported resource types:** `key`, `jwk`

## Deployment

### Docker

```bash
docker build -t go-trust:latest .

docker run -d \
  -p 6001:6001 \
  -v /path/to/trusted-certs.pem:/app/certs.pem:ro \
  go-trust:latest --etsi-cert-bundle /app/certs.pem
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-trust
spec:
  replicas: 3
  selector:
    matchLabels:
      app: go-trust
  template:
    metadata:
      labels:
        app: go-trust
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "6001"
    spec:
      containers:
      - name: go-trust
        image: go-trust:latest
        args:
        - --host=0.0.0.0
        - --port=6001
        - --etsi-cert-bundle=/config/trusted-certs.pem
        - --log-format=json
        ports:
        - containerPort: 6001
        livenessProbe:
          httpGet:
            path: /healthz
            port: 6001
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /readyz
            port: 6001
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /config
      volumes:
      - name: config
        configMap:
          name: go-trust-config
```

### Workflow: TSL Processing + PDP Server

For production deployment, use `tsl-tool` (from g119612) to process TSLs and generate certificate bundles:

```bash
# 1. Process TSLs with tsl-tool
tsl-tool --output trusted-certs.pem pipeline.yaml

# 2. Run gt with the generated certificate bundle
gt --etsi-cert-bundle trusted-certs.pem
```

Run tsl-tool via cron to update TSL data periodically:

```bash
# Crontab entry: Update TSLs daily at 2 AM
0 2 * * * /usr/local/bin/tsl-tool --output /etc/go-trust/trusted-certs.pem /etc/tsl-tool/pipeline.yaml
```

## Prometheus Metrics

The `/metrics` endpoint exposes:

| Metric | Description |
|--------|-------------|
| `api_requests_total` | HTTP requests by method, endpoint, status |
| `api_request_duration_seconds` | Request latency histogram |
| `api_requests_in_flight` | Current active requests |
| `cert_validation_total` | Certificate validations by result |
| `cert_validation_duration_seconds` | Validation latency |

Example Prometheus queries:

```promql
# Request rate by endpoint
rate(api_requests_total[5m])

# 95th percentile latency
histogram_quantile(0.95, rate(api_request_duration_seconds_bucket[5m]))

# Certificate validation error rate
rate(cert_validation_total{result="error"}[5m])
```

## Embedded Test Server

The `testserver` package provides an embedded test server for integration testing:

```go
import (
    "testing"
    "github.com/sirosfoundation/go-trust/pkg/testserver"
)

func TestMyApplication(t *testing.T) {
    // Create a test server that accepts all trust requests
    srv := testserver.New(testserver.WithAcceptAll())
    defer srv.Close()

    // Use srv.URL() to get the server address
    // Make AuthZEN requests to the server
}
```

### Test Server Options

| Option | Description |
|--------|-------------|
| `WithAcceptAll()` | Accept all trust requests |
| `WithRejectAll()` | Reject all trust requests |
| `WithMockRegistry(name, decision, types)` | Add a mock registry |
| `WithDecisionFunc(fn)` | Dynamic trust decisions |

## Development

### Requirements

- Go 1.25+ (check `go.mod` for exact version)
- CGO enabled (`CGO_ENABLED=1`)
- Make for build automation

### Building

```bash
make build          # Build the binary (./go-trust)
make test           # Run tests with race detection
make coverage       # Generate coverage report
make lint           # Run linters
make quick          # Quick pre-commit checks
```

### Project Structure

```
go-trust/
├── cmd/gt/         # Main application
├── pkg/
│   ├── api/        # HTTP API implementation
│   ├── authzen/    # AuthZEN protocol types
│   ├── registry/   # Trust registry interface and manager
│   │   ├── etsi/   # ETSI TSL registry
│   │   ├── oidfed/ # OpenID Federation registry
│   │   └── didweb/ # DID Web registry
│   ├── logging/    # Structured logging
│   └── testserver/ # Embedded test server
├── example/        # Example configurations
└── docs/           # Architecture documentation
```

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development workflow
git checkout -b feature/amazing-feature
make quick && make test
git commit -m 'feat: Add amazing feature'
git push origin feature/amazing-feature
# Open a Pull Request
```

## Related Projects

- [g119612](https://github.com/sirosfoundation/g119612) - ETSI TSL processing library and `tsl-tool` CLI
- [go-oidfed/lib](https://github.com/go-oidfed/lib) - OpenID Federation library
- [AuthZEN Specification](https://openid.net/wg/authzen/specifications/)
- [ETSI TS 119612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/)

## License

This project is licensed under the BSD 2-Clause License - see [LICENSE.txt](LICENSE.txt) for details.

## Acknowledgments

- [ETSI TS 119612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/) - Trust-service status list format
- [AuthZEN](https://openid.net/wg/authzen/specifications/) - Authorization framework
- [AuthZEN for Trust](https://datatracker.ietf.org/doc/draft-johansson-authzen-trust/)
- [SUNET](https://www.sunet.se/) - Swedish University Network
- [SIROS Foundation](https://siros.org/)
