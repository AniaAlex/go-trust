# Go-Trust

<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/SUNET/go-trust.svg)](https://pkg.go.dev/github.com/SUNET/go-trust)
[![Go Report Card](https://goreportcard.com/badge/github.com/SUNET/go-trust)](https://goreportcard.com/report/github.com/SUNET/go-trust)
[![Coverage](https://raw.githubusercontent.com/SUNET/go-trust/badges/.badges/main/coverage.svg)](https://github.com/SUNET/go-trust/actions/workflows/go.yml)
[![Go Compatibility](https://raw.githubusercontent.com/SUNET/go-trust/badges/.badges/main/golang.svg)](https://go.dev/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/SUNET/go-trust/go.yml?branch=main)](https://github.com/SUNET/go-trust/actions)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Latest Release](https://img.shields.io/github/v/release/SUNET/go-trust?include_prereleases)](https://github.com/SUNET/go-trust/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/SUNET/go-trust)](https://go.dev/)

[![Issues](https://img.shields.io/github/issues/SUNET/go-trust)](https://github.com/SUNET/go-trust/issues)
[![Last Commit](https://img.shields.io/github/last-commit/SUNET/go-trust)](https://github.com/SUNET/go-trust/commits/main)
[![CodeQL](https://github.com/SUNET/go-trust/actions/workflows/codeql.yml/badge.svg)](https://github.com/SUNET/go-trust/actions/workflows/codeql.yml)
[![Dependency Status](https://img.shields.io/librariesio/github/SUNET/go-trust)](https://libraries.io/github/SUNET/go-trust)

</div>

## Overview

Go-Trust is a local trust engine that provides trust decisions based on ETSI TS 119612 Trust Status Lists (TSLs). It allows clients to abstract trust decisions through an AuthZEN policy decision point (PDP). The service evaluates trust in subjects identified by X509 certificates using a set of TSLs.

Go-Trust is not meant to be used across trust boundaries. The reason for creating Go-Trust is to promote interoperability across implementations that rely on ETSI trust status lists such as the EUDI wallet. ETSI TS 119 612 is complex to implement correctly and hopefully Go-Trust provides a way to both ensure correct trust evaluation as well as provide performance enhancements by allowing for local caching etc. Go-Trust is an API service meant to be run inside the same trust domain as the entity that relies on trust evaluation (for instance a wallet unit or an issuer).

Future versions of Go-Trust will expand to cover other trust registries.

Go-Trust can also be used to maintain and publish ETSI trust status lists, act as a local distribution point and provide policy based transformation of trust status lists.

The design was inspired by the pyFF project which has been used to provide similar functions for SAML metadata at scale.

## Features

### Core Capabilities

- **AuthZEN Integration**: Policy decision point for trust evaluation
- **TSL Management**: Process and validate ETSI TS 119612 Trust Status Lists
- **Certificate Validation**: Evaluate X509 certificates against trusted services
- **Pipeline Processing**: Flexible TSL processing with configurable steps
- **XML Publishing**: Serialize TSLs to XML for distribution
- **XML Signing**: Sign XML documents using file-based keys or PKCS#11 hardware security modules

### Production-Ready Features

- **Health Checks**: Kubernetes-compatible liveness and readiness endpoints
- **Metrics**: Comprehensive Prometheus metrics for observability
- **Performance**: Concurrent TSL processing with XSLT caching (2-3x speedup)
- **Security**: Input validation, rate limiting, and path traversal protection
- **Configuration**: Flexible YAML-based config with environment variable support
- **Developer Tools**: Full VS Code integration, pre-commit hooks, and comprehensive testing

### Quality & Reliability

- **Test Coverage**: >80% overall, >85% for critical packages (api, pipeline, dsig)
- **Benchmarks**: Performance validated with comprehensive benchmark suite
- **Linting**: Multiple linters (golangci-lint, gosec, staticcheck)
- **CI/CD**: Automated testing, coverage tracking, and security scanning

## Architecture

### Multi-Registry Design

Go-Trust implements a flexible multi-registry architecture that allows multiple trust frameworks to be queried simultaneously for optimal performance and interoperability.

#### Registry Abstraction

The core `TrustRegistry` interface enables pluggable trust resolution backends:

```go
type TrustRegistry interface {
    Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)
    SupportedResourceTypes() []string
    Info() RegistryInfo
    Healthy() bool
    Refresh(ctx context.Context) error
}
```

Current implementations:
- **ETSI TSL Registry**: Validates X.509 certificates against ETSI TS 119 612 Trust Status Lists
- **OpenID Federation Registry**: Validates entity trust chains using OpenID Federation protocol
- **DID Methods**: *(planned)* Decentralized identifier resolution

#### Resolution Strategies

The `RegistryManager` coordinates multiple registries using simple routing strategies:

**Routing Strategies:**
- **FirstMatch** (default): Parallel queries return first positive match (fastest, OR with fast exit)
- **AllRegistries**: Query all registries and aggregate results (complete audit trail, OR semantics)
- **BestMatch**: Select highest confidence match from all results
- **Sequential**: Try registries in order until success (rate-limited APIs)

**Advanced Boolean Logic via CompositeRegistry:**

For complex trust policies, use `CompositeRegistry` to combine registries with boolean logic:
- **LogicAND**: ALL registries must agree (defense-in-depth)
- **LogicOR**: At least ONE registry must agree (fallback chain)
- **LogicMAJORITY**: >50% of registries must agree (consensus)
- **LogicQUORUM**: Configurable threshold (e.g., "2 of 3 must agree")

CompositeRegistry implements `TrustRegistry`, enabling **arbitrary nesting** for complex policies like `(A OR B) AND (C OR D)`.

For detailed documentation on multi-registry combinations, see [MULTI-REGISTRY-STRATEGIES.md](./docs/MULTI-REGISTRY-STRATEGIES.md).

**Quick Example:**
```go
// Defense in depth: BOTH ETSI-TSL AND OpenID Federation must approve
composite := registry.NewCompositeRegistry(
    "defense-in-depth",
    registry.LogicAND,
    etsiTSLRegistry,
    oidfRegistry,
)
manager.Register(composite)

// Complex nesting: (A OR B) AND C
orGroup := registry.NewCompositeRegistry("or-group", registry.LogicOR, regA, regB)
policy := registry.NewCompositeRegistry("main", registry.LogicAND, orGroup, regC)
manager.Register(policy)

// Quorum: 2 of 3 validators must agree
quorum := registry.NewCompositeRegistryWithOptions(
    "quorum",
    registry.LogicQUORUM,
    []registry.TrustRegistry{v1, v2, v3},
    registry.WithThreshold(2),
)
```

#### Circuit Breaker Pattern

Built-in circuit breakers prevent cascade failures:
- Automatic failure detection (5 failures trigger open circuit)
- Configurable reset timeout (default: 30s)
- Per-registry health tracking

#### Code Organization

The registry package is organized for clarity and maintainability:

```
pkg/registry/
├── interface.go         # TrustRegistry interface and type definitions
├── manager.go           # RegistryManager orchestration logic
├── strategies.go        # Resolution strategy implementations
├── circuit_breaker.go   # Failure handling
├── etsi/
│   └── tsl_registry.go  # ETSI TSL implementation
└── oidfed/
    └── oidfed_registry.go # OpenID Federation implementation
```

For detailed architecture documentation, see [ARCHITECTURE-MULTI-REGISTRY.md](./docs/ARCHITECTURE-MULTI-REGISTRY.md).

### OpenID Federation Registry

The OpenID Federation registry enables trust evaluation for entities in an OpenID Federation. It validates trust chains from entities to configured trust anchors using the [go-oidfed/lib](https://github.com/go-oidfed/lib) library.

#### Features

- **Trust Chain Validation**: Automatically builds and validates trust chains from entities to trust anchors
- **Signature Verification**: Verifies all entity statements in the chain using JWKS
- **Trust Mark Support**: Optional requirement for specific trust marks to be present
- **Metadata Extraction**: Extracts and returns entity metadata, trust marks, and certificates
- **Caching**: Built-in caching with automatic refresh for performance

#### Configuration Example

```go
import (
    "github.com/SUNET/go-trust/pkg/registry/oidfed"
)

// Create OpenID Federation registry
config := oidfed.Config{
    TrustAnchors: []oidfed.TrustAnchorConfig{
        {
            EntityID: "https://federation.example.com",
        },
    },
    RequiredTrustMarks: []string{
        "https://example.com/trustmark/wallet-provider",
    },
    EntityTypes: []string{"openid_provider"},
    Description: "EU Digital Identity Wallet Federation",
}

registry, err := oidfed.NewOIDFedRegistry(config)
if err != nil {
    log.Fatal(err)
}
```

#### AuthZEN Integration

The OpenID Federation registry maps federation concepts to AuthZEN evaluation:

**Request Format:**
```json
{
  "subject": {
    "type": "key",
    "id": "https://wallet.provider.example.com"
  },
  "resource": {
    "type": "x5c",
    "id": "https://wallet.provider.example.com",
    "key": ["<x5c-cert-chain>"]
  },
  "action": {
    "name": "http://ec.europa.eu/NS/wallet-provider"
  }
}
```

**Response with Valid Trust Chain:**
```json
{
  "decision": true,
  "context": {
    "reason": {
      "entity_id": "https://wallet.provider.example.com",
      "trust_chain_length": 3,
      "trust_anchor": "https://federation.example.com",
      "metadata": {
        "entity_types": ["openid_provider", "federation_entity"],
        "trust_marks": ["https://example.com/trustmark/wallet-provider"],
        "issuer": "https://wallet.provider.example.com",
        "subject": "https://wallet.provider.example.com",
        "expires_at": "2025-10-30T12:00:00Z"
      }
    }
  }
}
```

#### Trust Chain Validation

The registry performs the following validation steps:

1. **Entity Resolution**: Fetches the entity configuration from `/.well-known/openid-federation`
2. **Chain Building**: Follows authority hints to build trust chain to configured trust anchors
3. **Signature Verification**: Verifies all signatures in the chain using JWKS
4. **Policy Application**: Applies metadata policies from superior entities
5. **Constraint Checking**: Validates constraints (max path length, naming, entity types)
6. **Trust Mark Verification**: Checks for required trust marks if configured

For more details on OpenID Federation, see the [specification](https://openid.net/specs/openid-federation-1_0.html).

## Installation

```bash
# Clone the repository
git clone https://github.com/SUNET/go-trust.git
cd go-trust

# Build the project
make build

# Run tests
make test
```

## Examples

The [example](./example/) directory contains:
- Example directory structure for generating TSLs
- Sample pipeline configuration
- Usage examples for various trust scenarios

## XSLT Transformation & HTML Index Generation

Go-Trust includes built-in tools for transforming TSLs into user-friendly HTML documents and creating index pages for collections of TSLs.

### Using Embedded XSLT in Pipeline Configuration

The stylesheet is embedded in the binary, so you don't need to distribute separate files:

```yaml
- transform:
- embedded:tsl-to-html.xslt
- /output/directory
- html
```

This configuration transforms all TSLs in the pipeline to HTML using the embedded stylesheet and writes the output files to the specified directory.

### Available Embedded Stylesheets

- **tsl-to-html.xslt**: Transforms TSLs into comprehensive HTML documents with PicoCSS styling

### Generating an Index for HTML TSLs

After transforming TSLs to HTML, you can generate an index.html file that lists all the TSLs with key metadata:

```yaml
- generate_index:
- /output/directory
- "Trust Service Lists Index"
```

The index page includes:
- Links to each TSL HTML file
- Territory codes and badges
- Sequence numbers and dates
- Service counts
- TSL types

For a complete example, see [transform-with-index.yaml](./example/transform-with-index.yaml) in the examples directory.

### Performance Optimization

Go-Trust employs multiple performance optimizations for efficient TSL processing:

#### Concurrent Processing

XSLT transformations run in parallel using a worker pool:

- **Automatic parallelization**: Multiple TSLs transformed concurrently
- **2-3x speedup**: Significant performance gains on multi-core systems
- **Smart scaling**: Automatically scales to available CPU cores (up to 8 workers)
- **Zero configuration**: Enabled by default

Performance characteristics:
- **1 TSL**: ~15ms per transformation
- **20 TSLs**: ~300ms total (vs ~600ms sequential) - **2x faster**
- **50 TSLs**: ~700ms total (vs ~1500ms sequential) - **2.1x faster**

#### XSLT Caching

XSLT stylesheets are cached after first use to reduce I/O overhead:

- **Automatic caching**: Both file-based and embedded XSLTs are cached
- **5-10% improvement**: Additional speedup when processing multiple TSLs
- **Thread-safe**: Uses `sync.RWMutex` for concurrent access
- **Memory efficient**: Caches only stylesheet content, not transformation results

Combined with concurrent processing, these optimizations make Go-Trust particularly efficient when processing EU Trust Lists with 20+ member state TSLs.

### Security Features

Go-Trust implements comprehensive input validation and sanitization to protect against common security vulnerabilities:

#### Input Validation

All external inputs are validated before processing:

- **URL validation**: Enforces allowed schemes (http/https/file), detects path traversal attempts
- **File path validation**: Prevents null byte injection, path traversal, and access to system directories
- **XSLT path validation**: Validates embedded and file-based XSLT references
- **Output directory validation**: Blocks writes to system directories (/etc, /sys, C:\Windows)
- **Config file validation**: Ensures proper YAML file extensions and safe paths

#### Protection Features

- **Path traversal prevention**: Detects and blocks `..` sequences in paths
- **Null byte detection**: Prevents null byte injection attacks
- **System directory protection**: Blacklists known system directories
- **Scheme whitelisting**: Only allows explicitly permitted URL schemes
- **Automatic sanitization**: Cleans and normalizes file paths before use

The validation layer is automatically applied to:
- TSL loading from URLs or files
- XSLT transformation paths
- Output directories for publishing
- Certificate and key file paths for signing
- Configuration file paths

#### API Rate Limiting

Go-Trust includes per-IP rate limiting to prevent API abuse and ensure fair usage:

- **Token bucket algorithm**: Uses `golang.org/x/time/rate` for smooth rate limiting
- **Per-IP tracking**: Each client IP address has its own rate limit
- **Configurable limits**: Set requests per second (RPS) via configuration or environment variables
- **Automatic burst handling**: Allows brief bursts above the sustained rate limit
- **429 responses**: Clients exceeding limits receive standard HTTP 429 (Too Many Requests)

Configuration options:
```yaml
security:
  rate_limit_rps: 100  # Maximum requests per second per IP
```

Or via environment variable:
```bash
GT_RATE_LIMIT_RPS=100 ./gt pipeline.yaml
```

Rate limiting is applied to all API endpoints when `rate_limit_rps > 0`. Set to 0 to disable rate limiting entirely (not recommended for production).

## Digital Signatures

Go-Trust includes a dedicated package for XML digital signatures in [pkg/dsig](./pkg/dsig/). This package supports:

- File-based certificate and key signing
- PKCS#11 hardware security module integration
- Standardized interface for all signing methods
- Testing utilities for PKCS#11 with SoftHSM

## Usage

### Command Line Interface

Go-Trust provides a flexible command line interface with two operating modes:

#### API Server Mode (Default)

Run as a continuous service with periodic TSL processing:

```bash
# Run the trust service with a pipeline configuration
./gt ./pipeline.yaml

# Run with custom settings
./gt --host 0.0.0.0 --port 8080 --frequency 1h ./pipeline.yaml

# With logging configuration
./gt --log-level debug --log-format json ./pipeline.yaml
```

#### Command-Line Processing Mode

Process pipelines once and exit (no API server):

```bash
# One-shot pipeline execution
./gt --no-server ./pipeline.yaml

# With debug logging
./gt --no-server --log-level debug ./pipeline.yaml

# With JSON logging for parsing
./gt --no-server --log-format json ./pipeline.yaml > output.json

# In a cron job (daily HTML generation)
0 2 * * * /usr/local/bin/gt --no-server /etc/go-trust/daily-processing.yaml

# In CI/CD pipelines
./gt --no-server --log-format json ./ci-pipeline.yaml
```

The `--no-server` flag is useful for:
- **Batch processing**: Transform TSLs without running a server
- **CI/CD pipelines**: Generate reports in build systems
- **Scheduled jobs**: Cron jobs for periodic processing
- **Development**: Quick testing of pipeline configurations

See [example/cmdline-processing.yaml](./example/cmdline-processing.yaml) for a complete example.

#### Command-Line Options

```
Usage: gt [options] <pipeline.yaml>
Options:
  --help         Show this help message and exit
  --version      Show version information and exit
  --config       Configuration file path (YAML format)
  --host         API server hostname (default: 127.0.0.1)
  --port         API server port (default: 6001)
  --frequency    Pipeline update frequency (default: 5m)
  --no-server    Run pipeline once and exit (no API server)
Logging options:
  --log-level    Logging level: debug, info, warn, error, fatal (default: info)
  --log-format   Logging format: text or json (default: text)
  --log-output   Log output: stdout, stderr, or file path (default: stdout)

Configuration precedence (highest to lowest):
  1. Command-line flags
  2. Environment variables (GT_* prefix)
  3. Configuration file (--config)
  4. Built-in defaults
```

#### Configuration File

Go-Trust supports configuration via YAML files for easier deployment and management. Create a `config.yaml` file:

```yaml
server:
  host: "0.0.0.0"
  port: "6001"
  frequency: "5m"

logging:
  level: "info"
  format: "text"
  output: "stdout"

pipeline:
  timeout: "30s"
  max_request_size: 10485760
  max_redirects: 3
  allowed_hosts:
    - "*.europa.eu"

security:
  rate_limit_rps: 100
  enable_cors: false
  allowed_origins: []
```

Use the config file:

```bash
gt --config config.yaml pipeline.yaml
```

#### Environment Variables

All configuration options can be set via environment variables with the `GT_` prefix:

```bash
export GT_HOST="0.0.0.0"
export GT_PORT="8080"
export GT_LOG_LEVEL="debug"
export GT_FREQUENCY="10m"
export GT_RATE_LIMIT_RPS="200"

gt pipeline.yaml
```

See [example/config.yaml](./example/config.yaml) for a complete configuration example with all available options and documentation.

### API Endpoints

The service exposes a clean, standards-compliant API:

#### Health & Monitoring (Kubernetes-native)

- **GET /healthz**: Liveness probe (returns 200 OK when service is running)
- **GET /readyz**: Readiness probe (returns 200 when TSLs loaded, 503 otherwise)
  - Add `?verbose=true` to include detailed TSL summaries in the response
- **GET /metrics**: Prometheus metrics endpoint for monitoring and observability

The health endpoints follow Kubernetes conventions:
- **Liveness** (`/healthz`) - Checks if the service is alive (K8s restarts unhealthy containers)
- **Readiness** (`/readyz`) - Checks if the service is ready to accept traffic (K8s removes from load balancer if not ready)

See the [Deployment Guide](#deployment) for Kubernetes integration examples.

#### AuthZEN Discovery & Evaluation

- **GET /.well-known/authzen-configuration**: PDP discovery endpoint per RFC 8615 and AuthZEN spec Section 9
- **POST /evaluation**: Evaluate trust decisions for X.509 certificates (AuthZEN Trust Registry Profile)

#### TSL Information

- **GET /tsls**: Get comprehensive information about all loaded Trust Status Lists
  - Returns: TSL count, last update time, and detailed TSL metadata (territory, sequence, dates, service counts)

#### Deprecated Endpoints (removed in v2.0.0)

⚠️ **The following endpoints are deprecated and will be removed in the next major version:**

- **GET /status** → Use `GET /readyz` instead
- **GET /info** → Use `GET /tsls` instead

These deprecated endpoints return HTTP headers indicating their deprecation:
```
Deprecation: true
Link: </readyz>; rel="alternate"
X-API-Warn: This endpoint is deprecated. Please use GET /readyz instead.
```

**Migration Guide:**
- Replace `/status` calls with `/readyz` (same data, enhanced capabilities)
- Replace `/info` calls with `/tsls` (better structure: `{count, last_updated, tsls: [...]}`)
- Update Kubernetes probes to use `/healthz` and `/readyz` (not `/health`, `/ready`, or `/readiness`)
- Use `/readyz?verbose=true` to get detailed TSL information (replaces separate `/status` + `/info` calls)

See the [Deployment Guide](#deployment) for Kubernetes integration examples.

#### Prometheus Metrics

The `/metrics` endpoint exposes comprehensive operational metrics:

**Pipeline Metrics:**
- `pipeline_execution_duration_seconds` - Time to complete pipeline execution
- `pipeline_execution_total` - Total pipeline executions (with success/failure labels)
- `pipeline_execution_errors_total` - Pipeline execution errors by type
- `pipeline_tsl_count` - Number of TSLs in current pipeline
- `pipeline_tsl_processing_duration_seconds` - TSL processing time histogram

**API Metrics:**
- `api_requests_total` - HTTP requests by method, endpoint, and status code
- `api_request_duration_seconds` - Request latency histogram
- `api_requests_in_flight` - Current number of active requests

**Error Metrics:**
- `errors_total` - Application errors by type and operation

**Certificate Validation Metrics:**
- `cert_validation_total` - Certificate validations by result (valid/invalid/error)
- `cert_validation_duration_seconds` - Certificate validation latency

Example Prometheus queries:
```promql
# Request rate by endpoint
rate(api_requests_total[5m])

# 95th percentile latency
histogram_quantile(0.95, rate(api_request_duration_seconds_bucket[5m]))

# Pipeline success rate
rate(pipeline_execution_total{result="success"}[5m]) / rate(pipeline_execution_total[5m])

# Certificate validation error rate
rate(cert_validation_total{result="error"}[5m])
```

#### AuthZEN Decision API

Example AuthZEN decision request:

```json
{
  "subject": {
    "type": "x509_certificate",
    "id": "subject-123",
    "properties": {
      "x5c": [
        "MIIDQjCCAiqgAwIBAgIUJlq+zz4..."
      ]
    }
  },
  "resource": {
    "type": "service",
    "id": "resource-123",
    "properties": {}
  },
  "action": {
    "name": "trust",
    "properties": {}
  },
  "context": {}
}
```

Example response:

```json
{
  "decision": true
}
```

Or with error details:

```json
{
  "decision": false,
  "context": {
    "id": "err-123",
    "reason_admin": {
      "error": "certificate has expired or is not yet valid"
    },
    "reason_user": {
      "message": "The certificate is not trusted"
    }
  }
}
```

## Pipeline Steps

Go-Trust uses a pipeline architecture for TSL processing:

1. **Load**: Read TSLs from files or URLs
2. **Select**: Filter TSLs based on criteria
3. **Publish**: Serialize TSLs to XML files
4. **Custom**: Add your own processing steps

### XML Digital Signatures

Go-Trust supports XML-DSIG signatures for published TSLs using either:

1. **File-based certificates and keys**: Standard PEM-encoded X.509 certificates and private keys
2. **PKCS#11 hardware tokens**: HSMs or smart cards for secure key storage and operations

#### File-Based Signing

For development and testing environments, you can use file-based certificates and private keys:

```yaml
- publish: ["./output", "/path/to/cert.pem", "/path/to/key.pem"]
```

This method reads the certificate and private key from PEM-encoded files.

#### PKCS#11 Hardware Token Signing

For production environments, you can use PKCS#11 hardware security modules (HSMs) or smart cards:

```yaml
- publish: ["./output", "pkcs11:module=/path/to/lib;pin=1234;slot-id=0", "key-label", "cert-label"]
```

The PKCS#11 URI format follows RFC 7512 and supports these parameters:

- `module`: Path to PKCS#11 library/middleware (required)
- `pin`: PIN code for token access (required)
- `slot-id`: Numeric slot identifier (optional)
- `token`: Token label for identifying the token (optional, alternative to slot-id)

The `key-label` and `cert-label` arguments specify the labels used to identify the private key and certificate in the HSM.

Example pipeline configuration (YAML):

```yaml
# Pipeline YAML Format
# IMPORTANT: Pipeline steps are defined as a direct sequence of operations
# Each step is a mapping with a single key (the method name) and a list of arguments
# Do NOT use a "steps:" key in your YAML - steps are defined directly at the top level

- generate: ["./example/example-tsl"]  # Generate TSL from directory
- select: []                          # Extract certificates into a pool
- publish: ["./output"]               # Publish TSLs as XML files
- publish: ["./output", "/path/to/cert.pem", "/path/to/key.pem"]  # Publish with file-based XML-DSIG signatures
- publish: ["./output", "pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;pin=1234;slot-id=0", "tsl-signing-key", "tsl-signing-cert"]  # Publish with PKCS#11 XML-DSIG signatures
```

#### HSM Compatibility

The PKCS#11 implementation has been tested with:
- SoftHSM (for development/testing)
- Thales Luna HSM
- YubiKey (via PIV application)

For other HSMs, you may need to adjust the configuration according to your device's specifications.

## Configuration

The application is configured using command-line flags:

```bash
# Start the API server with custom settings
./gt --host 0.0.0.0 --port 8080 --frequency 1h ./path/to/pipeline.yaml

# Configure external URL for AuthZEN discovery (production deployments)
./gt --external-url https://pdp.example.com ./path/to/pipeline.yaml
```

Available command-line options:
- `--host`: API server hostname (default: 127.0.0.1)
- `--port`: API server port (default: 6001)
- `--external-url`: External URL for PDP discovery (e.g., https://pdp.example.com)
- `--frequency`: Pipeline update frequency (default: 5m)
- `--help`: Show help message
- `--version`: Show version information

### External URL Configuration

When deploying behind a reverse proxy or load balancer, configure the external URL for proper AuthZEN discovery:

**Command-line flag:**
```bash
./gt --external-url https://pdp.example.com pipeline.yaml
```

**Environment variable:**
```bash
export GO_TRUST_EXTERNAL_URL=https://pdp.example.com
./gt pipeline.yaml
```

**Priority order:** CLI flag > Environment variable > Default (http://host:port)

The `.well-known/authzen-configuration` endpoint will return the configured external URL:
```json
{
  "policy_decision_point": "https://pdp.example.com",
  "access_evaluation_endpoint": "https://pdp.example.com/evaluation"
}
```

See `example/authzen-discovery.yaml` for a complete configuration example.
```

## Development

### Requirements

- Go 1.18+
- Access to ETSI TS 119612 TSLs or sample data
- Make for build automation

### Quick Start

For detailed developer documentation, see [DEVELOPER.md](DEVELOPER.md).

```bash
# Clone the repository
git clone https://github.com/SUNET/go-trust.git
cd go-trust

# Set up development environment
make setup

# Run tests
make test

# Build binary
make build
```

### Building from Source

```bash
# Build binary
make build

# Run tests with coverage
make test

# Check code coverage
make coverage

# Run linters
make lint

# Run benchmarks
make bench
```

### Available Make Targets

Run `make help` to see all available targets:

```bash
make help
```

Key targets:
- `make all` - Run all checks and build (CI pipeline)
- `make test` - Run tests with race detection
- `make coverage` - Generate coverage report
- `make lint` - Run all linters
- `make fmt` - Format code
- `make quick` - Quick pre-commit checks (fmt + vet)
- `make bench` - Run benchmarks
- `make clean` - Remove build artifacts

## Deployment

### Docker

Build and run using Docker:

```bash
# Build Docker image
docker build -t go-trust:latest .

# Run container
docker run -d \
  --name go-trust-server \
  -p 6001:6001 \
  -v $(pwd)/pipeline.yaml:/app/pipeline.yaml \
  -v $(pwd)/config.yaml:/app/config.yaml \
  go-trust:latest --config /app/config.yaml /app/pipeline.yaml
```

### Kubernetes

Deploy to Kubernetes with health checks and metrics:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: go-trust
  labels:
    app: go-trust
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
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: go-trust
        image: go-trust:latest
        ports:
        - name: http
          containerPort: 6001
          protocol: TCP
        env:
        - name: GT_HOST
          value: "0.0.0.0"
        - name: GT_PORT
          value: "6001"
        - name: GT_LOG_LEVEL
          value: "info"
        - name: GT_LOG_FORMAT
          value: "json"
        - name: GT_RATE_LIMIT_RPS
          value: "100"
        livenessProbe:
          httpGet:
            path: /healthz
            port: http
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /readiness
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        - name: pipeline
          mountPath: /app/pipeline.yaml
          subPath: pipeline.yaml
      volumes:
      - name: config
        configMap:
          name: go-trust-config
      - name: pipeline
        configMap:
          name: go-trust-pipeline
---
apiVersion: v1
kind: Service
metadata:
  name: go-trust
  labels:
    app: go-trust
spec:
  type: ClusterIP
  ports:
  - port: 6001
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: go-trust
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: go-trust-config
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: "6001"
      frequency: "5m"
    logging:
      level: "info"
      format: "json"
      output: "stdout"
    security:
      rate_limit_rps: 100
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: go-trust-pipeline
data:
  pipeline.yaml: |
    # Your pipeline configuration here
```

### Prometheus Monitoring

Create a ServiceMonitor for Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: go-trust
  labels:
    app: go-trust
spec:
  selector:
    matchLabels:
      app: go-trust
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Health Check Configuration

The health endpoints are designed for Kubernetes probes:

- **Liveness probe** (`/healthz`): Checks if the service is running
  - Returns 200 OK if the service is alive
  - Should trigger container restart on failure

- **Readiness probe** (`/readiness`): Checks if the service is ready to accept traffic
  - Returns 200 OK when TSLs are loaded and service is ready
  - Returns 503 Service Unavailable during startup or when pipeline fails
  - Should remove pod from load balancer on failure

Recommended probe configuration:
- **Liveness**: `initialDelaySeconds: 10`, `periodSeconds: 30`, `failureThreshold: 3`
- **Readiness**: `initialDelaySeconds: 5`, `periodSeconds: 10`, `failureThreshold: 3`

### Project Structure

```
go-trust/
├── .github/        # GitHub configuration
│   └── workflows/  # GitHub Actions workflows
├── cmd/            # Command line tools
├── pkg/            # Core packages
│   ├── api/        # HTTP API implementation
│   ├── authzen/    # AuthZEN integration
│   └── pipeline/   # TSL processing pipeline
├── example/        # Example configurations and data
└── tests/          # Integration tests
```

### CI/CD Workflows

This project uses GitHub Actions for continuous integration and delivery:

- **Go Workflow** (`go.yml`): Builds, tests, and checks code coverage
- **Release Workflow** (`release.yml`): Creates releases when new tags are pushed
- **CodeQL Analysis** (`codeql.yml`): Scans code for security vulnerabilities
- **Dependency Review** (`dependency-review.yml`): Checks dependencies for security issues

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:

- Setting up your development environment
- Code style and standards
- Testing requirements
- Submitting pull requests
- Release process

Quick contribution workflow:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests and linters (`make quick && make test`)
4. Commit your changes (`git commit -m 'feat: Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

For detailed development documentation, see [DEVELOPER.md](DEVELOPER.md).

### Testing

Go-Trust has comprehensive test coverage (>80% overall, >85% for critical packages).

Before submitting a pull request, ensure:

```bash
# Run all tests
make test

# Check coverage
make coverage

# Run linters
make lint

# Quick pre-commit checks
make quick
```

The CI pipeline automatically runs these checks on all pull requests. All checks must pass before merging.

For detailed testing guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md#testing).

#### PKCS#11 Testing with SoftHSM

Go-Trust includes tests for PKCS#11-based XML-DSIG signing using SoftHSM. These tests are skipped if SoftHSM is not installed.

To run the PKCS#11 tests with SoftHSM:

1. Install SoftHSM version 2:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install softhsm2

   # CentOS/RHEL
   sudo yum install softhsm2

   # macOS with Homebrew
   brew install softhsm
   ```

2. Run the tests:
   ```bash
   # Run all tests, including SoftHSM tests if available
   go test ./...

   # Run only the SoftHSM tests
   go test ./pkg/pipeline -run TestPKCS11SignerWithSoftHSM
   ```

The test will:
1. Create a temporary SoftHSM token
2. Generate a test certificate and private key
3. Import them into the token
4. Use the PKCS11Signer to sign XML data
5. Clean up the temporary token when done

These tests ensure that the PKCS#11 signing functionality works correctly with hardware security modules.

### PKCS#11 Signing Implementation

Go-Trust now uses the improved Signer interface from the goxmldsig library to handle XML-DSIG signatures with PKCS#11 hardware tokens. This integration provides several benefits:

1. **More Consistent API**: The signing code follows a unified interface approach
2. **Better Abstraction**: The signing mechanism is abstracted behind the Signer interface
3. **Simpler Maintenance**: Reduced code duplication and complexity
4. **Improved Security**: Direct hardware token integration with no private key exposure

When using a PKCS#11 token for signing, the library:
1. Connects to the token using the provided configuration
2. Locates the key and certificate based on their labels/IDs
3. Creates a PKCS11Signer that implements the goxmldsig Signer interface
4. Uses the PKCS11Signer to sign the XML document without ever exposing the private key material

## Logging System

Go-Trust includes a flexible, structured logging system built around an abstract Logger interface, with implementations available for different logging backends.

### Logging Interface

The logging system is designed with the following features:

- **Structured Logging**: Log entries include structured fields, not just text messages
- **Log Levels**: Support for Debug, Info, Warn, Error, and Fatal levels
- **Context Awareness**: Logging with context propagation
- **Extensible**: Support for different logging backends through adapters

### Logging Configuration

Logging is configured through command-line arguments, not in pipeline YAML files:

```bash
# Configure logging via command line
./gt --log-level debug --log-format json ./pipeline.yaml
```

Logging statements in pipeline steps:

```yaml
# Example logging in pipeline
- log:
    - "Processing TSL files"
  - count=5
  - source=example.com

  - log:
  - level=debug "Detailed debugging information"
  - tsl_id=SETSL123
```

### Log Pipeline Step

The `log` pipeline step allows logging messages with structured data:

```yaml
- log:
- "Message to log"
- key1=value1
- key2=value2
```

To specify a log level other than the default (info):

```yaml
- log:
- level=debug "Debug message with more details"
- operation=validation
- result=success
```

### Programmatic Usage

When extending Go-Trust, you can use the logging system programmatically:

```go
import "github.com/SUNET/go-trust/pkg/logging"

func MyFunction() {
    logger := logging.DefaultLogger()

    // Simple logging
    logger.Info("Processing started")

    // With structured fields
    logger.Debug("Validation details",
        logging.F("certCount", 5),
        logging.F("valid", true),
    )

    // With context
    ctx := context.Background()
    ctxLogger := logger.WithContext(ctx)
    ctxLogger.Info("Operation completed")
}
```

## License

This project is licensed under the BSD 2-Clause License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Acknowledgments

- [ETSI TS 119612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/) - Trust-service status list format
- [AuthZEN](https://authzen.dev/) - Authorization framework
- [SUNET](https://www.sunet.se/) - Swedish University Network

