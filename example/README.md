# Go-Trust Examples

This directory contains configuration examples for running go-trust as an AuthZEN PDP server.

## Configuration Examples

| File | Description |
|------|-------------|
| `config.yaml` | Server configuration file example |
| `docker-compose.yaml` | Docker Compose deployment |
| `kubernetes.yaml` | Kubernetes deployment with Ingress and ServiceMonitor |
| `prometheus.yml` | Prometheus scrape configuration |

## Testing Examples

The `testing/` subdirectory contains Go code examples for integration testing:
- `testing/didweb-registry-example.go` - Using the did:web registry programmatically
- `testing/testserver-example.go` - Embedded test server for testing AuthZEN clients

## Quick Start

### Running Locally

```bash
# Build the binary
make build

# Run with certificate bundle
./gt --etsi-cert-bundle /path/to/trusted-certs.pem

# Run with config file
./gt --config example/config.yaml
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

See the main [README](../README.md) for complete documentation.
