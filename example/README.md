# Go-Trust Examples

This directory contains example code for using go-trust as an AuthZEN PDP server.

## Example Files

| File | Description |
|------|-------------|
| `didweb-registry-example.go` | Demonstrates programmatic use of the did:web registry |
| `testserver-example.go` | Shows how to use the embedded test server for integration testing |

## Running Examples

```bash
# DID Web registry example
go run example/didweb-registry-example.go

# Test server example  
go run example/testserver-example.go
```

## Server Configuration

Go-trust is configured via command-line options, not YAML files:

```bash
# Basic usage with certificate bundle
go-trust --etsi-cert-bundle /path/to/trusted-certs.pem

# Full configuration
go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /etc/go-trust/trusted-certs.pem \
  --external-url https://pdp.example.com \
  --log-level info \
  --log-format json
```

## TSL Processing

For TSL processing (load, transform, sign, publish), use `tsl-tool` from [g119612](https://github.com/sirosfoundation/g119612):

```bash
# Process TSLs and generate certificate bundle
tsl-tool --output trusted-certs.pem pipeline.yaml

# Then run go-trust with the generated bundle
go-trust --etsi-cert-bundle trusted-certs.pem
```

See the main [README](../README.md) for complete documentation.
