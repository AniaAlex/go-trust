# Go-Trust Examples

This directory contains example configurations for the go-trust TSL pipeline processing system.

## Quick Start

```bash
# Run as CLI tool (one-shot processing)
gt --no-server example/01-basic-cli.yaml

# Run as API server
gt --pipeline example/02-server-pipeline.yaml

# Generate a TSL from metadata
gt --no-server example/03-generate-tsl.yaml
```

## Example Files

| File | Description | Use Case |
|------|-------------|----------|
| `01-basic-cli.yaml` | Basic command-line processing | CI/CD, cron jobs, one-time transformations |
| `02-server-pipeline.yaml` | Full server mode with API | Production API server, AuthZEN PDP |
| `03-generate-tsl.yaml` | Generate TSL from YAML metadata | Creating custom trust lists |
| `didweb-registry-example.go` | Go code using did:web registry | Programmatic did:web resolution |

## Pipeline YAML Format

Pipeline configurations are YAML files containing a sequence of steps. Each step specifies a function and its arguments:

```yaml
# Pipeline is a direct list of steps (no 'steps:' key)
- function-name:
    - argument1
    - argument2

- another-function:
    - argument
```

## Available Pipeline Functions

| Function | Description | Arguments |
|----------|-------------|-----------|
| `load` | Load TSL from URL or file | `url` or `file-path` |
| `set-fetch-options` | Configure fetch behavior | `max-depth:N`, `timeout:Ns`, `user-agent:string` |
| `select` | Build certificate pool | `all`, `status:uri`, `service-type:uri` |
| `transform` | Apply XSLT transformation | `xslt-path`, `output-dir`, `extension` |
| `generate_index` | Create HTML index page | `directory`, `title` |
| `publish` | Write TSL to directory | `output-dir`, optionally `cert.pem`, `key.pem` |
| `generate` | Create TSL from metadata | `metadata-dir` |
| `log` | Log a message | `format-string` |
| `echo` | Echo arguments (debug) | `args...` |

### Function Details

#### `load`

```yaml
- load:
    - https://ec.europa.eu/tools/lotl/eu-lotl.xml
```

#### `set-fetch-options`

```yaml
- set-fetch-options:
    - max-depth:2              # Follow TSL references N levels deep
    - timeout:60s              # HTTP request timeout
    - user-agent:MyApp/1.0     # HTTP User-Agent header
```

#### `select`

```yaml
# Select all certificates
- select:
    - all

# Filter by service status and type
- select:
    - status:http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted
    - service-type:http://uri.etsi.org/TrstSvc/Svctype/CA/QC
```

#### `transform`

```yaml
- transform:
    - embedded:tsl-to-html.xslt    # Use bundled stylesheet
    - ./output/html                 # Output directory
    - html                          # File extension
```

#### `publish`

```yaml
# Publish without signing
- publish:
    - ./output/xml

# Publish with XML-DSIG signature
- publish:
    - ./output/signed
    - /path/to/cert.pem
    - /path/to/key.pem

# Publish with tree structure
- publish:
    - ./output/tree
    - tree:territory               # or tree:index
```

#### `generate`

```yaml
- generate:
    - ./metadata-directory
```

## TSL Generation Metadata Structure

To generate a TSL, create a directory with this structure:

```text
my-tsl/
├── scheme.yaml                    # Required: TSL scheme info
└── providers/
    └── my-provider/
        ├── provider.yaml          # Required: Provider info
        ├── service.yaml           # Required: Service metadata
        └── cert.pem               # Required: Certificate(s)
```

See `example-tsl/` for a complete example.

## Command-Line Options

```bash
# CLI mode (one-shot processing, no server)
gt --no-server pipeline.yaml

# Server mode
gt --pipeline pipeline.yaml [options]

# Common options
  --host 0.0.0.0              # Listen address
  --port 6001                 # Server port
  --frequency 5m              # Pipeline refresh interval
  --external-url URL          # External URL for .well-known discovery
  --log-level debug           # Log level: debug, info, warn, error
  --log-format json           # Log format: text, json
```

## did:web Registry Example

The `didweb-registry-example.go` file demonstrates programmatic use of the did:web registry for resolving Decentralized Identifiers:

```go
// Create a did:web registry
registry, _ := didweb.NewDIDWebRegistry(didweb.Config{
    Timeout:     30 * time.Second,
    Description: "DID Web Resolver",
})

// Evaluate an AuthZEN request
resp, _ := registry.Evaluate(ctx, &authzen.EvaluationRequest{
    Subject: authzen.Subject{
        Type: "key",
        ID:   "did:web:example.com",
    },
    Resource: authzen.Resource{
        Type: "jwk",
        ID:   "did:web:example.com",
        Key:  []interface{}{jwkData},
    },
})
```
