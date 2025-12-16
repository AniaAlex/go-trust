# Architecture Analysis: Separating AuthZEN Server from TSL Pipeline

## Implementation Status

> **Updated: December 2024**
>
> This analysis has been partially implemented. The ETSI registry has been refactored
> to eliminate direct pipeline dependency, following a hybrid of Options A and D.

### What Has Been Implemented

1. **Standalone TSLRegistry** (`pkg/registry/etsi/registry.go`):
   - Uses `etsi119612.FetchTSLWithOptions` directly (no pipeline dependency)
   - Can load from: PEM bundles, local TSL files, or remote URLs
   - `AllowNetworkAccess` flag controls whether network URLs are permitted
   - Suitable for tools and standalone applications

2. **PipelineBackedRegistry** (`pkg/registry/etsi/pipeline_backed.go`):
   - Wraps `PipelineContextProvider` interface (implemented by `pipeline.Context`)
   - Reads trust data updated by background pipeline
   - Used by go-trust server for automatic TSL refresh

3. **pipeline.Context Implements PipelineContextProvider**:
   - `GetCertPool()`, `GetTSLs()`, `GetTSLCount()` methods added
   - Decouples registry from pipeline package structure

### What Remains

- [ ] Create separate `etsi-tsl-tool` CLI for pipeline-only execution
- [ ] Add configuration file support for ETSI registry options
- [ ] Consider moving pipeline to separate module

---

## Current Architecture

The current `go-trust` codebase is a monolithic application that combines two distinct responsibilities:

### 1. TSL Pipeline Processing Engine
- **Location**: `pkg/pipeline/`, `xslt/`
- **Purpose**: Load, transform, filter, and publish ETSI TS 119612 Trust Status Lists
- **Features**:
  - YAML-defined pipeline steps (`load`, `select`, `transform`, `publish`, `generate`, etc.)
  - XSLT transformations for TSL-to-HTML conversion
  - Certificate pool construction from TSLs
  - Multi-TSL aggregation with pointer following
  - Publishing to filesystem, HTML reports, index generation

### 2. AuthZEN Trust Registry Server
- **Location**: `pkg/api/`, `pkg/authzen/`, `pkg/authzenclient/`, `pkg/registry/`
- **Purpose**: Provide AuthZEN-compliant PDP for trust evaluation
- **Features**:
  - HTTP API with `/evaluation` endpoint
  - Multi-registry support (ETSI TSL, did:web, did:key, OpenID Federation)
  - Resolution-only requests for DID/metadata resolution
  - `.well-known/authzen-configuration` discovery
  - Health/readiness endpoints, Prometheus metrics

### Coupling Points

The main coupling is in `main.go` and `pkg/registry/etsi/`:
```
Pipeline → Context (TSLs, CertPool) → TSLRegistry → RegistryManager → API
```

The `TSLRegistry` wraps `pipeline.Context` to provide `TrustRegistry` interface.

---

## Option A: Two Separate Tools (Recommended)

### go-trust (AuthZEN Server)
Keeps the name `go-trust` for the AuthZEN PDP server.

**Responsibilities**:
- AuthZEN evaluation endpoint (`/evaluation`)
- Multi-registry architecture (ETSI, DID methods, OIDF)
- Discovery endpoint (`.well-known/authzen-configuration`)
- Health/readiness/metrics endpoints
- Trust decision caching and circuit breakers

**Packages to keep**:
- `pkg/api/` - HTTP handlers
- `pkg/authzen/` - Protocol types
- `pkg/authzenclient/` - Client library
- `pkg/registry/` - All registries (etsi, did, didweb, oidfed)
- `pkg/config/`, `pkg/logging/`, `pkg/utils/`
- `pkg/validation/` - Certificate validation

**Data sources** (loaded at startup, not processed):
- Pre-built certificate pools (PEM bundles)
- TSL XML files from filesystem
- Remote trust anchors (URLs)

### etsi-tsl-tool (Pipeline Processor)
New dedicated CLI tool for ETSI TSL pipeline processing.

**Responsibilities**:
- Load TSLs from URLs/files
- Follow TSL pointers recursively
- XSLT transformations (HTML reports)
- Certificate pool extraction
- Publishing (filesystem, indexes)
- Custom TSL generation

**Packages to move/copy**:
- `pkg/pipeline/` - Core pipeline engine
- `xslt/` - XSLT stylesheets
- `pkg/dsig/` - XML signature handling

**Output formats**:
- PEM certificate bundles (for `go-trust` to consume)
- XML TSL files
- HTML reports
- JSON indexes

### Benefits
1. **Single Responsibility**: Each tool does one thing well
2. **Deployment Flexibility**: Pipeline can run as a cron job; server runs 24/7
3. **Reduced Attack Surface**: TSL processor doesn't need network server
4. **Independent Scaling**: Pipeline runs once daily; server handles real-time traffic
5. **Cleaner Testing**: Each tool can be tested in isolation

### Drawbacks
1. **Integration Complexity**: Need to coordinate outputs/inputs
2. **Two Binaries to Build/Release**: More release management
3. **Data Synchronization**: Server needs to reload when pipeline updates

---

## Option B: Subcommands in Single Binary

Keep everything in `go-trust` with subcommands:

```bash
go-trust serve --pipeline pipeline.yaml   # AuthZEN server mode (current behavior)
go-trust process pipeline.yaml            # One-shot pipeline processing
go-trust process --watch pipeline.yaml    # Continuous processing mode
```

### Benefits
1. **Single Binary**: Easier distribution
2. **Shared Code**: No duplication of utilities
3. **Existing Pattern**: Many tools use subcommands (git, docker, kubectl)

### Drawbacks
1. **Bloated Binary**: Server includes pipeline code it may never use
2. **Confusing Scope**: What is `go-trust` really?
3. **Dependency Contamination**: Server gets pipeline dependencies

---

## Option C: Plugin Architecture

Keep `go-trust` as AuthZEN server, make registries pluggable:

```yaml
registries:
  - type: etsi-tsl
    source: /var/lib/tsl/certpool.pem  # Pre-processed data
  - type: did:web
  - type: oidf
    trust_anchor: https://federation.example.com
```

The pipeline would be a completely separate project that produces data `go-trust` consumes.

### Benefits
1. **Maximum Decoupling**: Server knows nothing about TSL processing
2. **Standard Data Formats**: PEM bundles, JSON configs
3. **External Tools**: Could use any TSL processor (not just ours)

### Drawbacks
1. **Loss of Features**: No real-time TSL refresh in server
2. **Configuration Complexity**: Need to configure data paths
3. **More Moving Parts**: Separate orchestration needed

---

## Option D: Library-First Approach

Refactor into reusable libraries, make CLI tools thin wrappers:

```
github.com/sirosfoundation/go-trust/
├── pkg/
│   ├── authzen/         # Protocol types (already standalone)
│   ├── authzenclient/   # Client library (already standalone)
│   ├── trustregistry/   # Server-side registry framework
│   ├── tslpipeline/     # TSL processing library
│   └── ...
├── cmd/
│   ├── go-trust/        # AuthZEN server CLI
│   └── tsl-tool/        # Pipeline CLI
```

### Benefits
1. **Maximum Reuse**: Libraries usable by any Go project
2. **Clean Boundaries**: Package-level separation
3. **Testable**: Libraries have clear APIs

### Drawbacks
1. **More Upfront Work**: Significant refactoring
2. **API Stability**: Need to maintain library APIs

---

## Recommendation

**Option A (Two Separate Tools)** with elements of **Option D (Library-First)**:

### Phase 1: Extract Standalone Libraries
1. `pkg/authzen/` - Already standalone ✅
2. `pkg/authzenclient/` - Already standalone ✅
3. Extract `pkg/tslpipeline/` from current `pkg/pipeline/`

### Phase 2: Create `etsi-tsl-tool`
New repository or `cmd/tsl-tool/` in this repo:
```go
package main

import (
    "github.com/sirosfoundation/go-trust/pkg/tslpipeline"
)

func main() {
    // CLI for TSL processing
}
```

### Phase 3: Simplify `go-trust` Server
- Remove pipeline background updater
- Load pre-processed data (PEM bundles, TSL files)
- Focus on AuthZEN serving

### Data Flow
```
[etsi-tsl-tool] ---> [PEM/TSL files] ---> [go-trust server]
     │                                           │
     │ (cron job, CI/CD)                        │ (Kubernetes, Docker)
     │                                           │
     └─── Produces certificate bundles          └─── Serves AuthZEN API
```

---

## Migration Path

1. **v1.x (Current)**: Keep combined tool for backward compatibility
2. **v2.0**: Add `--no-server` mode for pipeline-only execution
3. **v2.1**: Extract `tsl-tool` as separate command
4. **v3.0**: Deprecate pipeline in `go-trust`, recommend `etsi-tsl-tool`

---

## Questions to Consider

1. **Who runs the pipeline?** Operations team (cron) vs. application (integrated)?
2. **How often do TSLs change?** Daily? Weekly? Real-time updates needed?
3. **Where is data stored?** Filesystem? Object storage? ConfigMap?
4. **What's the deployment model?** Kubernetes? Docker? Bare metal?

---

## Appendix: Package Dependencies

### Current `go-trust` Dependencies by Category

**Pipeline-specific** (can be removed from server):
- `github.com/PuerkitoBio/goquery` - HTML parsing for TSL scraping
- XSLT processing
- XML signature generation/validation

**Server-specific**:
- `github.com/gin-gonic/gin` - HTTP framework
- `github.com/prometheus/client_golang` - Metrics
- `github.com/swaggo/*` - Swagger docs

**Shared**:
- `github.com/beevik/etree` - XML parsing
- `github.com/sirupsen/logrus` - Logging
- Standard library

Separating would reduce `go-trust` binary size and dependencies.
