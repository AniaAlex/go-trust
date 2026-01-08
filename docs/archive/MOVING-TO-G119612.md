# Moving Pipeline Functionality to g119612

## Overview

This document outlines what needs to be moved from go-trust to g119612 to create the `tsl-tool` binary.

## Files to Move

### 1. Pipeline Package
**Source:** `go-trust/pkg/pipeline/`  
**Destination:** `g119612/pkg/pipeline/`

All files in the pipeline package:
- `pipeline.go` - Core pipeline framework
- `context.go` - Pipeline execution context
- `step_*.go` - All pipeline step implementations
- `transform.go` - XSLT transformation logic
- `publish.go` - XML publishing
- `tsl_tree.go` - TSL tree structure
- `errors.go` - Pipeline-specific errors
- All test files (`*_test.go`)
- `testdata/` directory

### 2. Digital Signature Package
**Source:** `go-trust/pkg/dsig/`  
**Destination:** `g119612/pkg/dsig/`

All files:
- `signer.go` - Signature interface
- `file_signer.go` - File-based signing
- `pkcs11_signer.go` - PKCS#11 HSM signing (if exists)
- All test files

### 3. XSLT Templates
**Source:** `go-trust/xslt/`  
**Destination:** `g119612/xslt/`

All embedded XSLT files:
- `tsl-to-html.xslt`
- Any other transformation templates

### 4. Supporting Utilities (if pipeline-specific)
**Source:** `go-trust/pkg/utils/`  
**Destination:** Review and move only pipeline-specific utils

Files to check:
- `stack.go` - Used by pipeline context (MOVE)
- `x509util.go` - Used by ETSI registry (KEEP in go-trust, maybe duplicate)
- Others - Evaluate case by case

### 5. Validation Package (if pipeline-specific)
**Source:** `go-trust/pkg/validation/`  
**Destination:** Check if used only by pipeline

If validation is only for pipeline input (paths, URLs), move it.
If also used by server API, keep in go-trust and duplicate minimal needed parts.

### 6. Logging Package
**Action:** KEEP in go-trust, ADD as dependency to g119612

The logging package should remain in go-trust as it's used by both.
Add it as a dependency in g119612's go.mod.

## New Files to Create in g119612

### 1. CLI Tool
**Location:** `g119612/cmd/tsl-tool/main.go`

Create a new command-line tool that:
- Loads pipeline YAML
- Executes pipeline steps
- Provides user-friendly error messages
- Supports --help, --version flags

Example structure:
```go
package main

import (
    "flag"
    "fmt"
    "os"
    
    "github.com/sirosfoundation/g119612/pkg/pipeline"
    "github.com/sirosfoundation/go-trust/pkg/logging"  // Import from go-trust
)

var Version = "1.0.0"

func main() {
    showHelp := flag.Bool("help", false, "Show help")
    showVersion := flag.Bool("version", false, "Show version")
    logLevel := flag.String("log-level", "info", "Logging level")
    flag.Parse()
    
    // ... rest of implementation
}
```

### 2. Update g119612 README.md

Add comprehensive documentation for tsl-tool:
- Installation instructions
- Pipeline configuration examples
- Common use cases (fetch, transform, publish, sign)
- Cron integration examples

### 3. Update g119612 Makefile

Add build targets:
```makefile
.PHONY: build-tsl-tool
build-tsl-tool:
    go build -o tsl-tool ./cmd/tsl-tool

.PHONY: install-tsl-tool  
install-tsl-tool:
    go install ./cmd/tsl-tool
```

## Import Path Updates

After moving code, update all import paths:

**Old imports in moved files:**
```go
import "github.com/sirosfoundation/go-trust/pkg/pipeline"
import "github.com/sirosfoundation/go-trust/pkg/dsig"
import "github.com/sirosfoundation/go-trust/pkg/utils"
```

**New imports:**
```go
import "github.com/sirosfoundation/g119612/pkg/pipeline"
import "github.com/sirosfoundation/g119612/pkg/dsig"
import "github.com/sirosfoundation/g119612/pkg/utils"
```

**Imports from go-trust (for shared code):**
```go
import "github.com/sirosfoundation/go-trust/pkg/logging"
```

## Dependencies to Add to g119612

Update `g119612/go.mod` to include:

```go
module github.com/sirosfoundation/g119612

go 1.21

require (
    github.com/sirosfoundation/go-trust v2.0.0  // For logging package
    github.com/moov-io/signedxml v1.0.0         // For XML signing (if used)
    gopkg.in/yaml.v3 v3.0.1                     // For pipeline YAML parsing
    // ... other dependencies from pipeline code
)
```

## Files to Remove from go-trust

After moving to g119612:

### Delete Completely
- `go-trust/pkg/pipeline/` (entire directory)
- `go-trust/pkg/dsig/` (entire directory)
- `go-trust/xslt/` (entire directory)
- `go-trust/main.go` (replaced by cmd/go-trust/main.go)
- `go-trust/pkg/registry/etsi/pipeline_backed.go` (no longer needed)

### Keep/Update in go-trust
- `go-trust/pkg/registry/etsi/registry.go` - Keep (file-based ETSI registry)
- `go-trust/pkg/utils/x509util.go` - Keep if used by ETSI registry
- `go-trust/pkg/logging/` - Keep (shared dependency)
- `go-trust/pkg/validation/` - Keep if used by API server, otherwise move

## Testing Strategy

### In g119612
1. Run all moved tests: `go test ./pkg/pipeline/... ./pkg/dsig/...`
2. Test tsl-tool binary: `tsl-tool --help`
3. Test complete pipeline: `tsl-tool examples/pipeline.yaml`

### In go-trust
1. Remove pipeline tests
2. Update ETSI registry tests to use file-based loading
3. Ensure server starts without pipeline dependencies
4. Test AuthZEN API endpoints

## Example Pipeline Migration

**Old (in go-trust):**
```bash
go-trust --frequency 6h pipeline.yaml
```

**New (with tsl-tool in g119612):**
```bash
# One-time execution
tsl-tool pipeline.yaml

# Or from cron
0 */6 * * * /usr/local/bin/tsl-tool /etc/tsl/pipeline.yaml
```

## Checklist

- [ ] Move pkg/pipeline/ to g119612
- [ ] Move pkg/dsig/ to g119612
- [ ] Move xslt/ to g119612
- [ ] Create cmd/tsl-tool/main.go in g119612
- [ ] Update all import paths in moved code
- [ ] Update g119612 go.mod with new dependencies
- [ ] Update g119612 README with tsl-tool documentation
- [ ] Update g119612 Makefile with build targets
- [ ] Delete moved packages from go-trust
- [ ] Delete go-trust/main.go
- [ ] Delete pipeline_backed.go from go-trust
- [ ] Update go-trust tests
- [ ] Update go-trust documentation
- [ ] Test tsl-tool builds and runs
- [ ] Test go-trust server builds and runs
- [ ] Create migration guide for users
- [ ] Update both project READMEs

## Timeline

1. **Phase 1:** Create tsl-tool in g119612 (copy, don't move yet)
2. **Phase 2:** Test tsl-tool independently
3. **Phase 3:** Create new go-trust server binary
4. **Phase 4:** Test server with pre-processed files
5. **Phase 5:** Remove pipeline code from go-trust
6. **Phase 6:** Notify users and provide migration guide

## Notes

- Consider keeping pipeline code in go-trust temporarily during migration
- Tag releases before breaking changes
- Provide clear migration examples for common deployments
- Update CI/CD pipelines for both repositories
