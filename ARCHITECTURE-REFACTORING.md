# Architecture Refactoring Summary

## What We've Done

### 1. Created New Server-Only Binary

**File:** `cmd/go-trust/main.go`

A clean AuthZEN PDP server that:
- ✅ No pipeline processing
- ✅ No background updates
- ✅ Loads TSLs from pre-processed files (PEM bundles or XML)
- ✅ Supports multiple registries (ETSI, OpenID Federation, DID Web)
- ✅ Configurable via command-line flags
- ✅ Production-ready logging

**Binary name:** `go-trust` (unchanged from v1)

### 2. Updated Build System

**File:** `Makefile`

Changes:
- Build from `cmd/go-trust/main.go` instead of `main.go`
- Output binary named `go-trust` (was `gt`)
- Updated swagger generation path
- Updated all build targets

### 3. Created Migration Documentation

**Files:**
- `MIGRATION-TO-V2.md` - User-facing migration guide
- `MOVING-TO-G119612.md` - Developer guide for moving code

## Architecture Overview

### Before (v1)
```
┌────────────────────────────────────┐
│       go-trust (monolith)          │
├────────────────────────────────────┤
│ • Pipeline processing (background) │
│ • XSLT transformations             │
│ • XML signing (PKCS#11)            │
│ • TSL publishing                   │
│ • AuthZEN server                   │
│ • Multi-registry support           │
└────────────────────────────────────┘
```

### After (v2)
```
┌──────────────────────┐    ┌─────────────────────┐
│ tsl-tool (g119612)   │    │ go-trust (server)   │
├──────────────────────┤    ├─────────────────────┤
│ • Load TSLs          │───▶│ • AuthZEN API       │
│ • Transform (XSLT)   │    │ • ETSI registry     │
│ • Publish XML        │    │ • OpenID Fed reg    │
│ • Sign (PKCS#11)     │    │ • DID Web reg       │
│                      │    │ • Future registries │
│ Runs from cron       │    │ Runs as service     │
└──────────────────────┘    └─────────────────────┘
```

## Command Line Changes

### Old (v1)
```bash
# Server with background pipeline
go-trust --frequency 6h pipeline.yaml
```

### New (v2)
```bash
# Separate concerns

# 1. Pipeline processing (cron)
tsl-tool pipeline.yaml  # From g119612

# 2. Server (systemd)
go-trust \
  --etsi-cert-bundle /var/lib/go-trust/eu-certs.pem \
  --host 0.0.0.0 \
  --port 6001
```

## Key Benefits

1. **Clean Separation**
   - Batch processing vs. online service
   - Each tool has a single, focused purpose

2. **Better Deployment**
   - Pipeline: cron/systemd timer (periodic)
   - Server: systemd service (continuous)

3. **Lighter Server**
   - No XSLT dependencies
   - No XML signing libraries
   - No pipeline overhead

4. **Clearer Ownership**
   - g119612: "Complete ETSI TSL solution"
   - go-trust: "Multi-framework trust PDP"

## Next Steps

### For go-trust Repository

1. ✅ Created `cmd/go-trust/main.go` - Server binary
2. ✅ Updated `Makefile` - Build configuration
3. ✅ Created migration guides - Documentation
4. ⏳ Regenerate swagger docs
5. ⏳ Test server startup
6. ⏳ Update README.md - Remove pipeline documentation
7. ⏳ Delete old `main.go`
8. ⏳ Tag v2.0.0 release

### For g119612 Repository

1. ⏳ Move `pkg/pipeline/` from go-trust
2. ⏳ Move `pkg/dsig/` from go-trust
3. ⏳ Move `xslt/` from go-trust
4. ⏳ Create `cmd/tsl-tool/main.go`
5. ⏳ Update `go.mod` dependencies
6. ⏳ Update `Makefile` with build targets
7. ⏳ Update README.md - Add CLI tool docs
8. ⏳ Tag release

### Testing

1. ⏳ Build and test tsl-tool
2. ⏳ Run pipeline from cron
3. ⏳ Build and test go-trust server
4. ⏳ Verify server loads pre-processed files
5. ⏳ Test AuthZEN API endpoints
6. ⏳ Integration tests

### User Communication

1. ⏳ Announce v2 breaking changes
2. ⏳ Provide migration examples
3. ⏳ Update documentation links
4. ⏳ Offer migration support

## Files Created/Modified

### New Files
- ✅ `cmd/go-trust/main.go` - Server binary
- ✅ `MIGRATION-TO-V2.md` - User migration guide
- ✅ `MOVING-TO-G119612.md` - Developer guide
- ✅ `ARCHITECTURE-REFACTORING.md` - This file

### Modified Files
- ✅ `Makefile` - Build targets updated

### To Be Deleted (after migration)
- ⏳ `main.go` - Replaced by cmd/go-trust/main.go
- ⏳ `pkg/pipeline/` - Moving to g119612
- ⏳ `pkg/dsig/` - Moving to g119612
- ⏳ `xslt/` - Moving to g119612
- ⏳ `pkg/registry/etsi/pipeline_backed.go` - No longer needed

## Example Deployment

### Production Setup

**1. Install both tools:**
```bash
# Install from g119612
go install github.com/sirosfoundation/g119612/cmd/tsl-tool@latest

# Install from go-trust
go install github.com/sirosfoundation/go-trust/cmd/go-trust@latest
```

**2. Configure TSL pipeline:**
```yaml
# /etc/tsl/fetch-eu-lotl.yaml
- load: https://ec.europa.eu/tools/lotl/eu-lotl.xml
- select: [include-referenced]
- publish: [/var/lib/go-trust/eu-certs.pem]
```

**3. Set up cron:**
```bash
# /etc/cron.d/update-tsls
0 */6 * * * root /usr/local/bin/tsl-tool /etc/tsl/fetch-eu-lotl.yaml && systemctl reload go-trust
```

**4. Configure systemd:**
```ini
# /etc/systemd/system/go-trust.service
[Unit]
Description=Go-Trust AuthZEN PDP
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /var/lib/go-trust/eu-certs.pem \
  --external-url https://pdp.example.com
Restart=always
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

**5. Start services:**
```bash
# Initial TSL fetch
tsl-tool /etc/tsl/fetch-eu-lotl.yaml

# Start server
systemctl enable --now go-trust
```

## Breaking Changes Summary

| Aspect | v1 | v2 |
|--------|----|----|
| Binary | `go-trust` | `go-trust` (server only) |
| Pipeline | Background in server | `tsl-tool` (separate) |
| TSL Updates | `--frequency` flag | Cron job |
| Input | pipeline.yaml | Pre-processed files |
| Dependencies | Many (XSLT, signing, etc.) | Minimal (API only) |
| Deployment | Single service | Server + cron job |

## Success Criteria

- ✅ go-trust binary builds successfully
- ⏳ go-trust starts without pipeline config
- ⏳ go-trust loads TSLs from PEM/XML files
- ⏳ AuthZEN API endpoints work
- ⏳ tsl-tool processes pipelines correctly
- ⏳ Integration works (cron → tsl-tool → files → go-trust)
- ⏳ Documentation is clear and complete
- ⏳ Migration path is tested

## Notes

- No backwards compatibility needed (small user base)
- Direct communication with users for migration
- Clean break, no deprecation period
- Focus on clarity over gradual transition
