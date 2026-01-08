# Migration Guide: go-trust v1 → v2

## Breaking Changes

### Architecture Split

go-trust v2 separates two previously combined concerns:

**Before (v1):**
```
go-trust binary = TSL Pipeline Processing + AuthZEN Server
```

**After (v2):**
```
tsl-tool (in g119612) = TSL Pipeline Processing (batch, cron-friendly)
go-trust              = AuthZEN Server only (consumes pre-processed TSLs)
```

## What Changed

### 1. TSL Pipeline Processing → Moved to g119612

All TSL processing functionality has moved to the `tsl-tool` binary in the g119612 package:
- Loading TSLs
- XSLT transformations
- Publishing XML
- Signing TSLs (PKCS#11/file-based)
- Background pipeline updates

### 2. go-trust → Server Only

The `go-trust` binary is now a pure AuthZEN PDP server:
- No pipeline processing
- No background TSL updates
- Consumes pre-processed trust data from files
- Supports multiple trust registries (ETSI, OpenID Federation, DID Web)

## Migration Steps

### Step 1: Install tsl-tool

The TSL processing tool is now in g119612:

```bash
# Install from g119612 repository
go install github.com/sirosfoundation/g119612/cmd/tsl-tool@latest
```

### Step 2: Update Pipeline Processing

**Old approach (v1):**
```bash
# go-trust ran as server with background pipeline
go-trust pipeline.yaml
```

**New approach (v2):**
```bash
# Run tsl-tool from cron for periodic updates
# /etc/cron.d/update-tsls
0 */6 * * * /usr/local/bin/tsl-tool /etc/tsl/fetch-eu-lotl.yaml
```

Example pipeline configuration remains the same:

```yaml
# /etc/tsl/fetch-eu-lotl.yaml
- load: https://ec.europa.eu/tools/lotl/eu-lotl.xml
- select: [include-referenced]
- publish: /var/lib/go-trust/tsl-xml/
```

To also generate a PEM bundle for go-trust server:

```yaml
- load: https://ec.europa.eu/tools/lotl/eu-lotl.xml
- select: [include-referenced]
- publish: [/var/lib/go-trust/eu-certs.pem]  # PEM bundle output
```

### Step 3: Configure go-trust Server

**Old approach (v1):**
```bash
# Server with pipeline argument
go-trust --host 0.0.0.0 --port 6001 --frequency 6h pipeline.yaml
```

**New approach (v2):**
```bash
# Server loads pre-processed files
go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /var/lib/go-trust/eu-certs.pem

# Or with TSL XML files directly
go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-tsl-files "/var/lib/go-trust/tsl-xml/eu-lotl.xml,/var/lib/go-trust/tsl-xml/uk-tsl.xml"
```

### Step 4: Update Systemd Service

**Old service (v1):**
```ini
[Unit]
Description=Go-Trust PDP with Pipeline
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/go-trust --frequency 6h /etc/go-trust/pipeline.yaml
Restart=always

[Install]
WantedBy=multi-user.target
```

**New service (v2):**
```ini
[Unit]
Description=Go-Trust AuthZEN PDP Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /var/lib/go-trust/eu-certs.pem \
  --external-url https://pdp.example.com
Restart=always

# Reload when TSL data changes (triggered by tsl-tool cron)
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
```

**New cron job for TSL updates:**
```bash
# /etc/cron.d/update-tsls
0 */6 * * * root /usr/local/bin/tsl-tool /etc/tsl/fetch-eu-lotl.yaml && systemctl reload go-trust
```

## Command Line Options

### Removed Options
- `--frequency` - Pipeline updates now handled by cron + tsl-tool
- `--no-server` - Pipeline processing is now in tsl-tool
- Pipeline YAML argument - Use tsl-tool instead

### New Options
- `--etsi-cert-bundle` - Path to PEM file with trusted CA certificates
- `--etsi-tsl-files` - Comma-separated list of local TSL XML files
- `--config` - Configuration file path (YAML format, planned)
- `--log-level` - Logging level (debug, info, warn, error)
- `--log-format` - Logging format (text, json)

### Unchanged Options
- `--host` - API server hostname
- `--port` - API server port
- `--external-url` - External URL for PDP discovery
- `--help` - Show help
- `--version` - Show version

## File Structure Changes

### What Moved to g119612

The following packages moved from go-trust to g119612:
- `pkg/pipeline/` - Pipeline framework and steps
- `pkg/dsig/` - XML signing (PKCS#11/file-based)
- `xslt/` - Embedded XSLT templates
- `cmd/tsl-tool/` - New pipeline processing CLI

### What Stayed in go-trust

- `pkg/api/` - HTTP API handlers
- `pkg/authzen/` - AuthZEN protocol
- `pkg/authzenclient/` - Client library
- `pkg/registry/` - Multi-registry framework
  - `pkg/registry/etsi/` - ETSI TSL registry (now file-based only)
  - `pkg/registry/oidfed/` - OpenID Federation registry
  - `pkg/registry/didweb/` - DID Web registry
- `cmd/go-trust/` - Server binary

### Removed from go-trust

- `main.go` - Replaced by `cmd/go-trust/main.go`
- `pkg/registry/etsi/pipeline_backed.go` - Pipeline integration (no longer needed)

## Example Deployment

### Complete Setup

**1. Install both tools:**
```bash
# Install tsl-tool for pipeline processing
go install github.com/sirosfoundation/g119612/cmd/tsl-tool@latest

# Install go-trust server
go install github.com/sirosfoundation/go-trust/cmd/go-trust@latest
```

**2. Create pipeline configuration:**
```yaml
# /etc/tsl/fetch-eu-lotl.yaml
- load: https://ec.europa.eu/tools/lotl/eu-lotl.xml
- select: [include-referenced]
- publish: [/var/lib/go-trust/eu-certs.pem]
```

**3. Run initial TSL fetch:**
```bash
mkdir -p /var/lib/go-trust
tsl-tool /etc/tsl/fetch-eu-lotl.yaml
```

**4. Configure cron for updates:**
```bash
# /etc/cron.d/update-tsls
0 */6 * * * root /usr/local/bin/tsl-tool /etc/tsl/fetch-eu-lotl.yaml && systemctl reload go-trust 2>&1 | logger -t tsl-tool
```

**5. Start go-trust server:**
```bash
go-trust \
  --host 0.0.0.0 \
  --port 6001 \
  --etsi-cert-bundle /var/lib/go-trust/eu-certs.pem \
  --external-url https://pdp.example.com \
  --log-level info
```

## Benefits of New Architecture

1. **Cleaner separation**: Batch processing vs. online service
2. **Better deployment**: cron for updates, systemd for server
3. **Lighter server**: No XSLT, signing, or pipeline dependencies
4. **Focused tools**:
   - g119612/tsl-tool: Everything ETSI TSL
   - go-trust: Multi-framework trust PDP

## Need Help?

- ETSI TSL processing: See g119612 documentation
- AuthZEN server: See go-trust documentation
- Migration issues: Open an issue on GitHub

## Timeline

- v1 (deprecated): Server with pipeline background updates
- v2 (current): Separate tsl-tool + go-trust server
- v1 will be supported until [DATE] for migration period
