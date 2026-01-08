# XSLT Transformation with libxslt via CGO

- Status: **Superseded** (Moved to g119612/tsl-tool)
- Deciders: Development Team
- Date: 2025-10-17
- Superseded Date: 2025-07-01

> **Note:** XSLT transformation has been moved to [g119612](https://github.com/sirosfoundation/g119612) as part of `tsl-tool`.
> Go-trust is now solely a PDP server that consumes pre-processed TSL data.
> See g119612 for current XSLT transformation implementation.

## Context and Problem Statement

Go-trust needs to transform TSL XML documents to HTML for human-readable viewing. XSLT is the standard transformation language for XML. How should we implement XSLT transformations in Go, given the lack of native XSLT 1.0 support in the standard library?

## Decision Drivers

- Need XSLT 1.0 support for standard TSL transformations
- Must handle complex XML transformations reliably
- Performance matters (transforming 20+ TSLs)
- Should use battle-tested transformation engine
- Need to embed stylesheets in binary
- Must support both embedded and file-based stylesheets
- Cross-platform support (Linux, macOS, Windows)

## Considered Options

- Pure Go XSLT library (if one existed)
- CGO bindings to libxslt (C library)
- Java-based transformation via JNI
- External XSLT processor (xsltproc) via exec
- Rewrite transformations in Go (custom logic)

## Decision Outcome

Chosen option: "CGO bindings to libxslt", because libxslt is the most mature, performant, and standards-compliant XSLT processor available, and CGO provides a safe bridge from Go.

### Positive Consequences

- Full XSLT 1.0 support (complete standard)
- Excellent performance (~15ms per transformation)
- Battle-tested and widely used (decades of production use)
- Standards-compliant transformations
- Can cache compiled stylesheets
- Embedded stylesheets work via Go embed
- Error messages from libxslt are helpful

### Negative Consequences

- Requires CGO (more complex builds)
- Cross-compilation is harder
- Requires libxml2/libxslt installed on target systems
- Binary size increases (~500KB)
- Not pure Go (some Go purists object)
- Memory management requires care (C/Go boundary)

## Implementation Details

### CGO Wrapper

```go
// #cgo pkg-config: libxslt libxml-2.0
// #include <libxslt/xsltInternals.h>
// #include <libxslt/transform.h>
import "C"

type Stylesheet struct {
    ptr *C.xsltStylesheet
}

func ParseStylesheet(data []byte) (*Stylesheet, error) {
    doc := C.xmlParseMemory(...)
    style := C.xsltParseStylesheetDoc(doc)
    return &Stylesheet{ptr: style}, nil
}

func (s *Stylesheet) Transform(xmlData []byte) ([]byte, error) {
    xmlDoc := C.xmlParseMemory(...)
    result := C.xsltApplyStylesheet(s.ptr, xmlDoc, nil)
    // Convert result to Go bytes
    return output, nil
}
```

### Stylesheet Caching

```go
type Cache struct {
    mu sync.RWMutex
    stylesheets map[string]*Stylesheet
}

func (c *Cache) Get(path string) (*Stylesheet, error) {
    c.mu.RLock()
    if style, ok := c.stylesheets[path]; ok {
        c.mu.RUnlock()
        return style, nil
    }
    c.mu.RUnlock()

    // Load and cache
    c.mu.Lock()
    defer c.mu.Unlock()
    style, err := ParseStylesheet(data)
    if err == nil {
        c.stylesheets[path] = style
    }
    return style, err
}
```

### Embedded Stylesheets

```go
//go:embed xslt/tsl-to-html.xslt
var embeddedStylesheets embed.FS

func LoadEmbedded(name string) (*Stylesheet, error) {
    data, err := embeddedStylesheets.ReadFile("xslt/" + name)
    if err != nil {
        return nil, err
    }
    return ParseStylesheet(data)
}
```

### Memory Management

- C memory must be explicitly freed
- Use `runtime.SetFinalizer` for automatic cleanup
- Double-check with valgrind in tests
- No memory leaks in production usage

## Pros and Cons of the Options

### Pure Go XSLT library

- Good, because no CGO
- Good, because easier cross-compilation
- Good, because pure Go toolchain
- Bad, because no complete XSLT 1.0 implementation exists
- Bad, because would need to implement spec ourselves
- Bad, because likely slower than libxslt

### CGO bindings to libxslt

- Good, because complete XSLT 1.0 support
- Good, because excellent performance
- Good, because battle-tested (20+ years)
- Good, because standards-compliant
- Bad, because requires CGO
- Bad, because cross-compilation complexity
- Bad, because deployment dependency

### Java-based transformation via JNI

- Good, because mature XSLT processors in Java
- Good, because standards-compliant
- Bad, because requires JVM
- Bad, because JNI is complex
- Bad, because large deployment footprint
- Bad, because slower startup

### External XSLT processor via exec

- Good, because no CGO
- Good, because uses system xsltproc
- Bad, because process startup overhead (10-50ms)
- Bad, because no stylesheet caching
- Bad, because difficult error handling
- Bad, because requires xsltproc installed

### Rewrite transformations in Go

- Good, because pure Go
- Good, because full control
- Bad, because massive development effort
- Bad, because difficult to maintain
- Bad, because likely to have bugs
- Bad, because not standards-compliant

## Build Configuration

### pkg-config Integration

```go
// #cgo pkg-config: libxslt libxml-2.0
```

This automatically finds:
- Include paths for headers
- Library paths for linking
- Required compiler flags

### Platform-Specific Notes

**Linux:**
- Install: `apt-get install libxslt1-dev libxml2-dev`
- Works out of the box with pkg-config

**macOS:**
- Install: `brew install libxslt libxml2`
- May need to set `PKG_CONFIG_PATH`

**Windows:**
- More complex, requires MSYS2 or pre-built DLLs
- Can use static linking to bundle libraries

## Performance Characteristics

- **Parse stylesheet**: ~1-2ms (cached after first use)
- **Transform TSL to HTML**: ~15ms average
- **Memory**: ~100KB per transformation
- **Caching speedup**: 5-10% (avoids re-parsing stylesheet)
- **Concurrent processing**: Scales linearly up to 8 workers

## Error Handling

libxslt provides detailed error messages:

```
xmlXPathCompOpEval: function concat not found
error: Transformation failed
```

We wrap these in Go errors:
```go
return fmt.Errorf("XSLT transformation failed: %w", err)
```

## Testing Strategy

- Unit tests with sample TSLs and stylesheets
- Error injection (malformed XML, invalid XSLT)
- Memory leak detection (valgrind, pprof)
- Performance benchmarks
- Concurrent access tests (race detector)

## Alternative Considered: Template-Based Generation

We considered using Go's `html/template` instead of XSLT:

**Pros:**
- Pure Go
- No CGO required
- Familiar to Go developers

**Cons:**
- Would need to parse XML first
- Complex TSL structure difficult to template
- Would need to rewrite existing XSLT logic
- No standard for TSL HTML transformation
- Harder to maintain than XSLT

**Decision:** XSLT is the standard for XML transformation, and libxslt is the standard implementation. The benefits outweigh the CGO complexity.

## Links

- Implementation: `pkg/xslt/xslt.go`
- Tests: `pkg/xslt/xslt_test.go`
- Embedded stylesheets: `xslt/tsl-to-html.xslt`
- Related: [ADR-0003](0003-concurrent-processing.md) - Concurrent Processing
