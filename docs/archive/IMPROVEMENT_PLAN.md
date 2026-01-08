# Go-Trust Improvement Plan

**Date:** October 16, 2025  
**Version:** 1.0  
**Status:** In Progress

## Executive Summary

This document outlines a comprehensive improvement plan for the go-trust project, a trust engine for processing ETSI TS 119612 Trust Status Lists. The plan addresses critical issues, quality improvements, and feature enhancements over an 8-week period.

**Current State:**
- **Codebase:** ~10,000 lines of Go code
- **Test Coverage:** 68-95% across packages
- **Critical Issues:** Duplicate file causing 52 compilation errors
- **Overall Quality:** Good foundation, needs refinement

## Critical Issues 🔴

### Issue #1: Duplicate File - steps.go
**Severity:** CRITICAL  
**Impact:** 52 compilation errors, code cannot build properly

**Description:**  
The file `pkg/pipeline/steps.go` (1539 lines) contains duplicate declarations of all pipeline step functions that were already split into separate files during recent refactoring:
- `step_registry.go` - Function registry
- `step_generate.go` - TSL generation  
- `step_load.go` - TSL loading
- `step_fetch_options.go` - Fetch configuration
- `step_select.go` - Certificate pool selection
- `step_log.go` - Logging functions
- `step_publish.go` - TSL publishing

**Resolution:**
```bash
git rm pkg/pipeline/steps.go
git commit -m "Remove duplicate steps.go after refactoring into separate files"
```

### Issue #2: Linter Warnings
**Severity:** HIGH  
**Count:** 52 warnings across multiple files

**Categories:**
1. Redundant nil checks before len() (6 occurrences)
2. Raw string literals needed for regex (2 occurrences)
3. Unused variable assignments in tests (4 occurrences)
4. Missing error handling (various)

## Implementation Phases

### Phase 1: Critical Fixes (Week 1) ✅ IN PROGRESS

**Goals:**
- Remove duplicate `steps.go` file
- Fix all linter warnings
- Ensure zero compilation errors
- Verify all tests pass

**Tasks:**
1. ✅ Remove `pkg/pipeline/steps.go`
2. ⏳ Fix redundant nil checks
3. ⏳ Fix regex raw string literals
4. ⏳ Fix unused value warnings in tests
5. ⏳ Run full test suite and verify

**Success Criteria:**
- ✅ Zero compilation errors
- ✅ All tests passing
- ✅ All linter warnings resolved
- ✅ Code builds successfully

### Phase 2: Quality & Coverage (Week 2-3)

**Goals:**
- Increase test coverage to >80% across all packages
- Add missing tests for untested packages
- Improve error handling consistency

**Tasks:**
1. Add integration tests for `cmd/main.go` (currently 0% coverage)
2. Add tests for `xslt` package (currently 0% coverage)
3. Increase `pkg/pipeline` coverage from 68.1% to 80%+
4. Increase `pkg/dsig` coverage from 64.1% to 75%+
5. Add edge case tests for error paths
6. Implement custom error types

**Success Criteria:**
- ✅ >80% coverage across all packages
- ✅ All error paths tested
- ✅ Custom error types defined and used

### Phase 3: Features & Performance (Week 4-6)

**Goals:**
- Add configuration file support
- Implement performance optimizations
- Add security features

**Tasks:**
1. Add YAML/JSON configuration file support
2. Add environment variable configuration
3. Implement concurrent TSL processing
4. Add XSLT transformation caching
5. Implement API rate limiting
6. Add request timeout controls
7. Add input validation and sanitization

**Success Criteria:**
- ✅ Config files supported (YAML + env vars)
- ✅ 2-3x faster TSL processing (concurrent)
- ✅ API rate limiting active
- ✅ All inputs validated

### Phase 4: Documentation & Polish (Week 7-8)

**Goals:**
- Comprehensive documentation
- Developer experience improvements
- Observability enhancements

**Tasks:**
1. Create Architecture Decision Records (ADRs)
2. Generate API documentation (Swagger/OpenAPI)
3. Add more usage examples
4. Create benchmark tests
5. Add Prometheus metrics
6. Add health check endpoints
7. Create developer tooling (VS Code config, pre-commit hooks)

**Success Criteria:**
- ✅ All ADRs documented
- ✅ API docs auto-generated
- ✅ 10+ usage examples
- ✅ Metrics exposed
- ✅ Health checks working

## Detailed Improvements

### Test Coverage Improvements

#### Current Coverage by Package
| Package | Coverage | Target | Priority |
|---------|----------|--------|----------|
| `pkg/utils` | 94.7% | 95% | Low |
| `pkg/api` | 86.9% | 90% | Medium |
| `pkg/logging` | 82.6% | 85% | Medium |
| `pkg/pipeline` | 68.1% | 80% | High |
| `pkg/dsig` | 64.1% | 75% | High |
| `cmd` | 0.0% | 60% | High |
| `xslt` | 0.0% | 80% | High |

#### Test Implementation Plan

**cmd/main.go Tests:**
```go
// cmd/main_test.go
package main

import (
    "os"
    "testing"
)

func TestMainVersionFlag(t *testing.T) {
    // Test --version flag
}

func TestMainHelpFlag(t *testing.T) {
    // Test --help flag
}

func TestMainInvalidArgs(t *testing.T) {
    // Test error handling
}
```

**xslt Package Tests:**
```go
// xslt/embedded_test.go
package xslt

import "testing"

func TestIsEmbeddedPath(t *testing.T) {
    // Test path detection
}

func TestGetEmbeddedXSLT(t *testing.T) {
    // Test XSLT retrieval
}
```

### Error Handling Improvements

#### Custom Error Types
```go
// pkg/pipeline/errors.go
package pipeline

import "errors"

var (
    ErrNoTSLs = errors.New("no TSLs available in context")
    ErrInvalidArguments = errors.New("invalid pipeline step arguments")
    ErrXSLTTransformFailed = errors.New("XSLT transformation failed")
)

type TSLLoadError struct {
    URL string
    Err error
}

func (e *TSLLoadError) Error() string {
    return fmt.Sprintf("failed to load TSL from %s: %v", e.URL, e.Err)
}

func (e *TSLLoadError) Unwrap() error {
    return e.Err
}
```

#### Error Wrapping Pattern
```go
// ❌ Before: loses context
if err != nil {
    return nil, err
}

// ✅ After: preserves context
if err != nil {
    return nil, fmt.Errorf("failed to load TSL from %s: %w", url, err)
}
```

### Performance Optimizations

#### Concurrent TSL Processing
```go
// pkg/pipeline/transform_concurrent.go
func (pl *Pipeline) transformConcurrent(tsls []*etsi119612.TSL, xsltPath string) error {
    var wg sync.WaitGroup
    errChan := make(chan error, len(tsls))
    semaphore := make(chan struct{}, runtime.NumCPU())
    
    for i, tsl := range tsls {
        wg.Add(1)
        go func(idx int, t *etsi119612.TSL) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            
            if err := pl.transformOne(t, xsltPath); err != nil {
                errChan <- fmt.Errorf("TSL %d: %w", idx, err)
            }
        }(i, tsl)
    }
    
    wg.Wait()
    close(errChan)
    
    for err := range errChan {
        if err != nil {
            return err
        }
    }
    return nil
}
```

**Expected Performance Gain:** 2-3x faster on multi-core systems

#### XSLT Caching
```go
// pkg/pipeline/xslt_cache.go
type XSLTCache struct {
    mu         sync.RWMutex
    processors map[string]*XSLTProcessor
}

func (c *XSLTCache) Get(name string) (*XSLTProcessor, error) {
    c.mu.RLock()
    proc, ok := c.processors[name]
    c.mu.RUnlock()
    
    if ok {
        return proc, nil
    }
    
    c.mu.Lock()
    defer c.mu.Unlock()
    
    proc, err := compileXSLT(name)
    if err != nil {
        return nil, err
    }
    c.processors[name] = proc
    return proc, nil
}
```

**Expected Performance Gain:** 10-20% reduction in transformation time

### Security Enhancements

#### Rate Limiting
```go
// pkg/api/middleware.go
func RateLimitMiddleware(rps int) gin.HandlerFunc {
    limiter := rate.NewLimiter(rate.Limit(rps), rps*2)
    
    return func(c *gin.Context) {
        if !limiter.Allow() {
            c.JSON(429, gin.H{"error": "rate limit exceeded"})
            c.Abort()
            return
        }
        c.Next()
    }
}
```

#### Input Validation
```go
// pkg/pipeline/validators.go
func ValidateURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil {
        return fmt.Errorf("invalid URL: %w", err)
    }
    
    if u.Scheme != "http" && u.Scheme != "https" {
        return fmt.Errorf("unsupported scheme: %s", u.Scheme)
    }
    
    return nil
}

func ValidateFilePath(path string) error {
    clean := filepath.Clean(path)
    if strings.Contains(clean, "..") {
        return fmt.Errorf("path traversal detected: %s", path)
    }
    return nil
}
```

### Configuration Management

#### Configuration File Structure
```yaml
# config.yaml
server:
  host: "127.0.0.1"
  port: "6001"
  frequency: "5m"

logging:
  level: "info"
  format: "text"
  output: "stdout"

pipeline:
  timeout: "30s"
  max_request_size: 10485760  # 10MB
  max_redirects: 3
  allowed_hosts:
    - "*.europa.eu"
    - "*.example.com"

security:
  rate_limit_rps: 100
  enable_cors: true
  allowed_origins:
    - "https://example.com"
```

#### Environment Variables
```bash
# .env
GT_HOST=0.0.0.0
GT_PORT=8080
GT_LOG_LEVEL=debug
GT_FREQUENCY=10m
GT_RATE_LIMIT_RPS=100
```

### Observability

#### Metrics
```go
// pkg/metrics/prometheus.go
var (
    TSLProcessingDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "tsl_processing_duration_seconds",
            Help: "Time spent processing TSLs",
        },
        []string{"step", "status"},
    )
    
    TSLCount = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "tsl_count_total",
            Help: "Current number of loaded TSLs",
        },
    )
    
    APIRequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "api_request_duration_seconds",
            Help: "API request duration",
        },
        []string{"endpoint", "method", "status"},
    )
)
```

#### Health Checks
```go
// GET /health
{
    "status": "healthy",
    "version": "1.0.0",
    "tsl_count": 23,
    "last_update": "2025-10-16T21:52:10Z",
    "dependencies": {
        "xsltproc": "available"
    }
}

// GET /metrics
# Prometheus metrics endpoint
```

## Success Metrics

### Phase 1 Success Criteria
- ✅ Zero compilation errors
- ✅ All tests passing (100% pass rate)
- ✅ Zero linter warnings
- ✅ Clean `go build` output

### Phase 2 Success Criteria
- ✅ >80% test coverage across all packages
- ✅ All error paths tested
- ✅ Custom error types implemented

### Phase 3 Success Criteria
- ✅ Configuration file support working
- ✅ 2-3x performance improvement in TSL processing
- ✅ API rate limiting functional
- ✅ All inputs validated

### Phase 4 Success Criteria
- ✅ Complete API documentation (OpenAPI/Swagger)
- ✅ All ADRs documented
- ✅ 10+ usage examples in documentation
- ✅ Metrics exposed via /metrics endpoint
- ✅ Health checks working via /health endpoint

## Timeline

```
Week 1: Phase 1 - Critical Fixes
├─ Day 1-2: Remove duplicates, fix linter warnings
├─ Day 3-4: Verify tests, fix issues
└─ Day 5: Documentation, code review

Week 2-3: Phase 2 - Quality & Coverage
├─ Week 2: Add tests for cmd and xslt packages
└─ Week 3: Improve pipeline and dsig coverage

Week 4-6: Phase 3 - Features & Performance
├─ Week 4: Configuration file support
├─ Week 5: Performance optimizations
└─ Week 6: Security enhancements

Week 7-8: Phase 4 - Documentation & Polish
├─ Week 7: Documentation and ADRs
└─ Week 8: Observability and developer tooling
```

## Risks & Mitigation

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Breaking changes during refactoring | High | Medium | Comprehensive test suite, incremental changes |
| Performance regression | Medium | Low | Benchmark tests before/after |
| Compatibility issues | Medium | Low | Maintain backward compatibility, deprecation warnings |
| Timeline delays | Low | Medium | Prioritize critical fixes first |

## Resources

### Required Tools
- Go 1.25.1+
- golangci-lint
- go-test-coverage
- Docker (for integration tests)
- xsltproc

### Documentation
- [ETSI TS 119612 Specification](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/)
- [Go Best Practices](https://go.dev/doc/effective_go)
- [Pipeline Architecture](./adr/001-pipeline-architecture.md) (to be created)

## Notes

- All changes will be made in feature branches and reviewed via PRs
- Breaking changes require major version bump
- Maintain backward compatibility where possible
- Document all significant decisions in ADRs

---

**Last Updated:** October 16, 2025  
**Next Review:** October 23, 2025  
**Owner:** Development Team
