# Observability with Prometheus and Health Checks

- Status: Accepted (Amended)
- Deciders: Development Team
- Date: 2025-10-17
- Amended: 2026-03-06

> **Note:** The implementation uses only `/healthz` and `/readyz` for health endpoints.
> The aliases `/health`, `/ready`, and `/readiness` mentioned below are NOT registered.

## Context and Problem Statement

Go-trust runs as a service in production environments (Kubernetes, Docker, VMs). Operators need to monitor service health, performance, and errors. How should we instrument the application for observability and ensure it integrates well with modern monitoring infrastructure?

## Decision Drivers

- Need health checks for Kubernetes liveness/readiness probes
- Must expose metrics for monitoring and alerting
- Should follow cloud-native best practices
- Need visibility into pipeline execution, API performance, errors
- Should integrate with Prometheus (de facto standard)
- Must support distributed tracing eventually
- Low overhead (metrics shouldn't slow down service)
- Easy to query and alert on

## Considered Options

- Prometheus metrics + health endpoints
- StatsD + custom health checks
- OpenTelemetry (metrics + traces)
- Custom metrics API
- Log-based metrics only

## Decision Outcome

Chosen option: "Prometheus metrics + Kubernetes health endpoints", because Prometheus is the standard for cloud-native monitoring, and Kubernetes health checks are essential for container orchestration.

### Positive Consequences

- Standard Prometheus metrics format
- Native Kubernetes integration
- Rich ecosystem (Grafana, AlertManager)
- Pull-based model (no push overhead)
- Per-instance metrics isolation
- Comprehensive operational visibility
- Low overhead (~6µs per request)
- Easy to add new metrics

### Negative Consequences

- Prometheus dependency for monitoring
- Metrics endpoint must be scraped
- Need to configure Prometheus/ServiceMonitor
- Counter resets on restart (handled by Prometheus)

## Health Check Endpoints

### Liveness Probe: `/health` or `/healthz`

**Purpose**: Is the service alive?

**Returns**:
- `200 OK` if service is running
- Used by Kubernetes to restart unhealthy containers

**Implementation**:
```go
func HealthHandler(c *gin.Context) {
    c.JSON(200, gin.H{
        "status": "ok",
        "timestamp": time.Now().Unix(),
    })
}
```

### Readiness Probe: `/ready` or `/readiness`

**Purpose**: Is the service ready to accept traffic?

**Returns**:
- `200 OK` when TSLs are loaded and service is ready
- `503 Service Unavailable` during startup or if pipeline fails

**Implementation**:
```go
func ReadinessHandler(ctx *ServerContext) gin.HandlerFunc {
    return func(c *gin.Context) {
        tslCount := ctx.GetTSLCount()

        if tslCount == 0 {
            c.JSON(503, gin.H{
                "status": "not ready",
                "reason": "no TSLs loaded",
            })
            return
        }

        c.JSON(200, gin.H{
            "status": "ready",
            "tsl_count": tslCount,
        })
    }
}
```

### Kubernetes Integration

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 6001
  initialDelaySeconds: 10
  periodSeconds: 30
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readiness
    port: 6001
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

## Prometheus Metrics

### Metrics Endpoint: `/metrics`

Exposes metrics in Prometheus text format:

```
# HELP pipeline_execution_duration_seconds Pipeline execution duration
# TYPE pipeline_execution_duration_seconds histogram
pipeline_execution_duration_seconds_bucket{le="0.1"} 45
pipeline_execution_duration_seconds_bucket{le="0.5"} 98
pipeline_execution_duration_seconds_bucket{le="1"} 100
pipeline_execution_duration_seconds_sum 23.4
pipeline_execution_duration_seconds_count 100

# HELP api_requests_total Total API requests
# TYPE api_requests_total counter
api_requests_total{method="POST",endpoint="/authzen/decision",status="200"} 1523
api_requests_total{method="GET",endpoint="/health",status="200"} 987
```

### Metric Types

**Pipeline Metrics:**
- `pipeline_execution_duration_seconds` (histogram) - Pipeline execution time
- `pipeline_execution_total` (counter) - Total executions by result (success/failure)
- `pipeline_execution_errors_total` (counter) - Errors by type
- `pipeline_tsl_count` (gauge) - Current number of TSLs loaded
- `pipeline_tsl_processing_duration_seconds` (histogram) - Individual TSL processing time

**API Metrics:**
- `api_requests_total` (counter) - HTTP requests by method, endpoint, status
- `api_request_duration_seconds` (histogram) - Request latency
- `api_requests_in_flight` (gauge) - Current concurrent requests

**Certificate Validation Metrics:**
- `cert_validation_total` (counter) - Validations by result (valid/invalid/error)
- `cert_validation_duration_seconds` (histogram) - Validation latency

**Error Metrics:**
- `errors_total` (counter) - Errors by type and operation

### Implementation

```go
type Metrics struct {
    registry *prometheus.Registry

    // Pipeline metrics
    pipelineExecutionDuration prometheus.Histogram
    pipelineExecutionTotal    *prometheus.CounterVec
    pipelineTSLCount          prometheus.Gauge

    // API metrics
    apiRequestsTotal    *prometheus.CounterVec
    apiRequestDuration  *prometheus.HistogramVec
    apiRequestsInFlight prometheus.Gauge

    // Error metrics
    errorsTotal *prometheus.CounterVec
}

func NewMetrics() *Metrics {
    registry := prometheus.NewRegistry()

    m := &Metrics{
        registry: registry,
        pipelineExecutionDuration: prometheus.NewHistogram(
            prometheus.HistogramOpts{
                Name:    "pipeline_execution_duration_seconds",
                Help:    "Pipeline execution duration in seconds",
                Buckets: prometheus.DefBuckets,
            },
        ),
        // ... other metrics
    }

    // Register all metrics
    registry.MustRegister(m.pipelineExecutionDuration)
    // ...

    return m
}
```

### Middleware Integration

```go
func (m *Metrics) MetricsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Skip /metrics endpoint itself
        if c.Request.URL.Path == "/metrics" {
            c.Next()
            return
        }

        start := time.Now()
        m.apiRequestsInFlight.Inc()

        c.Next()

        duration := time.Since(start).Seconds()
        m.apiRequestsInFlight.Dec()

        m.apiRequestsTotal.WithLabelValues(
            c.Request.Method,
            c.FullPath(),
            strconv.Itoa(c.Writer.Status()),
        ).Inc()

        m.apiRequestDuration.WithLabelValues(
            c.Request.Method,
            c.FullPath(),
        ).Observe(duration)
    }
}
```

## Pros and Cons of the Options

### Prometheus + Health Endpoints

- Good, because industry standard
- Good, because rich ecosystem
- Good, because pull-based (simple server)
- Good, because native Kubernetes support
- Good, because low overhead
- Bad, because requires Prometheus setup

### StatsD + Custom Health

- Good, because push-based
- Good, because language-agnostic
- Bad, because additional service (StatsD daemon)
- Bad, because less standard in cloud-native
- Bad, because harder to query

### OpenTelemetry

- Good, because includes tracing
- Good, because vendor-neutral
- Good, because comprehensive
- Bad, because more complex setup
- Bad, because less mature than Prometheus
- Bad, because higher overhead

### Custom Metrics API

- Good, because full control
- Bad, because reinventing wheel
- Bad, because no standard tooling
- Bad, because higher maintenance

### Log-based Metrics

- Good, because no extra instrumentation
- Bad, because parsing overhead
- Bad, because delayed metrics
- Bad, because less accurate

## Alerting Examples

```yaml
# Prometheus alerting rules
groups:
  - name: go-trust
    rules:
      - alert: HighErrorRate
        expr: |
          rate(errors_total[5m]) > 10
        annotations:
          summary: "High error rate in go-trust"

      - alert: PipelineFailures
        expr: |
          rate(pipeline_execution_total{result="failure"}[5m]) > 0.1
        annotations:
          summary: "Pipeline failures detected"

      - alert: HighLatency
        expr: |
          histogram_quantile(0.95,
            rate(api_request_duration_seconds_bucket[5m])
          ) > 1.0
        annotations:
          summary: "API latency above 1s (95th percentile)"
```

## Grafana Dashboard

Example PromQL queries:

```promql
# Request rate
rate(api_requests_total[5m])

# 95th percentile latency
histogram_quantile(0.95,
  rate(api_request_duration_seconds_bucket[5m])
)

# Error rate
rate(errors_total[5m])

# Pipeline success rate
rate(pipeline_execution_total{result="success"}[5m]) /
rate(pipeline_execution_total[5m])
```

## Performance Characteristics

- **Metrics overhead**: ~6µs per request (middleware)
- **Memory**: ~10KB for metric storage
- **Pipeline recording**: ~57ns per operation
- **Certificate validation**: ~96ns per operation
- **Scrape interval**: 15-30s (configurable)

## Testing Strategy

```go
func TestMetricsMiddleware(t *testing.T) {
    metrics := NewMetrics()
    router := gin.New()
    router.Use(metrics.MetricsMiddleware())

    router.GET("/test", func(c *gin.Context) {
        c.String(200, "ok")
    })

    // Make request
    req := httptest.NewRequest("GET", "/test", nil)
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    // Check metrics
    assert.Equal(t, 200, w.Code)
    // Verify counter incremented
}
```

## Future Enhancements

- **Distributed tracing**: OpenTelemetry for request tracing
- **Custom metrics**: User-defined metrics via configuration
- **Metric aggregation**: Aggregate across instances
- **SLO tracking**: Service Level Objectives and error budgets

## Links

- Implementation: `pkg/api/metrics.go`
- Health checks: `pkg/api/health.go`
- Tests: `pkg/api/metrics_test.go`, `pkg/api/health_test.go`
- Prometheus docs: <https://prometheus.io/>
- Related: [ADR-0005](0005-api-design.md) - API Design
- Related: [ADR-0006](0006-error-handling.md) - Error Handling
