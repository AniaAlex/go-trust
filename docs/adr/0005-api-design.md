# API Design with AuthZEN and Gin Framework

- Status: Accepted (Amended)
- Deciders: Development Team
- Date: 2025-10-17
- Amended: 2026-03-06

> **Note:** The request format documented below shows the initial design. The actual
> implementation follows the [AuthZEN Trust Registry Profile](https://leifj.github.io/draft-johansson-authzen-trust/)
> which uses `subject.type="key"`, `resource.type="jwk"|"x5c"`, and `resource.key` for key data.
> The actual endpoint is `POST /evaluation` (not `/authzen/decision`).
> Health endpoints are `/healthz` and `/readyz` only.

## Context and Problem Statement

Go-trust needs to provide a REST API for trust decisions on X.509 certificates. The API must be standards-based, performant, and easy to integrate with existing systems. Which API framework and protocol should we use?

## Decision Drivers

- Need RESTful API for trust decisions
- Should follow established standards (not custom protocol)
- Must support X.509 certificate validation
- Performance matters (low latency, high throughput)
- Need structured request/response format
- Should be easy to integrate with clients
- Require health checks for Kubernetes
- Need metrics for observability
- Want middleware support (logging, rate limiting)

## Considered Options

- Custom REST API with net/http
- AuthZEN protocol with Gin framework
- gRPC with Protocol Buffers
- GraphQL API
- OpenAPI/Swagger first approach

## Decision Outcome

Chosen option: "AuthZEN protocol with Gin framework", because AuthZEN provides a standard authorization protocol perfect for trust decisions, and Gin offers excellent performance with a rich middleware ecosystem.

### Positive Consequences

- Standards-based protocol (AuthZEN)
- Clear request/response structure
- Excellent performance (Gin is one of fastest Go frameworks)
- Rich middleware ecosystem
- Easy to test and mock
- Good documentation and community
- Supports JSON natively
- Middleware for metrics, logging, rate limiting

### Negative Consequences

- AuthZEN is relatively new (less mature than some standards)
- Gin is a third-party dependency
- Not using standard library's net/http directly
- Some Go purists prefer stdlib-only

## AuthZEN Protocol

### Decision Request Format

```json
{
  "subject": {
    "type": "x509_certificate",
    "id": "subject-123",
    "properties": {
      "x5c": ["MIID...base64cert..."]
    }
  },
  "resource": {
    "type": "service",
    "id": "resource-123"
  },
  "action": {
    "name": "trust"
  },
  "context": {}
}
```

### Decision Response Format

```json
{
  "decision": true,
  "context": {
    "id": "decision-123",
    "reason_admin": {
      "en": "Certificate is in trusted TSL"
    }
  }
}
```

### Why AuthZEN?

1. **Purpose-built for authorization**: Perfect fit for trust decisions
2. **Subject-Resource-Action model**: Natural for certificate validation
3. **Standardized**: OpenID Foundation standard
4. **Extensible**: Context and properties for custom data
5. **Clear semantics**: Boolean decision with optional context

## Gin Framework

### Why Gin?

1. **Performance**: One of the fastest Go web frameworks
   - 40x faster than Martini
   - Similar to net/http raw performance

2. **Middleware support**: Easy to add cross-cutting concerns
   ```go
   r.Use(LoggingMiddleware())
   r.Use(MetricsMiddleware())
   r.Use(RateLimitMiddleware())
   ```

3. **JSON handling**: Native support, automatic binding/validation
   ```go
   var req AuthZENRequest
   if err := c.ShouldBindJSON(&req); err != nil {
       c.JSON(400, gin.H{"error": err.Error()})
       return
   }
   ```

4. **Router**: Fast HTTP router with radix tree
   - Path parameters
   - Query parameters
   - Grouping

5. **Community**: Large ecosystem, active development

## API Endpoints

### Core Endpoints

- `POST /authzen/decision` - Trust decision evaluation
- `GET /status` - Service status
- `GET /info` - TSL information

### Health Endpoints

- `GET /health` or `/healthz` - Liveness probe
- `GET /ready` or `/readiness` - Readiness probe

### Observability

- `GET /metrics` - Prometheus metrics

## Implementation Pattern

```go
func RegisterAPIRoutes(r *gin.Engine, ctx *api.ServerContext) {
    // AuthZEN decision endpoint
    r.POST("/authzen/decision", func(c *gin.Context) {
        var req AuthZENRequest
        if err := c.ShouldBindJSON(&req); err != nil {
            c.JSON(400, gin.H{"error": "invalid request"})
            return
        }

        decision, err := evaluateTrust(ctx, &req)
        if err != nil {
            c.JSON(500, gin.H{
                "decision": false,
                "context": gin.H{
                    "reason_admin": gin.H{"error": err.Error()},
                },
            })
            return
        }

        c.JSON(200, decision)
    })

    // Health endpoints
    r.GET("/health", healthHandler(ctx))
    r.GET("/ready", readinessHandler(ctx))
}
```

## Pros and Cons of the Options

### Custom REST API with net/http

- Good, because standard library only
- Good, because full control
- Good, because no dependencies
- Bad, because more boilerplate
- Bad, because no standard protocol
- Bad, because slower development

### AuthZEN with Gin

- Good, because standards-based
- Good, because excellent performance
- Good, because rich middleware
- Good, because easy JSON handling
- Good, because good documentation
- Bad, because third-party dependency

### gRPC with Protocol Buffers

- Good, because very performant
- Good, because strong typing
- Good, because code generation
- Bad, because requires protobuf compilation
- Bad, because less HTTP-friendly
- Bad, because harder to test manually

### GraphQL API

- Good, because flexible queries
- Good, because single endpoint
- Bad, because overkill for simple API
- Bad, because complex client integration
- Bad, because harder to cache

### OpenAPI/Swagger first

- Good, because design-first approach
- Good, because auto-generated docs
- Bad, because requires code generation
- Bad, because can be restrictive
- Bad, because still need framework

## Middleware Stack

1. **Recovery** - Panic recovery
2. **Logging** - Request/response logging
3. **Metrics** - Prometheus instrumentation
4. **Rate Limiting** - Per-IP rate limiting
5. **CORS** - Cross-origin support (optional)

## Error Handling

AuthZEN allows rich error context:

```json
{
  "decision": false,
  "context": {
    "id": "err-123",
    "reason_admin": {
      "error": "certificate has expired"
    },
    "reason_user": {
      "message": "The certificate is not trusted"
    }
  }
}
```

This provides:
- Admin-facing details for debugging
- User-facing messages for display
- Unique error ID for tracking

## Testing Strategy

```go
func TestDecisionEndpoint(t *testing.T) {
    r := setupRouter()

    req := httptest.NewRequest("POST", "/authzen/decision", body)
    w := httptest.NewRecorder()

    r.ServeHTTP(w, req)

    assert.Equal(t, 200, w.Code)
    // Assert response
}
```

Gin provides excellent testability with `httptest`.

## Performance Characteristics

- **Latency**: ~1-5ms per request (excluding cert validation)
- **Throughput**: 10,000+ req/sec on modest hardware
- **Memory**: ~50KB per request
- **Middleware overhead**: ~100µs total

## Security Considerations

- **Input validation**: Gin's binding validates JSON
- **Rate limiting**: Per-IP token bucket
- **TLS**: Supported via standard `http.ListenAndServeTLS`
- **CORS**: Configurable per deployment
- **Request size limits**: Configured in Gin

## Links

- Implementation: `pkg/api/api.go`
- AuthZEN types: `pkg/authzen/types.go`
- Tests: `pkg/api/api_test.go`
- Gin documentation: https://gin-gonic.com/
- AuthZEN spec: https://openid.github.io/authzen/
- Related: [ADR-0007](0007-observability.md) - Observability
