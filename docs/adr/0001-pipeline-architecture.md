# Pipeline Architecture with YAML Configuration

- Status: **Superseded** (Moved to g119612/tsl-tool)
- Deciders: Development Team
- Date: 2025-10-17
- Superseded Date: 2025-07-01

> **Note:** This architecture has been moved to [g119612](https://github.com/sirosfoundation/g119612) as `tsl-tool`.
> Go-trust is now solely a PDP server that consumes pre-processed TSL data.
> See g119612 for current pipeline implementation.

## Context and Problem Statement

Go-trust needs to process Trust Status Lists (TSLs) in various ways: loading, filtering, transforming, publishing, and signing. How should we structure the processing logic to be flexible, maintainable, and user-configurable?

## Decision Drivers

- Need flexibility to handle different TSL processing workflows
- Users should be able to configure processing without code changes
- Processing steps should be composable and reusable
- Support both CLI and API server modes
- Enable testing of individual processing steps
- Minimize coupling between processing stages

## Considered Options

- Hardcoded processing workflow
- Plugin system with compiled extensions
- Pipeline architecture with YAML configuration
- DSL (Domain-Specific Language) for TSL processing
- REST API for orchestrating operations

## Decision Outcome

Chosen option: "Pipeline architecture with YAML configuration", because it provides the right balance of flexibility, simplicity, and configurability without requiring compilation or complex orchestration.

### Positive Consequences

- Users can define custom workflows via YAML files
- Processing steps are decoupled and testable
- Easy to add new pipeline steps
- No compilation required for configuration changes
- Clear sequence of operations visible in YAML
- Supports both one-shot (CLI) and recurring (API) execution
- Context object passes state between steps

### Negative Consequences

- YAML parsing adds slight overhead
- Error messages may be less clear than compile-time errors
- Pipeline step registry requires runtime registration
- Limited type safety compared to compile-time checking

## Pros and Cons of the Options

### Hardcoded processing workflow

- Good, because simple to implement
- Good, because type-safe and compile-time checked
- Bad, because inflexible
- Bad, because requires recompilation for changes
- Bad, because difficult to support different use cases

### Plugin system with compiled extensions

- Good, because extensible
- Good, because type-safe plugins
- Bad, because requires compilation for each plugin
- Bad, because complex build process
- Bad, because distribution complexity
- Bad, because security concerns with external plugins

### Pipeline architecture with YAML configuration

- Good, because flexible and configurable
- Good, because no compilation needed
- Good, because easy to version control configurations
- Good, because steps are independently testable
- Good, because supports composability
- Bad, because runtime configuration validation
- Bad, because limited type safety

### DSL for TSL processing

- Good, because potentially more expressive
- Good, because domain-specific optimizations
- Bad, because learning curve for new language
- Bad, because requires parser implementation
- Bad, because tooling ecosystem needed

### REST API for orchestrating operations

- Good, because flexible
- Good, because language-agnostic
- Bad, because requires API server for CLI use
- Bad, because network latency
- Bad, because more complex for simple workflows

## Implementation Details

### Pipeline Structure

```yaml
# Example pipeline configuration
- load: ["https://example.com/tsl.xml"]
- select: []
- transform: ["embedded:tsl-to-html.xslt", "/output", "html"]
- publish: ["/output/xml"]
```

### Key Components

1. **Pipeline**: Container for processing steps
2. **Context**: Carries state between steps (TSL tree, cert pool, logger)
3. **Step Functions**: Registered functions that process context
4. **Step Registry**: Maps step names to implementations

### Step Function Signature

```go
type StepFunc func(*Pipeline, *Context, ...string) (*Context, error)
```

This allows:
- Access to pipeline configuration
- State modification via context
- Variable arguments from YAML
- Error propagation

### Context Design

The Context object includes:
- `TSLTree`: Hierarchical TSL structure
- `CertPool`: X.509 certificate pool
- `Logger`: Structured logging
- `Data`: Generic data storage for custom steps

This enables:
- State passing between steps
- Immutability where needed
- Logging throughout pipeline
- Extension points for custom data

## Alternatives Considered

### Functional Composition

Initially considered pure functional composition:
```go
pipeline := Load().Then(Filter()).Then(Transform())
```

Rejected because:
- Less user-configurable
- Requires code changes for new workflows
- Harder to serialize/deserialize

### Event-Driven Architecture

Considered event bus with handlers:
```go
bus.On("tsl.loaded", transformHandler)
```

Rejected because:
- More complex than needed
- Harder to reason about execution order
- Overkill for sequential processing

## Links

- Implementation: `pkg/pipeline/pipeline.go`
- Step registry: `pkg/pipeline/step_registry.go`
- Context: `pkg/pipeline/context.go`
- Related: [ADR-0006](0006-error-handling.md) - Error Handling Strategy
