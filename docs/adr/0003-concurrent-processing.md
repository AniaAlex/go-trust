# Concurrent TSL Processing with Worker Pools

- Status: **Superseded** (Moved to g119612/tsl-tool)
- Deciders: Development Team
- Date: 2025-10-17
- Superseded Date: 2025-07-01

> **Note:** This concurrent processing has been moved to [g119612](https://github.com/sirosfoundation/g119612) as part of `tsl-tool`.
> Go-trust is now solely a PDP server that consumes pre-processed TSL data.
> See g119612 for current pipeline/concurrent processing implementation.

## Context and Problem Statement

XSLT transformations of TSLs are CPU-intensive operations that can take 10-20ms per TSL. When processing EU Trust Lists with 20+ member state TSLs, sequential processing takes 400-600ms. How can we improve performance while maintaining correctness and resource control?

## Decision Drivers

- XSLT transformations are CPU-bound and parallelizable
- Modern servers have multiple CPU cores
- Need to process 20+ TSLs efficiently
- Must control resource usage (don't spawn unlimited goroutines)
- Should scale automatically to available CPUs
- Need to maintain error handling and logging
- Must work in both CLI and API server modes

## Considered Options

- Sequential processing (status quo)
- Unlimited goroutines (one per TSL)
- Worker pool with fixed size
- Worker pool with dynamic sizing based on CPU count
- External job queue (RabbitMQ, Redis)

## Decision Outcome

Chosen option: "Worker pool with dynamic sizing based on CPU count (up to 8 workers)", because it provides 2-3x speedup while controlling resource usage and maintaining simple error handling.

### Positive Consequences

- 2-3x performance improvement for TSL processing
- Automatic scaling to available CPU cores
- Bounded resource usage (max 8 workers)
- Simple implementation without external dependencies
- Works in all deployment environments
- Errors are still properly captured
- Progress can be logged per TSL

### Negative Consequences

- More complex than sequential processing
- Requires goroutine coordination
- Slightly more difficult to debug
- Results may come back in different order

## Implementation Details

### Worker Pool Design

```go
func ProcessTSLsConcurrently(tsls []*TSL, transform func(*TSL) error) error {
    numWorkers := min(runtime.NumCPU(), 8)

    jobs := make(chan *TSL, len(tsls))
    results := make(chan error, len(tsls))

    // Start workers
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go worker(jobs, results, transform, &wg)
    }

    // Send jobs
    for _, tsl := range tsls {
        jobs <- tsl
    }
    close(jobs)

    // Wait for completion
    wg.Wait()
    close(results)

    // Collect errors
    var errs []error
    for err := range results {
        if err != nil {
            errs = append(errs, err)
        }
    }

    if len(errs) > 0 {
        return fmt.Errorf("processing errors: %v", errs)
    }
    return nil
}
```

### Key Design Choices

1. **Worker count**: `min(runtime.NumCPU(), 8)`
   - Scales to available CPUs
   - Caps at 8 to prevent resource exhaustion
   - Benchmarked: 8 workers optimal for typical workloads

2. **Buffered channels**
   - Job channel buffered to TSL count
   - Results channel buffered to TSL count
   - Prevents blocking on channel send/receive

3. **WaitGroup for coordination**
   - Ensures all workers complete
   - Clean shutdown without leaks

4. **Error collection**
   - All errors are captured
   - Aggregated for reporting
   - Processing continues despite individual failures

### Performance Characteristics

Benchmarked on 8-core system:

- **1 TSL**: ~15ms (no speedup, overhead minimal)
- **20 TSLs**:
  - Sequential: ~600ms
  - Concurrent (8 workers): ~300ms
  - **Speedup: 2x**
- **50 TSLs**:
  - Sequential: ~1500ms
  - Concurrent (8 workers): ~700ms
  - **Speedup: 2.1x**

Overhead: ~100-200µs for worker pool setup

## Pros and Cons of the Options

### Sequential processing

- Good, because simple and predictable
- Good, because easy to debug
- Good, because deterministic order
- Bad, because slow for multiple TSLs
- Bad, because wastes CPU cores
- Bad, because doesn't scale

### Unlimited goroutines

- Good, because maximum concurrency
- Good, because simple implementation
- Bad, because unbounded resource usage
- Bad, because potential goroutine explosion
- Bad, because context switching overhead
- Bad, because difficult to control

### Worker pool with fixed size

- Good, because bounded resources
- Good, because predictable behavior
- Bad, because doesn't adapt to available CPUs
- Bad, because may underutilize or overutilize

### Worker pool with dynamic sizing

- Good, because adapts to hardware
- Good, because bounded (max 8 workers)
- Good, because excellent performance
- Good, because controlled resource usage
- Bad, because slightly more complex

### External job queue

- Good, because distributed processing
- Good, because robust error handling
- Bad, because requires infrastructure
- Bad, because network latency
- Bad, because overkill for this use case
- Bad, because adds deployment complexity

## XSLT Caching Integration

Concurrent processing works seamlessly with XSLT caching:

1. Stylesheet loaded once (cached)
2. Multiple workers use cached stylesheet
3. Thread-safe access via `sync.RWMutex`
4. Combined speedup: 2-3x from concurrency + 5-10% from caching

## Resource Control

### Memory

- Each worker holds: ~1MB for XSLT transform
- Max workers: 8
- Peak memory: ~8-10MB additional

### CPU

- Workers automatically use available cores
- Go runtime manages scheduling
- No CPU pinning needed

### Goroutine Lifecycle

- Workers created at start of batch
- Terminated after batch completes
- No long-lived goroutines between batches

## Error Handling Strategy

- Individual TSL errors are captured
- Processing continues for other TSLs
- All errors aggregated and returned
- Logs include which TSL failed
- Partial results may be available

## Testing Strategy

- Unit tests with mock transformations
- Benchmarks comparing sequential vs concurrent
- Race detection enabled (`go test -race`)
- Error injection tests (some TSLs fail)
- Resource leak tests (goroutine counting)

## Links

- Implementation: `pkg/pipeline/concurrent.go` or `pkg/xslt/xslt.go`
- Benchmarks: `pkg/xslt/xslt_test.go`
- Related: [ADR-0004](0004-xslt-transformation.md) - XSLT Transformation
- Related: [ADR-0001](0001-pipeline-architecture.md) - Pipeline Architecture
