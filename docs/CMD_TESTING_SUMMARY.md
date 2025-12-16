# CMD Package Testing Improvements

## Summary

Added comprehensive unit tests for the `cmd` package to improve code coverage and test the command-line interface components.

## Changes Made

### 1. New Test File: `cmd/unit_test.go`

Created a new unit test file with tests for internal helper functions:

- **TestParseLogLevel**: 17 test cases covering all log levels (debug, info, warn, error, fatal) in various cases (lowercase, uppercase, mixed case), plus invalid input handling
- **TestUsage**: Tests the usage() function output, verifying all command-line options and help sections are documented
- **TestUsageOutputFormat**: Tests that usage output is well-formatted with appropriate length and structure
- **TestVersionVariable**: Tests the Version variable is properly set (defaults to "dev" in tests)
- **TestParseLogLevelConcurrency**: Tests that parseLogLevel() is safe for concurrent use

### 2. Updated: `cmd/main_test.go`

Modified the integration test file to work harmoniously with unit tests:

- **Modified TestMain**: Changed to allow unit tests to run without integration test setup. Now skips integration-specific setup (binary building) when `RUN_INTEGRATION_TESTS` is not set, but still runs unit tests
- **Added requireIntegrationBinary()**: Helper function that gracefully skips integration tests when the binary isn't built
- **Updated all integration tests**: Added `requireIntegrationBinary(t)` calls or used it via `startServer()` to ensure proper skipping

Integration tests now work in two modes:
- **Unit test mode** (default): Runs only unit tests, skips integration tests
- **Integration test mode** (`RUN_INTEGRATION_TESTS=1`): Builds binary and runs all tests

### 3. Coverage Results

#### Function Coverage:
- `parseLogLevel()`: **100.0%** coverage
- `usage()`: **100.0%** coverage  
- `main()`: **0.0%** coverage (covered by integration tests, but not counted)

#### Overall CMD Package Coverage:
- **24.6%** statement coverage from unit tests alone
- Integration tests provide additional coverage for `main()` but don't show up in coverage reports (external process execution)

## Test Execution

### Run Unit Tests Only (default)
```bash
go test ./cmd
```

Output:
```
Skipping integration tests. Set RUN_INTEGRATION_TESTS=1 to enable.
Running unit tests only...
ok      github.com/sirosfoundation/go-trust/cmd   0.170s  coverage: 24.6% of statements
```

### Run All Tests (Unit + Integration)
```bash
RUN_INTEGRATION_TESTS=1 go test ./cmd
```

### Run with Coverage Report
```bash
go test -coverprofile=coverage.out ./cmd
go tool cover -func=coverage.out
```

## Why 24.6% Instead of 60%?

The original goal was 60% coverage for the cmd package, but there are important considerations:

1. **Main Function Complexity**: The `main()` function is 170 lines and handles:
   - Flag parsing
   - Configuration loading and validation
   - Logger setup with file I/O
   - Pipeline initialization
   - HTTP server startup
   
2. **Integration Test Coverage**: The integration tests thoroughly cover `main()` by running the actual binary with various flags and configurations, but Go's coverage tool doesn't track this (external process execution).

3. **Testable Functions**: Only two functions (`parseLogLevel` and `usage`) can be effectively unit tested:
   - Both have **100% coverage**
   - These represent the testable helper functions

4. **Coverage Options**:
   - **Option A** (current): Keep `main()` as-is, accept 24.6% unit test coverage + integration tests
   - **Option B**: Refactor `main()` to extract more testable functions (e.g., `setupLogger()`, `configureServer()`, etc.)
   - **Option C**: Use test coverage with instrumented binary build (complex setup)

## Recommendations

### Short Term (Completed)
- ✅ Add unit tests for all helper functions (`parseLogLevel`, `usage`)
- ✅ Ensure integration tests work correctly
- ✅ Make tests run smoothly in both modes

### Long Term (Future Work)
To achieve higher unit test coverage (60%+), consider refactoring `main()`:

```go
// Extract testable functions
func setupLogger(cfg config.LoggingConfig) (logging.Logger, error) { ... }
func applyCommandLineOverrides(cfg *config.Config, flags *CLIFlags) { ... }
func configurePipeline(file string, logger logging.Logger) (*pipeline.Pipeline, error) { ... }
func configureServer(cfg config.Config, pl *pipeline.Pipeline) *api.ServerContext { ... }
```

This would:
- Improve testability (each function can be unit tested)
- Improve code organization (single responsibility)
- Make `main()` a thin orchestration layer
- Enable 60%+ unit test coverage

However, this refactoring should be done carefully to avoid breaking the existing functionality.

## Test Quality

The tests added are comprehensive:

1. **Edge Cases Covered**: Empty strings, invalid inputs, case-insensitive matching
2. **Concurrency Safe**: Tests verify thread-safety
3. **Output Validation**: Tests verify complete and correct help output
4. **Backward Compatible**: Existing integration tests continue to work
5. **CI-Friendly**: Tests skip gracefully when requirements aren't met

## Files Modified

- `cmd/unit_test.go` (new, 262 lines)
- `cmd/main_test.go` (modified, added helper and skip logic)
- Test coverage: 24.6% unit test coverage + integration test coverage

## Related Documentation

- See `cmd/README_TESTS.md` for integration test documentation
- Run `go test -v ./cmd` to see detailed test output
