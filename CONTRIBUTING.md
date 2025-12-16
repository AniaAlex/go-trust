# Contributing to Go-Trust

Thank you for your interest in contributing to Go-Trust! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project follows standard open source community guidelines. Please be respectful and professional in all interactions.

## Getting Started

### Prerequisites

- Go 1.18 or later
- Make
- Git
- (Optional) Docker for containerized testing

### Initial Setup

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/go-trust.git
   cd go-trust
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/sirosfoundation/go-trust.git
   ```

4. **Run the setup script**:
   ```bash
   make setup
   ```

   This will:
   - Install development tools (linters, formatters)
   - Set up Git pre-commit hooks
   - Verify your Go version
   - Run initial tests to ensure everything works

### Development Environment

For a comprehensive guide to the development environment, see [DEVELOPER.md](DEVELOPER.md).

## Development Workflow

### 1. Create a Feature Branch

Always create a new branch for your work:

```bash
# Update your main branch
git checkout main
git pull upstream main

# Create a feature branch
git checkout -b feature/my-new-feature
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `test/` - Test additions or improvements
- `refactor/` - Code refactoring

### 2. Make Your Changes

- Write clean, idiomatic Go code
- Follow the [coding standards](#coding-standards)
- Add tests for new functionality
- Update documentation as needed
- Keep commits focused and atomic

### 3. Test Your Changes

Before committing, ensure all tests pass:

```bash
# Run quick checks (formatting and vet)
make quick

# Run all tests
make test

# Check coverage
make coverage

# Run linters
make lint
```

### 4. Commit Your Changes

Write clear, descriptive commit messages following [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git commit -m "feat: Add support for new TSL format"
git commit -m "fix: Correct certificate validation logic"
git commit -m "docs: Update API documentation"
git commit -m "test: Add edge case tests for pipeline"
```

Commit message format:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks
- `ci:` - CI/CD changes

The pre-commit hook will automatically:
- Check code formatting
- Run `go vet`
- Run tests for changed packages
- Check for common issues

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/my-new-feature
```

Then create a Pull Request on GitHub.

## Coding Standards

### Go Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting (automatic with `make fmt`)
- Pass `go vet` without warnings
- Pass all configured linters

### Code Organization

- Keep functions small and focused (< 50 lines ideally)
- Use meaningful variable and function names
- Write comments for exported functions and types
- Document complex logic with inline comments
- Organize imports: standard library, external packages, internal packages

### Error Handling

- Always check and handle errors
- Use custom error types for domain errors
- Wrap errors with context using `fmt.Errorf` with `%w`
- Log errors at appropriate levels

Example:
```go
if err != nil {
    return fmt.Errorf("failed to load TSL from %s: %w", url, err)
}
```

### Logging

- Use structured logging with the `logging` package
- Include relevant context fields
- Use appropriate log levels:
  - `Debug` - Detailed debugging information
  - `Info` - General informational messages
  - `Warn` - Warning messages
  - `Error` - Error messages
  - `Fatal` - Fatal errors (exits program)

Example:
```go
logger.Info("Processing TSL",
    logging.F("url", url),
    logging.F("territory", territory))
```

## Testing

### Test Requirements

- All new features must include tests
- Bug fixes should include regression tests
- Aim for >80% code coverage overall
- Critical packages (api, pipeline, dsig) should have >85% coverage

### Writing Tests

Use table-driven tests for multiple scenarios:

```go
func TestMyFunction(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {
            name:    "valid input",
            input:   "test",
            want:    "TEST",
            wantErr: false,
        },
        {
            name:    "empty input",
            input:   "",
            want:    "",
            wantErr: false,
        },
        {
            name:    "invalid input",
            input:   "!@#",
            want:    "",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := MyFunction(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

### Test Organization

- Test files should be named `*_test.go`
- Place tests in the same package as the code they test
- Use `testify/assert` for assertions
- Use `testify/require` for setup that must succeed
- Mock external dependencies

### Running Tests

```bash
# All tests
make test

# Specific package
go test ./pkg/api -v

# Specific test
go test ./pkg/api -run TestHealthEndpoint -v

# With race detection (default)
go test -race ./...

# Coverage report
make coverage

# Coverage HTML report
make coverage-html
```

## Submitting Changes

### Pull Request Guidelines

1. **Update from upstream** before creating PR:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Ensure all checks pass**:
   - All tests pass
   - Code coverage is maintained or improved
   - Linters pass without warnings
   - No merge conflicts

3. **Write a clear PR description**:
   - Explain what changes you made and why
   - Reference any related issues
   - Include screenshots for UI changes
   - Note any breaking changes

4. **PR title** should follow conventional commit format:
   ```
   feat: Add support for new TSL format
   fix: Correct certificate validation in edge case
   docs: Improve API documentation
   ```

### PR Review Process

- All PRs require at least one approval
- CI checks must pass
- Code coverage should not decrease
- Address review feedback promptly
- Keep PRs focused and reasonably sized

### After PR Approval

- Maintainers will merge your PR using squash or rebase
- Delete your feature branch after merge
- Update your fork:
  ```bash
  git checkout main
  git pull upstream main
  git push origin main
  ```

## Release Process

### Versioning

Go-Trust follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality
- **PATCH** version for backwards-compatible bug fixes

### Creating a Release

Releases are created by maintainers:

1. Update CHANGELOG.md with release notes
2. Create and push a version tag:
   ```bash
   git tag -a v1.2.3 -m "Release v1.2.3"
   git push upstream v1.2.3
   ```
3. GitHub Actions will automatically create the release

## Additional Resources

- [Developer Guide](DEVELOPER.md) - Comprehensive development documentation
- [Architecture Decision Records](docs/adr/) - Key architectural decisions
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Effective Go](https://golang.org/doc/effective_go.html)

## Getting Help

- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check README.md and DEVELOPER.md

## Recognition

Contributors will be recognized in:
- Git commit history
- CHANGELOG.md for significant contributions
- GitHub contributors page

Thank you for contributing to Go-Trust! 🎉
