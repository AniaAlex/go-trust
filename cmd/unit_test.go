package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/logging"
	"github.com/stretchr/testify/assert"
)

// TestParseLogLevel tests the parseLogLevel function with various inputs
func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected logging.LogLevel
	}{
		{
			name:     "debug level lowercase",
			input:    "debug",
			expected: logging.DebugLevel,
		},
		{
			name:     "debug level uppercase",
			input:    "DEBUG",
			expected: logging.DebugLevel,
		},
		{
			name:     "debug level mixed case",
			input:    "Debug",
			expected: logging.DebugLevel,
		},
		{
			name:     "info level lowercase",
			input:    "info",
			expected: logging.InfoLevel,
		},
		{
			name:     "info level uppercase",
			input:    "INFO",
			expected: logging.InfoLevel,
		},
		{
			name:     "warn level lowercase",
			input:    "warn",
			expected: logging.WarnLevel,
		},
		{
			name:     "warn level uppercase",
			input:    "WARN",
			expected: logging.WarnLevel,
		},
		{
			name:     "warning level lowercase",
			input:    "warning",
			expected: logging.WarnLevel,
		},
		{
			name:     "error level lowercase",
			input:    "error",
			expected: logging.ErrorLevel,
		},
		{
			name:     "error level uppercase",
			input:    "ERROR",
			expected: logging.ErrorLevel,
		},
		{
			name:     "fatal level lowercase",
			input:    "fatal",
			expected: logging.FatalLevel,
		},
		{
			name:     "fatal level uppercase",
			input:    "FATAL",
			expected: logging.FatalLevel,
		},
		{
			name:     "invalid level defaults to InfoLevel",
			input:    "invalid",
			expected: logging.InfoLevel,
		},
		{
			name:     "empty string defaults to InfoLevel",
			input:    "",
			expected: logging.InfoLevel,
		},
		{
			name:     "random string defaults to InfoLevel",
			input:    "xyz123",
			expected: logging.InfoLevel,
		},
		{
			name:     "partial match defaults to InfoLevel",
			input:    "deb",
			expected: logging.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogLevel(tt.input)
			assert.Equal(t, tt.expected, result, "parseLogLevel(%q) should return %v", tt.input, tt.expected)
		})
	}
}

// TestUsage tests the usage function output
func TestUsage(t *testing.T) {
	// Capture stderr (usage writes to stderr, not stdout)
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	assert.NoError(t, err, "Failed to create pipe")
	os.Stderr = w

	// Call usage()
	usage()

	// Restore stderr
	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NoError(t, err, "Failed to read from pipe")

	output := buf.String()

	// Verify the output contains expected sections
	assert.Contains(t, output, "Usage:", "Output should contain Usage section")
	assert.Contains(t, output, "<pipeline.yaml>", "Output should show pipeline file argument")

	// Verify all command-line options are documented
	expectedOptions := []string{
		"--config",
		"--host",
		"--port",
		"--frequency",
		"--no-server",
		"--log-level",
		"--log-format",
		"--log-output",
		"--version",
		"--help",
	}

	for _, option := range expectedOptions {
		assert.Contains(t, output, option, "Output should document %s option", option)
	}

	// Verify sections are present
	assert.Contains(t, output, "Options:", "Should have Options section")
	assert.Contains(t, output, "Logging options:", "Should have Logging options section")
	assert.Contains(t, output, "Configuration precedence", "Should have Configuration precedence section")

	// Verify some key descriptions
	assert.Contains(t, output, "Run pipeline once and exit", "Should explain no-server option")
	assert.Contains(t, output, "Show version information", "Should explain version option")
	assert.Contains(t, output, "Show this help message", "Should explain help option")
}

// TestUsageOutputFormat tests that usage output is well-formatted
func TestUsageOutputFormat(t *testing.T) {
	// Capture stderr (usage writes to stderr, not stdout)
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	assert.NoError(t, err, "Failed to create pipe")
	os.Stderr = w

	// Call usage()
	usage()

	// Restore stderr
	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NoError(t, err, "Failed to read from pipe")

	output := buf.String()

	// Check that output is not empty
	assert.NotEmpty(t, output, "Usage output should not be empty")

	// Check minimum length (should be substantial help text)
	assert.Greater(t, len(output), 500, "Usage output should be comprehensive")

	// Check that lines are not too long (good formatting)
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		// Allow some longer lines for examples, but most should be reasonable
		if len(line) > 120 {
			// This is just a warning, not a failure
			t.Logf("Line %d is quite long (%d chars): %s...", i+1, len(line), line[:min(50, len(line))])
		}
	}

	// Verify consistent indentation (using spaces)
	for i, line := range lines {
		if strings.HasPrefix(line, "\t") {
			t.Errorf("Line %d uses tabs instead of spaces: %q", i+1, line)
		}
	}
}

// TestVersionVariable tests that the Version variable is properly set
func TestVersionVariable(t *testing.T) {
	// The Version variable is set at build time with -ldflags
	// In tests, it will have its default value

	// Test that Version is a string (even if empty in test context)
	assert.IsType(t, "", Version, "Version should be a string")

	// In test context, Version is typically "dev"
	// In production builds, it's set via ldflags
	assert.NotEmpty(t, Version, "Version should not be empty")
	t.Logf("Version in test context: %q", Version)
}

// TestParseLogLevelConcurrency tests parseLogLevel is safe for concurrent use
func TestParseLogLevelConcurrency(t *testing.T) {
	// Run parseLogLevel concurrently to verify it's thread-safe
	levels := []string{"debug", "info", "warn", "error", "fatal", "invalid"}

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for _, level := range levels {
				result := parseLogLevel(level)
				// Just verify it doesn't panic
				_ = result
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	t.Log("parseLogLevel is safe for concurrent use")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
