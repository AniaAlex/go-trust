// Package main provides the Go-Trust trust engine application entrypoint.
//
// Go-Trust is a local trust engine that provides trust decisions based on
// ETSI TS 119612 Trust Status Lists (TSLs). It allows clients to abstract trust
// decisions through an AuthZEN policy decision point (PDP). The service evaluates
// trust in subjects identified by X509 certificates using a set of TSLs.
//
// # Pipeline Overview
//
// Go-Trust processes TSLs using a YAML-defined pipeline. The pipeline consists of
// a series of steps, each performing specific operations on the TSLs. The YAML format
// is a sequence of pipeline steps, where each step has a name and a list of arguments.
//
// Example pipeline YAML format:
//
//   - load:
//   - https://example.com/tsl.xml
//   - transform:
//   - /path/to/stylesheet.xslt
//   - replace
//   - publish:
//   - /path/to/output
//
// # Available Pipeline Steps
//
// The following pipeline steps are available:
//
// - [pipeline.LoadTSL]: Loads a TSL from a URL or file path
//   - Args: URL or file path to load the TSL from
//
// - [pipeline.SelectCertPool]: Builds a certificate pool from the loaded TSLs
//   - Args: Service type URI filter (optional)
//
// - [pipeline.Echo]: Outputs debug information about the current pipeline context
//   - Args: Message prefix (optional)
//
// - [pipeline.GenerateTSL]: Generates a new TSL based on provided metadata
//   - Args: Path to scheme metadata YAML file, path to certificate metadata YAML file(s)
//
// - [pipeline.PublishTSL]: Serializes TSLs to XML files in a directory
//   - Args: Output directory path, optional signer configuration
//
// - [pipeline.TransformTSL]: Applies XSLT transformation to TSLs
//   - Args: XSLT stylesheet path, mode ("replace" or output directory), extension (optional)
//
// # Running the Application
//
// The application starts an API server that periodically processes the pipeline
// and provides endpoints for making trust decisions based on the processed TSLs.
//
// Command line options:
//
//	--host         API server hostname (default: 127.0.0.1)
//	--port         API server port (default: 6001)
//	--frequency    Pipeline update frequency (default: 5m)
//	--version      Show version information
//	--help         Show help message
//
// Logging options:
//
//	--log-level    Logging level: debug, info, warn, error, fatal (default: info)
//	--log-format   Logging format: text or json (default: text)
//	--log-output   Log output: stdout, stderr, or file path (default: stdout)
//
// # API Endpoints
//
// The API server provides the following endpoints:
//
//	GET /status             - Get server status and TSL count information
//	                          Returns: {"tsl_count": <number>, "last_processed": <timestamp>}
//
//	GET /info               - Get detailed information about all loaded TSLs
//	                          Returns: {"tsl_summaries": [<tsl_summary>, ...]}
//
//	POST /authzen/decision  - Make an authorization decision using AuthZEN protocol
//	                          Accepts: AuthZEN EvaluationRequest with x5c certificate chains
//	                          Returns: AuthZEN EvaluationResponse with trust decision
//
//	GET /health, /healthz   - Liveness probe for health checks (always returns 200 if running)
//	                          Returns: {"status": "ok", "timestamp": <timestamp>}
//
//	GET /ready, /readiness  - Readiness probe to check if service can accept traffic
//	                          Returns 200 if ready, 503 if not ready
//	                          Returns: {"status": "ready|not_ready", "ready": bool, "tsl_count": <number>, ...}
//
//	GET /metrics            - Prometheus metrics endpoint for monitoring
//	                          Returns: Prometheus-formatted metrics (text/plain)
//
// See: https://github.com/SUNET/go-trust for more information
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SUNET/go-trust/pkg/api"
	"github.com/SUNET/go-trust/pkg/config"
	"github.com/SUNET/go-trust/pkg/logging"
	"github.com/SUNET/go-trust/pkg/pipeline"
	"github.com/gin-gonic/gin"
)

// Version is set at build time using -ldflags
// It represents the current version of the Go-Trust application.
// Default value is "dev" for development builds. In production,
// this should be set to a specific version string using ldflags:
// go build -ldflags "-X main.Version=1.0.0" ./cmd
var Version = "dev"

// parseLogLevel converts a string log level to the corresponding LogLevel enum value.
// This is used to convert command-line arguments to the internal level representation.
//
// Valid values are:
//   - "debug": Detailed debugging information (most verbose)
//   - "info": Normal operation messages (default)
//   - "warn" or "warning": Warning conditions
//   - "error": Error conditions
//   - "fatal": Critical conditions that require application termination
//
// If an invalid or unknown level is provided, the function returns InfoLevel
// with a warning message printed to stderr.
func parseLogLevel(level string) logging.LogLevel {
	level = strings.ToLower(level)
	switch level {
	case "debug":
		return logging.DebugLevel
	case "info":
		return logging.InfoLevel
	case "warn", "warning":
		return logging.WarnLevel
	case "error":
		return logging.ErrorLevel
	case "fatal":
		return logging.FatalLevel
	default:
		fmt.Fprintf(os.Stderr, "Warning: unknown log level '%s', using 'info'\n", level)
		return logging.InfoLevel
	}
}

// usage prints the command-line usage information to stderr.
// It shows the available command-line options and their descriptions.
func usage() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "\nUsage: %s [options] <pipeline.yaml>\n", prog)
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  --help         Show this help message and exit.")
	fmt.Fprintln(os.Stderr, "  --version      Show version information and exit.")
	fmt.Fprintln(os.Stderr, "  --config       Configuration file path (YAML format)")
	fmt.Fprintln(os.Stderr, "  --host         API server hostname (default: 127.0.0.1)")
	fmt.Fprintln(os.Stderr, "  --port         API server port (default: 6001)")
	fmt.Fprintln(os.Stderr, "  --frequency    Pipeline update frequency (default: 5m)")
	fmt.Fprintln(os.Stderr, "  --no-server    Run pipeline once and exit (no API server)")
	fmt.Fprintln(os.Stderr, "TLS/HTTPS options:")
	fmt.Fprintln(os.Stderr, "  --tls-enable   Enable TLS/HTTPS (default: false)")
	fmt.Fprintln(os.Stderr, "  --tls-cert     TLS certificate file path")
	fmt.Fprintln(os.Stderr, "  --tls-key      TLS private key file path")
	fmt.Fprintln(os.Stderr, "Logging options:")
	fmt.Fprintln(os.Stderr, "  --log-level    Logging level: debug, info, warn, error, fatal (default: info)")
	fmt.Fprintln(os.Stderr, "  --log-format   Logging format: text or json (default: text)")
	fmt.Fprintln(os.Stderr, "  --log-output   Log output: stdout, stderr, or file path (default: stdout)")
	fmt.Fprintln(os.Stderr, "\nConfiguration precedence (highest to lowest):")
	fmt.Fprintln(os.Stderr, "  1. Command-line flags")
	fmt.Fprintln(os.Stderr, "  2. Environment variables (GT_* prefix)")
	fmt.Fprintln(os.Stderr, "  3. Configuration file (--config)")
	fmt.Fprintln(os.Stderr, "  4. Built-in defaults")
	fmt.Fprintln(os.Stderr, "")
}

// main is the entry point for the Go-Trust application.
//
// It performs the following operations:
// 1. Parses command-line arguments and options (including logging options)
// 2. Configures structured logging based on command line arguments
// 3. Loads the specified pipeline YAML file
// 4. Initializes the server context with configured logger
// 5. Starts a background updater to periodically process the pipeline
// 6. Sets up the HTTP API server with Gin
// 7. Starts the API server on the specified address and port
//
// The pipeline YAML file defines the steps to process Trust Status Lists (TSLs).
// The processed TSLs are used by the API server to make trust decisions.
// See the [pipeline.Pipeline] documentation for details on the pipeline format.
//
// Logging is configured using the --log-level, --log-format, and --log-output flags.
// The log level determines which message severity levels are output (debug, info, warn, error, fatal).
// The log format can be either human-readable text or structured JSON for machine processing.
// Log output can be directed to stdout, stderr, or a file path.
func main() {
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	configFile := flag.String("config", "", "Configuration file path (YAML format)")
	host := flag.String("host", "", "API server hostname (overrides config file)")
	port := flag.String("port", "", "API server port (overrides config file)")
	freq := flag.Duration("frequency", 0, "Pipeline update frequency (overrides config file)")
	noServer := flag.Bool("no-server", false, "Run pipeline once and exit (no API server)")

	// TLS configuration
	tlsEnabled := flag.Bool("tls-enable", false, "Enable TLS/HTTPS (overrides config file)")
	tlsCertFile := flag.String("tls-cert", "", "TLS certificate file path (overrides config file)")
	tlsKeyFile := flag.String("tls-key", "", "TLS private key file path (overrides config file)")

	// Logging configuration
	logLevel := flag.String("log-level", "", "Logging level (overrides config file)")
	logFormat := flag.String("log-format", "", "Logging format (overrides config file)")
	logOutput := flag.String("log-output", "", "Log output (overrides config file)")

	flag.Parse()

	if *showHelp {
		usage()
		os.Exit(0)
	}
	if *showVersion {
		fmt.Println("Version:", Version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing pipeline YAML file argument.")
		usage()
		os.Exit(1)
	}

	pipelineFile := args[0]

	// Load configuration with precedence: defaults → config file → env vars → command-line flags
	// Step 1 & 2 & 3: Load defaults, config file, and apply env vars
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Apply command-line flag overrides (highest precedence)
	if *host != "" {
		cfg.Server.Host = *host
	}
	if *port != "" {
		cfg.Server.Port = *port
	}
	if *freq != 0 {
		cfg.Server.Frequency = *freq
	}
	if *tlsEnabled {
		cfg.Server.TLS.Enabled = *tlsEnabled
	}
	if *tlsCertFile != "" {
		cfg.Server.TLS.CertFile = *tlsCertFile
	}
	if *tlsKeyFile != "" {
		cfg.Server.TLS.KeyFile = *tlsKeyFile
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	if *logFormat != "" {
		cfg.Logging.Format = *logFormat
	}
	if *logOutput != "" {
		cfg.Logging.Output = *logOutput
	}

	// Validate the final configuration
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Configure logger based on merged configuration
	parsedLogLevel := parseLogLevel(cfg.Logging.Level)
	var logger logging.Logger

	if strings.ToLower(cfg.Logging.Format) == "json" {
		logger = logging.JSONLogger(parsedLogLevel)
	} else {
		logger = logging.NewLogger(parsedLogLevel)
	}

	// Configure log output
	output := strings.ToLower(cfg.Logging.Output)
	switch output {
	case "stdout":
		// Default is already stdout
	case "stderr":
		logger.(logging.OutputConfigurable).SetOutput(os.Stderr)
	default:
		// Assume it's a file path
		dir := filepath.Dir(cfg.Logging.Output)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
			os.Exit(1)
		}

		file, err := os.OpenFile(cfg.Logging.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		logger.(logging.OutputConfigurable).SetOutput(file)
	}

	// Configure pipeline with logger
	pl, err := pipeline.NewPipeline(pipelineFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load pipeline: %v\n", err)
		os.Exit(1)
	}
	// Create a pipeline with our configured logger
	pl = pl.WithLogger(logger)

	// If --no-server flag is set, run pipeline once and exit
	if *noServer {
		logger.Info("Running pipeline in one-shot mode (no server)",
			logging.F("pipeline", pipelineFile),
			logging.F("version", Version))

		ctx := pipeline.NewContext()
		_, err := pl.Process(ctx)
		if err != nil {
			logger.Error("Pipeline execution failed",
				logging.F("error", err.Error()),
				logging.F("pipeline", pipelineFile))
			os.Exit(1)
		}

		logger.Info("Pipeline execution completed successfully",
			logging.F("pipeline", pipelineFile))
		os.Exit(0)
	}

	// Create server context with logger
	serverCtx := api.NewServerContext(logger)
	serverCtx.PipelineContext = pipeline.NewContext()

	// Initialize Prometheus metrics
	metrics := api.NewMetrics()
	serverCtx.Metrics = metrics
	logger.Info("Metrics initialized")

	// Configure rate limiting if enabled
	if cfg.Security.RateLimitRPS > 0 {
		// Use burst size of 10% of RPS, minimum of 5
		burst := cfg.Security.RateLimitRPS / 10
		if burst < 5 {
			burst = 5
		}
		serverCtx.RateLimiter = api.NewRateLimiter(cfg.Security.RateLimitRPS, burst)
		logger.Info("Rate limiting configured",
			logging.F("rps", cfg.Security.RateLimitRPS),
			logging.F("burst", burst))
	}

	// Start background updater
	api.StartBackgroundUpdater(pl, serverCtx, cfg.Server.Frequency)

	// Gin API server
	r := gin.Default()

	// Register metrics endpoint first (includes middleware)
	api.RegisterMetricsEndpoint(r, metrics)

	// Register other API routes
	api.RegisterAPIRoutes(r, serverCtx)
	api.RegisterHealthEndpoints(r, serverCtx)
	listenAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	// Log startup information
	protocol := "HTTP"
	if cfg.Server.TLS.Enabled {
		protocol = "HTTPS"
	}
	logger.Info("API server starting",
		logging.F("address", listenAddr),
		logging.F("protocol", protocol),
		logging.F("tls_enabled", cfg.Server.TLS.Enabled),
		logging.F("version", Version),
		logging.F("pipeline", pipelineFile),
		logging.F("log_level", cfg.Logging.Level),
		logging.F("frequency", cfg.Server.Frequency.String()))

	// Start server with or without TLS based on configuration
	var serverErr error
	if cfg.Server.TLS.Enabled {
		logger.Info("Starting HTTPS server",
			logging.F("cert_file", cfg.Server.TLS.CertFile),
			logging.F("key_file", cfg.Server.TLS.KeyFile))
		serverErr = r.RunTLS(listenAddr, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	} else {
		logger.Info("Starting HTTP server")
		serverErr = r.Run(listenAddr)
	}

	if serverErr != nil {
		logger.Error("API server failed to start",
			logging.F("error", serverErr.Error()),
			logging.F("address", listenAddr),
			logging.F("protocol", protocol))
		os.Exit(1)
	}
}
