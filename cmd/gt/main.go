package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	_ "github.com/sirosfoundation/go-trust/docs/swagger" // Import generated docs
	"github.com/sirosfoundation/go-trust/pkg/api"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Go-Trust API
// @version 2.0
// @description Multi-framework trust decision engine providing AuthZEN-based trust evaluation
// @description
// @description Go-Trust is a Policy Decision Point (PDP) that evaluates trust across multiple frameworks:
// @description - ETSI TS 119612 Trust Status Lists (for X.509 certificates)
// @description - OpenID Federation (for entity trust chains)
// @description - DID Web (for decentralized identifiers)
// @description
// @description The service provides health/metrics endpoints for production deployment.
// @termsOfService https://github.com/sirosfoundation/go-trust

// @contact.name sirosfoundation
// @contact.url https://github.com/sirosfoundation/go-trust
// @contact.email noreply@sunet.se

// @license.name BSD-2-Clause
// @license.url https://opensource.org/licenses/BSD-2-Clause

// @host localhost:6001
// @BasePath /

// @schemes http https

// @tag.name Health
// @tag.description Health check and readiness endpoints for Kubernetes and monitoring systems

// @tag.name Status
// @tag.description Server status and registry information endpoints

// @tag.name AuthZEN
// @tag.description AuthZEN protocol endpoints for trust decision evaluation

// Version is set at build time using -ldflags
var Version = "2.0.0-dev"

func usage() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "\nUsage: %s [options]\n", prog)
	fmt.Fprintln(os.Stderr, "\nGo-Trust: Multi-framework AuthZEN Trust Decision Point (PDP)")
	fmt.Fprintln(os.Stderr, "\nOptions:")
	fmt.Fprintln(os.Stderr, "  --help         Show this help message and exit")
	fmt.Fprintln(os.Stderr, "  --version      Show version information and exit")
	fmt.Fprintln(os.Stderr, "  --config       Configuration file path (YAML format)")
	fmt.Fprintln(os.Stderr, "  --host         API server hostname (default: 127.0.0.1)")
	fmt.Fprintln(os.Stderr, "  --port         API server port (default: 6001)")
	fmt.Fprintln(os.Stderr, "  --external-url External URL for PDP discovery (e.g., https://pdp.example.com)")
	fmt.Fprintln(os.Stderr, "                 Can also be set via GO_TRUST_EXTERNAL_URL environment variable")
	fmt.Fprintln(os.Stderr, "\nETSI TSL Registry Options:")
	fmt.Fprintln(os.Stderr, "  --etsi-cert-bundle   Path to PEM file with trusted CA certificates")
	fmt.Fprintln(os.Stderr, "  --etsi-tsl-files     Comma-separated list of local TSL XML files")
	fmt.Fprintln(os.Stderr, "\nLogging Options:")
	fmt.Fprintln(os.Stderr, "  --log-level    Logging level: debug, info, warn, error (default: info)")
	fmt.Fprintln(os.Stderr, "  --log-format   Logging format: text or json (default: text)")
	fmt.Fprintln(os.Stderr, "\nNotes:")
	fmt.Fprintln(os.Stderr, "  - For TSL processing (load, transform, sign, publish), use tsl-tool from g119612")
	fmt.Fprintln(os.Stderr, "  - This server consumes pre-processed TSL data (PEM bundles or XML files)")
	fmt.Fprintln(os.Stderr, "  - Run tsl-tool via cron to update TSL data periodically")
	fmt.Fprintln(os.Stderr, "")
}

func main() {
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	configFile := flag.String("config", "", "Configuration file path (YAML format)")
	host := flag.String("host", "127.0.0.1", "API server hostname")
	port := flag.String("port", "6001", "API server port")
	externalURL := flag.String("external-url", "", "External URL for PDP discovery")

	// ETSI registry options
	etsiCertBundle := flag.String("etsi-cert-bundle", "", "Path to PEM file with trusted CA certificates")
	etsiTSLFiles := flag.String("etsi-tsl-files", "", "Comma-separated list of local TSL XML files")

	// Logging options
	logLevel := flag.String("log-level", "info", "Logging level: debug, info, warn, error")
	logFormat := flag.String("log-format", "text", "Logging format: text or json")

	flag.Parse()

	if *showHelp {
		usage()
		os.Exit(0)
	}
	if *showVersion {
		fmt.Printf("go-trust version %s\n", Version)
		fmt.Println("Multi-framework AuthZEN Trust Decision Point")
		os.Exit(0)
	}

	// Configure logger
	var level logging.LogLevel
	switch *logLevel {
	case "debug":
		level = logging.DebugLevel
	case "info":
		level = logging.InfoLevel
	case "warn":
		level = logging.WarnLevel
	case "error":
		level = logging.ErrorLevel
	default:
		fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", *logLevel)
		os.Exit(1)
	}

	var logger logging.Logger
	if *logFormat == "json" {
		logger = logging.JSONLogger(level)
	} else {
		logger = logging.NewLogger(level)
	}

	logger.Info("Starting go-trust server",
		logging.F("version", Version),
		logging.F("host", *host),
		logging.F("port", *port))

	// TODO: Load configuration file if provided
	if *configFile != "" {
		logger.Warn("Configuration file support not yet implemented",
			logging.F("file", *configFile))
	}

	// Create server context
	serverCtx := api.NewServerContext(logger)

	// Initialize RegistryManager
	registryMgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)

	// Configure ETSI TSL registry if cert bundle or TSL files provided
	if *etsiCertBundle != "" || *etsiTSLFiles != "" {
		logger.Info("Configuring ETSI TSL registry")

		config := etsi.TSLConfig{
			Name:        "ETSI-TSL",
			Description: "ETSI TS 119612 Trust Status List Registry",
		}

		if *etsiCertBundle != "" {
			config.CertBundle = *etsiCertBundle
			logger.Info("Loading ETSI certificates from PEM bundle",
				logging.F("path", *etsiCertBundle))
		}

		if *etsiTSLFiles != "" {
			// Split comma-separated file list
			files := splitCSV(*etsiTSLFiles)
			config.TSLFiles = files
			logger.Info("Loading ETSI TSL files",
				logging.F("count", len(files)))
		}

		tslRegistry, err := etsi.NewTSLRegistry(config)
		if err != nil {
			logger.Fatal("Failed to create ETSI TSL registry",
				logging.F("error", err.Error()))
		}

		registryMgr.Register(tslRegistry)
		logger.Info("ETSI TSL registry registered")
	} else {
		logger.Warn("No ETSI TSL configuration provided (use --etsi-cert-bundle or --etsi-tsl-files)")
		logger.Warn("Server will start but ETSI trust evaluation will not be available")
	}

	// TODO: Add other registries (OpenID Federation, DID Web) based on config

	serverCtx.RegistryManager = registryMgr

	// Set BaseURL for .well-known discovery
	baseURL := *externalURL
	if baseURL == "" {
		baseURL = os.Getenv("GO_TRUST_EXTERNAL_URL")
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%s", *host, *port)
	}
	serverCtx.BaseURL = baseURL

	logger.Info("AuthZEN PDP base URL configured",
		logging.F("url", baseURL))

	// Gin API server
	if *logLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	// Register Swagger UI endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api.RegisterAPIRoutes(r, serverCtx)

	listenAddr := fmt.Sprintf("%s:%s", *host, *port)
	logger.Info("Starting API server",
		logging.F("address", listenAddr),
		logging.F("swagger", fmt.Sprintf("http://%s/swagger/index.html", listenAddr)))

	if err := r.Run(listenAddr); err != nil {
		logger.Fatal("API server error", logging.F("error", err.Error()))
	}
}

// splitCSV splits a comma-separated string and trims whitespace
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := []string{}
	for _, part := range splitString(s, ',') {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func splitString(s string, sep rune) []string {
	var parts []string
	var current []rune
	for _, r := range s {
		if r == sep {
			parts = append(parts, string(current))
			current = nil
		} else {
			current = append(current, r)
		}
	}
	if len(current) > 0 || len(parts) > 0 {
		parts = append(parts, string(current))
	}
	return parts
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && isSpace(rune(s[start])) {
		start++
	}
	for start < end && isSpace(rune(s[end-1])) {
		end--
	}
	return s[start:end]
}

func isSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}
