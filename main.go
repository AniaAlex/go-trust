package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/sirosfoundation/go-trust/docs/swagger" // Import generated docs
	"github.com/sirosfoundation/go-trust/pkg/api"
	"github.com/sirosfoundation/go-trust/pkg/pipeline"
	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/sirosfoundation/go-trust/pkg/registry/etsi"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Go-Trust API
// @version 1.0
// @description Trust decision engine for ETSI TS 119612 Trust Status Lists (TSLs)
// @description
// @description Go-Trust provides AuthZEN-based trust decisions for X.509 certificates using ETSI trust status lists.
// @description It processes TSLs, validates certificates, and provides health/metrics endpoints for production deployment.
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
// @tag.description Server status and TSL information endpoints

// @tag.name AuthZEN
// @tag.description AuthZEN protocol endpoints for trust decision evaluation

// Version is set at build time using -ldflags
var Version = "dev"

func usage() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "\nUsage: %s [options] <pipeline.yaml>\n", prog)
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  --help         Show this help message and exit.")
	fmt.Fprintln(os.Stderr, "  --version      Show version information and exit.")
	fmt.Fprintln(os.Stderr, "  --host         API server hostname (default: 127.0.0.1)")
	fmt.Fprintln(os.Stderr, "  --port         API server port (default: 6001)")
	fmt.Fprintln(os.Stderr, "  --external-url External URL for PDP discovery (e.g., https://pdp.example.com)")
	fmt.Fprintln(os.Stderr, "                 Can also be set via GO_TRUST_EXTERNAL_URL environment variable")
	fmt.Fprintln(os.Stderr, "  --frequency    Pipeline update frequency (default: 5m)")
	fmt.Fprintln(os.Stderr, "")
}

func main() {
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	host := flag.String("host", "127.0.0.1", "API server hostname")
	port := flag.String("port", "6001", "API server port")
	externalURL := flag.String("external-url", "", "External URL for PDP discovery (e.g., https://pdp.example.com)")
	freq := flag.Duration("frequency", 5*time.Minute, "Pipeline update frequency (e.g. 10s, 1m, 5m)")
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
	pl, err := pipeline.NewPipeline(pipelineFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load pipeline: %v\n", err)
		os.Exit(1)
	}

	serverCtx := api.NewServerContext(nil) // Creates ServerContext with default logger
	serverCtx.PipelineContext = &pipeline.Context{}

	// Initialize RegistryManager with ETSI TSL registry
	// TODO: Make resolution strategy configurable (currently defaults to FirstMatch)
	registryMgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)

	// Create ETSI TSL registry backed by the pipeline context
	// The pipeline context provides GetCertPool(), GetTSLs(), GetTSLCount() methods
	// that the registry uses to access trust data updated by the background pipeline
	tslRegistry := etsi.NewPipelineBackedRegistry(serverCtx.PipelineContext, "ETSI-TSL")
	registryMgr.Register(tslRegistry)

	serverCtx.RegistryManager = registryMgr

	// Set BaseURL for .well-known discovery
	// Priority: 1) --external-url flag, 2) GO_TRUST_EXTERNAL_URL env var, 3) local host:port
	baseURL := *externalURL
	if baseURL == "" {
		baseURL = os.Getenv("GO_TRUST_EXTERNAL_URL")
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%s", *host, *port)
	}
	serverCtx.BaseURL = baseURL

	// Start background updater
	api.StartBackgroundUpdater(pl, serverCtx, *freq)

	// Gin API server
	r := gin.Default()

	// Register Swagger UI endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	api.RegisterAPIRoutes(r, serverCtx)
	listenAddr := fmt.Sprintf("%s:%s", *host, *port)
	fmt.Printf("API server listening on %s\n", listenAddr)
	fmt.Printf("Swagger UI available at http://%s/swagger/index.html\n", listenAddr)
	if err := r.Run(listenAddr); err != nil {
		fmt.Fprintf(os.Stderr, "API server error: %v\n", err)
		os.Exit(1)
	}
}
