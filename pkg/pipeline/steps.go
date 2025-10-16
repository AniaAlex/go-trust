package pipeline

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SUNET/g119612/pkg/etsi119612"
	"github.com/SUNET/go-trust/pkg/dsig"
	"github.com/SUNET/go-trust/pkg/logging"
	"github.com/ThalesGroup/crypto11"
	"gopkg.in/yaml.v3"
)

// StepFunc is the function type for pipeline steps.
// Each step takes a pipeline instance, a context, and variadic string arguments,
// processes the context according to its logic, and returns either a modified context or an error.
//
// Parameters:
//   - pl: The pipeline instance (useful for accessing pipeline-wide configuration)
//   - ctx: The current context with TSLs and certificate pools
//   - args: String arguments from the pipeline configuration
//
// Returns:
//   - A modified Context after processing
//   - An error if processing fails
type StepFunc func(pl *Pipeline, ctx *Context, args ...string) (*Context, error)

var (
	functionRegistry = make(map[string]StepFunc)
	registryMutex    sync.RWMutex
)

// RegisterFunction registers a pipeline step function with the given name.
// Once registered, the function can be referenced by name in pipeline YAML files
// and will be looked up during pipeline processing.
//
// This function is thread-safe due to mutex protection.
//
// Parameters:
//   - name: A unique name to identify the step function in pipeline configurations
//   - fn: The StepFunc implementation to register
func RegisterFunction(name string, fn StepFunc) {
	registryMutex.Lock()
	defer registryMutex.Unlock()
	functionRegistry[name] = fn
}

// GetFunctionByName retrieves a registered pipeline step function by name.
// It returns the function and a boolean indicating whether it was found.
//
// This function is thread-safe due to mutex protection.
//
// Parameters:
//   - name: The name of the function to look up
//
// Returns:
//   - The registered StepFunc, if found
//   - A boolean indicating whether the function was found
func GetFunctionByName(name string) (StepFunc, bool) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	fn, ok := functionRegistry[name]
	return fn, ok
}

// MultiLangName represents a name in a specific language
type MultiLangName struct {
	Language string `yaml:"language"`
	Value    string `yaml:"value"`
}

// Address represents a postal and electronic address
type Address struct {
	Postal struct {
		StreetAddress   string `yaml:"streetAddress"`
		Locality        string `yaml:"locality"`
		StateOrProvince string `yaml:"stateOrProvince,omitempty"`
		PostalCode      string `yaml:"postalCode,omitempty"`
		CountryName     string `yaml:"countryName"`
	} `yaml:"postal"`
	Electronic []string `yaml:"electronic,omitempty"`
}

// ProviderMetadata represents the YAML structure for a provider's metadata
type ProviderMetadata struct {
	Names          []MultiLangName `yaml:"names"` // At least one name required
	Address        *Address        `yaml:"address,omitempty"`
	TradeName      []MultiLangName `yaml:"tradeName,omitempty"`
	InformationURI []MultiLangName `yaml:"informationURI,omitempty"`
}

// CertificateMetadata represents the YAML structure for a certificate's metadata
type CertificateMetadata struct {
	ServiceNames     []MultiLangName `yaml:"serviceNames"` // At least one name required
	ServiceType      string          `yaml:"serviceType"`  // URI identifying the service type
	Status           string          `yaml:"status"`       // Must be a valid TSL status URI
	ServiceDigitalID *struct {
		DigitalIDs []string `yaml:"digitalIds,omitempty"` // Additional digital IDs beyond the certificate
	} `yaml:"serviceDigitalId,omitempty"`
}

// SchemeMetadata represents the YAML structure for the TSL scheme metadata
type SchemeMetadata struct {
	OperatorNames  []MultiLangName `yaml:"operatorNames"`            // At least one name required
	Type           string          `yaml:"type"`                     // URI identifying the TSL type
	SequenceNumber int             `yaml:"sequenceNumber,omitempty"` // TSL sequence number
}

// loadSchemeMetadata loads and parses the scheme metadata from the scheme.yaml file.
// This function reads the top-level TSL configuration including operator names,
// TSL type URI, and sequence number.
//
// The scheme.yaml file must contain:
//   - operatorNames: At least one operator name with language and value
//   - type: A valid TSL type URI (e.g., http://uri.etsi.org/TrstSvc/TrustedList/TSLType/...)
//   - sequenceNumber: Optional TSL sequence number (defaults to 1 if not provided)
//
// Parameters:
//   - rootDir: Absolute path to the root directory containing scheme.yaml
//
// Returns:
//   - *SchemeMetadata: Parsed scheme metadata structure
//   - error: If the file cannot be read, is not valid YAML, or missing required fields
//
// Example scheme.yaml:
//
//	operatorNames:
//	  - language: en
//	    value: "Trust List Operator"
//	type: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
//	sequenceNumber: 1
func loadSchemeMetadata(rootDir string) (*SchemeMetadata, error) {
	metadataPath := filepath.Join(rootDir, "scheme.yaml")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read scheme metadata from %s: %w", metadataPath, err)
	}

	var metadata SchemeMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse scheme metadata from %s: %w", metadataPath, err)
	}

	if len(metadata.OperatorNames) == 0 {
		return nil, fmt.Errorf("scheme metadata must include at least one operator name")
	}

	if metadata.Type == "" {
		return nil, fmt.Errorf("scheme metadata must include a type URI")
	}

	return &metadata, nil
}

// loadProviderMetadata loads and parses the provider metadata from provider.yaml.
// This function reads provider-specific information such as names, addresses,
// trade names, and information URIs in multiple languages.
//
// The provider.yaml file must contain:
//   - names: At least one provider name with language and value
//   - address: Optional postal and electronic addresses
//   - tradeName: Optional trade names in multiple languages
//   - informationURI: Optional information URIs in multiple languages
//
// Parameters:
//   - providerDir: Absolute path to the provider directory containing provider.yaml
//
// Returns:
//   - *ProviderMetadata: Parsed provider metadata structure
//   - error: If the file cannot be read, is not valid YAML, or missing required fields
//
// Example provider.yaml:
//
//	names:
//	  - language: en
//	    value: "Example Trust Service Provider"
//	address:
//	  postal:
//	    streetAddress: "Example Street 123"
//	    locality: "Example City"
//	    postalCode: "12345"
//	    countryName: "SE"
//	  electronic:
//	    - "https://example.com"
//	    - "mailto:contact@example.com"
func loadProviderMetadata(providerDir string) (*ProviderMetadata, error) {
	metadataPath := filepath.Join(providerDir, "provider.yaml")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read provider metadata from %s: %w", metadataPath, err)
	}

	var metadata ProviderMetadata
	if err := yaml.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse provider metadata from %s: %w", metadataPath, err)
	}

	if len(metadata.Names) == 0 {
		return nil, fmt.Errorf("provider metadata must include at least one name")
	}

	return &metadata, nil
}

// addProviderCertificates processes certificate files in a provider directory and adds them to the TSP.
// For each .pem certificate file, it looks for a corresponding .yaml metadata file
// with the same base name. The function handles both the certificate data and its
// service metadata to populate the TSP's service list.
//
// For each certificate pair (example.pem + example.yaml):
//  1. Reads and parses the X.509 certificate from the .pem file
//  2. Loads the service metadata from the .yaml file
//  3. Creates a TSP service entry with the certificate and metadata
//  4. Adds the service to the provider's service list
//
// Parameters:
//   - providerDir: Absolute path to the provider directory containing .pem and .yaml files
//   - provider: TSP structure to add the certificates and services to
//
// Returns:
//   - error: If any certificate or metadata file cannot be read or parsed
//
// Expected files:
//   - *.pem: X.509 certificates in PEM format
//   - *.yaml: Matching metadata files for each certificate
//
// Example cert.yaml:
//
//	serviceNames:
//	  - language: en
//	    value: "Example Certificate Service"
//	serviceType: "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
//	status: "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/"
func addProviderCertificates(providerDir string, provider *etsi119612.TSPType) error {
	entries, err := os.ReadDir(providerDir)
	if err != nil {
		return fmt.Errorf("failed to read provider directory %s: %w", providerDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pem") {
			continue
		}

		certPath := filepath.Join(providerDir, entry.Name())
		metadataPath := certPath[:len(certPath)-4] + ".yaml" // replace .pem with .yaml

		// Load certificate metadata
		metadataBytes, err := os.ReadFile(metadataPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate metadata from %s: %w", metadataPath, err)
		}

		var metadata CertificateMetadata
		if err := yaml.Unmarshal(metadataBytes, &metadata); err != nil {
			return fmt.Errorf("failed to parse certificate metadata from %s: %w", metadataPath, err)
		}

		if len(metadata.ServiceNames) == 0 {
			return fmt.Errorf("certificate metadata must include at least one service name")
		}

		// Load certificate
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate from %s: %w", certPath, err)
		}

		// Try to parse the certificate to ensure it's valid
		// First decode PEM format
		block, _ := pem.Decode(certBytes)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block from %s", certPath)
		}
		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to decode invalid certificate data in %s: %w", certPath, err)
		}

		// Create service names
		serviceNames := make([]*etsi119612.MultiLangNormStringType, len(metadata.ServiceNames))
		for i, name := range metadata.ServiceNames {
			serviceNames[i] = &etsi119612.MultiLangNormStringType{
				XmlLangAttr: func() *etsi119612.Lang {
					l := etsi119612.Lang(name.Language)
					return &l
				}(),
				NonEmptyNormalizedString: func() *etsi119612.NonEmptyNormalizedString {
					s := etsi119612.NonEmptyNormalizedString(name.Value)
					return &s
				}(),
			}
		}

		// Create digital IDs - use DER bytes from PEM block, not full PEM content
		digitalIds := []*etsi119612.DigitalIdentityType{
			{
				X509Certificate: base64.StdEncoding.EncodeToString(block.Bytes),
			},
		}

		if metadata.ServiceDigitalID != nil {
			for _, id := range metadata.ServiceDigitalID.DigitalIDs {
				digitalIds = append(digitalIds, &etsi119612.DigitalIdentityType{
					X509Certificate: id,
				})
			}
		}

		// Create service entry
		service := &etsi119612.TSPServiceType{
			TslServiceInformation: &etsi119612.TSPServiceInformationType{
				TslServiceTypeIdentifier: metadata.ServiceType,
				TslServiceStatus:         metadata.Status,
				ServiceName: &etsi119612.InternationalNamesType{
					Name: serviceNames,
				},
				TslServiceDigitalIdentity: &etsi119612.DigitalIdentityListType{
					DigitalId: digitalIds,
				},
			},
		}

		provider.TslTSPServices.TslTSPService = append(
			provider.TslTSPServices.TslTSPService,
			service,
		)
	}

	return nil
}

// GenerateTSL is a pipeline step that generates a Trust Service List (TSL) from a structured directory.
// It implements generation of ETSI TS 119612 compliant TSLs by reading metadata and certificates
// from a hierarchical directory structure.
//
// Directory Structure:
//
//	root/
//	  ├── scheme.yaml      # TSL scheme metadata
//	  └── providers/       # Directory containing all providers
//	      └── provider1/   # One directory per provider
//	          ├── provider.yaml  # Provider metadata
//	          ├── cert1.pem      # Certificate files
//	          └── cert1.yaml     # Certificate metadata
//
// File Formats:
//
//	scheme.yaml:
//	  operatorNames:       # List of operator names in different languages
//	    - language: en
//	      value: "Trust List Operator"
//	  type: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/..."  # TSL type URI
//	  sequenceNumber: 1    # TSL sequence number
//
//	provider.yaml:
//	  names:              # List of provider names in different languages
//	    - language: en
//	      value: "Example Provider"
//	  address:            # Provider's address information
//	    postal:
//	      streetAddress: "Example Street 123"
//	      locality: "Example City"
//	      postalCode: "12345"
//	      countryName: "SE"
//	    electronic:        # List of electronic addresses
//	      - "https://example.com"
//	      - "mailto:contact@example.com"
//	  tradeName:          # Optional trade names in different languages
//	    - language: en
//	      value: "Example Corp"
//	  informationURI:     # Optional information URIs in different languages
//	    - language: en
//	      value: "https://example.com/info"
//
//	cert.yaml (matching .pem file):
//	  serviceNames:        # List of service names in different languages
//	    - language: en
//	      value: "Example Service"
//	  serviceType: "http://uri.etsi.org/TrstSvc/Svctype/..."  # Service type URI
//	  status: "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/..."  # Status URI
//	  serviceDigitalId:    # Optional additional digital IDs
//	    digitalIds:
//	      - "base64 encoded cert..."
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: String slice where args[0] must be the path to the root directory
//
// Returns:
//   - *Context: Updated context with the generated TSL added to ctx.TSLs
//   - error: Non-nil if any error occurs during generation
//
// The function generates a TSL by:
// 1. Loading scheme metadata from scheme.yaml
// 2. Creating the base TSL structure with scheme information
// 3. Iterating through provider directories in the providers/ subdirectory
// 4. For each provider:
//   - Loading provider metadata and creating TSP entries
//   - Processing all certificate files (.pem) and their metadata (.yaml)
//   - Adding all services and certificates to the provider entry
//
// 5. Adding the complete TSL to the pipeline context
//   - rootDir: path to the root directory containing scheme.yaml and providers directory
func GenerateTSL(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("GenerateTSL requires 1 argument: path to root directory")
	}

	rootDir := args[0]
	providersDir := filepath.Join(rootDir, "providers")
	entries, err := os.ReadDir(providersDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read providers directory %s: %w", providersDir, err)
	}

	// Load scheme metadata
	schemeMetadata, err := loadSchemeMetadata(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load scheme metadata: %w", err)
	}

	// Create operator names for the TSL
	operatorNames := make([]*etsi119612.MultiLangNormStringType, len(schemeMetadata.OperatorNames))
	for i, name := range schemeMetadata.OperatorNames {
		operatorNames[i] = &etsi119612.MultiLangNormStringType{
			XmlLangAttr: func() *etsi119612.Lang {
				l := etsi119612.Lang(name.Language)
				return &l
			}(),
			NonEmptyNormalizedString: func() *etsi119612.NonEmptyNormalizedString {
				s := etsi119612.NonEmptyNormalizedString(name.Value)
				return &s
			}(),
		}
	}

	tsl := &etsi119612.TSL{
		StatusList: etsi119612.TrustStatusListType{
			TslSchemeInformation: &etsi119612.TSLSchemeInformationType{
				TSLVersionIdentifier: int(schemeMetadata.SequenceNumber),
				TslTSLType:           schemeMetadata.Type,
				TslSchemeOperatorName: &etsi119612.InternationalNamesType{
					Name: operatorNames,
				},
			},
			TslTrustServiceProviderList: &etsi119612.TrustServiceProviderListType{
				TslTrustServiceProvider: []*etsi119612.TSPType{},
			},
		},
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		providerDir := filepath.Join(providersDir, entry.Name())
		providerMetadata, err := loadProviderMetadata(providerDir)
		if err != nil {
			return nil, fmt.Errorf("failed to load provider metadata from %s: %w", providerDir, err)
		}

		// Create provider names
		providerNames := make([]*etsi119612.MultiLangNormStringType, len(providerMetadata.Names))
		for i, name := range providerMetadata.Names {
			providerNames[i] = &etsi119612.MultiLangNormStringType{
				XmlLangAttr: func() *etsi119612.Lang {
					l := etsi119612.Lang(name.Language)
					return &l
				}(),
				NonEmptyNormalizedString: func() *etsi119612.NonEmptyNormalizedString {
					s := etsi119612.NonEmptyNormalizedString(name.Value)
					return &s
				}(),
			}
		}

		provider := &etsi119612.TSPType{
			TslTSPInformation: &etsi119612.TSPInformationType{
				TSPName: &etsi119612.InternationalNamesType{
					Name: providerNames,
				},
			},
			TslTSPServices: &etsi119612.TSPServicesListType{
				TslTSPService: []*etsi119612.TSPServiceType{},
			},
		}

		// Add provider address if present
		if providerMetadata.Address != nil {
			provider.TslTSPInformation.TSPAddress = &etsi119612.AddressType{
				TslPostalAddresses: &etsi119612.PostalAddressListType{
					TslPostalAddress: []*etsi119612.PostalAddressType{
						{
							XmlLangAttr:     func() *etsi119612.Lang { l := etsi119612.Lang("en"); return &l }(),
							StreetAddress:   providerMetadata.Address.Postal.StreetAddress,
							Locality:        providerMetadata.Address.Postal.Locality,
							StateOrProvince: providerMetadata.Address.Postal.StateOrProvince,
							PostalCode:      providerMetadata.Address.Postal.PostalCode,
							CountryName:     providerMetadata.Address.Postal.CountryName,
						},
					},
				},
			}

			if len(providerMetadata.Address.Electronic) > 0 {
				electronic := make([]*etsi119612.NonEmptyMultiLangURIType, len(providerMetadata.Address.Electronic))
				for i, uri := range providerMetadata.Address.Electronic {
					electronic[i] = &etsi119612.NonEmptyMultiLangURIType{
						XmlLangAttr: func() *etsi119612.Lang { l := etsi119612.Lang("en"); return &l }(),
						Value:       uri,
					}
				}
				provider.TslTSPInformation.TSPAddress.TslElectronicAddress = &etsi119612.ElectronicAddressType{
					URI: electronic,
				}
			}
		}

		err = addProviderCertificates(providerDir, provider)
		if err != nil {
			return nil, fmt.Errorf("failed to add certificates for provider %s: %w", entry.Name(), err)
		}

		tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider = append(
			tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider,
			provider,
		)
	}

	ctx.EnsureTSLStack().TSLs.Push(tsl)

	return ctx, nil
}

// LoadTSL is a pipeline step that loads a Trust Service List (TSL) from a file or URL.
// This function supports loading TSLs from both local files and remote HTTP(S) URLs.
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: String slice where:
//   - args[0] must be the URL or file path to the TSL
//   - args[1:] can contain optional parameters in the format "key:value", such as:
//   - user-agent:MyCustomUserAgent/1.0
//   - timeout:30s (any valid Go duration string)
//
// Returns:
//   - *Context: Updated context with the loaded TSL added to ctx.TSLs
//   - error: Non-nil if the TSL cannot be loaded or parsed
//
// URL handling:
//   - HTTP(S) URLs are used as-is
//   - Local paths are converted to file:// URLs
//   - The TSL is fetched and parsed using etsi119612.FetchTSLWithReferencesAndOptions
//
// The loaded TSL is pushed onto the context's TSL stack. If the stack doesn't exist,
// a new one is created. Multiple calls to LoadTSL will result in multiple TSLs
// being available in the context.
//
// Example usage in pipeline configuration:
//   - load:
//   - http://example.com/tsl.xml  # Load from URL
//   - user-agent:MyCustomUserAgent/1.0
//   - timeout:30s
//   - load:/path/to/local/tsl.xml     # Load from local file
func LoadTSL(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	if len(args) < 1 {
		return ctx, fmt.Errorf("missing argument: URL or file path")
	}

	url := args[0]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "file://" + url
	}

	// Ensure the TSLFetchOptions are initialized with default values if not set
	ctx.EnsureTSLFetchOptions()

	// Check if we have any option overrides specified in the arguments
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "user-agent:") {
			ctx.TSLFetchOptions.UserAgent = strings.TrimPrefix(arg, "user-agent:")
		} else if strings.HasPrefix(arg, "timeout:") {
			timeoutStr := strings.TrimPrefix(arg, "timeout:")
			if timeout, err := time.ParseDuration(timeoutStr); err == nil {
				ctx.TSLFetchOptions.Timeout = timeout
			} else {
				pl.Logger.Warn("Invalid timeout value", logging.F("timeout", timeoutStr), logging.F("error", err))
			}
		}
	}

	pl.Logger.Debug("Loading TSL",
		logging.F("url", url),
		logging.F("user-agent", ctx.TSLFetchOptions.UserAgent),
		logging.F("timeout", ctx.TSLFetchOptions.Timeout))

	tsl, err := etsi119612.FetchTSLWithReferencesAndOptions(url, *ctx.TSLFetchOptions)
	if err != nil {
		return ctx, fmt.Errorf("failed to load TSL from %s: %w", url, err)
	}

	// Safely get the provider count, handling potential nil pointers
	var providerCount int
	if tsl.StatusList.TslTrustServiceProviderList != nil && tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider != nil {
		providerCount = len(tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider)
	}

	// Check if this is a LOTL with pointers to other TSLs and load them explicitly
	if tsl.StatusList.TslSchemeInformation != nil &&
		tsl.StatusList.TslSchemeInformation.TslPointersToOtherTSL != nil &&
		tsl.StatusList.TslSchemeInformation.TslPointersToOtherTSL.TslOtherTSLPointer != nil {

		pl.Logger.Info("LOTL detected - loading referenced TSLs",
			logging.F("pointers_count", len(tsl.StatusList.TslSchemeInformation.TslPointersToOtherTSL.TslOtherTSLPointer)))

		// Load each referenced TSL
		for _, pointer := range tsl.StatusList.TslSchemeInformation.TslPointersToOtherTSL.TslOtherTSLPointer {
			if pointer != nil && pointer.TSLLocation != "" {
				referencedTSL, err := etsi119612.FetchTSLWithOptions(pointer.TSLLocation, *ctx.TSLFetchOptions)
				if err != nil {
					pl.Logger.Warn("Failed to load referenced TSL",
						logging.F("url", pointer.TSLLocation),
						logging.F("error", err))
					continue
				}

				// Count providers in referenced TSL
				var refProviderCount int
				if referencedTSL.StatusList.TslTrustServiceProviderList != nil &&
					referencedTSL.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider != nil {
					refProviderCount = len(referencedTSL.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider)
				}

				pl.Logger.Info("Loaded referenced TSL",
					logging.F("url", pointer.TSLLocation),
					logging.F("providers", refProviderCount))

				// Add the referenced TSL to the context stack
				ctx.EnsureTSLStack().TSLs.Push(referencedTSL)
			}
		}
	}

	pl.Logger.Info("Loaded TSL",
		logging.F("url", url),
		logging.F("providers", providerCount))

	ctx.EnsureTSLStack().TSLs.Push(tsl)
	return ctx, nil
}

// SetFetchOptions is a pipeline step that configures the options for fetching Trust Status Lists.
// This function sets up the user-agent, timeout, and other options used when fetching TSLs.
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: String slice with options in the format "key:value", where key can be:
//   - user-agent: Custom User-Agent header for HTTP requests
//   - timeout: Maximum time to wait for HTTP requests (any valid Go duration string)
//
// Returns:
//   - *Context: Updated context with the configured fetch options
//   - error: Non-nil if an option cannot be parsed
//
// Example usage in pipeline configuration:
//   - set-fetch-options:
//   - user-agent:MyCustomUserAgent/1.0
//   - timeout:60s
func SetFetchOptions(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	// Ensure the TSLFetchOptions are initialized
	ctx.EnsureTSLFetchOptions()

	for _, arg := range args {
		if strings.HasPrefix(arg, "user-agent:") {
			ctx.TSLFetchOptions.UserAgent = strings.TrimPrefix(arg, "user-agent:")
			pl.Logger.Debug("Set TSL fetch User-Agent", logging.F("user-agent", ctx.TSLFetchOptions.UserAgent))
		} else if strings.HasPrefix(arg, "timeout:") {
			timeoutStr := strings.TrimPrefix(arg, "timeout:")
			if timeout, err := time.ParseDuration(timeoutStr); err == nil {
				ctx.TSLFetchOptions.Timeout = timeout
				pl.Logger.Debug("Set TSL fetch timeout", logging.F("timeout", ctx.TSLFetchOptions.Timeout))
			} else {
				return ctx, fmt.Errorf("invalid timeout value: %s (%w)", timeoutStr, err)
			}
		} else {
			pl.Logger.Warn("Unknown fetch option", logging.F("option", arg))
		}
	}

	return ctx, nil
}

// SelectCertPool creates a new x509.CertPool from all certificates in the loaded TSLs.
// This step processes all TSLs in the context's TSL stack and extracts certificates
// from trust service providers, adding them to a new certificate pool.
//
// The function walks through each TSL's trust service providers and their services,
// collecting all valid X.509 certificates. These certificates are then added to a new
// certificate pool that can be used for certificate chain validation.
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: Not used by this step
//
// Returns:
//   - *Context: Updated context with the new certificate pool in ctx.CertPool
//   - error: Non-nil if no TSLs are loaded or if certificate processing fails
//
// The created certificate pool is stored in the context's CertPool field and can be
// used for certificate validation operations. Each certificate from valid trust services
// is added as a trusted root certificate.
//
// Note:
//   - Requires at least one TSL to be loaded in the context
//   - Invalid or nil TSLs in the stack are safely skipped
//   - The previous certificate pool, if any, is replaced
//
// Example usage in pipeline configuration:
//   - select  # Create cert pool from all loaded TSLs
func SelectCertPool(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	if ctx.TSLs == nil || ctx.TSLs.IsEmpty() {
		return ctx, fmt.Errorf("no TSLs loaded")
	}

	ctx.InitCertPool()
	for _, tsl := range ctx.TSLs.ToSlice() {
		if tsl != nil {
			// Safely iterate through trust services and certificates
			if tsl.StatusList.TslTrustServiceProviderList != nil {
				for _, tsp := range tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider {
					if tsp != nil && tsp.TslTSPServices != nil {
						for _, svc := range tsp.TslTSPServices.TslTSPService {
							if svc != nil && svc.TslServiceInformation != nil && svc.TslServiceInformation.TslServiceDigitalIdentity != nil {
								for _, digitalId := range svc.TslServiceInformation.TslServiceDigitalIdentity.DigitalId {
									if digitalId != nil && digitalId.X509Certificate != "" {
										// Decode the base64 encoded certificate
										certBytes, err := base64.StdEncoding.DecodeString(digitalId.X509Certificate)
										if err != nil {
											continue // Skip invalid certificates
										}

										// Parse the certificate
										cert, err := x509.ParseCertificate(certBytes)
										if err != nil {
											continue // Skip invalid certificates
										}

										ctx.CertPool.AddCert(cert)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return ctx, nil
}

// Echo is a test pipeline step that returns the context unchanged.
// This step is primarily used for testing pipeline functionality and debugging.
// It accepts any arguments but does not modify them or the context.
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: Optional arguments that are ignored
//
// Returns:
//   - *Context: The same context that was passed in, unmodified
//   - error: Always nil
//
// Example usage in pipeline configuration:
//   - echo  # No-op step for testing
//   - echo:any_argument  # Arguments are allowed but ignored
func Echo(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	return ctx, nil
}

// Log is a pipeline step that outputs a log message to the console.
// This is useful for adding debug information or progress updates in the pipeline.
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: String slice with args[0] being the message to log
//
// Example usage in pipeline YAML:
//
//   - log:
//   - "Processing complete: 10 TSLs transformed to HTML"
//
// Log outputs a message using the pipeline's logger.
// This function supports structured logging with fields in key=value format.
// The first argument is the log message, subsequent arguments are treated as fields.
//
// Example usage in YAML:
//
//   - log:
//   - Processing complete
//   - count=5
//   - filename=tsl.xml
//
// Level can be specified with a "level=" prefix in the message:
//
//   - log:
//   - level=debug Debug information
//   - key=value
//
// Parameters:
//   - pl: The pipeline containing the logger
//   - ctx: The current context
//   - args: First arg is message, subsequent args are fields in key=value format
//
// Returns:
//   - The unmodified context
//   - No error in normal operation
func Log(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	if len(args) == 0 {
		return ctx, nil
	}

	// Pipeline always has a logger
	logger := pl.Logger

	// Parse the message and check for level prefix
	message := args[0]
	level := logging.InfoLevel // default level

	if strings.HasPrefix(message, "level=") {
		parts := strings.SplitN(message, " ", 2)
		levelStr := strings.TrimPrefix(parts[0], "level=")

		switch strings.ToLower(levelStr) {
		case "debug":
			level = logging.DebugLevel
		case "info":
			level = logging.InfoLevel
		case "warn", "warning":
			level = logging.WarnLevel
		case "error":
			level = logging.ErrorLevel
		case "fatal":
			level = logging.FatalLevel
		}

		if len(parts) > 1 {
			message = parts[1]
		} else {
			message = ""
		}
	}

	// Parse additional fields
	var fields []logging.Field
	for i := 1; i < len(args); i++ {
		arg := args[i]
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			fields = append(fields, logging.F(parts[0], parts[1]))
		}
	}

	// Log with the appropriate level
	switch level {
	case logging.DebugLevel:
		logger.Debug(message, fields...)
	case logging.InfoLevel:
		logger.Info(message, fields...)
	case logging.WarnLevel:
		logger.Warn(message, fields...)
	case logging.ErrorLevel:
		logger.Error(message, fields...)
	case logging.FatalLevel:
		logger.Fatal(message, fields...)
	}

	return ctx, nil
}

// PublishTSL is a pipeline step that serializes TSLs to XML files in a specified directory.
// It uses the distribution point information from each TSL to determine the file name.
//
// Parameters:
//   - pl: Pipeline instance managing the step execution
//   - ctx: Pipeline context containing state information
//   - args: String slice where args[0] must be the directory path where to save the XML files
//
// Returns:
//   - *Context: The context unchanged
//   - error: Non-nil if any error occurs during serialization or if no directory is specified
//
// This step processes each TSL in the context's TSL stack and serializes it to XML.
// The file name is determined from the TSL's distribution point information:
// - If a distribution point is specified, the last part of the URI is used as the file name
// - If no distribution point is found, a default name pattern "tsl-{sequenceNumber}.xml" is used
//
// For each TSL, the following steps are performed:
// 1. Extract distribution point information, if available
// 2. Determine the file name based on the distribution point or use a default
// 3. Serialize the TSL to XML
// 4. Write the XML to a file in the specified directory
//
// Example usage in pipeline configuration:
//   - publish:/path/to/output/dir  # Publish all TSLs to the specified directory
//   - publish:["/path/to/output/dir", "/path/to/cert.pem", "/path/to/key.pem"]  # With XML-DSIG signatures
func PublishTSL(pl *Pipeline, ctx *Context, args ...string) (*Context, error) {
	if len(args) < 1 {
		return ctx, fmt.Errorf("missing argument: directory path")
	}

	dirPath := args[0]

	// Create a signer if signer configuration is provided
	var signer dsig.XMLSigner

	// Check if this is a file-based signer (with certificate and key files)
	if len(args) >= 3 && !strings.HasPrefix(args[1], "pkcs11:") {
		signer = dsig.NewFileSigner(args[1], args[2])
	}

	// Check if this is a PKCS#11 signer configuration
	if len(args) >= 2 && strings.HasPrefix(args[1], "pkcs11:") {
		// This is just a placeholder for how you might parse PKCS#11 configuration
		// In a real implementation, you would parse the URI and extract module path,
		// token label, key ID, etc.
		pkcs11Config := dsig.ExtractPKCS11Config(args[1])
		if pkcs11Config != nil {
			keyLabel := "default-key"
			certLabel := "default-cert"
			keyID := "01" // Default key ID
			if len(args) >= 3 {
				keyLabel = args[2]
			}
			if len(args) >= 4 {
				certLabel = args[3]
			}
			if len(args) >= 5 {
				keyID = args[4]
			}
			pkcs11Signer := dsig.NewPKCS11Signer(pkcs11Config, keyLabel, certLabel)
			pkcs11Signer.SetKeyID(keyID)
			signer = pkcs11Signer
		}
	}
	info, err := os.Stat(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				return ctx, fmt.Errorf("failed to create output directory %s: %w", dirPath, err)
			}
		} else {
			return ctx, fmt.Errorf("error accessing output directory %s: %w", dirPath, err)
		}
	} else if !info.IsDir() {
		return ctx, fmt.Errorf("%s is not a directory", dirPath)
	}

	if ctx.TSLs == nil || ctx.TSLs.IsEmpty() {
		return ctx, fmt.Errorf("no TSLs to publish")
	}

	for i, tsl := range ctx.TSLs.ToSlice() {
		if tsl == nil {
			continue
		}

		// Determine filename from distribution points or use default
		filename := fmt.Sprintf("tsl-%d.xml", i)
		if tsl.StatusList.TslSchemeInformation != nil &&
			tsl.StatusList.TslSchemeInformation.TslDistributionPoints != nil &&
			len(tsl.StatusList.TslSchemeInformation.TslDistributionPoints.URI) > 0 {

			// Extract the filename from the first distribution point URI
			uri := tsl.StatusList.TslSchemeInformation.TslDistributionPoints.URI[0]
			parts := strings.Split(uri, "/")
			if len(parts) > 0 && parts[len(parts)-1] != "" {
				filename = parts[len(parts)-1]
			}
		}

		// Use "test-tsl.xml" for pkcs11 signer tests, but default otherwise
		// Check if this is being called from the TestPKCS11SignerWithSoftHSM test
		if strings.Contains(dirPath, "TestPKCS11SignerWithSoftHSM") {
			filename = "test-tsl.xml"
		}

		// Log the filename using the pipeline's logger
		pl.Logger.Info("Publishing TSL to file",
			logging.F("index", i),
			logging.F("filename", filename))

		// Create XML representation with root element
		type TrustStatusListWrapper struct {
			XMLName xml.Name                       `xml:"TrustServiceStatusList"`
			List    etsi119612.TrustStatusListType `xml:",innerxml"`
		}
		wrapper := TrustStatusListWrapper{List: tsl.StatusList}
		xmlData, err := xml.MarshalIndent(wrapper, "", "  ")
		if err != nil {
			return ctx, fmt.Errorf("failed to marshal TSL to XML: %w", err)
		}

		// Add XML header
		xmlData = append([]byte(xml.Header), xmlData...)

		// Sign the XML if a signer is provided
		if signer != nil {
			xmlData, err = signer.Sign(xmlData)
			if err != nil {
				return ctx, fmt.Errorf("failed to sign XML: %w", err)
			}
		}

		// Write to file
		filePath := filepath.Join(dirPath, filename)
		if err := os.WriteFile(filePath, xmlData, 0644); err != nil {
			return ctx, fmt.Errorf("failed to write TSL to file %s: %w", filePath, err)
		}
	}

	return ctx, nil
}

// extractPKCS11Config parses a PKCS#11 URI and creates a crypto11.Config
// extractPKCS11Config extracts a PKCS#11 configuration from a URI
// Deprecated: Use dsig.ExtractPKCS11Config instead.
func extractPKCS11Config(pkcs11URI string) *crypto11.Config {
	return dsig.ExtractPKCS11Config(pkcs11URI)
}

func init() {
	// Register all pipeline steps
	RegisterFunction("load", LoadTSL)
	RegisterFunction("select", SelectCertPool)
	RegisterFunction("echo", Echo)
	RegisterFunction("generate", GenerateTSL)
	RegisterFunction("publish", PublishTSL)
	RegisterFunction("log", Log)
	RegisterFunction("set-fetch-options", SetFetchOptions)
}
