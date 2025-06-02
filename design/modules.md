# Module Structure and Interfaces

This document defines the module structure and interfaces for the CMS Vulnerability Scanner, ensuring clean separation of concerns and extensibility.

## Core Interfaces

### Scanner Interface

```go
// Scanner represents the main scanning interface
type Scanner interface {
    // Scan initiates a vulnerability scan on the target URL
    Scan(targetURL string, options ScanOptions) (*ScanResult, error)
    
    // GetSupportedCMS returns a list of supported CMS platforms
    GetSupportedCMS() []string
    
    // RegisterCMSPlugin registers a new CMS plugin with the scanner
    RegisterCMSPlugin(plugin CMSPlugin) error
}

// ScanOptions contains configuration for a scan
type ScanOptions struct {
    Depth           int           // Scanning depth (1-5)
    Threads         int           // Number of concurrent threads
    Timeout         time.Duration // Request timeout
    FollowRedirects bool          // Whether to follow redirects
    UserAgent       string        // Custom user agent
    Cookies         []*http.Cookie // Custom cookies
    Headers         map[string]string // Custom headers
    ProxyURL        string        // Proxy URL if needed
    DisableAI       bool          // Disable AI-enhanced detection
    OutputFormat    string        // Report output format
}

// ScanResult contains the results of a scan
type ScanResult struct {
    Target          string
    DetectedCMS     string
    CMSVersion      string
    ScanStartTime   time.Time
    ScanEndTime     time.Time
    Vulnerabilities []*Vulnerability
    Components      []*Component
    RawData         map[string]interface{} // Additional data
}
```

### CMS Plugin Interface

```go
// CMSPlugin represents a CMS-specific scanning plugin
type CMSPlugin interface {
    // GetName returns the name of the CMS
    GetName() string
    
    // Detect determines if the target is running this CMS
    Detect(targetURL string) (bool, error)
    
    // Fingerprint identifies the version and components
    Fingerprint(targetURL string) (*CMSFingerprint, error)
    
    // EnumerateComponents lists installed components
    EnumerateComponents(targetURL string) ([]*Component, error)
    
    // ScanVulnerabilities performs CMS-specific vulnerability checks
    ScanVulnerabilities(targetURL string, fingerprint *CMSFingerprint) ([]*Vulnerability, error)
}

// CMSFingerprint contains identification information about a CMS installation
type CMSFingerprint struct {
    CMSName         string
    Version         string
    VersionConfidence float64 // 0.0-1.0 confidence in version detection
    Components      []*Component
    Headers         map[string]string
    Cookies         []*http.Cookie
    ServerInfo      string
    AdditionalInfo  map[string]interface{}
}

// Component represents a CMS component (plugin, theme, module)
type Component struct {
    Name            string
    Type            string // "plugin", "theme", "module", etc.
    Version         string
    Location        string // URL path
    Active          bool
    Vulnerabilities []*Vulnerability
}
```

### Vulnerability Detector Interface

```go
// VulnerabilityDetector identifies vulnerabilities
type VulnerabilityDetector interface {
    // Detect checks for vulnerabilities
    Detect(target string, fingerprint *CMSFingerprint) ([]*Vulnerability, error)
    
    // GetName returns the detector name
    GetName() string
    
    // GetDescription returns the detector description
    GetDescription() string
}

// Vulnerability represents a detected security issue
type Vulnerability struct {
    ID              string
    Title           string
    Description     string
    Severity        Severity // Critical, High, Medium, Low, Info
    CVSS            float64  // CVSS score if available
    CVE             string   // CVE identifier if available
    DetectedBy      string   // Detector that found this
    AffectedComponent *Component // Related component
    References      []string // URLs to references
    ExploitAvailable bool    // Whether an exploit is available
    ExploitDetails  *Exploit // Details of the exploit if available
    Remediation     string   // Suggested fix
    ConfidenceLevel float64  // 0.0-1.0 confidence in detection
    DetectionMethod string   // How it was detected
    RawData         map[string]interface{} // Additional data
}

// Severity represents vulnerability severity levels
type Severity int

const (
    SeverityInfo Severity = iota
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)
```

### Exploit Database Interface

```go
// ExploitDatabase provides access to exploit information
type ExploitDatabase interface {
    // GetExploitByCVE retrieves exploit by CVE ID
    GetExploitByCVE(cve string) ([]*Exploit, error)
    
    // GetExploitByComponent finds exploits for a component
    GetExploitByComponent(cmsName, componentName, version string) ([]*Exploit, error)
    
    // UpdateDatabase refreshes the exploit database
    UpdateDatabase() error
    
    // AddExploit adds a new exploit to the database
    AddExploit(exploit *Exploit) error
    
    // GetExploitCount returns the number of exploits in the database
    GetExploitCount() (int, error)
}

// Exploit represents an exploit for a vulnerability
type Exploit struct {
    ID              string
    Title           string
    Description     string
    CVE             string
    ExploitDB_ID    string
    Author          string
    DatePublished   time.Time
    AffectedVersions string
    Type            string // RCE, SQLi, XSS, etc.
    Code            string // Actual exploit code or PoC
    URL             string // URL to the exploit
    Requirements    string // Requirements to run the exploit
    Reliability     float64 // 0.0-1.0 reliability rating
}
```

### Reporter Interface

```go
// Reporter generates reports from scan results
type Reporter interface {
    // Generate creates a report from scan results
    Generate(result *ScanResult, format string) ([]byte, error)
    
    // GetSupportedFormats returns available report formats
    GetSupportedFormats() []string
}
```

### AI Module Interface

```go
// AIEnhancer provides AI capabilities to the scanner
type AIEnhancer interface {
    // AnalyzeResponse examines HTTP responses for anomalies
    AnalyzeResponse(response *http.Response) ([]Anomaly, error)
    
    // EvaluateVulnerability assesses a potential vulnerability
    EvaluateVulnerability(vuln *Vulnerability, context map[string]interface{}) (*VulnerabilityAssessment, error)
    
    // SuggestExploits recommends exploits for a vulnerability
    SuggestExploits(vuln *Vulnerability) ([]*Exploit, error)
    
    // OptimizeScan suggests scan optimizations
    OptimizeScan(target string, partialResults *ScanResult) (*ScanOptimization, error)
}

// Anomaly represents an AI-detected anomaly
type Anomaly struct {
    Type            string
    Description     string
    Confidence      float64
    RelatedData     map[string]interface{}
    PotentialIssue  string
}

// VulnerabilityAssessment contains AI evaluation of a vulnerability
type VulnerabilityAssessment struct {
    IsVulnerable    bool
    Confidence      float64
    FalsePositiveRisk float64
    SuggestedSeverity Severity
    Reasoning       string
    AdditionalChecks []string
}

// ScanOptimization contains AI suggestions for scan improvement
type ScanOptimization struct {
    SuggestedPaths  []string
    FocusAreas      []string
    DepthAdjustments map[string]int
    Reasoning       string
}
```

## Implementation Guidelines

1. **Error Handling**:
   - All methods should return meaningful errors
   - Errors should be wrapped with context
   - Critical errors should be logged centrally

2. **Concurrency**:
   - Use Go's concurrency primitives (goroutines, channels)
   - Implement rate limiting for outgoing requests
   - Use context for cancellation and timeouts

3. **Configuration**:
   - Use environment variables for global settings
   - Support configuration files (YAML/JSON)
   - Allow command-line overrides

4. **Testing**:
   - Write unit tests for all interfaces
   - Create mock implementations for testing
   - Include integration tests for end-to-end validation

5. **Documentation**:
   - Document all interfaces with examples
   - Include usage patterns for each module
   - Provide extension guides for new plugins

## Directory Structure

```
cmd/
  cmsvulnscan/           # Main CLI application
lib/
  core/                  # Core engine implementation
  scanner/               # Scanner implementation
  detector/              # Vulnerability detectors
  exploit/               # Exploit database
  reporter/              # Report generators
  ai/                    # AI enhancement module
plugins/
  cms/
    wordpress/           # WordPress plugin
    joomla/              # Joomla plugin
    drupal/              # Drupal plugin
    wix/                 # Wix plugin
    shopify/             # Shopify plugin
  detector/              # Custom detectors
  reporter/              # Custom reporters
data/
  exploits/              # Exploit database files
  fingerprints/          # CMS fingerprint data
  ai/                    # AI models and data
docs/                    # Documentation
tests/                   # Test suite
```

This module structure provides a clean separation of concerns while maintaining extensibility through well-defined interfaces. Each component can be developed, tested, and maintained independently, allowing for easier collaboration and future expansion.
