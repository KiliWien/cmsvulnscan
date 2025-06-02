package ai

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/user/cmsvulnscan/lib/core"
)

// AIModule provides artificial intelligence capabilities for vulnerability detection
type AIModule struct {
	// Configuration
	config AIConfig

	// Pattern recognition
	patterns     map[string][]*regexp.Regexp
	patternsLock sync.RWMutex

	// False positive reduction
	fpRules     map[string][]FalsePositiveRule
	fpRulesLock sync.RWMutex

	// Contextual analysis
	contextRules     map[string][]ContextRule
	contextRulesLock sync.RWMutex
}

// AIConfig contains configuration for the AI module
type AIConfig struct {
	// Enable/disable AI features
	EnablePatternRecognition     bool
	EnableFalsePositiveReduction bool
	EnableContextualAnalysis     bool

	// Confidence thresholds
	MinConfidenceThreshold float64

	// Learning parameters
	LearningRate float64
}

// FalsePositiveRule defines a rule for reducing false positives
type FalsePositiveRule struct {
	ID          string
	Description string
	Condition   func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool
	Weight      float64
}

// ContextRule defines a rule for contextual analysis
type ContextRule struct {
	ID          string
	Description string
	Condition   func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool
	Impact      float64
}

// PatternMatch represents a pattern match result
type PatternMatch struct {
	PatternID   string
	Confidence  float64
	MatchedText string
	VulnType    string
	Severity    string
}

// NewAIModule creates a new AI module
func NewAIModule(config AIConfig) *AIModule {
	module := &AIModule{
		config:       config,
		patterns:     make(map[string][]*regexp.Regexp),
		fpRules:      make(map[string][]FalsePositiveRule),
		contextRules: make(map[string][]ContextRule),
	}

	// Initialize with default patterns and rules
	module.initializePatterns()
	module.initializeFalsePositiveRules()
	module.initializeContextRules()

	return module
}

// GetPatternCount returns the number of patterns
func (m *AIModule) GetPatternCount() int {
	m.patternsLock.RLock()
	defer m.patternsLock.RUnlock()

	count := 0
	for _, patterns := range m.patterns {
		count += len(patterns)
	}
	return count
}

// initializePatterns sets up default vulnerability detection patterns
func (m *AIModule) initializePatterns() {
	m.patternsLock.Lock()
	defer m.patternsLock.Unlock()

	// SQL Injection patterns
	m.patterns["sql_injection"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=\s*['"]`),
		regexp.MustCompile(`(?i)INSERT\s+INTO\s+.*\s+VALUES\s*\(`),
		regexp.MustCompile(`(?i)UPDATE\s+.*\s+SET\s+.*=`),
		regexp.MustCompile(`(?i)DELETE\s+FROM\s+.*\s+WHERE`),
		regexp.MustCompile(`(?i)UNION\s+SELECT`),
		regexp.MustCompile(`(?i)OR\s+1=1`),
		regexp.MustCompile(`(?i)AND\s+1=1`),
		regexp.MustCompile(`(?i)DROP\s+TABLE`),
	}

	// XSS patterns
	m.patterns["xss"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>[^<]*</script>`),
		regexp.MustCompile(`(?i)javascript:`),
		regexp.MustCompile(`(?i)onerror=`),
		regexp.MustCompile(`(?i)onload=`),
		regexp.MustCompile(`(?i)onclick=`),
		regexp.MustCompile(`(?i)onmouseover=`),
		regexp.MustCompile(`(?i)eval\(`),
		regexp.MustCompile(`(?i)document\.cookie`),
		regexp.MustCompile(`(?i)document\.write`),
	}

	// File inclusion patterns
	m.patterns["file_inclusion"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)include\s*\(`),
		regexp.MustCompile(`(?i)require\s*\(`),
		regexp.MustCompile(`(?i)include_once\s*\(`),
		regexp.MustCompile(`(?i)require_once\s*\(`),
		regexp.MustCompile(`(?i)file_get_contents\s*\(`),
		regexp.MustCompile(`(?i)readfile\s*\(`),
		regexp.MustCompile(`(?i)fopen\s*\(`),
		regexp.MustCompile(`(?i)\.\.\/`), // Path traversal
	}

	// Command injection patterns
	m.patterns["command_injection"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)system\s*\(`),
		regexp.MustCompile(`(?i)exec\s*\(`),
		regexp.MustCompile(`(?i)shell_exec\s*\(`),
		regexp.MustCompile(`(?i)passthru\s*\(`),
		regexp.MustCompile(`(?i)proc_open\s*\(`),
		regexp.MustCompile(`(?i)popen\s*\(`),
		regexp.MustCompile(`(?i)\|\s*sh`),
		regexp.MustCompile(`(?i);\s*sh`),
	}

	// Sensitive data exposure patterns
	m.patterns["sensitive_data"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)password\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)passwd\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)pwd\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)username\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)secret\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)api[_-]?key\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)access[_-]?token\s*=\s*['"][^'"]{3,}['"]`),
		regexp.MustCompile(`(?i)admin[_-]?password\s*=\s*['"][^'"]{3,}['"]`),
	}

	// Insecure configuration patterns
	m.patterns["insecure_config"] = []*regexp.Regexp{
		regexp.MustCompile(`(?i)debug\s*=\s*true`),
		regexp.MustCompile(`(?i)debug\s*=\s*1`),
		regexp.MustCompile(`(?i)display_errors\s*=\s*On`),
		regexp.MustCompile(`(?i)allow_url_include\s*=\s*On`),
		regexp.MustCompile(`(?i)expose_php\s*=\s*On`),
		regexp.MustCompile(`(?i)register_globals\s*=\s*On`),
		regexp.MustCompile(`(?i)allow_url_fopen\s*=\s*On`),
	}
}

// initializeFalsePositiveRules sets up default false positive reduction rules
func (m *AIModule) initializeFalsePositiveRules() {
	m.fpRulesLock.Lock()
	defer m.fpRulesLock.Unlock()

	// WordPress false positive rules
	m.fpRules["wordpress"] = []FalsePositiveRule{
		{
			ID:          "WP-FP-001",
			Description: "WordPress core files with known safe patterns",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				// Check if vulnerability is in WordPress core and matches known safe patterns
				return strings.Contains(vuln.ID, "WP-") &&
					strings.Contains(vuln.DetectionMethod, "Pattern recognition") &&
					strings.Contains(vuln.Title, "core")
			},
			Weight: 0.7,
		},
		{
			ID:          "WP-FP-002",
			Description: "WordPress admin area false positives",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				// Admin area often has legitimate SQL queries and JavaScript
				return strings.Contains(vuln.ID, "WP-") &&
					(vuln.Title == "SQL Injection" || vuln.Title == "XSS") &&
					strings.Contains(vuln.Description, "wp-admin")
			},
			Weight: 0.5,
		},
	}

	// Joomla false positive rules
	m.fpRules["joomla"] = []FalsePositiveRule{
		{
			ID:          "JLA-FP-001",
			Description: "Joomla administrator area false positives",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				return strings.Contains(vuln.ID, "JLA-") &&
					strings.Contains(vuln.Description, "administrator")
			},
			Weight: 0.6,
		},
	}

	// Drupal false positive rules
	m.fpRules["drupal"] = []FalsePositiveRule{
		{
			ID:          "DPL-FP-001",
			Description: "Drupal module installation false positives",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				return strings.Contains(vuln.ID, "DPL-") &&
					strings.Contains(vuln.Description, "module installation")
			},
			Weight: 0.5,
		},
	}

	// Wix false positive rules
	m.fpRules["wix"] = []FalsePositiveRule{
		{
			ID:          "WIX-FP-001",
			Description: "Wix editor code false positives",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				return strings.Contains(vuln.ID, "WIX-") &&
					strings.Contains(vuln.Description, "editor")
			},
			Weight: 0.4,
		},
	}

	// Generic false positive rules for all CMS
	m.fpRules["generic"] = []FalsePositiveRule{
		{
			ID:          "GEN-FP-001",
			Description: "Common JavaScript libraries false positives",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				return (vuln.Title == "XSS" || vuln.Title == "JavaScript Injection") &&
					(strings.Contains(vuln.Description, "jquery") ||
						strings.Contains(vuln.Description, "bootstrap") ||
						strings.Contains(vuln.Description, "angular") ||
						strings.Contains(vuln.Description, "react"))
			},
			Weight: 0.8,
		},
		{
			ID:          "GEN-FP-002",
			Description: "Documentation examples false positives",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint) bool {
				return strings.Contains(vuln.Description, "example") ||
					strings.Contains(vuln.Description, "documentation")
			},
			Weight: 0.7,
		},
	}
}

// initializeContextRules sets up default contextual analysis rules
func (m *AIModule) initializeContextRules() {
	m.contextRulesLock.Lock()
	defer m.contextRulesLock.Unlock()

	// WordPress contextual rules
	m.contextRules["wordpress"] = []ContextRule{
		{
			ID:          "WP-CTX-001",
			Description: "WordPress outdated plugins increase risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// Check if there are outdated plugins
				outdatedCount := 0
				for _, comp := range components {
					if comp.Type == "plugin" && strings.Contains(comp.Version, "outdated") {
						outdatedCount++
					}
				}
				return outdatedCount > 2 // If more than 2 outdated plugins
			},
			Impact: 0.2, // Increase confidence by 20%
		},
		{
			ID:          "WP-CTX-002",
			Description: "WordPress debug mode increases risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// Check if debug mode is enabled
				return fingerprint.AdditionalInfo != nil &&
					fingerprint.AdditionalInfo["debug_mode"] == true
			},
			Impact: 0.3, // Increase confidence by 30%
		},
	}

	// Joomla contextual rules
	m.contextRules["joomla"] = []ContextRule{
		{
			ID:          "JLA-CTX-001",
			Description: "Joomla outdated components increase risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// Check if there are outdated components
				outdatedCount := 0
				for _, comp := range components {
					if comp.Type == "component" && strings.Contains(comp.Version, "outdated") {
						outdatedCount++
					}
				}
				return outdatedCount > 1 // If more than 1 outdated component
			},
			Impact: 0.25, // Increase confidence by 25%
		},
	}

	// Drupal contextual rules
	m.contextRules["drupal"] = []ContextRule{
		{
			ID:          "DPL-CTX-001",
			Description: "Drupal outdated modules increase risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// Check if there are outdated modules
				outdatedCount := 0
				for _, comp := range components {
					if comp.Type == "module" && strings.Contains(comp.Version, "outdated") {
						outdatedCount++
					}
				}
				return outdatedCount > 2 // If more than 2 outdated modules
			},
			Impact: 0.2, // Increase confidence by 20%
		},
	}

	// Wix contextual rules
	m.contextRules["wix"] = []ContextRule{
		{
			ID:          "WIX-CTX-001",
			Description: "Wix custom code increases risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// Check if custom code is used
				for _, comp := range components {
					if comp.Name == "Wix Code" || comp.Name == "Wix Custom Elements" {
						return true
					}
				}
				return false
			},
			Impact: 0.15, // Increase confidence by 15%
		},
	}

	// Generic contextual rules for all CMS
	m.contextRules["generic"] = []ContextRule{
		{
			ID:          "GEN-CTX-001",
			Description: "Outdated CMS core increases risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// Check if CMS version is outdated (simplified check)
				return fingerprint.Version != "Unknown" &&
					strings.Contains(fingerprint.Version, "outdated")
			},
			Impact: 0.3, // Increase confidence by 30%
		},
		{
			ID:          "GEN-CTX-002",
			Description: "Multiple vulnerabilities increase overall risk",
			Condition: func(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
				// This would be checked against the full vulnerability list
				// For now, we'll use a placeholder condition
				return vuln.ID != ""
			},
			Impact: 0.1, // Increase confidence by 10%
		},
	}
}

// AddPattern adds a new pattern for vulnerability detection
func (m *AIModule) AddPattern(category string, pattern string) error {
	m.patternsLock.Lock()
	defer m.patternsLock.Unlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	if _, ok := m.patterns[category]; !ok {
		m.patterns[category] = []*regexp.Regexp{}
	}

	m.patterns[category] = append(m.patterns[category], re)
	return nil
}

// AddFalsePositiveRule adds a new false positive reduction rule
func (m *AIModule) AddFalsePositiveRule(cms string, rule FalsePositiveRule) {
	m.fpRulesLock.Lock()
	defer m.fpRulesLock.Unlock()

	if _, ok := m.fpRules[cms]; !ok {
		m.fpRules[cms] = []FalsePositiveRule{}
	}

	m.fpRules[cms] = append(m.fpRules[cms], rule)
}

// AddContextRule adds a new contextual analysis rule
func (m *AIModule) AddContextRule(cms string, rule ContextRule) {
	m.contextRulesLock.Lock()
	defer m.contextRulesLock.Unlock()

	if _, ok := m.contextRules[cms]; !ok {
		m.contextRules[cms] = []ContextRule{}
	}

	m.contextRules[cms] = append(m.contextRules[cms], rule)
}

// DetectVulnerabilities uses AI to detect potential vulnerabilities
func (m *AIModule) DetectVulnerabilities(content string, cms string) []*PatternMatch {
	if !m.config.EnablePatternRecognition {
		return []*PatternMatch{}
	}

	m.patternsLock.RLock()
	defer m.patternsLock.RUnlock()

	matches := []*PatternMatch{}

	// Check each pattern category
	for category, patterns := range m.patterns {
		for _, pattern := range patterns {
			// Find all matches
			found := pattern.FindAllString(content, -1)
			for _, match := range found {
				// Calculate confidence based on match characteristics
				confidence := m.calculateConfidence(match, category)

				// Only include matches above the confidence threshold
				if confidence >= m.config.MinConfidenceThreshold {
					// Determine vulnerability type and severity
					vulnType, severity := m.categorizeVulnerability(category, match)

					matches = append(matches, &PatternMatch{
						PatternID:   category,
						Confidence:  confidence,
						MatchedText: match,
						VulnType:    vulnType,
						Severity:    severity,
					})
				}
			}
		}
	}

	return matches
}

// calculateConfidence determines the confidence level for a pattern match
func (m *AIModule) calculateConfidence(match string, category string) float64 {
	// Base confidence
	confidence := 0.5

	// Adjust based on match length
	if len(match) > 50 {
		confidence += 0.1 // Longer matches may be more significant
	}

	// Adjust based on category
	switch category {
	case "sql_injection":
		// SQL injection patterns are often more reliable
		confidence += 0.2
	case "xss":
		// XSS patterns can have false positives
		confidence += 0.1
	case "file_inclusion":
		// File inclusion patterns are moderately reliable
		confidence += 0.15
	case "command_injection":
		// Command injection patterns are highly reliable
		confidence += 0.25
	case "sensitive_data":
		// Sensitive data patterns can have false positives
		confidence += 0.05
	case "insecure_config":
		// Insecure configuration patterns are moderately reliable
		confidence += 0.15
	}

	// Adjust for specific high-confidence indicators
	if strings.Contains(match, "UNION SELECT") || strings.Contains(match, "1=1") {
		confidence += 0.2 // Strong SQL injection indicators
	}
	if strings.Contains(match, "<script>alert") {
		confidence += 0.15 // Common XSS test pattern
	}

	return confidence
}

// categorizeVulnerability categorizes the vulnerability based on pattern match
func (m *AIModule) categorizeVulnerability(category string, match string) (string, string) {
	var vulnType, severity string

	// Basic categorization based on category and match content
	switch category {
	case "sql_injection":
		vulnType = "SQL Injection"
		severity = "High"
	case "xss":
		vulnType = "Cross-Site Scripting"
		severity = "Medium"
	case "file_inclusion":
		vulnType = "File Inclusion"
		severity = "High"
	case "command_injection":
		vulnType = "Command Injection"
		severity = "Critical"
	case "sensitive_data":
		vulnType = "Sensitive Data Exposure"
		severity = "High"
	case "insecure_config":
		vulnType = "Insecure Configuration"
		severity = "Medium"
	default:
		vulnType = "Unknown"
		severity = "Low"
	}

	// Further refinement based on specific match characteristics can be added here

	return vulnType, severity
}

// ScanURL scans a URL for vulnerabilities using the AI module
func (m *AIModule) ScanURL(url string, cms string) ([]*PatternMatch, error) {
	// Fetch the content from the URL
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read the response body
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Detect vulnerabilities in the fetched content
	matches := m.DetectVulnerabilities(string(content), cms)
	return matches, nil
}

// ConvertPatternMatchesToVulnerabilities converts pattern matches to Vulnerability objects
func (m *AIModule) ConvertPatternMatchesToVulnerabilities(matches []*PatternMatch, cmsName string) []*core.Vulnerability {
	var vulns []*core.Vulnerability
	for _, match := range matches {
		vulns = append(vulns, &core.Vulnerability{
			ID:              fmt.Sprintf("AI-%s-%s", cmsName, match.PatternID),
			Title:           fmt.Sprintf("Potential %s detected", match.VulnType),
			Description:     fmt.Sprintf("Pattern match: %s", match.MatchedText),
			Severity:        match.Severity,
			DetectedBy:      "AI Module",
			ConfidenceLevel: match.Confidence,
		})
	}
	return vulns
}

// AnalyzeResponse analyzes an HTTP response and returns pattern matches
func (m *AIModule) AnalyzeResponse(resp *http.Response, bodyContent string) []*PatternMatch {
	return m.DetectVulnerabilities(bodyContent, "")
}

// ReduceFalsePositives applies false positive reduction rules
func (m *AIModule) ReduceFalsePositives(vulns []*core.Vulnerability, fingerprint *core.CMSFingerprint) []*core.Vulnerability {
	// Stub: just return input for now
	return vulns
}

// ApplyContextualAnalysis applies contextual analysis rules
func (m *AIModule) ApplyContextualAnalysis(vulns []*core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) []*core.Vulnerability {
	// Stub: just return input for now
	return vulns
}

// DefaultAIConfig returns a default AIConfig
func DefaultAIConfig() AIConfig {
	return AIConfig{
		EnablePatternRecognition:     true,
		EnableFalsePositiveReduction: true,
		EnableContextualAnalysis:     true,
		MinConfidenceThreshold:       0.6,
		LearningRate:                 0.01,
	}
}

// Example usage
func Example() {
	// Create a new AI module with default config
	aiModule := NewAIModule(AIConfig{
		EnablePatternRecognition: true,
		MinConfidenceThreshold:   0.6,
		LearningRate:             0.01,
	})

	// Scan a URL (example.com) for vulnerabilities
	vulnerabilities, err := aiModule.ScanURL("http://example.com", "wordpress")
	if err != nil {
		fmt.Println("Error scanning URL:", err)
		return
	}

	// Print detected vulnerabilities
	for _, vuln := range vulnerabilities {
		fmt.Printf("Detected %s (Severity: %s) - %s\n", vuln.VulnType, vuln.Severity, vuln.MatchedText)
	}
}
