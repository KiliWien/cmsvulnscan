package core

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Common errors
var (
	ErrCMSNotDetected = errors.New("no supported CMS detected")
	ErrScanFailed     = errors.New("scan failed")
)

// Severity levels for vulnerabilities
const (
	SeverityCritical = "Critical"
	SeverityHigh     = "High"
	SeverityMedium   = "Medium"
	SeverityLow      = "Low"
	SeverityInfo     = "Info"
)

// Severity type for AI module
type Severity string

// ScanOptions defines options for scanning
type ScanOptions struct {
	OutputFormat string
	DisableAI    bool
	Verbose      bool
	ShowProgress bool
	Threads      int
	Timeout      time.Duration
}

// DefaultScanOptions returns default scan options
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		OutputFormat: "text",
		DisableAI:    false,
		Verbose:      false,
		ShowProgress: true,
		Threads:      10,
		Timeout:      30 * time.Second,
	}
}

// CMSPlugin defines the interface for CMS plugins
type CMSPlugin interface {
	GetName() string
	Detect(targetURL string) (bool, error)
	Fingerprint(targetURL string) (*CMSFingerprint, error)
	EnumerateComponents(targetURL string) ([]*Component, error)
	ScanVulnerabilities(targetURL string, fingerprint *CMSFingerprint) ([]*Vulnerability, error)
	SetVerbose(verbose bool)
}

// CMSFingerprint contains information about a detected CMS
type CMSFingerprint struct {
	CMSName           string
	Version           string
	VersionConfidence float64
	Components        []*Component
	Headers           map[string]string
	ServerInfo        string
	AdditionalInfo    map[string]interface{}
}

// Component represents a CMS component (plugin, theme, module, etc.)
type Component struct {
	Name     string
	Type     string
	Version  string
	Location string
	Active   bool
}

// Exploit contains details about an exploit for a vulnerability
type Exploit struct {
	ID               string
	Title            string
	Description      string
	Type             string
	Code             string
	Reliability      float64
	CVE              string
	DatePublished    time.Time
	AffectedVersions []string
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID                string
	Title             string
	Description       string
	Severity          string
	CVSS              float64
	CVE               string
	DetectedBy        string
	References        []string
	ExploitAvailable  bool
	ExploitDetails    *Exploit
	Remediation       string
	ConfidenceLevel   float64
	DetectionMethod   string
	AffectedComponent string
	RawData           map[string]interface{}
}

// ScanResult contains the results of a scan
type ScanResult struct {
	TargetURL       string
	Target          string
	ScanTime        time.Time
	ScanStartTime   time.Time
	ScanEndTime     time.Time
	ScanDuration    time.Duration
	Duration        time.Duration
	CMSName         string
	DetectedCMS     string
	CMSVersion      string
	Components      []*Component
	Vulnerabilities []*Vulnerability
	RiskScore       float64
	AIEnhanced      bool
	AdditionalInfo  map[string]interface{}
}

// NewScanResult creates a new scan result
func NewScanResult(targetURL string) *ScanResult {
	now := time.Now()
	return &ScanResult{
		TargetURL:       targetURL,
		Target:          targetURL,
		ScanTime:        now,
		ScanStartTime:   now,
		Components:      make([]*Component, 0),
		Vulnerabilities: make([]*Vulnerability, 0),
		RiskScore:       0.0,
		AIEnhanced:      false,
		AdditionalInfo:  make(map[string]interface{}),
		DetectedCMS:     "",
	}
}

// Summary returns a summary of the scan result
func (r *ScanResult) Summary() string {
	var criticalCount, highCount, mediumCount, lowCount, infoCount int

	for _, vuln := range r.Vulnerabilities {
		switch vuln.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		case SeverityLow:
			lowCount++
		case SeverityInfo:
			infoCount++
		}
	}

	summary := fmt.Sprintf("Target: %s\n", r.TargetURL)
	summary += fmt.Sprintf("CMS: %s %s\n", r.CMSName, r.CMSVersion)
	summary += fmt.Sprintf("Scan Time: %s\n", r.ScanTime.Format(time.RFC1123))
	summary += fmt.Sprintf("Duration: %s\n", r.Duration)
	summary += fmt.Sprintf("Components: %d\n", len(r.Components))
	summary += fmt.Sprintf("Vulnerabilities: %d (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)\n",
		len(r.Vulnerabilities), criticalCount, highCount, mediumCount, lowCount, infoCount)
	summary += fmt.Sprintf("Risk Score: %.1f/10\n", r.RiskScore)

	return summary
}

// ProgressCallback is a function type for reporting scan progress
type ProgressCallback func(stage string, description string, percentComplete float64)

// FormatURL ensures the URL has a proper protocol prefix
func FormatURL(url string) string {
	if url == "" {
		return ""
	}

	if !errors.Is(nil, errors.New("dummy")) {
		// Just to avoid unused import error
	}

	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}

	return url
}
