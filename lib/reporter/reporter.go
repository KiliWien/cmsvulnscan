package reporter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/user/cmsvulnscan/lib/core"
)

// Reporter generates reports from scan results
type Reporter struct {
	formats  map[string]ReportFormatter
	useColor bool
}

// ReportFormatter defines the interface for report formatters
type ReportFormatter interface {
	Format(result *core.ScanResult) ([]byte, error)
}

// NewReporter creates a new reporter instance
func NewReporter(useColor bool) *Reporter {
	r := &Reporter{
		formats:  make(map[string]ReportFormatter),
		useColor: useColor,
	}

	// Register default formatters
	r.RegisterFormatter("text", &TextFormatter{})
	r.RegisterFormatter("json", &JSONFormatter{})

	return r
}

// RegisterFormatter registers a new report formatter
func (r *Reporter) RegisterFormatter(name string, formatter ReportFormatter) {
	r.formats[strings.ToLower(name)] = formatter
}

// Generate creates a report from scan results
func (r *Reporter) Generate(result *core.ScanResult, format string) ([]byte, error) {
	format = strings.ToLower(format)
	formatter, ok := r.formats[format]
	if !ok {
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}

	return formatter.Format(result)
}

// GetSupportedFormats returns available report formats
func (r *Reporter) GetSupportedFormats() []string {
	formats := make([]string, 0, len(r.formats))
	for format := range r.formats {
		formats = append(formats, format)
	}
	return formats
}

// TextFormatter formats scan results as plain text
type TextFormatter struct{}

// Format formats the scan result as plain text
func (f *TextFormatter) Format(result *core.ScanResult) ([]byte, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("=======================================================\n")
	sb.WriteString("               CMS VULNERABILITY SCAN REPORT           \n")
	sb.WriteString("=======================================================\n\n")

	// Summary
	sb.WriteString("SCAN SUMMARY\n")
	sb.WriteString("-------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Target:         %s\n", result.TargetURL))
	sb.WriteString(fmt.Sprintf("CMS:            %s %s\n", result.CMSName, result.CMSVersion))
	sb.WriteString(fmt.Sprintf("Scan Started:   %s\n", result.ScanTime.Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("Scan Completed: %s\n", result.ScanTime.Add(result.Duration).Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("Duration:       %s\n", result.Duration))
	sb.WriteString("\n")

	// Vulnerability summary
	var criticalCount, highCount, mediumCount, lowCount, infoCount int
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case core.SeverityCritical:
			criticalCount++
		case core.SeverityHigh:
			highCount++
		case core.SeverityMedium:
			mediumCount++
		case core.SeverityLow:
			lowCount++
		case core.SeverityInfo:
			infoCount++
		}
	}

	sb.WriteString("VULNERABILITY SUMMARY\n")
	sb.WriteString("-------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n", len(result.Vulnerabilities)))
	sb.WriteString(fmt.Sprintf("  Critical: %d\n", criticalCount))
	sb.WriteString(fmt.Sprintf("  High:     %d\n", highCount))
	sb.WriteString(fmt.Sprintf("  Medium:   %d\n", mediumCount))
	sb.WriteString(fmt.Sprintf("  Low:      %d\n", lowCount))
	sb.WriteString(fmt.Sprintf("  Info:     %d\n", infoCount))
	sb.WriteString("\n")

	// Components
	sb.WriteString("DETECTED COMPONENTS\n")
	sb.WriteString("-------------------------------------------------------\n")
	if len(result.Components) > 0 {
		for _, comp := range result.Components {
			sb.WriteString(fmt.Sprintf("- %s: %s (Version: %s)\n", comp.Type, comp.Name, comp.Version))
			sb.WriteString(fmt.Sprintf("  Location: %s\n", comp.Location))
			sb.WriteString(fmt.Sprintf("  Active: %t\n", comp.Active))
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("No components detected.\n\n")
	}

	// Vulnerabilities
	sb.WriteString("VULNERABILITIES\n")
	sb.WriteString("-------------------------------------------------------\n")
	if len(result.Vulnerabilities) > 0 {
		for i, vuln := range result.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, vuln.Title))
			sb.WriteString(fmt.Sprintf("    Severity: %s", vuln.Severity))
			if vuln.CVSS > 0 {
				sb.WriteString(fmt.Sprintf(" (CVSS: %.1f)", vuln.CVSS))
			}
			sb.WriteString("\n")

			if vuln.CVE != "" {
				sb.WriteString(fmt.Sprintf("    CVE: %s\n", vuln.CVE))
			}

			sb.WriteString(fmt.Sprintf("    Description: %s\n", vuln.Description))

			if vuln.AffectedComponent != "" {
				sb.WriteString(fmt.Sprintf("    Affected Component: %s\n", vuln.AffectedComponent))
			}

			if vuln.ExploitAvailable {
				sb.WriteString("    Exploit Available: Yes\n")
				if vuln.ExploitDetails != nil {
					sb.WriteString(fmt.Sprintf("    Exploit: %s\n", vuln.ExploitDetails.Title))
				}
			}

			if len(vuln.References) > 0 {
				sb.WriteString("    References:\n")
				for _, ref := range vuln.References {
					sb.WriteString(fmt.Sprintf("      - %s\n", ref))
				}
			}

			if vuln.Remediation != "" {
				sb.WriteString(fmt.Sprintf("    Remediation: %s\n", vuln.Remediation))
			}

			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("No vulnerabilities detected.\n\n")
	}

	// Footer
	sb.WriteString("=======================================================\n")
	sb.WriteString("                  END OF REPORT                        \n")
	sb.WriteString("=======================================================\n")

	return []byte(sb.String()), nil
}

// JSONFormatter formats scan results as JSON
type JSONFormatter struct{}

// Format formats the scan result as JSON
func (f *JSONFormatter) Format(result *core.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
