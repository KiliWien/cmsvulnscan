package scanner

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/user/cmsvulnscan/lib/ai"
	"github.com/user/cmsvulnscan/lib/core"
	"github.com/user/cmsvulnscan/lib/database"
)

// DefaultProgressCallback is the default implementation of progress reporting
func DefaultProgressCallback(phase string, message string, percentComplete float64) {
	// Create colored phase indicator
	var phaseColored string
	switch phase {
	case "INIT":
		phaseColored = color.New(color.FgBlue, color.Bold).Sprintf("[%s]", phase)
	case "DETECT":
		phaseColored = color.New(color.FgCyan, color.Bold).Sprintf("[%s]", phase)
	case "FINGERPRINT":
		phaseColored = color.New(color.FgMagenta, color.Bold).Sprintf("[%s]", phase)
	case "COMPONENTS":
		phaseColored = color.New(color.FgYellow, color.Bold).Sprintf("[%s]", phase)
	case "VULNSCAN":
		phaseColored = color.New(color.FgRed, color.Bold).Sprintf("[%s]", phase)
	case "DATABASE":
		phaseColored = color.New(color.FgGreen, color.Bold).Sprintf("[%s]", phase)
	case "AI":
		phaseColored = color.New(color.FgHiMagenta, color.Bold).Sprintf("[%s]", phase)
	default:
		phaseColored = color.New(color.FgWhite, color.Bold).Sprintf("[%s]", phase)
	}

	// Create progress bar
	width := 30
	completed := int(percentComplete / 100 * float64(width))
	bar := strings.Repeat("█", completed) + strings.Repeat("░", width-completed)

	// Color the progress bar based on completion
	var barColored string
	if percentComplete < 33 {
		barColored = color.New(color.FgRed).Sprint(bar)
	} else if percentComplete < 66 {
		barColored = color.New(color.FgYellow).Sprint(bar)
	} else {
		barColored = color.New(color.FgGreen).Sprint(bar)
	}

	// Format and print the progress line
	fmt.Printf("\r%s %s %s %.1f%%",
		phaseColored,
		barColored,
		message,
		percentComplete)

	// Add a newline if we're at 100%
	if percentComplete >= 100 {
		fmt.Println()
	}
}

// ProgressCallback defines a function type for progress updates
type ProgressCallback func(phase string, message string, percentComplete float64)

// DefaultScanner implements the core.Scanner interface
type DefaultScanner struct {
	plugins          map[string]core.CMSPlugin
	pluginsLock      sync.RWMutex
	client           *http.Client
	db               *database.VulnerabilityDatabase
	aiModule         *ai.AIModule
	progressCallback ProgressCallback
	verbose          bool
	logger           *log.Logger
}

// NewScanner creates a new scanner instance
func NewScanner() *DefaultScanner {
	return &DefaultScanner{
		plugins: make(map[string]core.CMSPlugin),
		client:  &http.Client{Timeout: 30 * time.Second},
		verbose: false,
		logger:  log.New(os.Stdout, "[SCANNER] ", log.LstdFlags),
	}
}

// RegisterCMSPlugin registers a CMS plugin with the scanner
func (s *DefaultScanner) RegisterCMSPlugin(plugin core.CMSPlugin) error {
	s.pluginsLock.Lock()
	defer s.pluginsLock.Unlock()

	name := plugin.GetName()
	if _, exists := s.plugins[name]; exists {
		return fmt.Errorf("plugin for %s already registered", name)
	}

	s.plugins[name] = plugin

	// Set verbose mode on the plugin if scanner is in verbose mode
	if s.verbose {
		plugin.SetVerbose(true)
		s.logVerbose("Registered plugin for %s with verbose mode", name)
	} else {
		s.logVerbose("Registered plugin for %s", name)
	}

	return nil
}

// SetVulnerabilityDatabase sets the vulnerability database
func (s *DefaultScanner) SetVulnerabilityDatabase(db *database.VulnerabilityDatabase) {
	s.db = db
	if s.verbose {
		s.logVerbose("Database set with %d vulnerabilities", db.GetVulnerabilityCount())
	}
}

// SetAIModule sets the AI module
func (s *DefaultScanner) SetAIModule(aiModule *ai.AIModule) {
	s.aiModule = aiModule
	if s.verbose {
		s.logVerbose("AI module initialized with %d detection patterns", aiModule.GetPatternCount())
	}
}

// SetProgressCallback sets the callback function for progress updates
func (s *DefaultScanner) SetProgressCallback(callback ProgressCallback) {
	s.progressCallback = callback
	if s.verbose {
		s.logVerbose("Progress callback registered")
	}
}

// SetVerbose sets the verbose output mode
func (s *DefaultScanner) SetVerbose(verbose bool) {
	s.verbose = verbose

	// Also set verbose mode on all registered plugins
	s.pluginsLock.RLock()
	defer s.pluginsLock.RUnlock()

	for _, plugin := range s.plugins {
		plugin.SetVerbose(verbose)
	}

	if verbose {
		s.logVerbose("Verbose mode enabled")
	}
}

// logVerbose logs a message if verbose mode is enabled
func (s *DefaultScanner) logVerbose(format string, args ...interface{}) {
	if s.verbose {
		message := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("15:04:05.000")

		// Use different colors for different types of messages
		if strings.Contains(strings.ToLower(message), "error") {
			color.New(color.FgRed).Printf("[%s] %s\n", timestamp, message)
		} else if strings.Contains(strings.ToLower(message), "warning") {
			color.New(color.FgYellow).Printf("[%s] %s\n", timestamp, message)
		} else if strings.Contains(strings.ToLower(message), "success") ||
			strings.Contains(strings.ToLower(message), "found") ||
			strings.Contains(strings.ToLower(message), "detected") {
			color.New(color.FgGreen).Printf("[%s] %s\n", timestamp, message)
		} else if strings.Contains(strings.ToLower(message), "request") ||
			strings.Contains(strings.ToLower(message), "http") {
			color.New(color.FgCyan).Printf("[%s] %s\n", timestamp, message)
		} else {
			color.New(color.FgWhite).Printf("[%s] %s\n", timestamp, message)
		}
	}
}

// reportProgress sends a progress update through the callback if available
func (s *DefaultScanner) reportProgress(phase string, message string, percentComplete float64) {
	if s.progressCallback != nil {
		s.progressCallback(phase, message, percentComplete)
	}

	if s.verbose {
		timestamp := time.Now().Format("15:04:05")
		fmt.Printf("[%s] [%s] %s (%.1f%%)\n", timestamp, phase, message, percentComplete)
	}
}

// Scan initiates a vulnerability scan on the target URL
func (s *DefaultScanner) Scan(targetURL string, options core.ScanOptions) (*core.ScanResult, error) {
	// Format and validate URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	if targetURL == "" {
		return nil, fmt.Errorf("invalid target URL")
	}

	// Initialize scan result
	result := core.NewScanResult(targetURL)

	// Configure HTTP client based on options
	s.client.Timeout = options.Timeout

	// Set verbose mode from options
	s.SetVerbose(options.Verbose)

	if s.verbose {
		s.logVerbose("Starting scan of %s with options: threads=%d, timeout=%s, ai=%v",
			targetURL, options.Threads, options.Timeout, !options.DisableAI)
	}

	// Report initial progress
	s.reportProgress("INIT", "Starting scan of "+targetURL, 0.0)

	// Detect CMS
	s.reportProgress("DETECT", "Detecting CMS type...", 5.0)

	if s.verbose {
		s.logVerbose("Sending initial HTTP request to %s", targetURL)
		startTime := time.Now()
		resp, err := s.client.Get(targetURL)
		if err != nil {
			s.logVerbose("Error in initial request: %v", err)
		} else {
			defer resp.Body.Close()
			s.logVerbose("Initial response: status=%s, size=%d bytes, time=%s",
				resp.Status, resp.ContentLength, time.Since(startTime))

			// Log headers in verbose mode
			s.logVerbose("Response headers:")
			for name, values := range resp.Header {
				s.logVerbose("  %s: %s", name, values[0])
			}
		}
	}

	detectedCMS, err := s.detectCMS(targetURL)
	if err != nil {
		if s.verbose {
			s.logVerbose("CMS detection failed: %v", err)
		}
		return nil, fmt.Errorf("CMS detection failed: %w", err)
	}

	if detectedCMS == nil {
		if s.verbose {
			s.logVerbose("No supported CMS detected on target")
		}
		return nil, core.ErrCMSNotDetected
	}

	// Set detected CMS in result
	result.CMSName = detectedCMS.GetName()
	s.reportProgress("DETECT", fmt.Sprintf("Detected CMS: %s", result.CMSName), 15.0)

	if s.verbose {
		s.logVerbose("Successfully detected %s on target", result.CMSName)
	}

	// Fingerprint CMS
	s.reportProgress("FINGERPRINT", fmt.Sprintf("Fingerprinting %s installation...", result.CMSName), 20.0)

	if s.verbose {
		s.logVerbose("Starting fingerprinting process for %s", result.CMSName)
		s.logVerbose("Checking version indicators, file paths, and metadata")
	}

	fingerprint, err := detectedCMS.Fingerprint(targetURL)
	if err != nil {
		if s.verbose {
			s.logVerbose("Fingerprinting failed: %v", err)
		}
		return nil, fmt.Errorf("CMS fingerprinting failed: %w", err)
	}

	// Set CMS version in result
	result.CMSVersion = fingerprint.Version
	s.reportProgress("FINGERPRINT", fmt.Sprintf("Identified version: %s", result.CMSVersion), 30.0)

	if s.verbose {
		s.logVerbose("Fingerprinting complete: version=%s, confidence=%.2f",
			fingerprint.Version, fingerprint.VersionConfidence)

		if fingerprint.ServerInfo != "" {
			s.logVerbose("Server information: %s", fingerprint.ServerInfo)
		}

		// Log additional fingerprint info
		for key, value := range fingerprint.AdditionalInfo {
			s.logVerbose("Additional info - %s: %v", key, value)
		}
	}

	// Enumerate components
	s.reportProgress("COMPONENTS", "Enumerating components (plugins, themes, modules)...", 35.0)

	if s.verbose {
		s.logVerbose("Starting component enumeration for %s %s",
			result.CMSName, result.CMSVersion)
		s.logVerbose("Checking for plugins, themes, and modules")
	}

	components, err := detectedCMS.EnumerateComponents(targetURL)
	if err != nil {
		if s.verbose {
			s.logVerbose("Component enumeration failed: %v", err)
		}
		return nil, fmt.Errorf("component enumeration failed: %w", err)
	}

	// Add components to result
	result.Components = components
	s.reportProgress("COMPONENTS", fmt.Sprintf("Found %d components", len(components)), 45.0)

	if s.verbose {
		// Categorize components by type
		pluginCount := 0
		themeCount := 0
		moduleCount := 0
		otherCount := 0

		for _, comp := range components {
			switch strings.ToLower(comp.Type) {
			case "plugin":
				pluginCount++
			case "theme":
				themeCount++
			case "module":
				moduleCount++
			default:
				otherCount++
			}
		}

		s.logVerbose("Component summary: %d plugins, %d themes, %d modules, %d other",
			pluginCount, themeCount, moduleCount, otherCount)
	}

	// Scan for vulnerabilities using the CMS plugin
	s.reportProgress("VULNSCAN", fmt.Sprintf("Scanning for %s-specific vulnerabilities...", result.CMSName), 50.0)

	if s.verbose {
		s.logVerbose("Starting CMS-specific vulnerability scan")
		s.logVerbose("Checking for known %s vulnerabilities", result.CMSName)
	}

	vulnerabilities, err := detectedCMS.ScanVulnerabilities(targetURL, fingerprint)
	if err != nil {
		if s.verbose {
			s.logVerbose("Vulnerability scanning failed: %v", err)
		}
		return nil, fmt.Errorf("vulnerability scanning failed: %w", err)
	}

	// Add vulnerabilities to result
	vulnCount := 0
	for _, vulnerability := range vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerability)
		vulnCount++

		if s.verbose {
			s.logVerbose("Found vulnerability: %s (severity: %s, CVE: %s)",
				vulnerability.Title, vulnerability.Severity, vulnerability.CVE)
		}
	}
	s.reportProgress("VULNSCAN", fmt.Sprintf("Found %d CMS-specific vulnerabilities", vulnCount), 60.0)

	if s.verbose && vulnCount > 0 {
		s.logVerbose("CMS-specific vulnerability scan complete, found %d issues", vulnCount)
	} else if s.verbose {
		s.logVerbose("CMS-specific vulnerability scan complete, no issues found")
	}

	// If database is available, check for additional vulnerabilities
	if s.db != nil {
		s.reportProgress("DATABASE", "Checking vulnerability database...", 65.0)

		if s.verbose {
			s.logVerbose("Querying vulnerability database for %s", result.CMSName)
		}

		dbVulnerabilities := s.db.GetVulnerabilitiesByCMS(result.CMSName)

		if s.verbose {
			s.logVerbose("Retrieved %d potential vulnerabilities from database",
				len(dbVulnerabilities))
			s.logVerbose("Starting parallel vulnerability analysis with %d workers", options.Threads)
		}

		// Use a worker pool for parallel vulnerability checking
		var wg sync.WaitGroup
		vulnChan := make(chan *core.Vulnerability, 10)
		resultChan := make(chan *core.Vulnerability, 10)

		// Start worker goroutines
		workerCount := options.Threads // Use thread count from options
		for i := 0; i < workerCount; i++ {
			wg.Add(1)
			go func(workerId int) {
				defer wg.Done()

				if s.verbose {
					s.logVerbose("Worker %d started", workerId)
				}

				vulnProcessed := 0
				for vuln := range vulnChan {
					// Check if vulnerability applies to this version
					if s.vulnerabilityApplies(vuln, fingerprint, components) {
						// Check if exploit is available
						if vuln.ExploitAvailable && vuln.CVE != "" && vuln.ExploitDetails == nil {
							if s.verbose {
								s.logVerbose("Worker %d: Checking for exploit for CVE %s", workerId, vuln.CVE)
							}

							exploit := s.db.GetExploitByCVE(vuln.CVE)
							if len(exploit) > 0 {
								vuln.ExploitDetails = exploit[0]
								if s.verbose {
									s.logVerbose("Worker %d: Found exploit for CVE %s: %s", workerId, vuln.CVE, exploit[0].Title)
								}
							}
						}
						resultChan <- vuln

						if s.verbose {
							s.logVerbose("Worker %d: Vulnerability applies: %s (CVE: %s)",
								workerId, vuln.Title, vuln.CVE)
						}
					} else if s.verbose {
						s.logVerbose("Worker %d: Vulnerability doesn't apply: %s (CVE: %s)",
							workerId, vuln.Title, vuln.CVE)
					}

					vulnProcessed++
				}

				if s.verbose {
					s.logVerbose("Worker %d finished after processing %d vulnerabilities",
						workerId, vulnProcessed)
				}
			}(i)
		}

		// Start a goroutine to close the result channel when all workers are done
		go func() {
			wg.Wait()
			close(resultChan)

			if s.verbose {
				s.logVerbose("All vulnerability analysis workers completed")
			}
		}()

		// Feed vulnerabilities to workers
		go func() {
			if s.verbose {
				s.logVerbose("Distributing %d vulnerabilities to worker pool", len(dbVulnerabilities))
			}

			for _, vuln := range dbVulnerabilities {
				vulnChan <- vuln
			}
			close(vulnChan)

			if s.verbose {
				s.logVerbose("All vulnerabilities distributed to worker pool")
			}
		}()

		// Collect results
		dbVulnCount := 0
		for vuln := range resultChan {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			dbVulnCount++

			// Update progress periodically
			if dbVulnCount%10 == 0 {
				progress := 65.0 + (float64(dbVulnCount) / float64(len(dbVulnerabilities)) * 10.0)
				s.reportProgress("DATABASE", fmt.Sprintf("Processing vulnerabilities (%d/%d)...",
					dbVulnCount, len(dbVulnerabilities)), progress)
			}
		}

		s.reportProgress("DATABASE", fmt.Sprintf("Found %d additional vulnerabilities from database", dbVulnCount), 75.0)

		if s.verbose {
			s.logVerbose("Database vulnerability check complete, found %d applicable vulnerabilities", dbVulnCount)
		}
	}

	// If AI module is available and not disabled, use it for additional detection
	if s.aiModule != nil && !options.DisableAI {
		s.reportProgress("AI", "Running AI-powered vulnerability detection...", 80.0)

		if s.verbose {
			s.logVerbose("Starting AI-powered vulnerability detection")
			s.logVerbose("Fetching page content for AI analysis")
		}

		// Get page content for AI analysis
		aiStart := time.Now()
		resp, err := s.client.Get(targetURL)
		if err != nil {
			if s.verbose {
				s.logVerbose("Error fetching content for AI analysis: %v", err)
			}
		} else {
			defer resp.Body.Close()

			if s.verbose {
				s.logVerbose("Received response for AI analysis: status=%s, time=%s",
					resp.Status, time.Since(aiStart))
			}

			if resp.StatusCode == http.StatusOK {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					if s.verbose {
						s.logVerbose("Error reading response body: %v", err)
					}
				} else {
					bodyContent := string(bodyBytes)

					if s.verbose {
						s.logVerbose("Read %d bytes of content for AI analysis", len(bodyBytes))
						s.logVerbose("Starting pattern-based vulnerability detection")
					}

					s.reportProgress("AI", "Analyzing page content for patterns...", 85.0)
					// Use AI to detect potential vulnerabilities
					patternMatches := s.aiModule.DetectVulnerabilities(bodyContent, result.CMSName)

					if s.verbose {
						s.logVerbose("Pattern analysis found %d potential matches", len(patternMatches))
					}

					aiVulnerabilities := s.aiModule.ConvertPatternMatchesToVulnerabilities(patternMatches, result.CMSName)

					if s.verbose {
						s.logVerbose("Converted %d pattern matches to %d vulnerabilities",
							len(patternMatches), len(aiVulnerabilities))
						s.logVerbose("Starting HTTP response analysis")
					}

					s.reportProgress("AI", "Analyzing HTTP response...", 90.0)
					// Analyze HTTP response
					responseMatches := s.aiModule.AnalyzeResponse(resp, bodyContent)

					if s.verbose {
						s.logVerbose("HTTP response analysis found %d potential issues", len(responseMatches))
					}

					responseVulnerabilities := s.aiModule.ConvertPatternMatchesToVulnerabilities(responseMatches, result.CMSName)

					if s.verbose {
						s.logVerbose("Converted %d response issues to %d vulnerabilities",
							len(responseMatches), len(responseVulnerabilities))
					}

					// Combine all AI-detected vulnerabilities
					aiVulnerabilities = append(aiVulnerabilities, responseVulnerabilities...)

					if s.verbose {
						s.logVerbose("Combined AI detection found %d potential vulnerabilities", len(aiVulnerabilities))
						s.logVerbose("Starting false positive reduction")
					}

					s.reportProgress("AI", "Reducing false positives...", 92.0)
					// Reduce false positives
					beforeCount := len(aiVulnerabilities)
					aiVulnerabilities = s.aiModule.ReduceFalsePositives(aiVulnerabilities, fingerprint)

					if s.verbose {
						s.logVerbose("False positive reduction: %d → %d vulnerabilities (removed %d)",
							beforeCount, len(aiVulnerabilities), beforeCount-len(aiVulnerabilities))
						s.logVerbose("Starting contextual analysis")
					}

					s.reportProgress("AI", "Applying contextual analysis...", 95.0)
					// Apply contextual analysis
					aiVulnerabilities = s.aiModule.ApplyContextualAnalysis(aiVulnerabilities, fingerprint, components)

					if s.verbose {
						s.logVerbose("After contextual analysis: %d vulnerabilities", len(aiVulnerabilities))
					}

					// Add AI-detected vulnerabilities to result
					aiVulnCount := 0
					for _, vuln := range aiVulnerabilities {
						// Mark as AI-detected
						vuln.DetectedBy = "AI Module"
						result.Vulnerabilities = append(result.Vulnerabilities, vuln)
						aiVulnCount++

						if s.verbose {
							s.logVerbose("AI detected vulnerability: %s (severity: %s, confidence: %.2f)",
								vuln.Title, vuln.Severity, vuln.ConfidenceLevel)
						}
					}

					// Mark result as AI-enhanced
					result.AIEnhanced = true

					s.reportProgress("AI", fmt.Sprintf("AI detection found %d additional vulnerabilities", aiVulnCount), 98.0)

					if s.verbose {
						s.logVerbose("AI-powered vulnerability detection complete, found %d issues", aiVulnCount)
					}
				}
			} else if s.verbose {
				s.logVerbose("Failed to get page content for AI analysis, status: %s", resp.Status)
			}
		}
	}

	// Calculate risk score
	s.calculateRiskScore(result)

	// Set scan duration
	result.Duration = time.Since(result.ScanTime)

	s.reportProgress("COMPLETE", "Scan completed successfully", 100.0)

	if s.verbose {
		s.logVerbose("Scan completed in %s", result.Duration)
		s.logVerbose("Found %d vulnerabilities with overall risk score: %.1f/10",
			len(result.Vulnerabilities), result.RiskScore)
	}

	return result, nil
}

// detectCMS tries to detect which CMS the target is running
func (s *DefaultScanner) detectCMS(targetURL string) (core.CMSPlugin, error) {
	s.pluginsLock.RLock()
	defer s.pluginsLock.RUnlock()

	if len(s.plugins) == 0 {
		return nil, fmt.Errorf("no CMS plugins registered")
	}

	if s.verbose {
		s.logVerbose("Starting CMS detection with %d registered plugins", len(s.plugins))
	}

	// Try each plugin
	for name, plugin := range s.plugins {
		if s.verbose {
			s.logVerbose("Trying to detect %s...", name)
		}

		detected, err := plugin.Detect(targetURL)
		if err != nil {
			if s.verbose {
				s.logVerbose("Error during %s detection: %v", name, err)
			}
			continue
		}

		if detected {
			if s.verbose {
				s.logVerbose("Successfully detected %s", name)
			}
			return plugin, nil
		} else if s.verbose {
			s.logVerbose("%s not detected", name)
		}
	}

	if s.verbose {
		s.logVerbose("No supported CMS detected")
	}

	return nil, nil
}

// vulnerabilityApplies checks if a vulnerability applies to the target
func (s *DefaultScanner) vulnerabilityApplies(vuln *core.Vulnerability, fingerprint *core.CMSFingerprint, components []*core.Component) bool {
	// This is a simplified implementation
	// In a real-world scenario, this would involve version comparison, component checking, etc.
	return true
}

// calculateRiskScore calculates the overall risk score for the scan result
func (s *DefaultScanner) calculateRiskScore(result *core.ScanResult) {
	// Count vulnerabilities by severity
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

	// Calculate risk score (0-10)
	// This is a simplified formula - in a real implementation, this would be more sophisticated
	score := 0.0
	score += float64(criticalCount) * 2.0
	score += float64(highCount) * 1.0
	score += float64(mediumCount) * 0.5
	score += float64(lowCount) * 0.2
	score += float64(infoCount) * 0.1

	// Cap at 10
	if score > 10.0 {
		score = 10.0
	}

	result.RiskScore = score
}

// configureClient configures the HTTP client based on scan options
func (s *DefaultScanner) configureClient(options *core.ScanOptions) {
	s.client.Timeout = options.Timeout
}
