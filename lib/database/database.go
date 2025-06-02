package database

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/user/cmsvulnscan/lib/core"
)

// VulnerabilityDatabase manages the vulnerability database
type VulnerabilityDatabase struct {
	vulnerabilities map[string][]*core.Vulnerability // Map CMS name to vulnerabilities
	exploits        map[string]*core.Exploit         // Map exploit ID to exploit
	cveMap          map[string][]*core.Vulnerability // Map CVE to vulnerabilities
	componentMap    map[string][]*core.Vulnerability // Map component name to vulnerabilities
	mutex           sync.RWMutex
	lastUpdate      time.Time
	dbPath          string
}

// NewVulnerabilityDatabase creates a new vulnerability database
func NewVulnerabilityDatabase(dbPath string) (*VulnerabilityDatabase, error) {
	db := &VulnerabilityDatabase{
		vulnerabilities: make(map[string][]*core.Vulnerability),
		exploits:        make(map[string]*core.Exploit),
		cveMap:          make(map[string][]*core.Vulnerability),
		componentMap:    make(map[string][]*core.Vulnerability),
		dbPath:          dbPath,
	}

	// Create database directory if it doesn't exist
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Load existing database if available
	if err := db.Load(); err != nil {
		// If database doesn't exist, initialize it
		if os.IsNotExist(err) {
			if err := db.Initialize(); err != nil {
				return nil, fmt.Errorf("failed to initialize database: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load database: %w", err)
		}
	}

	return db, nil
}

// Initialize creates a new vulnerability database
func (db *VulnerabilityDatabase) Initialize() error {
	// Initialize with empty collections
	db.mutex.Lock()
	db.vulnerabilities = make(map[string][]*core.Vulnerability)
	db.exploits = make(map[string]*core.Exploit)
	db.cveMap = make(map[string][]*core.Vulnerability)
	db.componentMap = make(map[string][]*core.Vulnerability)
	db.lastUpdate = time.Now()
	db.mutex.Unlock()

	// Create CMS-specific directories
	cmsList := []string{"wordpress", "joomla", "drupal", "wix"}
	for _, cms := range cmsList {
		cmsPath := filepath.Join(db.dbPath, cms)
		if err := os.MkdirAll(cmsPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", cms, err)
		}
	}

	// Create exploits directory
	exploitsPath := filepath.Join(db.dbPath, "exploits")
	if err := os.MkdirAll(exploitsPath, 0755); err != nil {
		return fmt.Errorf("failed to create exploits directory: %w", err)
	}

	// Save after releasing the lock
	return db.Save()
}

// Load loads the vulnerability database from disk
func (db *VulnerabilityDatabase) Load() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Load metadata
	metadataPath := filepath.Join(db.dbPath, "metadata.json")
	metadataBytes, err := ioutil.ReadFile(metadataPath)
	if err != nil {
		return err
	}

	var metadata struct {
		LastUpdate time.Time `json:"last_update"`
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse metadata: %w", err)
	}
	db.lastUpdate = metadata.LastUpdate

	// Load vulnerabilities for each CMS
	cmsList := []string{"wordpress", "joomla", "drupal", "wix"}
	for _, cms := range cmsList {
		cmsPath := filepath.Join(db.dbPath, cms, "vulnerabilities.json")
		vulnBytes, err := ioutil.ReadFile(cmsPath)
		if err != nil {
			if os.IsNotExist(err) {
				// If file doesn't exist, initialize with empty slice
				db.vulnerabilities[cms] = []*core.Vulnerability{}
				continue
			}
			return fmt.Errorf("failed to read vulnerabilities for %s: %w", cms, err)
		}

		var vulns []*core.Vulnerability
		if err := json.Unmarshal(vulnBytes, &vulns); err != nil {
			return fmt.Errorf("failed to parse vulnerabilities for %s: %w", cms, err)
		}
		db.vulnerabilities[cms] = vulns

		// Build CVE and component maps
		for _, vuln := range vulns {
			if vuln.CVE != "" {
				db.cveMap[vuln.CVE] = append(db.cveMap[vuln.CVE], vuln)
			}
			// Use the AffectedComponent field (string) correctly
			if vuln.AffectedComponent != "" {
				compKey := fmt.Sprintf("%s:%s", cms, vuln.AffectedComponent)
				db.componentMap[compKey] = append(db.componentMap[compKey], vuln)
			}
		}
	}

	// Load exploits
	exploitsPath := filepath.Join(db.dbPath, "exploits", "exploits.json")
	exploitBytes, err := ioutil.ReadFile(exploitsPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If file doesn't exist, initialize with empty map
			db.exploits = make(map[string]*core.Exploit)
			return nil
		}
		return fmt.Errorf("failed to read exploits: %w", err)
	}

	var exploits map[string]*core.Exploit
	if err := json.Unmarshal(exploitBytes, &exploits); err != nil {
		return fmt.Errorf("failed to parse exploits: %w", err)
	}
	db.exploits = exploits

	return nil
}

// Save saves the vulnerability database to disk
func (db *VulnerabilityDatabase) Save() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Save metadata
	metadata := struct {
		LastUpdate time.Time `json:"last_update"`
	}{
		LastUpdate: db.lastUpdate,
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}
	metadataPath := filepath.Join(db.dbPath, "metadata.json")
	if err := ioutil.WriteFile(metadataPath, metadataBytes, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Save vulnerabilities for each CMS
	for cms, vulns := range db.vulnerabilities {
		vulnBytes, err := json.MarshalIndent(vulns, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to serialize vulnerabilities for %s: %w", cms, err)
		}
		cmsPath := filepath.Join(db.dbPath, cms, "vulnerabilities.json")
		if err := ioutil.WriteFile(cmsPath, vulnBytes, 0644); err != nil {
			return fmt.Errorf("failed to write vulnerabilities for %s: %w", cms, err)
		}
	}

	// Save exploits
	exploitBytes, err := json.MarshalIndent(db.exploits, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize exploits: %w", err)
	}
	exploitsPath := filepath.Join(db.dbPath, "exploits", "exploits.json")
	if err := ioutil.WriteFile(exploitsPath, exploitBytes, 0644); err != nil {
		return fmt.Errorf("failed to write exploits: %w", err)
	}
	return nil
}

// Update updates the vulnerability database from online sources
func (db *VulnerabilityDatabase) Update() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Update WordPress vulnerabilities
	if err := db.updateWordPressVulnerabilities(); err != nil {
		return fmt.Errorf("failed to update WordPress vulnerabilities: %w", err)
	}

	// Update Joomla vulnerabilities
	if err := db.updateJoomlaVulnerabilities(); err != nil {
		return fmt.Errorf("failed to update Joomla vulnerabilities: %w", err)
	}

	// Update Drupal vulnerabilities
	if err := db.updateDrupalVulnerabilities(); err != nil {
		return fmt.Errorf("failed to update Drupal vulnerabilities: %w", err)
	}

	// Update Wix vulnerabilities
	if err := db.updateWixVulnerabilities(); err != nil {
		return fmt.Errorf("failed to update Wix vulnerabilities: %w", err)
	}

	// Update exploits
	if err := db.updateExploits(); err != nil {
		return fmt.Errorf("failed to update exploits: %w", err)
	}

	// Update last update time
	db.lastUpdate = time.Now()

	// Save updated database
	return db.Save()
}

// updateWordPressVulnerabilities updates WordPress vulnerabilities from online sources
func (db *VulnerabilityDatabase) updateWordPressVulnerabilities() error {
	// In a real implementation, this would fetch from WPScan API or similar
	// For this implementation, we'll use a sample set of vulnerabilities

	// Sample WordPress vulnerabilities
	vulns := []*core.Vulnerability{
		{
			ID:                "WP-CVE-2022-21662",
			Title:             "WordPress < 5.8.3 - Stored XSS via Post Slugs",
			Description:       "WordPress before 5.8.3 allows stored XSS via post slugs.",
			Severity:          core.SeverityHigh,
			CVSS:              7.5,
			CVE:               "CVE-2022-21662",
			DetectedBy:        "WordPress Plugin",
			References:        []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21662"},
			ExploitAvailable:  true,
			Remediation:       "Update WordPress to version 5.8.3 or later.",
			ConfidenceLevel:   0.9,
			DetectionMethod:   "Version comparison",
			AffectedComponent: "WordPress Core",
		},
		{
			ID:                "WP-CVE-2021-34520",
			Title:             "WordPress < 5.7.2 - Object Injection in PHPMailer",
			Description:       "WordPress before 5.7.2 is affected by a PHPMailer object injection vulnerability.",
			Severity:          core.SeverityHigh,
			CVSS:              8.1,
			CVE:               "CVE-2021-34520",
			DetectedBy:        "WordPress Plugin",
			References:        []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34520"},
			ExploitAvailable:  true,
			Remediation:       "Update WordPress to version 5.7.2 or later.",
			ConfidenceLevel:   0.9,
			DetectionMethod:   "Version comparison",
			AffectedComponent: "WordPress Core",
		},
		// Add more WordPress vulnerabilities here
	}

	// Update database
	db.vulnerabilities["wordpress"] = vulns

	// Update CVE map
	for _, vuln := range vulns {
		if vuln.CVE != "" {
			db.cveMap[vuln.CVE] = append(db.cveMap[vuln.CVE], vuln)
		}
	}

	return nil
}

// updateJoomlaVulnerabilities updates Joomla vulnerabilities from online sources
func (db *VulnerabilityDatabase) updateJoomlaVulnerabilities() error {
	// In a real implementation, this would fetch from Joomla security advisories or similar
	// For this implementation, we'll use a sample set of vulnerabilities

	// Sample Joomla vulnerabilities
	vulns := []*core.Vulnerability{
		{
			ID:                "JLA-CVE-2021-23132",
			Title:             "Joomla! < 3.9.26 - Unauthenticated Arbitrary File Disclosure",
			Description:       "A vulnerability in Joomla! before 3.9.26 allows attackers to disclose arbitrary files via the Media Manager component.",
			Severity:          core.SeverityCritical,
			CVSS:              8.8,
			CVE:               "CVE-2021-23132",
			DetectedBy:        "Joomla Plugin",
			References:        []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23132"},
			ExploitAvailable:  true,
			Remediation:       "Update Joomla to version 3.9.26 or later.",
			ConfidenceLevel:   0.9,
			DetectionMethod:   "Version comparison",
			AffectedComponent: "Joomla Core",
		},
		{
			ID:                "JLA-CVE-2022-21702",
			Title:             "Joomla! < 4.0.6 - Unauthenticated Information Disclosure",
			Description:       "A vulnerability in Joomla! before 4.0.6 allows attackers to access sensitive information.",
			Severity:          core.SeverityHigh,
			CVSS:              7.5,
			CVE:               "CVE-2022-21702",
			DetectedBy:        "Joomla Plugin",
			References:        []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21702"},
			ExploitAvailable:  true,
			Remediation:       "Update Joomla to version 4.0.6 or later.",
			ConfidenceLevel:   0.9,
			DetectionMethod:   "Version comparison",
			AffectedComponent: "Joomla Core",
		},
		// Add more Joomla vulnerabilities here
	}

	// Update database
	db.vulnerabilities["joomla"] = vulns

	// Update CVE map
	for _, vuln := range vulns {
		if vuln.CVE != "" {
			db.cveMap[vuln.CVE] = append(db.cveMap[vuln.CVE], vuln)
		}
	}

	return nil
}

// updateDrupalVulnerabilities updates Drupal vulnerabilities from online sources
func (db *VulnerabilityDatabase) updateDrupalVulnerabilities() error {
	// In a real implementation, this would fetch from Drupal security advisories or similar
	// For this implementation, we'll use a sample set of vulnerabilities

	// Sample Drupal vulnerabilities
	vulns := []*core.Vulnerability{
		{
			ID:          "DPL-CVE-2018-7600",
			Title:       "Drupal < 7.58 - Remote Code Execution (Drupalgeddon2)",
			Description: "A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised.",
			Severity:    core.SeverityCritical,
			CVSS:        9.8,
			CVE:         "CVE-2018-7600",
			DetectedBy:  "Drupal Plugin",
			References: []string{
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7600",
				"https://www.drupal.org/sa-core-2018-002",
			},
			ExploitAvailable:  true,
			Remediation:       "Update Drupal core to version 7.58 or later.",
			ConfidenceLevel:   0.95,
			DetectionMethod:   "Version comparison",
			AffectedComponent: "Drupal Core",
		},
		{
			ID:          "DPL-CVE-2019-6340",
			Title:       "Drupal < 8.5.11 / < 8.6.10 - Remote Code Execution (Drupalgeddon3)",
			Description: "Some field types do not properly sanitize data from non-form sources in Drupal 8.5.x before 8.5.11 and Drupal 8.6.x before 8.6.10. This can lead to arbitrary PHP code execution in some cases.",
			Severity:    core.SeverityCritical,
			CVSS:        8.8,
			CVE:         "CVE-2019-6340",
			DetectedBy:  "Drupal Plugin",
			References: []string{
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6340",
				"https://www.drupal.org/sa-core-2019-003",
			},
			ExploitAvailable:  true,
			Remediation:       "Update Drupal core to version 8.5.11/8.6.10 or later, or disable the REST API if not in use.",
			ConfidenceLevel:   0.9,
			DetectionMethod:   "Version comparison",
			AffectedComponent: "Drupal Core",
		},
		// Add more Drupal vulnerabilities here
	}

	// Update database
	db.vulnerabilities["drupal"] = vulns

	// Update CVE map
	for _, vuln := range vulns {
		if vuln.CVE != "" {
			db.cveMap[vuln.CVE] = append(db.cveMap[vuln.CVE], vuln)
		}
	}

	return nil
}

// updateWixVulnerabilities updates Wix vulnerabilities from online sources
func (db *VulnerabilityDatabase) updateWixVulnerabilities() error {
	// In a real implementation, this would fetch from security advisories or similar
	// For this implementation, we'll use a sample set of vulnerabilities

	// Sample Wix vulnerabilities
	vulns := []*core.Vulnerability{
		{
			ID:                "WIX-EXPOSED-KEYS",
			Title:             "Exposed API Keys or Secrets in JavaScript",
			Description:       "The Wix site may contain exposed API keys, secrets, or other sensitive information in client-side JavaScript code.",
			Severity:          core.SeverityHigh,
			DetectedBy:        "Wix Plugin",
			ExploitAvailable:  true,
			Remediation:       "Move API keys and secrets to server-side code and use proper authentication mechanisms.",
			ConfidenceLevel:   0.7,
			DetectionMethod:   "Source code analysis",
			AffectedComponent: "Wix Site Code",
		},
		{
			ID:                "WIX-MIXED-CONTENT",
			Title:             "Mixed Content Loading",
			Description:       "The Wix site loads resources over insecure HTTP connections, which can lead to man-in-the-middle attacks.",
			Severity:          core.SeverityMedium,
			DetectedBy:        "Wix Plugin",
			ExploitAvailable:  false,
			Remediation:       "Ensure all resources are loaded over HTTPS.",
			ConfidenceLevel:   0.8,
			DetectionMethod:   "Source code analysis",
			AffectedComponent: "Wix Site Configuration",
		},
		// Add more Wix vulnerabilities here
	}

	// Update database
	db.vulnerabilities["wix"] = vulns

	return nil
}

// updateExploits updates exploits from online sources
func (db *VulnerabilityDatabase) updateExploits() error {
	// In a real implementation, this would fetch from Exploit-DB or similar
	// For this implementation, we'll use a sample set of exploits

	// Sample exploits
	exploits := map[string]*core.Exploit{
		"EXP-CVE-2022-21662": {
			// Correctly initialize fields based on core.Exploit struct
			Title:       "WordPress < 5.8.3 - Stored XSS via Post Slugs",
			Description: "This exploit demonstrates the stored XSS vulnerability in WordPress post slugs.",
			Type:        "xss",
			Code: `
# Proof of Concept for CVE-2022-21662
# This script creates a post with a malicious slug that triggers XSS
`,
		},
		// Add more exploits here
	}

	// Update database
	db.exploits = exploits

	return nil
}

// GetVulnerabilityCount returns the total number of vulnerabilities in the database
func (db *VulnerabilityDatabase) GetVulnerabilityCount() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	total := 0
	for _, vulns := range db.vulnerabilities {
		total += len(vulns)
	}
	return total
}

// GetVulnerabilitiesByCMS returns vulnerabilities for a given CMS
func (db *VulnerabilityDatabase) GetVulnerabilitiesByCMS(cms string) []*core.Vulnerability {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return db.vulnerabilities[cms]
}

// GetExploitByCVE returns exploits for a given CVE
func (db *VulnerabilityDatabase) GetExploitByCVE(cve string) []*core.Exploit {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	var exploits []*core.Exploit
	for _, exploit := range db.exploits {
		if exploit.CVE == cve {
			exploits = append(exploits, exploit)
		}
	}
	return exploits
}

// GetExploitCount returns the number of exploits in the database
func (db *VulnerabilityDatabase) GetExploitCount() int {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return len(db.exploits)
}

// GetLastUpdateTime returns the last update time of the database
func (db *VulnerabilityDatabase) GetLastUpdateTime() time.Time {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	return db.lastUpdate
}
