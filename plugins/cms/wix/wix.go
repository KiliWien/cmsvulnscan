package wix

import (
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/user/cmsvulnscan/lib/core"
)

// WixPlugin implements the core.CMSPlugin interface for Wix
type WixPlugin struct {
	client  *http.Client
	verbose bool
	logger  *log.Logger
}

// NewWixPlugin creates a new Wix plugin instance
func NewWixPlugin() *WixPlugin {
	return &WixPlugin{
		client:  &http.Client{Timeout: core.DefaultScanOptions().Timeout},
		verbose: false,
		logger:  log.New(log.Writer(), "[Wix] ", log.LstdFlags),
	}
}

// SetVerbose enables or disables verbose logging
func (p *WixPlugin) SetVerbose(verbose bool) {
	p.verbose = verbose
}

// logVerbose logs a message if verbose mode is enabled
func (p *WixPlugin) logVerbose(format string, args ...interface{}) {
	if p.verbose {
		p.logger.Printf(format, args...)
	}
}

// GetName returns the name of the CMS
func (p *WixPlugin) GetName() string {
	return "Wix"
}

// Detect determines if the target is running Wix
func (p *WixPlugin) Detect(targetURL string) (bool, error) {
	if p.verbose {
		p.logVerbose("Starting Wix detection on %s", targetURL)
	}

	// Common Wix detection patterns
	patterns := []struct {
		path    string
		pattern string
	}{
		{"/", "(?i)wix.com"},
		{"/", "(?i)wix-code"},
		{"/", "(?i)wix-instantsearchplus"},
		{"/", "(?i)wix-dropdown-menu"},
		{"/", "(?i)wix-image"},
		{"/", "(?i)wix-custom-element"},
		{"/", "(?i)wix-viewer"},
		{"/", "(?i)static.wixstatic.com"},
		{"/", "(?i)static.parastorage.com"},
		{"/", "(?i)editor.wix.com"},
	}

	for _, pattern := range patterns {
		url := targetURL + pattern.path
		if p.verbose {
			p.logVerbose("Checking URL: %s for pattern: %s", url, pattern.pattern)
		}

		resp, err := p.client.Get(url)
		if err != nil {
			if p.verbose {
				p.logVerbose("Error accessing %s: %v", url, err)
			}
			continue
		}
		defer resp.Body.Close()

		// Check if response status is successful
		if resp.StatusCode != http.StatusOK {
			if p.verbose {
				p.logVerbose("Got status %d for %s, skipping", resp.StatusCode, url)
			}
			continue
		}

		// Read response body (limited to 50KB to avoid memory issues)
		buf := make([]byte, 50*1024)
		n, _ := resp.Body.Read(buf)
		body := string(buf[:n])

		// Check if pattern matches
		matched, _ := regexp.MatchString(pattern.pattern, body)
		if matched {
			if p.verbose {
				p.logVerbose("Wix detected! Pattern '%s' matched at %s", pattern.pattern, url)
			}
			return true, nil
		} else if p.verbose {
			p.logVerbose("Pattern '%s' not found at %s", pattern.pattern, url)
		}
	}

	// Check for Wix meta tags
	if p.verbose {
		p.logVerbose("Checking for Wix meta tags")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Check for Wix-specific meta tags or scripts
			wixPatterns := []string{
				`<meta\s+name=["']generator["']\s+content=["']Wix\.com`,
				`<script\s+[^>]*src=["'][^"']*static\.wixstatic\.com`,
				`<script\s+[^>]*src=["'][^"']*static\.parastorage\.com`,
				`<script\s+[^>]*src=["'][^"']*editor\.wix\.com`,
				`var\s+wixBiSession`,
				`window\.wixPerformance`,
				`wixEmbedsAPI`,
			}

			for _, pattern := range wixPatterns {
				re := regexp.MustCompile(pattern)
				if re.MatchString(body) {
					if p.verbose {
						p.logVerbose("Wix detected via pattern: %s", pattern)
					}
					return true, nil
				}
			}
		}
	}

	if p.verbose {
		p.logVerbose("Wix not detected on %s", targetURL)
	}
	return false, nil
}

// Fingerprint identifies the version and components
func (p *WixPlugin) Fingerprint(targetURL string) (*core.CMSFingerprint, error) {
	if p.verbose {
		p.logVerbose("Starting Wix fingerprinting on %s", targetURL)
	}

	fingerprint := &core.CMSFingerprint{
		CMSName:           p.GetName(),
		Version:           "Unknown", // Wix doesn't typically expose version numbers
		VersionConfidence: 0.0,
		Headers:           make(map[string]string),
		AdditionalInfo:    make(map[string]interface{}),
	}

	// Get headers and server info
	if p.verbose {
		p.logVerbose("Checking headers for Wix fingerprinting")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()

		// Store headers for analysis
		for k, v := range resp.Header {
			fingerprint.Headers[k] = strings.Join(v, ", ")
			if p.verbose {
				p.logVerbose("Header: %s: %s", k, strings.Join(v, ", "))
			}
		}

		fingerprint.ServerInfo = resp.Header.Get("Server")
		if p.verbose && fingerprint.ServerInfo != "" {
			p.logVerbose("Server information: %s", fingerprint.ServerInfo)
		}

		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Try to identify Wix site type
			if strings.Contains(body, "wix-commerce") || strings.Contains(body, "wixstores") {
				fingerprint.AdditionalInfo["site_type"] = "e-commerce"
				if p.verbose {
					p.logVerbose("Detected Wix e-commerce site")
				}
			} else if strings.Contains(body, "wix-blog") || strings.Contains(body, "wixblog") {
				fingerprint.AdditionalInfo["site_type"] = "blog"
				if p.verbose {
					p.logVerbose("Detected Wix blog site")
				}
			} else if strings.Contains(body, "wix-portfolio") {
				fingerprint.AdditionalInfo["site_type"] = "portfolio"
				if p.verbose {
					p.logVerbose("Detected Wix portfolio site")
				}
			} else if strings.Contains(body, "wix-events") {
				fingerprint.AdditionalInfo["site_type"] = "events"
				if p.verbose {
					p.logVerbose("Detected Wix events site")
				}
			} else {
				fingerprint.AdditionalInfo["site_type"] = "standard"
				if p.verbose {
					p.logVerbose("Detected standard Wix site")
				}
			}

			// Try to detect if it's a premium or free site
			if strings.Contains(body, "wixsite.com") || strings.Contains(targetURL, "wixsite.com") {
				fingerprint.AdditionalInfo["premium"] = false
				if p.verbose {
					p.logVerbose("Detected free Wix site (wixsite.com subdomain)")
				}
			} else {
				fingerprint.AdditionalInfo["premium"] = true
				if p.verbose {
					p.logVerbose("Detected premium Wix site (custom domain)")
				}
			}

			// Try to detect Wix editor version from script URLs
			editorVersionPattern := `static\.parastorage\.com\/services\/wix-thunderbolt\/dist\/([^/]+)/`
			reEditor := regexp.MustCompile(editorVersionPattern)
			matchesEditor := reEditor.FindStringSubmatch(body)
			if len(matchesEditor) > 1 {
				fingerprint.AdditionalInfo["editor_version"] = matchesEditor[1]
				if p.verbose {
					p.logVerbose("Detected Wix editor version: %s", matchesEditor[1])
				}
			}
		}
	}

	if p.verbose {
		p.logVerbose("Wix fingerprinting complete")
	}

	return fingerprint, nil
}

// EnumerateComponents lists installed Wix apps and components
func (p *WixPlugin) EnumerateComponents(targetURL string) ([]*core.Component, error) {
	if p.verbose {
		p.logVerbose("Starting Wix component enumeration on %s", targetURL)
	}

	components := make([]*core.Component, 0)

	// Get the main page to analyze for components
	if p.verbose {
		p.logVerbose("Analyzing main page for Wix components")
	}

	resp, err := p.client.Get(targetURL)
	if err != nil {
		if p.verbose {
			p.logVerbose("Error accessing %s: %v", targetURL, err)
		}
		return components, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if p.verbose {
			p.logVerbose("Got status %d for %s, cannot enumerate components", resp.StatusCode, targetURL)
		}
		return components, nil
	}

	// Read response body
	buf := make([]byte, 100*1024) // Larger buffer for Wix sites which can be quite large
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Common Wix apps to check for
	wixApps := map[string]string{
		"wix-stores":         "Wix Stores",
		"wix-blog":           "Wix Blog",
		"wix-bookings":       "Wix Bookings",
		"wix-events":         "Wix Events",
		"wix-forum":          "Wix Forum",
		"wix-members":        "Wix Members Area",
		"wix-chat":           "Wix Chat",
		"wix-restaurants":    "Wix Restaurants",
		"wix-hotels":         "Wix Hotels",
		"wix-music":          "Wix Music",
		"wix-video":          "Wix Video",
		"wix-portfolio":      "Wix Portfolio",
		"wix-instagram-feed": "Wix Instagram Feed",
		"wix-forms":          "Wix Forms",
		"wix-pricing-plans":  "Wix Pricing Plans",
		"wix-comments":       "Wix Comments",
		"wix-photo-albums":   "Wix Photo Albums",
		"wix-faq":            "Wix FAQ",
		"wix-testimonials":   "Wix Testimonials",
		"wix-contact":        "Wix Contact",
	}

	// Check for each app
	for appId, appName := range wixApps {
		if strings.Contains(body, appId) {
			if p.verbose {
				p.logVerbose("Detected Wix app: %s", appName)
			}

			components = append(components, &core.Component{
				Name:     appName,
				Type:     "app",
				Version:  "Unknown", // Wix doesn't typically expose app versions
				Location: "/",
				Active:   true,
			})
		}
	}

	// Check for third-party integrations
	thirdPartyIntegrations := map[string]string{
		"googleAnalytics":  "Google Analytics",
		"facebookPixel":    "Facebook Pixel",
		"googleTagManager": "Google Tag Manager",
		"hotjar":           "Hotjar",
		"mailchimp":        "Mailchimp",
		"zapier":           "Zapier",
		"paypal":           "PayPal",
		"stripe":           "Stripe",
		"disqus":           "Disqus",
		"intercom":         "Intercom",
		"zendesk":          "Zendesk",
		"hubspot":          "HubSpot",
	}

	for integrationId, integrationName := range thirdPartyIntegrations {
		if strings.Contains(strings.ToLower(body), strings.ToLower(integrationId)) {
			if p.verbose {
				p.logVerbose("Detected third-party integration: %s", integrationName)
			}

			components = append(components, &core.Component{
				Name:     integrationName,
				Type:     "integration",
				Version:  "Unknown",
				Location: "/",
				Active:   true,
			})
		}
	}

	if p.verbose {
		p.logVerbose("Wix component enumeration complete. Found %d components", len(components))
	}

	return components, nil
}

// ScanVulnerabilities performs Wix-specific vulnerability checks
func (p *WixPlugin) ScanVulnerabilities(targetURL string, fingerprint *core.CMSFingerprint) ([]*core.Vulnerability, error) {
	if p.verbose {
		p.logVerbose("Starting Wix vulnerability scan on %s", targetURL)
	}

	vulnerabilities := make([]*core.Vulnerability, 0)

	// Wix sites are generally less vulnerable to traditional CMS vulnerabilities since they're hosted platforms
	// However, there are still some checks we can perform

	// Check for sensitive information exposure
	if p.verbose {
		p.logVerbose("Checking for sensitive information exposure")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 100*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Check for exposed API keys
			apiKeyPatterns := []struct {
				name    string
				pattern string
			}{
				{"Google Maps API Key", `(?i)googleMapsApiKey["'\s]*[:=]\s*["']([A-Za-z0-9_\-]+)["']`},
				{"Google Analytics ID", `(?i)UA-\d{4,10}-\d{1,4}`},
				{"Facebook App ID", `(?i)facebook[Aa]pp[Ii][Dd]["'\s]*[:=]\s*["'](\d{14,16})["']`},
				{"Mailchimp API Key", `(?i)[0-9a-f]{32}-us\d{1,2}`},
				{"Stripe Publishable Key", `(?i)pk_live_[0-9a-zA-Z]{24}`},
				{"AWS Access Key", `(?i)AKIA[0-9A-Z]{16}`},
			}

			for _, pattern := range apiKeyPatterns {
				re := regexp.MustCompile(pattern.pattern)
				matches := re.FindStringSubmatch(body)
				if len(matches) > 0 {
					vuln := &core.Vulnerability{
						ID:                "WIX-API-KEY-EXPOSURE",
						Title:             "Exposed API Key: " + pattern.name,
						Description:       "An API key was found exposed in the page source code, which could be used by attackers to access services or incur charges on the site owner's account.",
						Severity:          core.SeverityHigh,
						DetectedBy:        "Wix Plugin",
						ExploitAvailable:  false,
						Remediation:       "Remove the API key from the client-side code and use server-side methods to protect sensitive keys.",
						ConfidenceLevel:   0.8,
						DetectionMethod:   "Pattern matching",
						AffectedComponent: "Wix Custom Code",
					}

					vulnerabilities = append(vulnerabilities, vuln)

					if p.verbose {
						p.logVerbose("Vulnerability detected: %s", vuln.Title)
					}
				}
			}

			// Check for misconfigured CORS
			corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
			if corsHeader == "*" {
				vuln := &core.Vulnerability{
					ID:                "WIX-CORS-MISCONFIGURATION",
					Title:             "Misconfigured CORS Policy",
					Description:       "The site has a permissive CORS policy (Access-Control-Allow-Origin: *) which could potentially allow cross-origin attacks.",
					Severity:          core.SeverityMedium,
					DetectedBy:        "Wix Plugin",
					ExploitAvailable:  false,
					Remediation:       "Configure CORS to only allow specific trusted domains.",
					ConfidenceLevel:   0.9,
					DetectionMethod:   "Header analysis",
					AffectedComponent: "Wix Configuration",
				}

				vulnerabilities = append(vulnerabilities, vuln)

				if p.verbose {
					p.logVerbose("Vulnerability detected: %s", vuln.Title)
				}
			}

			// Check for insecure content
			if strings.HasPrefix(targetURL, "https://") && strings.Contains(body, "http://") {
				// Check if there are non-secure resources loaded on a secure page
				insecurePattern := `src=["']http://[^"']*["']|href=["']http://[^"']*["']`
				reInsecure := regexp.MustCompile(insecurePattern)
				if reInsecure.MatchString(body) {
					vuln := &core.Vulnerability{
						ID:                "WIX-MIXED-CONTENT",
						Title:             "Mixed Content Vulnerability",
						Description:       "The site loads resources over insecure HTTP on a secure HTTPS page, which can lead to mixed content warnings or blocks in browsers.",
						Severity:          core.SeverityLow,
						DetectedBy:        "Wix Plugin",
						ExploitAvailable:  false,
						Remediation:       "Ensure all resources are loaded over HTTPS.",
						ConfidenceLevel:   0.9,
						DetectionMethod:   "Content analysis",
						AffectedComponent: "Wix Custom Code",
					}

					vulnerabilities = append(vulnerabilities, vuln)

					if p.verbose {
						p.logVerbose("Vulnerability detected: %s", vuln.Title)
					}
				}
			}

			// Check for outdated libraries
			outdatedLibraries := map[string]string{
				`jquery-1\.`:      "jQuery 1.x",
				`jquery-2\.`:      "jQuery 2.x",
				`bootstrap-3\.`:   "Bootstrap 3.x",
				`angular\.js/1\.`: "AngularJS 1.x",
			}

			for pattern, libName := range outdatedLibraries {
				re := regexp.MustCompile(pattern)
				if re.MatchString(body) {
					vuln := &core.Vulnerability{
						ID:                "WIX-OUTDATED-LIBRARY",
						Title:             "Outdated Library: " + libName,
						Description:       "The site is using an outdated version of " + libName + " which may contain known security vulnerabilities.",
						Severity:          core.SeverityMedium,
						DetectedBy:        "Wix Plugin",
						ExploitAvailable:  false,
						Remediation:       "Update to the latest version of the library.",
						ConfidenceLevel:   0.7,
						DetectionMethod:   "Content analysis",
						AffectedComponent: "Wix Custom Code",
					}

					vulnerabilities = append(vulnerabilities, vuln)

					if p.verbose {
						p.logVerbose("Vulnerability detected: %s", vuln.Title)
					}
				}
			}
		}
	}

	if p.verbose {
		p.logVerbose("Wix vulnerability scan complete. Found %d vulnerabilities", len(vulnerabilities))
	}

	return vulnerabilities, nil
}
