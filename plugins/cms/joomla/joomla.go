package joomla

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/user/cmsvulnscan/lib/core"
)

// JoomlaPlugin implements the core.CMSPlugin interface for Joomla
type JoomlaPlugin struct {
	client  *http.Client
	verbose bool
	logger  *log.Logger
}

// NewJoomlaPlugin creates a new Joomla plugin instance
func NewJoomlaPlugin() *JoomlaPlugin {
	return &JoomlaPlugin{
		client:  &http.Client{Timeout: core.DefaultScanOptions().Timeout},
		verbose: false,
		logger:  log.New(log.Writer(), "[Joomla] ", log.LstdFlags),
	}
}

// SetVerbose enables or disables verbose logging
func (p *JoomlaPlugin) SetVerbose(verbose bool) {
	p.verbose = verbose
}

// logVerbose logs a message if verbose mode is enabled
func (p *JoomlaPlugin) logVerbose(format string, args ...interface{}) {
	if p.verbose {
		p.logger.Printf(format, args...)
	}
}

// GetName returns the name of the CMS
func (p *JoomlaPlugin) GetName() string {
	return "Joomla"
}

// Detect determines if the target is running Joomla
func (p *JoomlaPlugin) Detect(targetURL string) (bool, error) {
	if p.verbose {
		p.logVerbose("Starting Joomla detection on %s", targetURL)
	}

	// Common Joomla detection patterns
	patterns := []struct {
		path    string
		pattern string
	}{
		{"/administrator/", "(?i)joomla"},
		{"/administrator/index.php", "(?i)joomla"},
		{"/administrator/manifests/files/joomla.xml", "(?i)<name>Joomla!</name>"},
		{"/language/en-GB/en-GB.xml", "(?i)<name>English \\(United Kingdom\\)</name>"},
		{"/robots.txt", "(?i)joomla"},
		{"/", "(?i)content=\"Joomla"},
		{"/", "(?i)/media/jui/"},
		{"/", "(?i)/media/system/js/"},
		{"/", "(?i)joomla!"},
		{"/", "(?i)window.joomla"},
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
				p.logVerbose("Joomla detected! Pattern '%s' matched at %s", pattern.pattern, url)
			}
			return true, nil
		} else if p.verbose {
			p.logVerbose("Pattern '%s' not found at %s", pattern.pattern, url)
		}
	}

	// Check for Joomla meta generator tag
	if p.verbose {
		p.logVerbose("Checking for Joomla meta generator tag")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			metaPattern := `<meta\s+name=["']generator["']\s+content=["']Joomla!([^"']*)["']`
			re := regexp.MustCompile(metaPattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 0 {
				if p.verbose {
					p.logVerbose("Joomla detected via meta generator tag! Version hint: %s", matches[1])
				}
				return true, nil
			}
		}
	}

	if p.verbose {
		p.logVerbose("Joomla not detected on %s", targetURL)
	}
	return false, nil
}

// Fingerprint identifies the version and components
func (p *JoomlaPlugin) Fingerprint(targetURL string) (*core.CMSFingerprint, error) {
	if p.verbose {
		p.logVerbose("Starting Joomla fingerprinting on %s", targetURL)
	}

	fingerprint := &core.CMSFingerprint{
		CMSName:           p.GetName(),
		Version:           "Unknown",
		VersionConfidence: 0.0,
		Headers:           make(map[string]string),
		AdditionalInfo:    make(map[string]interface{}),
	}

	// Try to get version from XML manifest
	if p.verbose {
		p.logVerbose("Checking for version in XML manifest")
	}

	manifestURLs := []string{
		targetURL + "/administrator/manifests/files/joomla.xml",
		targetURL + "/language/en-GB/en-GB.xml",
		targetURL + "/libraries/cms/version/version.php",
	}

	for _, url := range manifestURLs {
		if p.verbose {
			p.logVerbose("Checking manifest URL: %s", url)
		}

		resp, err := p.client.Get(url)
		if err != nil {
			if p.verbose {
				p.logVerbose("Error accessing %s: %v", url, err)
			}
			continue
		}
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

			// Check for version in XML
			versionPattern := `<version>([0-9.]+)</version>`
			re := regexp.MustCompile(versionPattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				fingerprint.Version = matches[1]
				fingerprint.VersionConfidence = 0.95
				if p.verbose {
					p.logVerbose("Found Joomla version %s in manifest (confidence: 95%%)", matches[1])
				}
				break
			}

			// Check for version in PHP file
			phpVersionPattern := `(?i)RELEASE\s*=\s*'([0-9.]+)'`
			rePhp := regexp.MustCompile(phpVersionPattern)
			matchesPhp := rePhp.FindStringSubmatch(body)
			if len(matchesPhp) > 1 {
				fingerprint.Version = matchesPhp[1]
				fingerprint.VersionConfidence = 0.9
				if p.verbose {
					p.logVerbose("Found Joomla version %s in PHP file (confidence: 90%%)", matchesPhp[1])
				}
				break
			}
		} else if p.verbose {
			p.logVerbose("Manifest URL returned status %d", resp.StatusCode)
		}
	}

	// Try to get version from meta generator tag
	if fingerprint.Version == "Unknown" {
		if p.verbose {
			p.logVerbose("Version not found in manifests, checking meta generator tag")
		}

		resp, err := p.client.Get(targetURL)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				buf := make([]byte, 50*1024)
				n, _ := resp.Body.Read(buf)
				body := string(buf[:n])

				// Check for version in meta generator tag
				metaPattern := `<meta\s+name=["']generator["']\s+content=["']Joomla!\s+([0-9.]+)["']`
				re := regexp.MustCompile(metaPattern)
				matches := re.FindStringSubmatch(body)
				if len(matches) > 1 {
					fingerprint.Version = matches[1]
					fingerprint.VersionConfidence = 0.8
					if p.verbose {
						p.logVerbose("Found Joomla version %s in meta generator tag (confidence: 80%%)", matches[1])
					}
				}
			}
		}
	}

	// Try to determine Joomla major version based on directory structure
	if p.verbose {
		p.logVerbose("Checking directory structure for Joomla version hints")
	}

	// Joomla 4.x specific paths
	joomla4Paths := []string{
		"/administrator/components/com_admin/sql/updates/mysql/4",
		"/libraries/vendor/joomla/filesystem/",
	}

	// Joomla 3.x specific paths
	joomla3Paths := []string{
		"/administrator/components/com_admin/sql/updates/mysql/3",
		"/libraries/joomla/filesystem/",
	}

	// Joomla 2.5.x specific paths
	joomla25Paths := []string{
		"/administrator/components/com_admin/sql/updates/mysql/2.5",
		"/libraries/joomla/html/html/",
	}

	// Check for Joomla 4.x
	for _, path := range joomla4Paths {
		resp, err := p.client.Get(targetURL + path)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				fingerprint.AdditionalInfo["joomla_major_version"] = "4"
				if p.verbose {
					p.logVerbose("Detected Joomla 4.x based on directory structure")
				}
				break
			}
		}
	}

	// Check for Joomla 3.x
	if _, ok := fingerprint.AdditionalInfo["joomla_major_version"]; !ok {
		for _, path := range joomla3Paths {
			resp, err := p.client.Get(targetURL + path)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					fingerprint.AdditionalInfo["joomla_major_version"] = "3"
					if p.verbose {
						p.logVerbose("Detected Joomla 3.x based on directory structure")
					}
					break
				}
			}
		}
	}

	// Check for Joomla 2.5.x
	if _, ok := fingerprint.AdditionalInfo["joomla_major_version"]; !ok {
		for _, path := range joomla25Paths {
			resp, err := p.client.Get(targetURL + path)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					fingerprint.AdditionalInfo["joomla_major_version"] = "2.5"
					if p.verbose {
						p.logVerbose("Detected Joomla 2.5.x based on directory structure")
					}
					break
				}
			}
		}
	}

	if p.verbose {
		if fingerprint.Version != "Unknown" {
			p.logVerbose("Joomla fingerprinting complete. Version: %s, Confidence: %.1f%%",
				fingerprint.Version, fingerprint.VersionConfidence*100)
		} else {
			p.logVerbose("Joomla fingerprinting complete. Version could not be determined.")
		}
	}

	return fingerprint, nil
}

// EnumerateComponents lists installed components, modules, plugins, and templates
func (p *JoomlaPlugin) EnumerateComponents(targetURL string) ([]*core.Component, error) {
	if p.verbose {
		p.logVerbose("Starting Joomla component enumeration on %s", targetURL)
	}

	components := make([]*core.Component, 0)

	// Common Joomla components to check
	commonComponents := []string{
		"com_content", "com_users", "com_contact", "com_banners", "com_categories",
		"com_config", "com_finder", "com_mailto", "com_media", "com_menus",
		"com_modules", "com_newsfeeds", "com_plugins", "com_search", "com_weblinks",
		"com_wrapper", "com_ajax", "com_contenthistory", "com_fields", "com_tags",
		"com_joomlaupdate", "com_languages", "com_login", "com_messages", "com_templates",
		"com_admin", "com_cache", "com_installer", "com_redirect", "com_actionlogs",
		"com_privacy", "com_cpanel", "com_checkin", "com_postinstall", "com_associations",
	}

	// Popular third-party components
	thirdPartyComponents := []string{
		"com_akeeba", "com_jce", "com_virtuemart", "com_hikashop", "com_fabrik",
		"com_acymailing", "com_jdownloads", "com_kunena", "com_easyblog", "com_easysocial",
		"com_community", "com_k2", "com_phocagallery", "com_phocadownload", "com_chronoforms",
		"com_foxcontact", "com_creativecontactform", "com_sexycontactform", "com_jnews", "com_joomgallery",
		"com_zoo", "com_jshopping", "com_mijoshop", "com_redshop", "com_bt_portfolio",
		"com_rokgallery", "com_jbcatalog", "com_sobipro", "com_joomshopping", "com_rsform",
	}

	allComponents := append(commonComponents, thirdPartyComponents...)

	if p.verbose {
		p.logVerbose("Checking for %d Joomla components", len(allComponents))
	}

	// Check for components
	for _, component := range allComponents {
		// Check if component exists by requesting its directory
		componentUrl := fmt.Sprintf("%s/components/%s/", targetURL, component)

		if p.verbose {
			p.logVerbose("Checking for component: %s at %s", component, componentUrl)
		}

		resp, err := p.client.Get(componentUrl)
		if err == nil {
			defer resp.Body.Close()

			// If we get a 200 or 403, the component likely exists
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				if p.verbose {
					p.logVerbose("Component detected: %s (status: %d)", component, resp.StatusCode)
				}

				components = append(components, &core.Component{
					Name:     component,
					Type:     "component",
					Version:  "Unknown", // In a real implementation, we would try to detect the version
					Location: fmt.Sprintf("/components/%s/", component),
					Active:   true, // Assuming active for the proof of concept
				})
				continue
			} else if p.verbose {
				p.logVerbose("Component %s not found (status: %d)", component, resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error checking component %s: %v", component, err)
		}

		// Also check in administrator components
		adminComponentUrl := fmt.Sprintf("%s/administrator/components/%s/", targetURL, component)

		if p.verbose {
			p.logVerbose("Checking for admin component: %s at %s", component, adminComponentUrl)
		}

		resp, err = p.client.Get(adminComponentUrl)
		if err == nil {
			defer resp.Body.Close()

			// If we get a 200 or 403, the component likely exists
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				if p.verbose {
					p.logVerbose("Admin component detected: %s (status: %d)", component, resp.StatusCode)
				}

				// Check if we already added this component
				found := false
				for _, comp := range components {
					if comp.Name == component {
						found = true
						break
					}
				}

				if !found {
					components = append(components, &core.Component{
						Name:     component,
						Type:     "component",
						Version:  "Unknown",
						Location: fmt.Sprintf("/administrator/components/%s/", component),
						Active:   true,
					})
				}
			} else if p.verbose {
				p.logVerbose("Admin component %s not found (status: %d)", component, resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error checking admin component %s: %v", component, err)
		}
	}

	// Common Joomla templates to check
	commonTemplates := []string{
		"beez3", "protostar", "hathor", "isis", "atomic", "beez_20", "beez5",
		"cassiopeia", "atum", "system", "bluestork", "ja_purity", "rhuk_milkyway",
		"template_preview", "beez", "siteground-j16-1", "siteground-j16-2",
	}

	if p.verbose {
		p.logVerbose("Checking for %d common Joomla templates", len(commonTemplates))
	}

	// Check for templates
	for _, template := range commonTemplates {
		// Check site templates
		templateUrl := fmt.Sprintf("%s/templates/%s/", targetURL, template)

		if p.verbose {
			p.logVerbose("Checking for template: %s at %s", template, templateUrl)
		}

		resp, err := p.client.Get(templateUrl)
		if err == nil {
			defer resp.Body.Close()

			// If we get a 200 or 403, the template likely exists
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				if p.verbose {
					p.logVerbose("Template detected: %s (status: %d)", template, resp.StatusCode)
				}

				components = append(components, &core.Component{
					Name:     template,
					Type:     "template",
					Version:  "Unknown",
					Location: fmt.Sprintf("/templates/%s/", template),
					Active:   false, // Can't determine if active without more analysis
				})
			} else if p.verbose {
				p.logVerbose("Template %s not found (status: %d)", template, resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error checking template %s: %v", template, err)
		}

		// Check admin templates
		adminTemplateUrl := fmt.Sprintf("%s/administrator/templates/%s/", targetURL, template)

		if p.verbose {
			p.logVerbose("Checking for admin template: %s at %s", template, adminTemplateUrl)
		}

		resp, err = p.client.Get(adminTemplateUrl)
		if err == nil {
			defer resp.Body.Close()

			// If we get a 200 or 403, the template likely exists
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				if p.verbose {
					p.logVerbose("Admin template detected: %s (status: %d)", template, resp.StatusCode)
				}

				components = append(components, &core.Component{
					Name:     template,
					Type:     "admin_template",
					Version:  "Unknown",
					Location: fmt.Sprintf("/administrator/templates/%s/", template),
					Active:   false,
				})
			} else if p.verbose {
				p.logVerbose("Admin template %s not found (status: %d)", template, resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error checking admin template %s: %v", template, err)
		}
	}

	// Try to detect active template from homepage
	if p.verbose {
		p.logVerbose("Checking for active template from homepage")
	}

	// Fetch the homepage
	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Look for template name in body
			for _, template := range commonTemplates {
				if strings.Contains(body, template) {
					if p.verbose {
						p.logVerbose("Active template detected: %s (found in homepage)", template)
					}

					// Mark the template as active
					for _, comp := range components {
						if comp.Name == template {
							comp.Active = true
							break
						}
					}
					break
				}
			}
		}
	}

	if p.verbose {
		p.logVerbose("Joomla component enumeration complete. Found %d components and templates.", len(components))
	}

	return components, nil
}

// ScanVulnerabilities performs Joomla-specific vulnerability checks
func (p *JoomlaPlugin) ScanVulnerabilities(targetURL string, fingerprint *core.CMSFingerprint) ([]*core.Vulnerability, error) {
	// TODO: Implement vulnerability scanning logic for Joomla
	return nil, nil
}
