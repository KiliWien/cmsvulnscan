package drupal

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/user/cmsvulnscan/lib/core"
)

// DrupalPlugin implements the core.CMSPlugin interface for Drupal
type DrupalPlugin struct {
	client  *http.Client
	verbose bool
	logger  *log.Logger
}

// NewDrupalPlugin creates a new Drupal plugin instance
func NewDrupalPlugin() *DrupalPlugin {
	return &DrupalPlugin{
		client:  &http.Client{Timeout: core.DefaultScanOptions().Timeout},
		verbose: false,
		logger:  log.New(log.Writer(), "[Drupal] ", log.LstdFlags),
	}
}

// SetVerbose enables or disables verbose logging
func (p *DrupalPlugin) SetVerbose(verbose bool) {
	p.verbose = verbose
}

// logVerbose logs a message if verbose mode is enabled
func (p *DrupalPlugin) logVerbose(format string, args ...interface{}) {
	if p.verbose {
		p.logger.Printf(format, args...)
	}
}

// GetName returns the name of the CMS
func (p *DrupalPlugin) GetName() string {
	return "Drupal"
}

// Detect determines if the target is running Drupal
func (p *DrupalPlugin) Detect(targetURL string) (bool, error) {
	if p.verbose {
		p.logVerbose("Starting Drupal detection on %s", targetURL)
	}

	// Common Drupal detection patterns
	patterns := []struct {
		path    string
		pattern string
	}{
		{"/CHANGELOG.txt", "(?i)drupal"},
		{"/core/CHANGELOG.txt", "(?i)drupal"},
		{"/core/misc/drupal.js", "(?i)drupal"},
		{"/core/misc/drupal.min.js", "(?i)drupal"},
		{"/misc/drupal.js", "(?i)drupal"},
		{"/", "(?i)drupal.settings"},
		{"/", "(?i)/sites/default/files/"},
		{"/", "(?i)/sites/all/themes/"},
		{"/", "(?i)/sites/all/modules/"},
		{"/", "(?i)jQuery.extend\\(Drupal.settings"},
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
				p.logVerbose("Drupal detected! Pattern '%s' matched at %s", pattern.pattern, url)
			}
			return true, nil
		} else if p.verbose {
			p.logVerbose("Pattern '%s' not found at %s", pattern.pattern, url)
		}
	}

	// Check for Drupal generator meta tag
	if p.verbose {
		p.logVerbose("Checking for Drupal generator meta tag")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			metaPattern := `<meta\s+name=["']generator["']\s+content=["']Drupal([^"']*)["']`
			re := regexp.MustCompile(metaPattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 0 {
				if p.verbose {
					p.logVerbose("Drupal detected via meta generator tag! Version hint: %s", matches[1])
				}
				return true, nil
			}
		}
	}

	if p.verbose {
		p.logVerbose("Drupal not detected on %s", targetURL)
	}
	return false, nil
}

// Fingerprint identifies the version and components
func (p *DrupalPlugin) Fingerprint(targetURL string) (*core.CMSFingerprint, error) {
	if p.verbose {
		p.logVerbose("Starting Drupal fingerprinting on %s", targetURL)
	}

	fingerprint := &core.CMSFingerprint{
		CMSName:           p.GetName(),
		Version:           "Unknown",
		VersionConfidence: 0.0,
		Headers:           make(map[string]string),
		AdditionalInfo:    make(map[string]interface{}),
	}

	// Try to get version from CHANGELOG.txt
	if p.verbose {
		p.logVerbose("Checking for version in CHANGELOG.txt")
	}

	changelogURLs := []string{
		targetURL + "/CHANGELOG.txt",
		targetURL + "/core/CHANGELOG.txt",
	}

	for _, url := range changelogURLs {
		if p.verbose {
			p.logVerbose("Checking changelog URL: %s", url)
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

			// Check for version in CHANGELOG.txt
			versionPattern := `(?i)Drupal\s+([0-9]+\.[0-9]+\.[0-9]+)`
			re := regexp.MustCompile(versionPattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				fingerprint.Version = matches[1]
				fingerprint.VersionConfidence = 0.95
				if p.verbose {
					p.logVerbose("Found Drupal version %s in changelog (confidence: 95%%)", matches[1])
				}
				break
			}
		} else if p.verbose {
			p.logVerbose("Changelog URL returned status %d", resp.StatusCode)
		}
	}

	// Try to get version from meta generator tag
	if fingerprint.Version == "Unknown" {
		if p.verbose {
			p.logVerbose("Version not found in changelog, checking meta generator tag")
		}

		resp, err := p.client.Get(targetURL)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				buf := make([]byte, 50*1024)
				n, _ := resp.Body.Read(buf)
				body := string(buf[:n])

				// Check for version in meta generator tag
				metaPattern := `<meta\s+name=["']generator["']\s+content=["']Drupal\s+([0-9]+\.[0-9]+)(?:\.[0-9]+)?(?:\s+\([^)]+\))?["']`
				re := regexp.MustCompile(metaPattern)
				matches := re.FindStringSubmatch(body)
				if len(matches) > 1 {
					fingerprint.Version = matches[1]
					fingerprint.VersionConfidence = 0.8
					if p.verbose {
						p.logVerbose("Found Drupal version %s in meta generator tag (confidence: 80%%)", matches[1])
					}
				}
			}
		}
	}

	// Try to determine Drupal major version based on directory structure
	if p.verbose {
		p.logVerbose("Checking directory structure for Drupal version hints")
	}

	// Drupal 9/10 specific paths
	drupal9Paths := []string{
		"/core/lib/Drupal.php",
		"/core/lib/Drupal/Core/",
	}

	// Drupal 8 specific paths
	drupal8Paths := []string{
		"/core/lib/Drupal.php",
		"/core/includes/bootstrap.inc",
	}

	// Drupal 7 specific paths
	drupal7Paths := []string{
		"/includes/bootstrap.inc",
		"/includes/database/database.inc",
	}

	// Check for Drupal 9/10
	for _, path := range drupal9Paths {
		resp, err := p.client.Get(targetURL + path)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				fingerprint.AdditionalInfo["drupal_major_version"] = "9+"
				if p.verbose {
					p.logVerbose("Detected Drupal 9+ based on directory structure")
				}
				break
			}
		}
	}

	// Check for Drupal 8
	if _, ok := fingerprint.AdditionalInfo["drupal_major_version"]; !ok {
		for _, path := range drupal8Paths {
			resp, err := p.client.Get(targetURL + path)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					fingerprint.AdditionalInfo["drupal_major_version"] = "8"
					if p.verbose {
						p.logVerbose("Detected Drupal 8 based on directory structure")
					}
					break
				}
			}
		}
	}

	// Check for Drupal 7
	if _, ok := fingerprint.AdditionalInfo["drupal_major_version"]; !ok {
		for _, path := range drupal7Paths {
			resp, err := p.client.Get(targetURL + path)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					fingerprint.AdditionalInfo["drupal_major_version"] = "7"
					if p.verbose {
						p.logVerbose("Detected Drupal 7 based on directory structure")
					}
					break
				}
			}
		}
	}

	if p.verbose {
		if fingerprint.Version != "Unknown" {
			p.logVerbose("Drupal fingerprinting complete. Version: %s, Confidence: %.1f%%",
				fingerprint.Version, fingerprint.VersionConfidence*100)
		} else {
			p.logVerbose("Drupal fingerprinting complete. Version could not be determined.")
		}
	}

	return fingerprint, nil
}

// EnumerateComponents lists installed modules and themes
func (p *DrupalPlugin) EnumerateComponents(targetURL string) ([]*core.Component, error) {
	if p.verbose {
		p.logVerbose("Starting Drupal component enumeration on %s", targetURL)
	}

	components := make([]*core.Component, 0)

	// Common Drupal modules to check
	commonModules := []string{
		"views", "ctools", "token", "pathauto", "webform",
		"admin_menu", "entity", "field_group", "imce", "ckeditor",
		"google_analytics", "metatag", "date", "link", "colorbox",
		"features", "rules", "media", "entityreference", "libraries",
		"panels", "xmlsitemap", "captcha", "wysiwyg", "jquery_update",
	}

	if p.verbose {
		p.logVerbose("Checking for %d common Drupal modules", len(commonModules))
	}

	// Determine module paths based on Drupal version
	modulePaths := []string{
		"/modules/",
		"/sites/all/modules/",
		"/sites/default/modules/",
	}

	// Add Drupal 8+ paths
	modulePaths = append(modulePaths,
		"/modules/contrib/",
		"/core/modules/",
		"/sites/all/modules/contrib/",
		"/sites/default/modules/contrib/",
	)

	// Check for modules
	for _, module := range commonModules {
		moduleFound := false

		for _, basePath := range modulePaths {
			// Check if module exists by requesting its directory
			moduleUrl := fmt.Sprintf("%s%s%s/", targetURL, basePath, module)

			if p.verbose {
				p.logVerbose("Checking for module: %s at %s", module, moduleUrl)
			}

			resp, err := p.client.Get(moduleUrl)
			if err == nil {
				defer resp.Body.Close()

				// If we get a 200 or 403, the module likely exists
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					if p.verbose {
						p.logVerbose("Module detected: %s (status: %d)", module, resp.StatusCode)
					}

					// Try to get module version from .info file
					version := "Unknown"
					infoUrl := fmt.Sprintf("%s%s%s/%s.info", targetURL, basePath, module, module)
					infoResp, err := p.client.Get(infoUrl)
					if err == nil {
						defer infoResp.Body.Close()
						if infoResp.StatusCode == http.StatusOK {
							buf := make([]byte, 50*1024)
							n, _ := infoResp.Body.Read(buf)
							body := string(buf[:n])

							// Check for version in .info file
							versionPattern := `(?i)version\s*=\s*["']?([0-9x.]+)["']?`
							reVersion := regexp.MustCompile(versionPattern)
							matchesVersion := reVersion.FindStringSubmatch(body)
							if len(matchesVersion) > 1 {
								version = matchesVersion[1]
								if p.verbose {
									p.logVerbose("Found module %s version: %s", module, version)
								}
							}
						}
					}

					components = append(components, &core.Component{
						Name:     module,
						Type:     "module",
						Version:  version,
						Location: fmt.Sprintf("%s%s/", basePath, module),
						Active:   true, // Assuming active for the proof of concept
					})

					moduleFound = true
					break
				} else if p.verbose {
					p.logVerbose("Module %s not found at %s (status: %d)", module, moduleUrl, resp.StatusCode)
				}
			} else if p.verbose {
				p.logVerbose("Error checking module %s at %s: %v", module, moduleUrl, err)
			}
		}

		if p.verbose && !moduleFound {
			p.logVerbose("Module %s not found in any standard location", module)
		}
	}

	// Common Drupal themes to check
	commonThemes := []string{
		"bartik", "seven", "garland", "stark", "classy",
		"stable", "bootstrap", "zen", "omega", "adaptive_theme",
		"business", "corporate", "professional", "responsive_blog", "bluemasters",
		"danland", "marinelli", "mayo", "nucleus", "pixture_reloaded",
	}

	if p.verbose {
		p.logVerbose("Checking for %d common Drupal themes", len(commonThemes))
	}

	// Determine theme paths based on Drupal version
	themePaths := []string{
		"/themes/",
		"/sites/all/themes/",
		"/sites/default/themes/",
	}

	// Add Drupal 8+ paths
	themePaths = append(themePaths,
		"/themes/contrib/",
		"/core/themes/",
		"/sites/all/themes/contrib/",
		"/sites/default/themes/contrib/",
	)

	// Check for themes
	for _, theme := range commonThemes {
		themeFound := false

		for _, basePath := range themePaths {
			// Check if theme exists by requesting its directory
			themeUrl := fmt.Sprintf("%s%s%s/", targetURL, basePath, theme)

			if p.verbose {
				p.logVerbose("Checking for theme: %s at %s", theme, themeUrl)
			}

			resp, err := p.client.Get(themeUrl)
			if err == nil {
				defer resp.Body.Close()

				// If we get a 200 or 403, the theme likely exists
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
					if p.verbose {
						p.logVerbose("Theme detected: %s (status: %d)", theme, resp.StatusCode)
					}

					// Try to get theme version from .info file
					version := "Unknown"
					infoUrl := fmt.Sprintf("%s%s%s/%s.info", targetURL, basePath, theme, theme)
					infoResp, err := p.client.Get(infoUrl)
					if err == nil {
						defer infoResp.Body.Close()
						if infoResp.StatusCode == http.StatusOK {
							buf := make([]byte, 50*1024)
							n, _ := infoResp.Body.Read(buf)
							body := string(buf[:n])

							// Check for version in .info file
							versionPattern := `(?i)version\s*=\s*["']?([0-9x.]+)["']?`
							reVersion := regexp.MustCompile(versionPattern)
							matchesVersion := reVersion.FindStringSubmatch(body)
							if len(matchesVersion) > 1 {
								version = matchesVersion[1]
								if p.verbose {
									p.logVerbose("Found theme %s version: %s", theme, version)
								}
							}
						}
					}

					components = append(components, &core.Component{
						Name:     theme,
						Type:     "theme",
						Version:  version,
						Location: fmt.Sprintf("%s%s/", basePath, theme),
						Active:   false, // Can't determine if active without more analysis
					})

					themeFound = true
					break
				} else if p.verbose {
					p.logVerbose("Theme %s not found at %s (status: %d)", theme, themeUrl, resp.StatusCode)
				}
			} else if p.verbose {
				p.logVerbose("Error checking theme %s at %s: %v", theme, themeUrl, err)
			}
		}

		if p.verbose && !themeFound {
			p.logVerbose("Theme %s not found in any standard location", theme)
		}
	}

	// Try to detect active theme from homepage
	if p.verbose {
		p.logVerbose("Checking for active Drupal theme")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Look for theme in body class
			themePattern := `<body[^>]+class="[^"]*(?:theme|page)-([-_a-zA-Z0-9]+)`
			re := regexp.MustCompile(themePattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				themeName := matches[1]
				if p.verbose {
					p.logVerbose("Active theme detected: %s", themeName)
				}

				// Check if we already have this theme
				themeFound := false
				for i, comp := range components {
					if comp.Type == "theme" && comp.Name == themeName {
						components[i].Active = true
						themeFound = true
						if p.verbose {
							p.logVerbose("Marked theme %s as active", themeName)
						}
						break
					}
				}

				// If not found, add it
				if !themeFound {
					components = append(components, &core.Component{
						Name:     themeName,
						Type:     "theme",
						Version:  "Unknown",
						Location: "Unknown",
						Active:   true, // Assuming active if detected as the current theme
					})
					if p.verbose {
						p.logVerbose("Added new active theme %s", themeName)
					}
				}
			} else if p.verbose {
				p.logVerbose("No active theme detected in body class")
			}
		} else if p.verbose {
			p.logVerbose("Homepage response status: %d", resp.StatusCode)
		}
	} else if p.verbose {
		p.logVerbose("Error accessing homepage for active theme detection: %v", err)
	}

	if p.verbose {
		p.logVerbose("Drupal component enumeration complete. Found %d components.", len(components))
	}

	return components, nil
}

// ScanVulnerabilities performs Drupal-specific vulnerability checks
func (p *DrupalPlugin) ScanVulnerabilities(targetURL string, fingerprint *core.CMSFingerprint) ([]*core.Vulnerability, error) {
	// TODO: Implement vulnerability scanning logic for Drupal
	return nil, nil
}
