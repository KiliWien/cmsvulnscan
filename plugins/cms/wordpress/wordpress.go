package wordpress

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/user/cmsvulnscan/lib/core"
)

// WordPressPlugin implements the core.CMSPlugin interface for WordPress
type WordPressPlugin struct {
	client  *http.Client
	verbose bool
	logger  *log.Logger
}

// NewWordPressPlugin creates a new WordPress plugin instance
func NewWordPressPlugin() *WordPressPlugin {
	return &WordPressPlugin{
		client:  &http.Client{Timeout: core.DefaultScanOptions().Timeout},
		verbose: false,
		logger:  log.New(log.Writer(), "[WordPress] ", log.LstdFlags),
	}
}

// SetVerbose enables or disables verbose logging
func (p *WordPressPlugin) SetVerbose(verbose bool) {
	p.verbose = verbose
}

// logVerbose logs a message if verbose mode is enabled
func (p *WordPressPlugin) logVerbose(format string, args ...interface{}) {
	if p.verbose {
		p.logger.Printf(format, args...)
	}
}

// GetName returns the name of the CMS
func (p *WordPressPlugin) GetName() string {
	return "WordPress"
}

// Detect determines if the target is running WordPress
func (p *WordPressPlugin) Detect(targetURL string) (bool, error) {
	if p.verbose {
		p.logVerbose("Starting WordPress detection on %s", targetURL)
	}

	// Common WordPress detection patterns
	patterns := []struct {
		path    string
		pattern string
	}{
		{"/wp-login.php", "(?i)wordpress"},
		{"/wp-admin/", "(?i)wordpress"},
		{"/wp-content/", "(?i)wordpress"},
		{"/wp-includes/", "(?i)wordpress"},
		{"/xmlrpc.php", "(?i)XML-RPC server accepts POST requests only"},
		{"/", "(?i)wp-content"},
		{"/", "(?i)wp-includes"},
		{"/", "(?i)wp-json"},
		{"/", "(?i)content=\"WordPress"},
		{"/", "(?i)wp-embed.min.js"},
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
				p.logVerbose("WordPress detected! Pattern '%s' matched at %s", pattern.pattern, url)
			}
			return true, nil
		} else if p.verbose {
			p.logVerbose("Pattern '%s' not found at %s", pattern.pattern, url)
		}
	}

	// Check for WordPress meta generator tag
	if p.verbose {
		p.logVerbose("Checking for WordPress meta generator tag")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			metaPattern := `<meta\s+name=["']generator["']\s+content=["']WordPress([^"']*)["']`
			re := regexp.MustCompile(metaPattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 0 {
				if p.verbose {
					p.logVerbose("WordPress detected via meta generator tag! Version hint: %s", matches[1])
				}
				return true, nil
			}
		}
	}

	if p.verbose {
		p.logVerbose("WordPress not detected on %s", targetURL)
	}
	return false, nil
}

// Fingerprint identifies the version and components
func (p *WordPressPlugin) Fingerprint(targetURL string) (*core.CMSFingerprint, error) {
	if p.verbose {
		p.logVerbose("Starting WordPress fingerprinting on %s", targetURL)
	}

	fingerprint := &core.CMSFingerprint{
		CMSName:           p.GetName(),
		Version:           "Unknown",
		VersionConfidence: 0.0,
		Headers:           make(map[string]string),
		AdditionalInfo:    make(map[string]interface{}),
	}

	// Try to get version from meta generator tag
	if p.verbose {
		p.logVerbose("Checking for version in meta generator tag")
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

			// Check for version in meta generator tag
			metaPattern := `<meta\s+name=["']generator["']\s+content=["']WordPress\s+([0-9.]+)["']`
			re := regexp.MustCompile(metaPattern)
			matches := re.FindStringSubmatch(body)
			if len(matches) > 1 {
				fingerprint.Version = matches[1]
				fingerprint.VersionConfidence = 0.9
				if p.verbose {
					p.logVerbose("Found WordPress version %s in meta generator tag (confidence: 90%%)", matches[1])
				}
			}

			// Check for version in RSS feed
			if fingerprint.Version == "Unknown" {
				rssPattern := `<generator>https://wordpress.org/\?v=([0-9.]+)</generator>`
				reRSS := regexp.MustCompile(rssPattern)
				matchesRSS := reRSS.FindStringSubmatch(body)
				if len(matchesRSS) > 1 {
					fingerprint.Version = matchesRSS[1]
					fingerprint.VersionConfidence = 0.8
					if p.verbose {
						p.logVerbose("Found WordPress version %s in RSS feed (confidence: 80%%)", matchesRSS[1])
					}
				}
			}
		}
	}

	// Try to get version from readme.html
	if fingerprint.Version == "Unknown" {
		if p.verbose {
			p.logVerbose("Version not found in meta tags, checking readme.html")
		}

		resp, err := p.client.Get(targetURL + "/readme.html")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				buf := make([]byte, 50*1024)
				n, _ := resp.Body.Read(buf)
				body := string(buf[:n])

				// Check for version in readme.html
				readmePattern := `(?i)<br />\s*[vV]ersion\s+([0-9.]+)`
				reReadme := regexp.MustCompile(readmePattern)
				matchesReadme := reReadme.FindStringSubmatch(body)
				if len(matchesReadme) > 1 {
					fingerprint.Version = matchesReadme[1]
					fingerprint.VersionConfidence = 0.95
					if p.verbose {
						p.logVerbose("Found WordPress version %s in readme.html (confidence: 95%%)", matchesReadme[1])
					}
				}
			} else if p.verbose {
				p.logVerbose("readme.html returned status %d", resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error accessing readme.html: %v", err)
		}
	}

	// Try to get version from feed
	if fingerprint.Version == "Unknown" {
		if p.verbose {
			p.logVerbose("Version not found in readme.html, checking feed")
		}

		resp, err := p.client.Get(targetURL + "/feed/")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				buf := make([]byte, 50*1024)
				n, _ := resp.Body.Read(buf)
				body := string(buf[:n])

				// Check for version in feed
				feedPattern := `<generator>https://wordpress.org/\?v=([0-9.]+)</generator>`
				reFeed := regexp.MustCompile(feedPattern)
				matchesFeed := reFeed.FindStringSubmatch(body)
				if len(matchesFeed) > 1 {
					fingerprint.Version = matchesFeed[1]
					fingerprint.VersionConfidence = 0.9
					if p.verbose {
						p.logVerbose("Found WordPress version %s in feed (confidence: 90%%)", matchesFeed[1])
					}
				}
			} else if p.verbose {
				p.logVerbose("feed/ returned status %d", resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error accessing feed/: %v", err)
		}
	}

	// Check for WordPress version in JavaScript files
	if fingerprint.Version == "Unknown" {
		if p.verbose {
			p.logVerbose("Version not found in feed, checking wp-includes/js/wp-emoji-release.min.js")
		}

		resp, err := p.client.Get(targetURL + "/wp-includes/js/wp-emoji-release.min.js")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				buf := make([]byte, 50*1024)
				n, _ := resp.Body.Read(buf)
				body := string(buf[:n])

				// Check for version in JavaScript
				jsPattern := `wpEmoji.version\s*=\s*["']([0-9.]+)["']`
				reJS := regexp.MustCompile(jsPattern)
				matchesJS := reJS.FindStringSubmatch(body)
				if len(matchesJS) > 1 {
					fingerprint.Version = matchesJS[1]
					fingerprint.VersionConfidence = 0.85
					if p.verbose {
						p.logVerbose("Found WordPress version %s in JavaScript (confidence: 85%%)", matchesJS[1])
					}
				}
			} else if p.verbose {
				p.logVerbose("wp-emoji-release.min.js returned status %d", resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error accessing wp-emoji-release.min.js: %v", err)
		}
	}

	if p.verbose {
		if fingerprint.Version != "Unknown" {
			p.logVerbose("WordPress fingerprinting complete. Version: %s, Confidence: %.1f%%",
				fingerprint.Version, fingerprint.VersionConfidence*100)
		} else {
			p.logVerbose("WordPress fingerprinting complete. Version could not be determined.")
		}
	}

	return fingerprint, nil
}

// EnumerateComponents lists installed plugins and themes
func (p *WordPressPlugin) EnumerateComponents(targetURL string) ([]*core.Component, error) {
	if p.verbose {
		p.logVerbose("Starting WordPress component enumeration on %s", targetURL)
	}

	components := make([]*core.Component, 0)

	// Common WordPress plugins to check
	commonPlugins := []string{
		"akismet", "contact-form-7", "woocommerce", "jetpack", "yoast-seo",
		"wordfence", "elementor", "wp-super-cache", "all-in-one-seo-pack", "google-analytics-for-wordpress",
		"ninja-forms", "wpforms-lite", "duplicate-post", "classic-editor", "tinymce-advanced",
		"wp-mail-smtp", "redirection", "wordpress-seo", "wp-optimize", "advanced-custom-fields",
		"bbpress", "wp-smushit", "updraftplus", "really-simple-ssl", "w3-total-cache",
	}

	if p.verbose {
		p.logVerbose("Checking for %d common WordPress plugins", len(commonPlugins))
	}

	// Check for plugins
	for _, plugin := range commonPlugins {
		// Check if plugin exists by requesting its directory
		pluginUrl := fmt.Sprintf("%s/wp-content/plugins/%s/", targetURL, plugin)

		if p.verbose {
			p.logVerbose("Checking for plugin: %s at %s", plugin, pluginUrl)
		}

		resp, err := p.client.Get(pluginUrl)
		if err == nil {
			defer resp.Body.Close()

			// If we get a 200 or 403, the plugin likely exists
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
				if p.verbose {
					p.logVerbose("Plugin detected: %s (status: %d)", plugin, resp.StatusCode)
				}

				// Try to get plugin version from readme.txt
				version := "Unknown"
				readmeUrl := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", targetURL, plugin)
				readmeResp, err := p.client.Get(readmeUrl)
				if err == nil {
					defer readmeResp.Body.Close()
					if readmeResp.StatusCode == http.StatusOK {
						buf := make([]byte, 50*1024)
						n, _ := readmeResp.Body.Read(buf)
						body := string(buf[:n])

						// Check for version in readme.txt
						versionPattern := `(?i)Stable tag:\s*([0-9.]+)`
						reVersion := regexp.MustCompile(versionPattern)
						matchesVersion := reVersion.FindStringSubmatch(body)
						if len(matchesVersion) > 1 {
							version = matchesVersion[1]
							if p.verbose {
								p.logVerbose("Found plugin %s version: %s", plugin, version)
							}
						}
					}
				}

				components = append(components, &core.Component{
					Name:     plugin,
					Type:     "plugin",
					Version:  version,
					Location: fmt.Sprintf("/wp-content/plugins/%s/", plugin),
					Active:   true, // Assuming active for the proof of concept
				})
			} else if p.verbose {
				p.logVerbose("Plugin %s not found (status: %d)", plugin, resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error checking plugin %s: %v", plugin, err)
		}
	}

	// Common WordPress themes to check
	commonThemes := []string{
		"twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen", "twentysixteen",
		"twentyfifteen", "twentyfourteen", "twentythirteen", "twentytwelve", "twentyeleven",
		"twentyten", "astra", "generatepress", "oceanwp", "neve",
		"hello-elementor", "storefront", "divi", "avada", "sydney",
	}

	if p.verbose {
		p.logVerbose("Checking for %d common WordPress themes", len(commonThemes))
	}

	// Check for themes
	for _, theme := range commonThemes {
		// Check if theme exists by requesting its directory
		themeUrl := fmt.Sprintf("%s/wp-content/themes/%s/", targetURL, theme)

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

				// Try to get theme version from style.css
				version := "Unknown"
				styleUrl := fmt.Sprintf("%s/wp-content/themes/%s/style.css", targetURL, theme)
				styleResp, err := p.client.Get(styleUrl)
				if err == nil {
					defer styleResp.Body.Close()
					if styleResp.StatusCode == http.StatusOK {
						buf := make([]byte, 50*1024)
						n, _ := styleResp.Body.Read(buf)
						body := string(buf[:n])

						// Check for version in style.css
						versionPattern := `(?i)Version:\s*([0-9.]+)`
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
					Location: fmt.Sprintf("/wp-content/themes/%s/", theme),
					Active:   false, // Can't determine if active without more analysis
				})
			} else if p.verbose {
				p.logVerbose("Theme %s not found (status: %d)", theme, resp.StatusCode)
			}
		} else if p.verbose {
			p.logVerbose("Error checking theme %s: %v", theme, err)
		}
	}

	// Try to detect active theme from homepage
	if p.verbose {
		p.logVerbose("Checking for active WordPress theme")
	}

	resp, err := p.client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			buf := make([]byte, 50*1024)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])

			// Look for theme in body class
			themePattern := `<body[^>]+class="[^"]*theme-([a-zA-Z0-9_-]+)`
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
						Location: fmt.Sprintf("/wp-content/themes/%s/", themeName),
						Active:   true,
					})

					if p.verbose {
						p.logVerbose("Added active theme %s to components", themeName)
					}
				}
			} else if p.verbose {
				p.logVerbose("Could not detect active theme from body class")
			}
		}
	}

	if p.verbose {
		p.logVerbose("WordPress component enumeration complete. Found %d components", len(components))
	}

	return components, nil
}

// ScanVulnerabilities performs WordPress-specific vulnerability checks
func (p *WordPressPlugin) ScanVulnerabilities(targetURL string, fingerprint *core.CMSFingerprint) ([]*core.Vulnerability, error) {
	// TODO: Implement vulnerability scanning logic for WordPress
	return nil, nil
}
