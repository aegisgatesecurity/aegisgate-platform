// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package security provides XSS protection middleware and utilities
package security

import (
	"html"
	"net/http"
	"strings"
)

// XSSConfig holds configuration for XSS protection
type XSSConfig struct {
	ContentSecurityPolicy string
	EnableCSP             bool
	EnableCSPReportOnly   bool
	CSPReportURI          string
	XSSProtection         bool
	ContentTypeOptions    bool
	FrameOptions          string
	ReferrerPolicy        string
	PermissionsPolicy     string
	AllowInlineScripts    bool
}

// DefaultXSSConfig returns secure default XSS protection configuration
func DefaultXSSConfig() *XSSConfig {
	return &XSSConfig{
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
		EnableCSP:             true,
		EnableCSPReportOnly:   false,
		CSPReportURI:          "",
		XSSProtection:         true,
		ContentTypeOptions:    true,
		FrameOptions:          "DENY",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		PermissionsPolicy:     "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
		AllowInlineScripts:    false,
	}
}

// XSSProtectionMiddleware provides XSS protection through security headers
type XSSProtectionMiddleware struct {
	config *XSSConfig
}

// NewXSSProtectionMiddleware creates a new XSS protection middleware
func NewXSSProtectionMiddleware(config *XSSConfig) *XSSProtectionMiddleware {
	if config == nil {
		config = DefaultXSSConfig()
	}
	return &XSSProtectionMiddleware{config: config}
}

// Handler wraps an HTTP handler with XSS protection headers
func (x *XSSProtectionMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if x.config.ContentTypeOptions {
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		if x.config.FrameOptions != "" {
			w.Header().Set("X-Frame-Options", x.config.FrameOptions)
		}
		if x.config.XSSProtection {
			w.Header().Set("X-XSS-Protection", "1; mode=block")
		}
		if x.config.ReferrerPolicy != "" {
			w.Header().Set("Referrer-Policy", x.config.ReferrerPolicy)
		}
		if x.config.PermissionsPolicy != "" {
			w.Header().Set("Permissions-Policy", x.config.PermissionsPolicy)
		}
		if x.config.EnableCSP && x.config.ContentSecurityPolicy != "" {
			csp := x.config.ContentSecurityPolicy
			if x.config.CSPReportURI != "" {
				csp += " report-uri " + x.config.CSPReportURI
			}
			if x.config.EnableCSPReportOnly {
				w.Header().Set("Content-Security-Policy-Report-Only", csp)
			} else {
				w.Header().Set("Content-Security-Policy", csp)
			}
		}
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	})
}

// SanitizeHTML escapes HTML entities to prevent XSS
func SanitizeHTML(input string) string {
	if input == "" {
		return ""
	}
	return html.EscapeString(input)
}

// StripTags removes all HTML tags from input
// For script and style tags, also removes their content
func StripTags(input string) string {
	// First pass: remove script tags and their contents
	// Handle both <script>...</script> and <script ...>...</script>
	result := input
	scripts := true
	for scripts {
		startIdx := strings.Index(strings.ToLower(result), "<script")
		if startIdx == -1 {
			scripts = false
			continue
		}
		endIdx := strings.Index(strings.ToLower(result[startIdx:]), "</script>")
		if endIdx == -1 {
			// No closing tag, remove from start to end
			result = result[:startIdx]
			scripts = false
		} else {
			endIdx += startIdx + len("</script>")
			result = result[:startIdx] + result[endIdx:]
		}
	}

	// Second pass: remove style tags and their contents
	styles := true
	for styles {
		startIdx := strings.Index(strings.ToLower(result), "<style")
		if startIdx == -1 {
			styles = false
			continue
		}
		endIdx := strings.Index(strings.ToLower(result[startIdx:]), "</style>")
		if endIdx == -1 {
			result = result[:startIdx]
			styles = false
		} else {
			endIdx += startIdx + len("</style>")
			result = result[:startIdx] + result[endIdx:]
		}
	}

	// Third pass: remove all remaining HTML tags
	var output []rune
	inTag := false
	for _, ch := range result {
		if ch == '<' {
			inTag = true
			continue
		}
		if ch == '>' {
			inTag = false
			continue
		}
		if !inTag {
			output = append(output, ch)
		}
	}

	return strings.TrimSpace(string(output))
}

// IsValidURL checks if a URL is safe
func IsValidURL(url string) bool {
	lowerURL := strings.ToLower(strings.TrimSpace(url))
	dangerousSchemes := []string{"javascript:", "data:", "vbscript:", "file:", "about:"}
	for _, scheme := range dangerousSchemes {
		if strings.HasPrefix(lowerURL, scheme) {
			return false
		}
	}
	return true
}

// SafeRedirect validates a redirect URL for open redirect vulnerabilities
func SafeRedirect(url string, allowedHosts []string) string {
	if url == "" {
		return "/"
	}
	if strings.HasPrefix(url, "//") {
		url = "https:" + url
	}
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		for _, host := range allowedHosts {
			if strings.Contains(url, host) {
				return url
			}
		}
		return "/"
	}
	if !IsValidURL(url) {
		return "/"
	}
	return url
}
