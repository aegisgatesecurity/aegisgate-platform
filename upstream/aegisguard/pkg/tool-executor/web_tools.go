// Package tool-executor - Web tool implementations
package toolexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WebTools provides web-related tool executors
type WebTools struct {
	allowedDomains []string
	client         *http.Client
	timeout        time.Duration
}

// NewWebTools creates a new web tools executor
func NewWebTools(allowedDomains []string, timeout time.Duration) *WebTools {
	return &WebTools{
		allowedDomains: allowedDomains,
		client: &http.Client{
			Timeout: timeout,
			// SECURITY (H-2): Custom transport with SSRF-safe dialer.
			// Prevents DNS rebinding by checking the resolved IP immediately
			// before connecting, blocking private/loopback/link-local IPs.
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					host, port, err := net.SplitHostPort(addr)
					if err != nil {
						return nil, fmt.Errorf("invalid address: %w", err)
					}
					// Resolve hostname to IP(s)
					ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
					if err != nil {
						return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
					}
					for _, ipAddr := range ips {
						if isPrivateOrBlockedIP(ipAddr.IP) {
							return nil, fmt.Errorf("SSRF blocked: %s resolves to private/blocked IP %s", host, ipAddr.IP)
						}
					}
					// All resolved IPs are public — connect to the first one
					dialer := &net.Dialer{Timeout: 30 * time.Second}
					return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
				},
			},
		},
		timeout: timeout,
	}
}

// HTTPToolExecutor handles HTTP requests
type HTTPToolExecutor struct {
	tools *WebTools
}

// NewHTTPToolExecutor creates a new HTTP tool executor
func NewHTTPToolExecutor(tools *WebTools) *HTTPToolExecutor {
	return &HTTPToolExecutor{tools: tools}
}

// validateURL delegates to WebTools
func (e *HTTPToolExecutor) validateURL(url string) error {
	return e.tools.validateURL(url)
}

// Name returns the tool name
func (e *HTTPToolExecutor) Name() string {
	return "http_request"
}

// Execute performs an HTTP request
func (e *HTTPToolExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	url, ok := params["url"].(string)
	if !ok || url == "" {
		return nil, errors.New("url parameter required")
	}

	// Security: validate URL
	if err := e.validateURL(url); err != nil {
		return nil, err
	}

	method := "GET"
	if m, ok := params["method"].(string); ok {
		method = strings.ToUpper(m)
	}

	// Validate method
	validMethods := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true}
	if !validMethods[method] {
		return nil, errors.New("invalid HTTP method")
	}

	// Build request
	var body io.Reader
	if bodyParam, ok := params["body"].(string); ok && bodyParam != "" {
		body = strings.NewReader(bodyParam)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	if headers, ok := params["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	// Execute request
	resp, err := e.tools.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Build response
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return map[string]interface{}{
		"status_code": resp.StatusCode,
		"status":      resp.Status,
		"headers":     headers,
		"body":        string(respBody),
		"url":         url,
		"method":      method,
	}, nil
}

// Validate checks parameters
func (e *HTTPToolExecutor) Validate(params map[string]interface{}) error {
	url, ok := params["url"].(string)
	if !ok || url == "" {
		return errors.New("url parameter required")
	}
	return e.validateURL(url)
}

// Timeout returns the execution timeout
func (e *HTTPToolExecutor) Timeout() time.Duration {
	return e.tools.timeout
}

// RiskLevel returns the risk level
func (e *HTTPToolExecutor) RiskLevel() int {
	return int(RiskMedium)
}

// Description returns a description
func (e *HTTPToolExecutor) Description() string {
	return "Make HTTP requests"
}

// validateURL ensures the URL is allowed and not targeting private/internal resources.
// SECURITY (H-2): SSRF protection — always blocks:
//   - Loopback addresses (127.0.0.0/8, ::1)
//   - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
//   - Link-local addresses (169.254.0.0/16, fe80::/10)
//   - Cloud metadata endpoints (169.254.169.254, metadata.google.internal, etc.)
//   - Non-http(s) schemes
//
// If an allowlist is configured, only allowlisted domains are permitted.
// If no allowlist is configured, all public domains are allowed.
func (e *WebTools) validateURL(urlStr string) error {
	if len(urlStr) > 4096 {
		return errors.New("URL too long")
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Enforce http/https scheme only
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scheme not allowed: %s (only http/https)", scheme)
	}

	host := parsed.Hostname()
	if host == "" {
		return errors.New("URL has no host")
	}

	// Always block known-bad hosts (cloud metadata endpoints, localhost)
	if isBlockedMetadataHost(host) {
		return fmt.Errorf("SSRF blocked: cloud metadata endpoint %s", host)
	}
	if isBlockedHostname(host) {
		return fmt.Errorf("SSRF blocked: internal/loopback hostname %s", host)
	}

	// If the host is a literal IP address, check it against private ranges
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateOrBlockedIP(ip) {
			return fmt.Errorf("SSRF blocked: private/loopback IP %s", host)
		}
	}

	// If allowlist is configured, enforce it
	if len(e.allowedDomains) > 0 {
		allowed := false
		for _, domain := range e.allowedDomains {
			if host == domain || strings.HasSuffix(host, "."+domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("domain not in allowlist: %s", host)
		}
	}

	return nil
}

// isBlockedMetadataHost checks if the host is a known cloud metadata endpoint.
func isBlockedMetadataHost(host string) bool {
	lower := strings.ToLower(host)
	switch lower {
	case "metadata.google.internal",
		"metadata",
		"169.254.169.254",
		"metadata.aws.internal",
		"metadata.azure.com",
		"instance-data",
		"fd00:ec2::254": // AWS IPv6 metadata
		return true
	}
	// Block any subdomain of metadata endpoints
	if strings.HasSuffix(lower, ".metadata.google.internal") ||
		strings.HasSuffix(lower, ".metadata.aws.internal") ||
		strings.HasSuffix(lower, ".metadata.azure.com") {
		return true
	}
	return false
}

// isBlockedHostname checks if the hostname is a known internal/loopback name
// that should never be accessible from the MCP http_request tool.
func isBlockedHostname(host string) bool {
	lower := strings.ToLower(host)
	switch lower {
	case "localhost",
		"localhost.localdomain",
		"ip6-localhost",
		"ip6-loopback",
		"broadcasthost":
		return true
	}
	// Block .local mDNS addresses
	if strings.HasSuffix(lower, ".local") {
		return true
	}
	return false
}

// isPrivateOrBlockedIP checks if an IP address is private, loopback, link-local,
// or otherwise should be blocked for SSRF protection.
func isPrivateOrBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true // nil IP = block
	}
	// Loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}
	// Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
	if ip.IsPrivate() {
		return true
	}
	// Link-local (169.254.0.0/16, fe80::/10) — includes cloud metadata
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}
	// Explicitly block AWS metadata IP even if IsLinkLocal doesn't catch it
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	return false
}

// WebSearchExecutor handles web search operations
type WebSearchExecutor struct {
	tools *WebTools
}

// NewWebSearchExecutor creates a new web search executor
func NewWebSearchExecutor(tools *WebTools) *WebSearchExecutor {
	return &WebSearchExecutor{tools: tools}
}

// Name returns the tool name
func (e *WebSearchExecutor) Name() string {
	return "web_search"
}

// Execute performs a web search
func (e *WebSearchExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	query, ok := params["query"].(string)
	if !ok || query == "" {
		return nil, errors.New("query parameter required")
	}

	// Use DuckDuckGo as a simple search API (no API key required)
	searchURL := fmt.Sprintf("https://duckduckgo.com/html/?q=%s", urlEncode(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AegisGuard/1.0)")

	resp, err := e.tools.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Parse results (simplified - extract links)
	results := e.parseSearchResults(string(body))

	return map[string]interface{}{
		"query":   query,
		"results": results,
		"count":   len(results),
	}, nil
}

// Validate checks parameters
func (e *WebSearchExecutor) Validate(params map[string]interface{}) error {
	query, ok := params["query"].(string)
	if !ok || query == "" {
		return errors.New("query parameter required")
	}
	if len(query) > 500 {
		return errors.New("query too long")
	}
	return nil
}

// Timeout returns the execution timeout
func (e *WebSearchExecutor) Timeout() time.Duration {
	return 30 * time.Second
}

// RiskLevel returns the risk level
func (e *WebSearchExecutor) RiskLevel() int {
	return int(RiskLow)
}

// Description returns a description
func (e *WebSearchExecutor) Description() string {
	return "Search the web"
}

// parseSearchResults extracts search results from HTML (simplified)
func (e *WebSearchExecutor) parseSearchResults(html string) []map[string]string {
	results := make([]map[string]string, 0, 10)

	// Simple link extraction - in production use proper HTML parsing
	// Look for <a href="..." class="result__a">...</a>
	lines := strings.Split(html, "\n")
	for _, line := range lines {
		if strings.Contains(line, "class=\"result__a\"") {
			// Extract URL
			start := strings.Index(line, "href=\"")
			if start > 0 {
				start += 6
				end := strings.Index(line[start:], "\"")
				if end > 0 {
					url := line[start : start+end]
					if strings.HasPrefix(url, "http") {
						// Extract title
						titleStart := strings.Index(line, ">")
						titleEnd := strings.LastIndex(line, "<")
						title := ""
						if titleStart > 0 && titleEnd > titleStart {
							title = line[titleStart+1 : titleEnd]
							title = strings.TrimSpace(title)
						}

						if len(results) < 10 {
							results = append(results, map[string]string{
								"url":   url,
								"title": title,
							})
						}
					}
				}
			}
		}
	}

	return results
}

// urlEncode encodes a string for URL use
func urlEncode(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if r == ' ' || r == '&' || r == '=' || r == '%' || r == '?' || r == '+' {
			fmt.Fprintf(&buf, "%%%02X", r)
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

// JSONFetchExecutor fetches and parses JSON from a URL
type JSONFetchExecutor struct {
	tools *WebTools
}

// NewJSONFetchExecutor creates a new JSON fetch executor
func NewJSONFetchExecutor(tools *WebTools) *JSONFetchExecutor {
	return &JSONFetchExecutor{tools: tools}
}

// Name returns the tool name
func (e *JSONFetchExecutor) Name() string {
	return "json_fetch"
}

// Execute fetches and parses JSON
func (e *JSONFetchExecutor) Execute(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	url, ok := params["url"].(string)
	if !ok || url == "" {
		return nil, errors.New("url parameter required")
	}

	// Security: validate URL
	if err := e.tools.validateURL(url); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.tools.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, err
	}

	// Parse JSON
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return map[string]interface{}{
		"status_code": resp.StatusCode,
		"data":        data,
		"url":         url,
	}, nil
}

// Validate checks parameters
func (e *JSONFetchExecutor) Validate(params map[string]interface{}) error {
	url, ok := params["url"].(string)
	if !ok || url == "" {
		return errors.New("url parameter required")
	}
	return e.tools.validateURL(url)
}

// Timeout returns the execution timeout
func (e *JSONFetchExecutor) Timeout() time.Duration {
	return e.tools.timeout
}

// RiskLevel returns the risk level
func (e *JSONFetchExecutor) RiskLevel() int {
	return int(RiskMedium)
}

// Description returns a description
func (e *JSONFetchExecutor) Description() string {
	return "Fetch and parse JSON from URL"
}
