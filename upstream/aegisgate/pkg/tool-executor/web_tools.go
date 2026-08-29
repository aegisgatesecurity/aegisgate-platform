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
	"strings"
	"syscall"
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
			Transport: &http.Transport{
				DialContext: newSSRFSafeDialer(timeout).DialContext,
			},
		},
		timeout: timeout,
	}
}

// ssrfSafeDialer wraps net.Dialer with a Control function that checks
// the resolved IP address AFTER DNS resolution but BEFORE the TCP
// connection completes. This prevents DNS-rebinding attacks where
// isBlockedHost() passes on the hostname but the DNS server returns
// an internal IP.
type ssrfSafeDialer struct {
	*net.Dialer
}

func newSSRFSafeDialer(timeout time.Duration) *ssrfSafeDialer {
	return &ssrfSafeDialer{
		Dialer: &net.Dialer{
			Timeout: timeout,
			Control: ssrfControl,
		},
	}
}

// ssrfControl is the Dialer.Control callback that fires after DNS
// resolution. The address parameter contains the resolved IP:port,
// not the hostname. We parse the IP and reject if it's internal.
func ssrfControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("ssrf: failed to parse address %q: %w", address, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("ssrf: failed to parse IP from %q", host)
	}

	if isBlockedIP(ip) {
		return fmt.Errorf("blocked: resolved IP %s is internal or reserved (SSRF protection)", ip)
	}

	return nil
}

// isBlockedIP checks if a resolved net.IP targets an internal, private,
// or reserved network range. This is the IP-level equivalent of
// isBlockedHost() and catches DNS-rebinding attacks where the hostname
// passes string checks but resolves to an internal address.
func isBlockedIP(ip net.IP) bool {
	// Loopback (127.0.0.0/8, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Private ranges (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	if ip.IsPrivate() {
		return true
	}

	// Link-local (169.254.0.0/16, fe80::/10) — includes cloud metadata
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// Unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return true
	}

	// IPv6 unique-local (fc00::/7)
	if ip.IsPrivate() {
		return true
	}

	// Block IPv4-mapped IPv6 addresses (::ffff:127.0.0.1 etc.)
	if v4 := ip.To4(); v4 != nil && v4.IsLoopback() {
		return true
	}

	return false
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

// validateURL ensures the URL is allowed and blocks SSRF attacks
// targeting internal networks, cloud metadata, and localhost.
func (e *WebTools) validateURL(urlStr string) error {
	// SECURITY: Block SSRF — always reject internal/private/metadata URLs
	// regardless of allowedDomains configuration. This is defense-in-depth
	// even when allowedDomains is empty (allow-all mode).
	parsed, err := urlParse(urlStr)
	if err != nil {
		return errors.New("invalid URL")
	}

	// Block non-HTTP schemes
	scheme := parsed.Scheme()
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scheme not allowed: %s (only http/https)", scheme)
	}

	host := parsed.Hostname()

	// SECURITY: SSRF protection — block internal/private/metadata hostnames
	// This runs BEFORE the allowedDomains check so it can't be bypassed.
	if isBlockedHost(host) {
		return fmt.Errorf("blocked: target host %q is internal or reserved (SSRF protection)", host)
	}

	// Check against allowedDomains if configured
	if len(e.allowedDomains) > 0 {
		domainAllowed := false
		for _, domain := range e.allowedDomains {
			if strings.HasSuffix(host, domain) || host == domain {
				domainAllowed = true
				break
			}
		}
		if !domainAllowed {
			return fmt.Errorf("domain not allowed: %s", host)
		}
	}

	return nil
}

// isBlockedHost checks if a hostname targets an internal, private, or reserved
// network range that should be blocked for SSRF protection.
func isBlockedHost(host string) bool {
	// Lowercase for comparison
	host = strings.ToLower(strings.TrimSpace(host))

	// Block localhost variants
	if host == "localhost" || host == "localhost." {
		return true
	}
	if strings.HasSuffix(host, ".localhost") {
		return true
	}

	// Block IPv4/IPv6 loopback
	if host == "127.0.0.1" || strings.HasPrefix(host, "127.") {
		return true
	}
	if host == "::1" || host == "0:0:0:0:0:0:0:1" {
		return true
	}

	// Block cloud metadata endpoints
	if host == "169.254.169.254" { // AWS/Azure/GCP metadata
		return true
	}
	if host == "metadata.google.internal" { // GCP metadata (also accessible via DNS)
		return true
	}
	if host == "metadata.azure.com" { // Azure metadata
		return true
	}

	// Block link-local addresses (169.254.0.0/16)
	if strings.HasPrefix(host, "169.254.") {
		return true
	}

	// Block private IPv4 ranges (RFC 1918)
	if strings.HasPrefix(host, "10.") {
		return true
	}
	if strings.HasPrefix(host, "172.") {
		// 172.16.0.0 – 172.31.255.255
		parts := strings.SplitN(host, ".", 4)
		if len(parts) >= 2 {
			if parts[0] == "172" && len(parts[1]) > 0 {
				second := parts[1]
				if second >= "16" && second <= "31" {
					return true
				}
			}
		}
	}
	if strings.HasPrefix(host, "192.168.") {
		return true
	}

	// Block 0.0.0.0 (unspecified)
	if host == "0.0.0.0" {
		return true
	}

	// Block IPv6 unique-local (fc00::/7, fd00::/7)
	if strings.HasPrefix(host, "fc") || strings.HasPrefix(host, "fd") {
		return true
	}
	// Block IPv6 link-local (fe80::/10)
	if strings.HasPrefix(host, "fe80") || strings.HasPrefix(host, "fe8") {
		return true
	}
	// Block IPv6 loopback (::1)
	if strings.HasPrefix(host, "::") {
		return true
	}

	return false
}

// urlParse is a wrapper for net/url Parse to allow testing
var urlParse = func(rawURL string) (*urlInfo, error) {
	// Simple URL parsing without net/url import for isolation
	scheme := "https"
	if strings.HasPrefix(rawURL, "http://") {
		scheme = "http"
		rawURL = strings.TrimPrefix(rawURL, "http://")
	} else if strings.HasPrefix(rawURL, "https://") {
		scheme = "https"
		rawURL = strings.TrimPrefix(rawURL, "https://")
	} else {
		rawURL = "https://" + rawURL
		rawURL = strings.TrimPrefix(rawURL, "https://")
	}

	// Basic validation
	if len(rawURL) > 4096 {
		return nil, errors.New("URL too long")
	}

	// Extract host (simplified - in production use net/url)
	host := rawURL
	if idx := strings.Index(host, "/"); idx > 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, "?"); idx > 0 {
		host = host[:idx]
	}
	// Strip port for host validation
	if idx := strings.Index(host, ":"); idx > 0 {
		host = host[:idx]
	}

	return &urlInfo{host: host, scheme: scheme}, nil
}

type urlInfo struct {
	host   string
	scheme string
}

// Host returns the host from parsed URL
func (u *urlInfo) Hostname() string {
	return u.host
}

// Scheme returns the URL scheme
func (u *urlInfo) Scheme() string {
	return u.scheme
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
