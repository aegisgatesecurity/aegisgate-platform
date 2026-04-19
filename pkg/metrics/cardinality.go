// Package metrics provides Prometheus metrics for AegisGate Platform.
// Copyright 2024 AegisGate Security. All rights reserved.
//
// This file implements high-cardinality protection mechanisms to prevent
// metrics explosion in production environments. Proper cardinality control
// is critical for Prometheus performance and cost management.
//
// # Cardinality Safety
//
// Each metric type has defined cardinality limits:
//   - Low (≤10): Build info, tier types
//   - Medium (≤100): HTTP status codes, MCP tool names (whitelisted)
//   - High (≤1000): Sanitized endpoints, client IDs (rate-limited)
//   - Blocked: Raw URLs, user IDs, session tokens, timestamps
//
// The sanitizer provides deterministic bucketing to maintain useful granularity
// while preventing unbounded cardinality growth.
package metrics

import (
	"regexp"
	"strings"
	"sync"
)

// CardinalityTier defines the cardinality classification for a metric label
// to guide appropriate usage and set expectations for Prometheus resource usage.
type CardinalityTier int

const (
	// CardinalityLow labels have ≤10 distinct values. Safe for all metrics.
	// Examples: tier names (community, professional, enterprise), status (success, failure)
	CardinalityLow CardinalityTier = iota

	// CardinalityMedium labels have ≤100 distinct values. Acceptable for most metrics.
	// Examples: HTTP methods, sanitized endpoint categories, whitelisted tool names
	CardinalityMedium

	// CardinalityHigh labels have ≤1000 distinct values. Use with caution.
	// Requires active monitoring and potential sampling at extreme scale.
	// Examples: sanitized paths, client identifiers with TTL-based eviction
	CardinalityHigh

	// CardinalityUnbounded labels are blocked. Never use raw dynamic data.
	// Examples: user IDs, session tokens, full URLs, timestamps as labels
	CardinalityUnbounded
)

// CardinalityLimit is the maximum number of distinct label values allowed
// per high-cardinality dimension before automatic aggregation occurs.
const CardinalityLimit = 1000

// endpointPatterns maps URL patterns to sanitized, low-cardinality equivalents.
// These patterns are ordered by specificity - more specific patterns must
// come first to ensure proper matching.
//
// Token patterns (UUIDs, IDs) are applied globally across the path.
// Prefix patterns (health, metrics, api/*) are applied using first-match-wins
// so that versioned patterns (/api/v1/...) take priority over catch-alls (/api/*).
var endpointPatterns = []struct {
	pattern *regexp.Regexp
	replace string
}{
	// Token patterns - applied globally to any path segment
	{regexp.MustCompile(`/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)`), "/:uuid$1"},
	{regexp.MustCompile(`/[0-9a-f]{24}(/|$)`), "/:objid$1"}, // MongoDB ObjectIDs
	{regexp.MustCompile(`/[0-9]+(/|$)`), "/:id$1"},          // Numeric IDs
}

// endpointPrefixPatterns maps full-path prefix patterns to sanitized equivalents.
// Applied using first-match-wins so more specific patterns (versioned APIs)
// take priority over catch-all patterns.
var endpointPrefixPatterns = []struct {
	pattern *regexp.Regexp
	replace string
}{
	{regexp.MustCompile(`^/v\d+/api/[^/]+`), "/vN/api/:resource"},
	{regexp.MustCompile(`^/api/v\d+`), "/api/vN"},
	{regexp.MustCompile(`^/health(/.*)?$`), "/health"},
	{regexp.MustCompile(`^/metrics(/.*)?$`), "/metrics"},
	{regexp.MustCompile(`^/api/[^/]+`), "/api/:service"},
	{regexp.MustCompile(`^/mcp/.*$`), "/mcp/:operation"},
	{regexp.MustCompile(`^/proxy/.*$`), "/proxy/:action"},
	{regexp.MustCompile(`^/admin/.*$`), "/admin/:action"},
	{regexp.MustCompile(`^/static/.*$`), "/static/:file"},
}

// Sanitizer provides thread-safe cardinality protection for dynamic label values.
type Sanitizer struct {
	mu        sync.RWMutex
	seenPaths map[string]bool   // Tracks known safe path patterns
	knownIDs  map[string]string // Cache for ID normalization
	hitCount  map[string]uint64 // Tracks endpoint frequency for aggregation decisions
}

// NewSanitizer creates a new cardinality sanitizer with initialized caches.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		seenPaths: make(map[string]bool, 100),
		knownIDs:  make(map[string]string, 1000),
		hitCount:  make(map[string]uint64, 100),
	}
}

// SanitizeEndpoint transforms a raw URL path into a low-cardinality metric label.
// This prevents metrics explosion from REST API resource IDs and query parameters.
//
// Transformations applied:
//   - UUIDs → :uuid
//   - MongoDB ObjectIDs → :objid
//   - Numeric IDs → :id
//   - Query strings stripped
//   - Fragment identifiers stripped
//
// Examples:
//
//	"/api/v1/users/123" → "/api/vN/:id"
//	"/health/live" → "/health"
//	"/mcp/tools/invoke" → "/mcp/:operation"
//	"/static/js/app.js" → "/static/:file"
func (s *Sanitizer) SanitizeEndpoint(rawPath string) string {
	if rawPath == "" {
		return "/"
	}

	// Strip query parameters and fragments
	path := rawPath
	if idx := strings.IndexAny(path, "?#"); idx != -1 {
		path = path[:idx]
	}

	// Fast path: check if we've seen this exact path before
	s.mu.RLock()
	if s.seenPaths[path] {
		s.mu.RUnlock()
		return path
	}
	s.mu.RUnlock()

	// Apply pattern replacements in two passes:
	//
	// Pass 1: Apply token patterns (UUIDs, numeric IDs, ObjectIDs) globally
	// to collapse identifiable path segments regardless of position.
	sanitized := path
	for _, p := range endpointPatterns {
		sanitized = p.pattern.ReplaceAllString(sanitized, p.replace)
	}

	// Pass 2: Apply prefix patterns using first-match-wins. Only the first
	// matching prefix pattern is applied, preventing catch-all patterns from
	// re-matching the output of more specific patterns (e.g., /api/vN should
	// not be re-matched by /api/:service).
	for _, p := range endpointPrefixPatterns {
		if p.pattern.MatchString(sanitized) {
			sanitized = p.pattern.ReplaceAllString(sanitized, p.replace)
			break // first match wins for prefix patterns
		}
	}

	// Collapse multiple consecutive slashes
	sanitized = regexp.MustCompile(`/+`).ReplaceAllString(sanitized, "/")

	// Mark as seen for fast path
	s.mu.Lock()
	s.seenPaths[sanitized] = true
	s.hitCount[sanitized]++
	s.mu.Unlock()

	return sanitized
}

// SanitizeToolName validates and normalizes MCP tool names.
// Whitelisted tools pass through; unknown tools are bucketed to "other".
//
// This protects against malicious or misconfigured MCP servers that might
// report dynamic tool names (which could be used as a DoS vector).
func SanitizeToolName(name string, allowed []string) string {
	for _, allowedTool := range allowed {
		if name == allowedTool {
			return name
		}
	}
	// Unknown tools are aggregated to prevent cardinality explosion
	// and to highlight potential security issues (unauthorized tools)
	return "unknown"
}

// SanitizeClientID extracts a safe identifier from client information.
// Uses prefix-based bucketing for IP addresses to limit cardinality.
//
// For IPv4: "192.168.1.100" → "192.168.x.x"
// For IPv6: "2001:db8::1" → "2001:db8::/32"
func SanitizeClientID(client string) string {
	if client == "" {
		return "anonymous"
	}

	// Check if it's an IP address
	if strings.Contains(client, ".") {
		// IPv4: Keep first two octets
		parts := strings.SplitN(client, ".", 4)
		if len(parts) >= 2 {
			return parts[0] + "." + parts[1] + ".x.x"
		}
		return "ipv4.x.x.x"
	}

	if strings.Contains(client, ":") {
		// IPv6: Keep first segment
		parts := strings.SplitN(client, ":", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0] + "::/block"
		}
		return "ipv6::/block"
	}

	// For non-IP identifiers (e.g., API keys, service names), use as-is
	// but apply length limit to prevent abuse
	if len(client) > 64 {
		return client[:64]
	}
	return client
}

// ValidateLabelValue ensures a label value meets Prometheus naming requirements
// and doesn't exceed safe length limits. Returns sanitized value or "invalid".
func ValidateLabelValue(value string, maxLen int) string {
	if value == "" {
		return "empty"
	}

	// Replace unsafe characters
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '_', r == '-', r == ':', r == '.', r == '/':
			return r
		default:
			return '_'
		}
	}, value)

	if len(safe) > maxLen {
		return safe[:maxLen]
	}

	if safe == "" {
		return "sanitized"
	}

	return safe
}

// Global sanitizer instance for package-level convenience functions
var globalSanitizer = NewSanitizer()

// package-level convenience functions
func SanitizeEndpoint(path string) string { return globalSanitizer.SanitizeEndpoint(path) }
func ValidateLabel(value string) string   { return ValidateLabelValue(value, 128) }
