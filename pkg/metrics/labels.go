// Copyright 2024 AegisGate Security. All rights reserved.
//
// This file defines standard metric labels and dimensions for consistent
// observability across the AegisGate Platform.
package metrics

import (
	"strconv"
	"strings"
)

// Label names must follow Prometheus conventions: lowercase, underscores only
// See: https://prometheus.io/docs/practices/naming/
const (
	// LabelMethod represents the HTTP method (GET, POST, etc.)
	// Cardinality: Medium (~10 values)
	LabelMethod = "method"

	// LabelEndpoint represents the sanitized request path
	// Cardinality: High (up to CardinalityLimit, with aggregation)
	LabelEndpoint = "endpoint"

	// LabelStatus represents the HTTP status code category
	// Cardinality: Low (~6 values: 2xx, 3xx, 4xx, 5xx, error, unknown)
	// Implementation uses status_class bucket, not raw code
	LabelStatus = "status"

	// LabelStatusCode represents the specific HTTP status code
	// Cardinality: Medium (~40 values)
	// Use sparingly; prefer status_class for high-volume metrics
	LabelStatusCode = "status_code"

	// LabelService identifies the originating service component
	// Cardinality: Low (~8 values: proxy, mcp, dashboard, persistence, etc.)
	LabelService = "service"

	// LabelClient identifies the client or source category
	// Cardinality: High (IP prefix buckets, service names)
	LabelClient = "client"

	// LabelTool represents the MCP tool name
	// Cardinality: Medium (whitelisted tool names only)
	LabelTool = "tool"

	// LabelTier represents the license tier
	// Cardinality: Low (community, professional, enterprise)
	LabelTier = "tier"

	// LabelResult represents generic success/failure buckets
	// Cardinality: Low (~5 values: success, failure, blocked, error, timeout)
	LabelResult = "result"

	// LabelScanType represents the security scan category
	// Cardinality: Low (~6 values: vuln, secret, dependency, sbom, config, runtime)
	LabelScanType = "scan_type"

	// LabelDirection represents traffic direction
	// Cardinality: Low (inbound, outbound)
	LabelDirection = "direction"

	// LabelProtocol represents the network protocol
	// Cardinality: Low (http, https, http2, http3, ws, wss, grpc)
	LabelProtocol = "protocol"

	// LabelVersion represents the semantic version
	// Cardinality: Low (changes only on deployment)
	LabelVersion = "version"

	// LabelGoVersion tracks the Go runtime version
	// Cardinality: Low (changes only on Go upgrades)
	LabelGoVersion = "goversion"

	// LabelPlatform tracks the OS/architecture
	// Cardinality: Low (~10 combinations)
	LabelPlatform = "platform"

	// LabelGuardrail identifies the guardrail component
	// Cardinality: Low (~8 values)
	LabelGuardrail = "guardrail"

	// LabelPolicy identifies the policy that triggered an action
	// Cardinality: Medium (policy names, limited by deployment config)
	LabelPolicy = "policy"

	// LabelAction represents the enforcement action taken
	// Cardinality: Low (allow, block, log, alert, throttle)
	LabelAction = "action"

	// LabelCache represents cache operation outcomes
	// Cardinality: Low (hit, miss, expired, error)
	LabelCache = "cache"
)

// Standard values for consistent labeling
const (
	// HTTP Methods
	MethodGET     = "GET"
	MethodPOST    = "POST"
	MethodPUT     = "PUT"
	MethodDelete  = "DELETE"
	MethodPatch   = "PATCH"
	MethodHead    = "HEAD"
	MethodOptions = "OPTIONS"
	MethodConnect = "CONNECT"

	// Status classes (preferred for high-volume metrics)
	Status2xx     = "2xx"
	Status3xx     = "3xx"
	Status4xx     = "4xx"
	Status5xx     = "5xx"
	StatusError   = "error"
	StatusUnknown = "unknown"

	// Result values
	ResultSuccess        = "success"
	ResultFailure        = "failure"
	ResultBlocked        = "blocked"
	ResultError          = "error"
	ResultTimeout        = "timeout"
	ResultRateLimited    = "rate_limited"
	ResultUnauthorized   = "unauthorized"
	ResultAuthenticated  = "authenticated"

	// Service component names
	ServiceProxy       = "proxy"
	ServiceMCP         = "mcp"
	ServiceDashboard   = "dashboard"
	ServicePersistence = "persistence"
	ServiceCertificate = "certificate"
	ServiceScanner     = "scanner"

	// Guardrail types
	GuardrailFilesystem = "filesystem"
	GuardrailNetwork    = "network"
	GuardrailExecution  = "execution"
	GuardrailData       = "data"
	GuardrailAudit      = "audit"

	// Actions
	ActionAllow     = "allow"
	ActionBlock     = "block"
	ActionLog       = "log"
	ActionAlert     = "alert"
	ActionThrottle  = "throttle"
	ActionSanitize  = "sanitize"

	// Scan types
	ScanVuln       = "vulnerability"
	ScanSecret     = "secret"
	ScanDependency = "dependency"
	ScanSBOM       = "sbom"
	ScanConfig     = "config"
	ScanRuntime    = "runtime"

	// Cache outcomes
	CacheHit     = "hit"
	CacheMiss    = "miss"
	CacheExpired = "expired"
	CacheError   = "error"

	// Directions
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"

	// Protocols
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
	ProtocolHTTP2 = "http2"
	ProtocolHTTP3 = "http3"
	ProtocolWS    = "ws"
	ProtocolWSS   = "wss"
	ProtocolGRPC  = "grpc"

	// Tier names
	TierCommunity     = "community"
	TierProfessional  = "professional"
	TierEnterprise    = "enterprise"
	TierUnknown       = "unknown"

	// Special values
	ValueUnknown    = "unknown"
	ValueEmpty      = "empty"
	ValueError      = "error"
	ValueAnonymous  = "anonymous"
	ValueInternal   = "internal"
	ValueExternal   = "external"
)

// LabelSet provides a type-safe builder for metric labels
type LabelSet struct {
	labels map[string]string
}

// NewLabelSet creates a new label set
func NewLabelSet() *LabelSet {
	return &LabelSet{labels: make(map[string]string)}
}

// With adds a label to the set
func (ls *LabelSet) With(name, value string) *LabelSet {
	if ls.labels == nil {
		ls.labels = make(map[string]string)
	}
	ls.labels[name] = ValidateLabel(value)
	return ls
}

// WithMethod adds HTTP method label
func (ls *LabelSet) WithMethod(method string) *LabelSet {
	return ls.With(LabelMethod, strings.ToUpper(method))
}

// WithEndpoint adds sanitized endpoint label
func (ls *LabelSet) WithEndpoint(endpoint string) *LabelSet {
	return ls.With(LabelEndpoint, SanitizeEndpoint(endpoint))
}

// WithStatus adds status class label (preferred over raw status code)
func (ls *LabelSet) WithStatus(code int) *LabelSet {
	return ls.With(LabelStatus, StatusClass(code))
}

// WithStatusCode adds specific status code label
func (ls *LabelSet) WithStatusCode(code int) *LabelSet {
	return ls.With(LabelStatusCode, strconv.Itoa(code))
}

// WithService adds service label
func (ls *LabelSet) WithService(service string) *LabelSet {
	return ls.With(LabelService, service)
}

// WithClient adds sanitized client identifier
func (ls *LabelSet) WithClient(client string) *LabelSet {
	return ls.With(LabelClient, SanitizeClientID(client))
}

// WithTool adds tool name label (validates against whitelist)
func (ls *LabelSet) WithTool(tool string, allowed []string) *LabelSet {
	return ls.With(LabelTool, SanitizeToolName(tool, allowed))
}

// WithTier adds tier label
func (ls *LabelSet) WithTier(tier string) *LabelSet {
	return ls.With(LabelTier, tier)
}

// WithResult adds result label
func (ls *LabelSet) WithResult(result string) *LabelSet {
	return ls.With(LabelResult, result)
}

// Build returns the complete label map
func (ls *LabelSet) Build() map[string]string {
	return ls.labels
}

// BuildSlice returns labels as a slice of alternating key/value strings
// for use with Prometheus label vectors
func (ls *LabelSet) BuildSlice() []string {
	result := make([]string, 0, len(ls.labels)*2)
	for k, v := range ls.labels {
		result = append(result, k, v)
	}
	return result
}

// StatusClass converts an HTTP status code to a status class label
// 200 → "2xx", 404 → "4xx", etc.
func StatusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return Status2xx
	case code >= 300 && code < 400:
		return Status3xx
	case code >= 400 && code < 500:
		return Status4xx
	case code >= 500 && code < 600:
		return Status5xx
	default:
		return StatusUnknown
	}
}
