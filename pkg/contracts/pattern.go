// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Canonical Pattern Contract
//
// This package defines the canonical pattern format used across the entire
// AegisGate ecosystem (Platform, Scanner, Rampart, Lens, MCP). All products
// that exchange pattern definitions — via HTTP pull, shared Go module, or
// bundled configuration — use this format.
//
// Design principles:
//   - Raw regex STRING, not compiled *regexp.Regexp (serializable over HTTP)
//   - Severity as STRING, not int (self-documenting in JSON, portable to JS)
//   - Category as STRING (consistent naming across all products)
//   - Languages field for code-scanning patterns (dangerous functions, etc.)
//   - Version field for pattern set versioning and backward compatibility
//   - Superset of Platform's scanner.Pattern, Scanner's detectors.PatternDef,
//     and Rampart's pattern definitions
//
// Air-gap behavior: Patterns are bundled at build time. The pull endpoint
// (/api/v1/patterns/latest) is opt-in — no platform_url means no pull, and
// bundled patterns provide full function.

package contracts

// PatternSeverity is the risk level of a detected pattern.
// This is a string type (not int) for JSON portability across Go and JS products.
type PatternSeverity string

const (
	SeverityCritical PatternSeverity = "critical"
	SeverityHigh     PatternSeverity = "high"
	SeverityMedium   PatternSeverity = "medium"
	SeverityLow      PatternSeverity = "low"
	SeverityInfo     PatternSeverity = "info"
)

// PatternCategory is the detection category for a pattern.
// Values are lowercase kebab-case for consistency across products.
type PatternCategory string

const (
	CategorySecrets           PatternCategory = "secrets"
	CategoryPIIUSCore         PatternCategory = "pii-us-core"
	CategoryPIIUSExtended     PatternCategory = "pii-us-extended"
	CategoryPIIFinancial      PatternCategory = "pii-financial"
	CategoryPIIInternational  PatternCategory = "pii-international"
	CategoryXSS               PatternCategory = "xss"
	CategoryCompliance        PatternCategory = "compliance"
	CategoryDangerousFunction PatternCategory = "dangerous-function"
	CategoryOTProtocols       PatternCategory = "ot-protocols"
	CategoryPrompt            PatternCategory = "prompt-injection"
	CategoryNetwork           PatternCategory = "network"
	CategoryCredential        PatternCategory = "credential"
	CategoryCryptographic     PatternCategory = "cryptographic"
)

// PatternLanguage restricts a pattern to specific programming languages.
// Empty string means the pattern applies to all languages.
type PatternLanguage string

const (
	LangAny     PatternLanguage = ""
	LangPython  PatternLanguage = "python"
	LangJS      PatternLanguage = "javascript"
	LangTS      PatternLanguage = "typescript"
	LangGo      PatternLanguage = "go"
	LangJava    PatternLanguage = "java"
	LangC       PatternLanguage = "c"
	LangCPP     PatternLanguage = "cpp"
	LangRuby    PatternLanguage = "ruby"
	LangPHP     PatternLanguage = "php"
	LangShell   PatternLanguage = "shell"
	LangYAML    PatternLanguage = "yaml"
	LangJSON    PatternLanguage = "json"
	LangXML     PatternLanguage = "xml"
	LangHTML    PatternLanguage = "html"
	LangSQL     PatternLanguage = "sql"
	LangGeneric PatternLanguage = "generic"
)

// Pattern is the canonical pattern definition exchanged across all AegisGate products.
//
// This is a superset of:
//   - Platform's scanner.Pattern (adds raw regex string, languages, version, id, confidence)
//   - Scanner's detectors.PatternDef (adds id, version, confidence, keywords)
//   - Rampart's pattern definitions (shares Scanner lineage)
//
// The Regex field is a raw Go RE2 regex string — NOT a compiled *regexp.Regexp.
// This is critical for HTTP serialization: compiled regex cannot be marshaled.
// Each product compiles the regex locally after receiving it.
type Pattern struct {
	// ID is a unique identifier for the pattern (e.g., "secret_aws_key").
	// This is the primary key for pattern versioning and deduplication.
	ID string `json:"id"`

	// Name is a human-readable name for the pattern.
	// May be the same as ID for simple patterns.
	Name string `json:"name"`

	// Regex is the raw Go RE2 regex string (no lookbehind/lookahead).
	// Products compile this locally — never serialize compiled regex.
	Regex string `json:"regex"`

	// Severity is the risk level of the pattern.
	Severity PatternSeverity `json:"severity"`

	// Category is the detection category.
	Category PatternCategory `json:"category"`

	// Description is a human-readable description of what the pattern detects.
	Description string `json:"description"`

	// Languages restricts this pattern to specific programming languages.
	// Empty or nil means the pattern applies to all languages.
	// Used primarily by code-scanning patterns (dangerous functions, etc.).
	Languages []PatternLanguage `json:"languages,omitempty"`

	// Confidence is a 0-1 confidence score for matches from this pattern.
	// Defaults to 1.0 for exact regex matches. ML-based patterns may use lower values.
	Confidence float64 `json:"confidence,omitempty"`

	// Keywords are optional optimization hints for fast pre-filtering.
	// If non-empty, the scanner can check for keyword presence before running the full regex.
	Keywords []string `json:"keywords,omitempty"`

	// Version is the pattern format version (not the pattern content version).
	// Currently "v1". Used for backward compatibility when the format changes.
	Version string `json:"version"`
}

// PatternSet is a collection of patterns with metadata, returned by the
// Platform pull endpoint (/api/v1/patterns/latest) and used for bundled
// pattern configuration in FOSS tools.
type PatternSet struct {
	// Version is the format version of this pattern set.
	Version string `json:"version"` // "v1"

	// Source identifies the origin of this pattern set ("platform", "scanner", "rampart").
	Source string `json:"source"`

	// GeneratedAt is the timestamp when this pattern set was generated.
	GeneratedAt string `json:"generated_at"` // RFC3339

	// Hash is a content hash of all pattern IDs + regex strings.
	// Used for cache invalidation: if hash matches, client skips recompilation.
	Hash string `json:"hash"`

	// Patterns is the list of canonical pattern definitions.
	Patterns []Pattern `json:"patterns"`
}

// PatternSetResponse is the full HTTP response from the pull endpoint.
// It includes the pattern set and metadata for the client to decide
// whether to update its local patterns.
type PatternSetResponse struct {
	// Version is the API version ("v1").
	APIVersion string `json:"api_version"`

	// PatternSet is the requested pattern set.
	PatternSet PatternSet `json:"pattern_set"`

	// UpdatedAt is the timestamp of the last pattern change on the server.
	// Clients can send If-Modified-Since with this value to avoid
	// re-downloading unchanged patterns.
	UpdatedAt string `json:"updated_at"` // RFC3339
}
