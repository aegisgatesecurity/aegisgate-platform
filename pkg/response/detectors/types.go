// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Detector Types
// =========================================================================
//
// Shared types for the regex detector packages. These types are used
// across secrets, PII, XSS, and compliance detectors.
// =========================================================================

package detectors

// Severity represents the risk level of a detected pattern.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Category represents the detection category.
type Category string

const (
	CategorySecrets          Category = "secrets"
	CategoryPIIUSCore        Category = "pii-us-core"
	CategoryPIIUSExtended    Category = "pii-us-extended"
	CategoryPIIFinancial     Category = "pii-financial"
	CategoryPIIInternational Category = "pii-international"
	CategoryXSS              Category = "xss"
	CategoryCompliance       Category = "compliance"
)

// Match represents a single regex detection match.
type Match struct {
	// Category is the specific pattern name (e.g., "secret_aws_key", "pii_ssn")
	Category string

	// Severity is the risk level (critical, high, medium, low)
	Severity Severity

	// Confidence is a 0-1 confidence score for the match
	Confidence float64

	// Value is the matched text (may be truncated for long matches)
	Value string

	// Index is the byte offset where the match starts
	Index int

	// End is the byte offset where the match ends
	End int
}

// PatternDef defines a single regex detection pattern.
type PatternDef struct {
	// Name is the pattern identifier (e.g., "secret_aws_key")
	Name string

	// Severity is the risk level
	Severity Severity

	// Regex is the Go regex string (RE2 syntax, no lookbehind/lookahead)
	Regex string

	// Description is a human-readable description of what the pattern detects
	Description string
}

// DetectionResult holds the results from scanning text with all patterns
// in a category.
type DetectionResult struct {
	// Category is the detection category
	Category Category

	// Matches is the list of detected matches
	Matches []Match

	// PatternCount is the total number of patterns in this category
	PatternCount int

	// ElapsedNS is the time taken to scan in nanoseconds
	ElapsedNS int64
}
