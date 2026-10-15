// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — SARIF Output Formatter
// =========================================================================
//
// Produces SARIF 2.1.0 output for Platform detection results. Adapted
// from the Scanner's SARIF output (pkg/output/sarif.go) for Platform's
// HTTP content scanning model.
//
// Key differences from Scanner SARIF:
//   - Locations use API endpoint (host:path:direction) not file paths
//   - Regions use character offset, not line/column
//   - Tool name is "aegisgate-platform"
//   - Rule metadata sourced from pkg/remediation/ (ported from Scanner)
//
// =========================================================================

package sarifoutput

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/remediation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// ---------------------------------------------------------------------
// ScanContext — metadata about the scan that produced the findings
// ---------------------------------------------------------------------

// ScanContext provides metadata about the HTTP scan that produced
// findings. This is used to populate SARIF locations.
type ScanContext struct {
	// Host is the API host being scanned (e.g., "api.openai.com")
	Host string

	// Path is the API path (e.g., "/v1/chat/completions")
	Path string

	// Direction is "request" or "response"
	Direction string

	// Timestamp is when the scan occurred (RFC3339)
	Timestamp string

	// CorrelationID links related request/response scans
	CorrelationID string
}

// ---------------------------------------------------------------------
// SARIF schema types (SARIF 2.1.0)
// ---------------------------------------------------------------------

// sarifLog is the top-level SARIF log object.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun represents a single scan run.
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

// sarifTool describes the scanning tool.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver provides tool metadata and rule definitions.
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

// sarifRule defines a detection rule for SARIF consumers.
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	Help             sarifMessage   `json:"help,omitempty"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       sarifRuleProps `json:"properties,omitempty"`
}

// sarifRuleProps holds rule properties including framework references.
type sarifRuleProps struct {
	Tags         []string `json:"tags,omitempty"`
	Precision    string   `json:"precision,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	Category     string   `json:"category,omitempty"`
	CWE          []int    `json:"cwe,omitempty"`
	OWASP        string   `json:"owasp,omitempty"`
	NISTAIRMF    []string `json:"nist-ai-rmf,omitempty"`
	NISTCSF      []string `json:"nist-csf,omitempty"`
	EUAIArticles []string `json:"eu-ai-act,omitempty"`
}

// sarifResult represents a single finding.
type sarifResult struct {
	RuleID              string                   `json:"ruleId"`
	Level               string                   `json:"level"`
	Message             sarifMessage             `json:"message"`
	Locations           []sarifLocation          `json:"locations"`
	PartialFingerprints sarifPartialFingerprints `json:"partialFingerprints,omitempty"`
}

// sarifMessage is a SARIF message object.
type sarifMessage struct {
	Text string `json:"text"`
}

// sarifLocation describes where a finding was detected.
type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

// sarifPhysicalLocation provides artifact and region information.
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

// sarifArtifactLocation identifies the scanned content source.
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifRegion defines the position within the content.
type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	// CharOffset is used for content scanning (non-file contexts).
	// SARIF allows startLine to be omitted; we use charOffset as a
	// byte offset within the scanned content string.
	CharOffset int `json:"-"`
}

// sarifPartialFingerprints provides fingerprinting for deduplication.
type sarifPartialFingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash,omitempty"`
}

// ---------------------------------------------------------------------
// Formatter
// ---------------------------------------------------------------------

// FormatSARIF produces SARIF 2.1.0 JSON output from Platform scan findings.
//
// findings are the detections from scanner.Scanner.Scan().
// ctx provides metadata about the scan (host, path, direction).
// toolVersion is the Platform version string.
func FormatSARIF(findings []scanner.Finding, ctx *ScanContext, toolVersion string) ([]byte, error) {
	rules := buildSARIFRules(findings)

	var results []sarifResult
	for _, f := range findings {
		ruleID := ""
		if f.Pattern != nil {
			ruleID = f.Pattern.Name
		}

		// Build artifact URI from scan context
		artifactURI := buildArtifactURI(ctx)

		// Build fingerprint for deduplication
		fingerprint := fmt.Sprintf("%s:%d:%s", artifactURI, f.Position, ruleID)

		// Build message from pattern description + context
		msgText := ""
		if f.Pattern != nil {
			msgText = f.Pattern.Description
		}
		if f.Context != "" {
			msgText = msgText + " (context: " + truncate(f.Context, 100) + ")"
		}

		// Determine severity string
		sevStr := "warning"
		if f.Pattern != nil {
			sevStr = f.Pattern.Severity.String()
		}

		sr := sarifResult{
			RuleID: ruleID,
			Level:  severityToSARIFLevel(sevStr),
			Message: sarifMessage{
				Text: msgText,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: artifactURI,
						},
						Region: sarifRegion{
							CharOffset: f.Position,
						},
					},
				},
			},
			PartialFingerprints: sarifPartialFingerprints{
				PrimaryLocationLineHash: fingerprint,
			},
		}
		results = append(results, sr)
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "aegisgate-platform",
						Version:        toolVersion,
						InformationURI: "https://aegisgatesecurity.io",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(log, "", "  ")
}

// buildSARIFRules extracts unique rule definitions from findings.
func buildSARIFRules(findings []scanner.Finding) []sarifRule {
	ruleMap := make(map[string]sarifRule)

	for _, f := range findings {
		if f.Pattern == nil {
			continue
		}
		ruleID := f.Pattern.Name
		if ruleID == "" {
			continue
		}
		if _, exists := ruleMap[ruleID]; exists {
			continue
		}

		meta := remediation.GetRuleMetadata(ruleID)
		catStr := string(f.Pattern.Category)

		rule := sarifRule{
			ID:   ruleID,
			Name: strings.ReplaceAll(ruleID, "_", "-"),
			ShortDescription: sarifMessage{
				Text: meta.Description,
			},
			FullDescription: sarifMessage{
				Text: meta.Description,
			},
			Help: sarifMessage{
				Text: meta.Remediation,
			},
			HelpURI: "https://aegisgatesecurity.io/docs/platform/rules/" + ruleID,
			Properties: sarifRuleProps{
				Tags:         buildRuleTags(catStr),
				Precision:    "high",
				Severity:     f.Pattern.Severity.String(),
				Category:     catStr,
				CWE:          meta.CWE,
				OWASP:        meta.OWASPLLMTop,
				NISTAIRMF:    meta.NISTAIRMF,
				NISTCSF:      meta.NISTCSF,
				EUAIArticles: meta.EUAIArticles,
			},
		}

		ruleMap[ruleID] = rule
	}

	// Sort rules by ID for deterministic output
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	return rules
}

// buildRuleTags generates tags for a finding based on its category.
func buildRuleTags(category string) []string {
	tags := []string{"security", "ai-security"}

	switch strings.ToLower(category) {
	case "prompt", "prompt-injection":
		tags = append(tags, "prompt-injection", "owasp-llm01")
	case "credential":
		tags = append(tags, "secrets", "credentials")
	case "pii", "financial":
		tags = append(tags, "pii", "privacy")
	case "xss":
		tags = append(tags, "xss", "injection")
	case "compliance":
		tags = append(tags, "compliance")
	case "network":
		tags = append(tags, "network")
	case "cryptographic":
		tags = append(tags, "cryptographic", "keys")
	}

	return tags
}

// severityToSARIFLevel maps Platform severity string to SARIF level.
func severityToSARIFLevel(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	case "info":
		return "none"
	default:
		return "warning"
	}
}

// buildArtifactURI creates a URI from the scan context.
func buildArtifactURI(ctx *ScanContext) string {
	if ctx == nil {
		return "unknown"
	}
	dir := ctx.Direction
	if dir == "" {
		dir = "unknown"
	}
	host := ctx.Host
	if host == "" {
		host = "unknown"
	}
	path := ctx.Path
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s:%s%s", dir, host, path)
}

// truncate limits a string to maxLen characters, adding "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ---------------------------------------------------------------------
// Convenience: FormatFindingsSARIF
// ---------------------------------------------------------------------

// FormatFindingsSARIF is a convenience wrapper that creates a ScanContext
// from basic parameters and formats findings as SARIF.
func FormatFindingsSARIF(findings []scanner.Finding, host, path, direction, toolVersion string) ([]byte, error) {
	ctx := &ScanContext{
		Host:      host,
		Path:      path,
		Direction: direction,
	}
	return FormatSARIF(findings, ctx, toolVersion)
}

// ---------------------------------------------------------------------
// Exported types for consumers
// ---------------------------------------------------------------------

// SARIFLog is the exported top-level SARIF log structure.
// It mirrors the internal sarifLog but is exported for consumers that
// want to construct SARIF output programmatically.
type SARIFLog = sarifLog

// SARIFRun is the exported run structure.
type SARIFRun = sarifRun

// SARIFResult is the exported result structure.
type SARIFResult = sarifResult

// SARIFRule is the exported rule structure.
type SARIFRule = sarifRule
