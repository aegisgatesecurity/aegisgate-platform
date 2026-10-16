// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Tool Description Scanner
//
// Screens MCP tool descriptions and input schemas for security threats
// at registration time. This is the Platform equivalent of MCP standalone's
// validateToolNotPoisoned, enhanced with Scanner's dangerous function patterns.
//
// Detection coverage:
//   - Prompt injection (ignore instructions, role-play, system prompt leakage)
//   - Prompt leakage (system prompt disclosure, meta-instruction references)
//   - RAG attacks (RAG poisoning, smuggling, retrieval bypass, embedding poisoning)
//   - Path traversal (dotdot, encoded traversal, sensitive file references)
//   - Dangerous functions (eval, exec, os.system, child_process, etc.)
//   - Secrets and credentials in descriptions
//   - PII in descriptions
//   - XSS patterns in descriptions
//   - Compliance violations (OWASP LLM Top 10)
//
// Integration point: pkg/mcpserver/tools.go registerTool()
// When a tool fails screening, registration is rejected with a detailed error.

package mcpserver

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	scannerdetectors "github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// ToolDescriptionScanner screens MCP tool descriptions and input schemas
// for security threats before registration.
type ToolDescriptionScanner struct {
	// Prompt injection patterns (compiled from Platform's scanner patterns)
	promptPatterns []compiledScanPattern

	// Dangerous function patterns (imported from Scanner's pkg/detectors)
	dangerousPatterns []compiledScanPattern

	// Additional patterns from Scanner's full pattern set
	secretPatterns     []compiledScanPattern
	piiPatterns        []compiledScanPattern
	xssPatterns        []compiledScanPattern
	compliancePatterns []compiledScanPattern

	logger *slog.Logger
}

// compiledScanPattern is a pre-compiled regex with metadata.
type compiledScanPattern struct {
	name        string
	regex       *regexp.Regexp
	severity    string
	category    string
	description string
}

// ToolScreeningResult describes the result of screening a tool.
type ToolScreeningResult struct {
	ToolName string
	Passed   bool
	Findings []ToolScreeningFinding
}

// ToolScreeningFinding is a single security finding from tool screening.
type ToolScreeningFinding struct {
	RuleID      string
	Category    string
	Severity    string
	Description string
	Field       string // "description", "inputSchema.properties.x.description", etc.
	MatchedText string // the text that matched (safe to log — it's from a tool description, not user data)
}

// NewToolDescriptionScanner creates a scanner with all detection patterns.
func NewToolDescriptionScanner() *ToolDescriptionScanner {
	s := &ToolDescriptionScanner{
		logger: slog.Default().With("component", "tool-description-scanner"),
	}
	s.compilePatterns()
	return s
}

// compilePatterns builds the compiled pattern sets from Scanner's pkg/detectors.
// PatternDef.Category is not populated in the source patterns — categories are
// determined by which variable the patterns belong to. So we access each
// pattern slice directly and assign the category ourselves.
func (s *ToolDescriptionScanner) compilePatterns() {
	// Dangerous function patterns (34 patterns: eval, exec, os.system, etc.)
	s.dangerousPatterns = compilePatternSet(scannerdetectors.DangerousFunctionPatterns, "dangerous-function")

	// Secret patterns (64 patterns: AWS keys, GitHub tokens, JWT, etc.)
	s.secretPatterns = compilePatternSet(scannerdetectors.SecretsPatterns, "secrets")

	// XSS patterns
	s.xssPatterns = compilePatternSet(scannerdetectors.XSSPatterns, "xss")

	// Compliance patterns
	s.compliancePatterns = compilePatternSet(scannerdetectors.CompliancePatterns, "compliance")

	// PII patterns (all 4 PII categories combined)
	s.piiPatterns = concatPatterns(
		compilePatternSet(scannerdetectors.PIIUSCorePatterns, "pii"),
		compilePatternSet(scannerdetectors.PIIUSExtendedPatterns, "pii"),
		compilePatternSet(scannerdetectors.PIIFinancialPatterns, "pii"),
		compilePatternSet(scannerdetectors.PIIInternationalPatterns, "pii"),
	)

	// Prompt leakage patterns (16 patterns: system prompt disclosure, meta-instruction refs)
	// RAG attack patterns (17 patterns: RAG poisoning, smuggling, retrieval bypass)
	// Path traversal patterns (19 patterns: dotdot, encoded traversal, sensitive file refs)
	// These catch tool descriptions that try to leak system context, inject hidden
	// instructions via zero-width chars or HTML comments, or reference sensitive files.
	s.promptPatterns = concatPatterns(
		compilePatternSet(scannerdetectors.PromptLeakageResponsePatterns, "prompt-leakage"),
		compilePatternSet(scannerdetectors.RAGPatterns, "rag-attack"),
		compilePatternSet(scannerdetectors.PathTraversalPatterns, "path-traversal"),
	)

	s.logger.Info("tool description scanner initialized",
		"dangerous_functions", len(s.dangerousPatterns),
		"secrets", len(s.secretPatterns),
		"pii", len(s.piiPatterns),
		"xss", len(s.xssPatterns),
		"compliance", len(s.compliancePatterns),
		"prompt_leakage_rag_traversal", len(s.promptPatterns),
	)
}

// compilePatternSet compiles a slice of PatternDef into compiledScanPatterns.
func compilePatternSet(defs []scannerdetectors.PatternDef, category string) []compiledScanPattern {
	var result []compiledScanPattern
	for _, def := range defs {
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			continue
		}
		result = append(result, compiledScanPattern{
			name:        def.Name,
			regex:       re,
			severity:    string(def.Severity),
			category:    category,
			description: def.Description,
		})
	}
	return result
}

// ScreenTool screens a tool's name, description, and input schema for threats.
// Returns a result with findings if any threats are detected.
func (s *ToolDescriptionScanner) ScreenTool(name, description string, inputSchema map[string]interface{}) *ToolScreeningResult {
	result := &ToolScreeningResult{
		ToolName: name,
		Passed:   true,
	}

	// Screen the description
	if description != "" {
		s.scanText(description, "description", result)
	}

	// Screen the input schema (descriptions, enums, defaults)
	if inputSchema != nil {
		s.scanSchema(inputSchema, "inputSchema", result)
	}

	// Screen the tool name itself (catches names like "ignore_all_instructions")
	if name != "" {
		s.scanText(name, "name", result)
	}

	if len(result.Findings) > 0 {
		result.Passed = false
	}

	return result
}

// scanText scans a text string against all pattern sets.
func (s *ToolDescriptionScanner) scanText(text, field string, result *ToolScreeningResult) {
	allPatterns := s.allPatterns()
	for _, p := range allPatterns {
		// Only flag high/critical severity
		if p.severity != "critical" && p.severity != "high" {
			continue
		}
		match := p.regex.FindString(text)
		if match != "" {
			result.Findings = append(result.Findings, ToolScreeningFinding{
				RuleID:      p.name,
				Category:    p.category,
				Severity:    p.severity,
				Description: p.description,
				Field:       field,
				MatchedText: match,
			})
		}
	}
}

// scanSchema recursively scans string values in a JSON schema map.
func (s *ToolDescriptionScanner) scanSchema(schema map[string]interface{}, path string, result *ToolScreeningResult) {
	for key, val := range schema {
		fieldPath := fmt.Sprintf("%s.%s", path, key)
		switch v := val.(type) {
		case string:
			// Scan description, enum, default fields
			if key == "description" || key == "enum" || key == "default" || key == "title" {
				s.scanText(v, fieldPath, result)
			}
		case map[string]interface{}:
			s.scanSchema(v, fieldPath, result)
		case []interface{}:
			for i, elem := range v {
				if str, ok := elem.(string); ok {
					s.scanText(str, fmt.Sprintf("%s.%s[%d]", path, key, i), result)
				}
			}
		}
	}
}

// allPatterns returns all compiled patterns concatenated.
func (s *ToolDescriptionScanner) allPatterns() []compiledScanPattern {
	return concatPatterns(
		s.dangerousPatterns,
		s.secretPatterns,
		s.piiPatterns,
		s.xssPatterns,
		s.compliancePatterns,
		s.promptPatterns,
	)
}

// concatPatterns concatenates multiple pattern slices.
func concatPatterns(slices ...[]compiledScanPattern) []compiledScanPattern {
	var total int
	for _, s := range slices {
		total += len(s)
	}
	result := make([]compiledScanPattern, 0, total)
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

// ScreeningError is returned when a tool fails security screening.
type ScreeningError struct {
	ToolName string
	Findings []ToolScreeningFinding
}

func (e *ScreeningError) Error() string {
	var rules []string
	for _, f := range e.Findings {
		rules = append(rules, f.RuleID)
	}
	return fmt.Sprintf("tool %q failed security screening: %s", e.ToolName, strings.Join(rules, ", "))
}
