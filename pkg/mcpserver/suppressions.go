// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Inline Suppression Support
//
// Ports Scanner's inline suppression system to Platform. Parses
// aegisgate-ignore comments in source files and filters out matching
// findings. Supports multiple comment styles:
//
//	# aegisgate-ignore: rule_id          (Python, YAML, shell, TOML)
//	// aegisgate-ignore: rule_id         (Go, JS, TS, C, Java)
//	<!-- aegisgate-ignore: rule_id -->   (HTML, XML, Markdown)
//	/* aegisgate-ignore: rule_id */      (CSS, C, multi-line)
//
// Suppression can also use "all" to suppress all findings on the line:
//
//	# aegisgate-ignore: all
//
// A suppression applies to the line it appears on AND the next non-empty
// line (similar to eslint's // eslint-disable-next-line).
//
// Provenance: github.com/aegisgatesecurity/aegisgate-scanner/pkg/scanner/suppressions.go

package mcpserver

import (
	"regexp"
	"strings"
)

// suppressionRegex matches aegisgate-ignore comments in any language style.
var suppressionRegex = regexp.MustCompile(
	`aegisgate-ignore:\s*([a-zA-Z0-9_\-]+)`,
)

// Suppression represents a single inline suppression directive.
type Suppression struct {
	RuleID string // rule ID to suppress, or "all"
	Line   int    // line where the suppression comment appears
}

// ParseSuppressions scans content for aegisgate-ignore comments and
// returns the list of suppressions found.
func ParseSuppressions(content string) []Suppression {
	var suppressions []Suppression
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		matches := suppressionRegex.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				suppressions = append(suppressions, Suppression{
					RuleID: strings.TrimSpace(m[1]),
					Line:   i + 1, // 1-based line number
				})
			}
		}
	}

	return suppressions
}

// SuppressedFinding is a finding that can be suppressed by inline comments.
// This is a minimal interface — any finding type with a RuleID and Line
// can be filtered.
type SuppressedFinding struct {
	RuleID string
	Line   int
}

// ApplySuppressions filters out findings that are suppressed by inline
// comments. A suppression on line N applies to findings on line N and
// line N+1 (the next non-empty line, like eslint-disable-next-line).
func ApplySuppressions(findings []SuppressedFinding, suppressions []Suppression) []SuppressedFinding {
	if len(suppressions) == 0 {
		return findings
	}

	// Build a lookup: (ruleID or "all") → set of suppressed lines.
	type suppressKey struct {
		ruleID string
		line   int
	}
	suppressed := make(map[suppressKey]bool)

	for _, s := range suppressions {
		// Suppress the line the comment is on.
		suppressed[suppressKey{s.RuleID, s.Line}] = true
		// Suppress the next line (common pattern: suppression on the
		// line above the finding, like eslint-disable-next-line).
		suppressed[suppressKey{s.RuleID, s.Line + 1}] = true
	}

	var filtered []SuppressedFinding
	for _, f := range findings {
		// Check if this finding is suppressed.
		// "all" suppressions match any rule ID.
		if suppressed[suppressKey{"all", f.Line}] {
			continue
		}
		if suppressed[suppressKey{f.RuleID, f.Line}] {
			continue
		}
		filtered = append(filtered, f)
	}

	if filtered == nil {
		filtered = []SuppressedFinding{}
	}

	return filtered
}
