// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Scanner Detector Adapter
//
// Wraps the vendored aegisgate-scanner/pkg/detectors engine (516 patterns
// across 21 categories) for integration into the proxy scan pipeline.
// This closes the detection parity gap with Rampart by adding coverage
// for categories not present in the upstream scanner (283 patterns) or
// ATLAS compliance (66 patterns):
//   - data_exfil, evasion, agent_poisoning, RAG, path_traversal
//   - social_engineering, context_manipulation, prompt_leakage
//   - injection, malware, dangerous_functions, xss_request
//   - prompt_injection_request, ot_protocols

package scanner

import (
	"log/slog"
	"strings"

	scannerdetectors "github.com/aegisgatesecurity/aegisgate-scanner/pkg/detectors"
)

// DetectorAdapter wraps the vendored scanner detectors for proxy integration.
// It provides a simple block/allow API on top of the 516-pattern detector engine.
type DetectorAdapter struct {
	// blockSeverities defines which severity levels trigger a block.
	// Defaults to High and Critical, matching the upstream scanner's
	// BlockThreshold (High) and Rampart's shouldBlock logic.
	blockSeverities map[scannerdetectors.Severity]bool
}

// NewDetectorAdapter creates a new adapter with default block thresholds
// (High and Critical severity).
func NewDetectorAdapter() *DetectorAdapter {
	return &DetectorAdapter{
		blockSeverities: map[scannerdetectors.Severity]bool{
			scannerdetectors.SeverityHigh:     true,
			scannerdetectors.SeverityCritical: true,
		},
	}
}

// TotalDetectorPatterns returns the total number of compiled detector
// patterns across all categories in the vendored scanner detectors.
func TotalDetectorPatterns() int {
	return scannerdetectors.TotalCompiledPatterns()
}

// Scan runs all detector patterns against the content and returns matches.
func (d *DetectorAdapter) Scan(content string) []scannerdetectors.Match {
	if content == "" {
		return nil
	}
	return scannerdetectors.DetectAll(content)
}

// ShouldBlock returns true if any match has a blocking severity (High or Critical).
func (d *DetectorAdapter) ShouldBlock(matches []scannerdetectors.Match) bool {
	for _, m := range matches {
		if d.blockSeverities[m.Severity] {
			return true
		}
	}
	return false
}

// ScanAndBlock is a convenience method that scans content and returns
// whether it should be blocked plus the list of blocking match names.
func (d *DetectorAdapter) ScanAndBlock(content string) (bool, []string) {
	matches := d.Scan(content)
	if len(matches) == 0 {
		return false, nil
	}

	var blockingNames []string
	blocked := false
	seen := make(map[string]bool)

	for _, m := range matches {
		if d.blockSeverities[m.Severity] {
			blocked = true
			if !seen[m.Category] {
				blockingNames = append(blockingNames, m.Category)
				seen[m.Category] = true
			}
		}
	}

	return blocked, blockingNames
}

// dataCategories are pattern categories that look for specific data formats
// (SSN, credit card, API keys, etc.). These should NOT be run on normalization
// variants — a ROT13 of "of" becomes "id" which FPs the pii_letter_only_id
// pattern. Data patterns only run on the original content.
var dataCategories = map[string]bool{
	"secrets":           true,
	"pii-us-core":       true,
	"pii-us-extended":   true,
	"pii-financial":     true,
	"pii-international": true,
}

// ScanVariants scans the original content plus normalization variants
// and returns whether any variant should be blocked. Uses early exit
// when a block is found.
//
// Data categories (secrets, PII) are only scanned on the original content,
// not on normalization variants. A ROT13 transform can turn "of" into "id"
// and the next word into 8-12 uppercase letters, causing false positives on
// the pii_letter_only_id pattern. Data patterns look for specific formats
// (SSN, credit card, API keys) that don't need variant scanning.
//
// Attack categories (injection, evasion, social engineering, etc.) ARE
// scanned on variants because attackers use obfuscation to evade detection.
func (d *DetectorAdapter) ScanVariants(content string, variants []string) (bool, []string) {
	// Scan original first (all categories including data)
	blocked, names := d.ScanAndBlock(content)
	if blocked {
		return true, names
	}

	// Scan variants — only attack categories, not data categories
	for _, v := range variants {
		if v == "" || v == content {
			continue
		}
		matches := d.Scan(v)
		if len(matches) == 0 {
			continue
		}
		var blockingNames []string
		seen := make(map[string]bool)
		for _, m := range matches {
			if d.blockSeverities[m.Severity] && !dataCategories[string(m.Severity)] {
				// Check if the match's pattern name belongs to a data category.
				// We do this by checking if the category name starts with "pii" or "secret"
				if !isDataCategoryMatch(m.Category) {
					if !seen[m.Category] {
						blockingNames = append(blockingNames, m.Category)
						seen[m.Category] = true
					}
				}
			}
		}
		if len(blockingNames) > 0 {
			return true, blockingNames
		}
	}

	return false, nil
}

// isDataCategoryMatch returns true if the match's pattern name suggests
// it belongs to a data category (PII or secrets). Pattern names in data
// categories start with "pii_", "secret_", or contain "_pii_".
func isDataCategoryMatch(patternName string) bool {
	return strings.HasPrefix(patternName, "pii_") ||
		strings.HasPrefix(patternName, "secret_") ||
		strings.Contains(patternName, "_pii_")
}

// LogFindings logs detector matches at the appropriate level.
func (d *DetectorAdapter) LogFindings(direction, path string, matches []scannerdetectors.Match) {
	if len(matches) == 0 {
		return
	}

	var blocking, nonBlocking []string
	for _, m := range matches {
		if d.blockSeverities[m.Severity] {
			blocking = append(blocking, m.Category)
		} else {
			nonBlocking = append(nonBlocking, m.Category)
		}
	}

	if len(blocking) > 0 {
		slog.Error("detector findings (blocking)",
			"direction", direction,
			"path", path,
			"blocking", strings.Join(blocking, ", "),
			"non_blocking", strings.Join(nonBlocking, ", "),
		)
	} else if len(nonBlocking) > 0 {
		slog.Debug("detector findings (non-blocking)",
			"direction", direction,
			"path", path,
			"patterns", strings.Join(nonBlocking, ", "),
		)
	}
}
