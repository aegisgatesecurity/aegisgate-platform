// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Pattern Serving
//
// Converts Platform's internal scanner patterns to the canonical
// contracts.Pattern format for serving via the pull endpoint
// (GET /api/v1/patterns/latest). Also provides SHA-256 content
// hashing for cache invalidation.

package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

// LoadPlatformPatterns converts Platform's internal scanner patterns
// (pkg/scanner.DefaultPatterns) to the canonical contracts.Pattern
// format for serving via the pull endpoint.
//
// Platform's Pattern stores compiled *regexp.Regexp; the canonical
// format requires raw regex strings. We use regexp.Regexp.String()
// to recover the source pattern.
func LoadPlatformPatterns() []contracts.Pattern {
	platformPatterns := scanner.DefaultPatterns()

	result := make([]contracts.Pattern, 0, len(platformPatterns))
	for _, p := range platformPatterns {
		if p == nil || p.Regex == nil {
			continue
		}

		cp := contracts.Pattern{
			ID:          p.Name,
			Name:        p.Name,
			Regex:       p.Regex.String(), // recover raw regex from compiled
			Severity:    contracts.PatternSeverity(severityToString(p.Severity)),
			Category:    contracts.PatternCategory(strings.ToLower(string(p.Category))),
			Description: p.Description,
		}
		result = append(result, cp)
	}

	return result
}

// severityToString maps Platform's int Severity to canonical string.
func severityToString(sev scanner.Severity) string {
	switch sev {
	case scanner.Critical:
		return "critical"
	case scanner.High:
		return "high"
	case scanner.Medium:
		return "medium"
	case scanner.Low:
		return "low"
	case scanner.Info:
		return "info"
	default:
		return "medium"
	}
}

// HashPatternsSHA256 computes a SHA-256 hash of all pattern IDs + regex
// strings for cache invalidation. Patterns are sorted by ID before
// hashing to ensure deterministic output.
func HashPatternsSHA256(patterns []contracts.Pattern) string {
	// Sort by ID for deterministic hash
	sorted := make([]contracts.Pattern, len(patterns))
	copy(sorted, patterns)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	h := sha256.New()
	for _, p := range sorted {
		h.Write([]byte(p.ID))
		h.Write([]byte{0}) // separator
		h.Write([]byte(p.Regex))
		h.Write([]byte{0})
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// EventStorerAdapter wraps the server's appendEvent to satisfy the
// EventStorer interface used by EventRouter.
type EventStorerAdapter struct {
	appendFn func(contracts.Event) error
}

// NewEventStorerAdapter creates an EventStorer from an append function.
func NewEventStorerAdapter(appendFn func(contracts.Event) error) *EventStorerAdapter {
	return &EventStorerAdapter{appendFn: appendFn}
}

// StoreEvent delegates to the wrapped append function.
func (a *EventStorerAdapter) StoreEvent(e contracts.Event) error {
	return a.appendFn(e)
}