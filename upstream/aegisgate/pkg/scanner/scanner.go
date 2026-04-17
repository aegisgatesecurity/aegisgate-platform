// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package scanner

import (
	"log/slog"
	"regexp"
)

// Finding represents a single detection of sensitive data
type Finding struct {
	Pattern  *Pattern
	Match    string
	Position int
	Context  string // Additional context around the match (optional)
}

// Config holds scanner configuration
type Config struct {
	Patterns       []*Pattern
	BlockThreshold Severity
	LogFindings    bool
	IncludeContext bool
	ContextSize    int // Characters before and after match to include
	MaxFindings    int // Maximum number of findings to return per scan
}

// DefaultConfig returns a default scanner configuration
func DefaultConfig() *Config {
	return &Config{
		Patterns:       DefaultPatterns(),
		BlockThreshold: Critical,
		LogFindings:    true,
		IncludeContext: false,
		ContextSize:    50,
		MaxFindings:    100,
	}
}

// Scanner represents the content scanning engine
type Scanner struct {
	config *Config
}

// New creates a new Scanner with the given configuration
func New(config *Config) *Scanner {
	if config == nil {
		config = DefaultConfig()
	}
	return &Scanner{
		config: config,
	}
}

// SetConfig updates the scanner configuration
func (s *Scanner) SetConfig(config *Config) {
	if config != nil {
		s.config = config
	}
}

// Scan analyzes content against all configured patterns and returns findings
func (s *Scanner) Scan(content string) []Finding {
	var findings []Finding

	if s.config.MaxFindings > 0 && len(findings) >= s.config.MaxFindings {
		return findings
	}

	for _, pattern := range s.config.Patterns {
		if pattern == nil || pattern.Regex == nil {
			continue
		}

		matches := pattern.Regex.FindAllStringIndex(content, -1)

		for _, matchIdx := range matches {
			if s.config.MaxFindings > 0 && len(findings) >= s.config.MaxFindings {
				slog.Warn("Maximum findings limit reached", "limit", s.config.MaxFindings)
				return findings
			}

			match := content[matchIdx[0]:matchIdx[1]]
			finding := Finding{
				Pattern:  pattern,
				Match:    match,
				Position: matchIdx[0],
			}

			// Capture context if enabled
			if s.config.IncludeContext {
				finding.Context = s.extractContext(content, matchIdx[0], matchIdx[1])
			}

			findings = append(findings, finding)

			// Log the finding
			if s.config.LogFindings {
				s.logFinding(finding)
			}
		}
	}

	return findings
}

// ScanWithContext analyzes content and returns findings with their surrounding context
func (s *Scanner) ScanWithContext(content string) []Finding {
	s.config.IncludeContext = true
	return s.Scan(content)
}

// ScanBytes converts bytes to string and scans
func (s *Scanner) ScanBytes(content []byte) []Finding {
	return s.Scan(string(content))
}

// HasViolation checks if any finding meets or exceeds the configured block threshold
func (s *Scanner) HasViolation(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Pattern.Severity >= s.config.BlockThreshold {
			return true
		}
	}
	return false
}

// GetCriticalFindings returns only Critical severity findings
func (s *Scanner) GetCriticalFindings(findings []Finding) []Finding {
	var critical []Finding
	for _, f := range findings {
		if f.Pattern.Severity == Critical {
			critical = append(critical, f)
		}
	}
	return critical
}

// GetFindingsByCategory returns findings filtered by category
func (s *Scanner) GetFindingsByCategory(findings []Finding, category Category) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if f.Pattern.Category == category {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// GetFindingsBySeverity returns findings filtered by minimum severity
func (s *Scanner) GetFindingsBySeverity(findings []Finding, minSeverity Severity) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if f.Pattern.Severity >= minSeverity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// ShouldBlock checks if any finding should trigger a block action
func (s *Scanner) ShouldBlock(findings []Finding) bool {
	for _, finding := range findings {
		if ShouldBlock(finding.Pattern.Severity) {
			return true
		}
	}
	return false
}

// GetViolationSummary returns a summary of all findings by severity
func (s *Scanner) GetViolationSummary(findings []Finding) map[Severity]int {
	summary := make(map[Severity]int)
	for _, finding := range findings {
		summary[finding.Pattern.Severity]++
	}
	return summary
}

// GetViolationNames returns the names of patterns that triggered violations
func (s *Scanner) GetViolationNames(findings []Finding) []string {
	names := make(map[string]bool)
	for _, finding := range findings {
		names[finding.Pattern.Name] = true
	}

	var result []string
	for name := range names {
		result = append(result, name)
	}
	return result
}

// extractContext extracts surrounding text around a match position
func (s *Scanner) extractContext(content string, start, end int) string {
	contextSize := s.config.ContextSize
	if contextSize <= 0 {
		contextSize = 50
	}

	// Calculate start position with boundary check
	ctxStart := start - contextSize
	if ctxStart < 0 {
		ctxStart = 0
	}

	// Calculate end position with boundary check
	ctxEnd := end + contextSize
	if ctxEnd > len(content) {
		ctxEnd = len(content)
	}

	return content[ctxStart:ctxEnd]
}

// logFinding logs a finding with appropriate severity
func (s *Scanner) logFinding(finding Finding) {
	attrs := []any{
		"pattern", finding.Pattern.Name,
		"severity", finding.Pattern.Severity.String(),
		"category", finding.Pattern.Category,
	}

	// Mask the match value for logging to avoid exposure
	maskedMatch := maskMatch(finding.Match)
	attrs = append(attrs, "match_preview", maskedMatch, "position", finding.Position)

	switch finding.Pattern.Severity {
	case Critical:
		slog.Error("Critical data exposure detected", attrs...)
	case High:
		slog.Warn("High severity data exposure detected", attrs...)
	case Medium:
		slog.Info("Medium severity data exposure detected", attrs...)
	case Low:
		slog.Debug("Low severity data exposure detected", attrs...)
	default:
		slog.Debug("Data pattern found", attrs...)
	}
}

// maskMatch masks the middle portion of a matched value for logging
func maskMatch(match string) string {
	if len(match) <= 8 {
		// For short matches, show first and last char only
		if len(match) <= 4 {
			return "****"
		}
		return match[:2] + "..." + match[len(match)-2:]
	}
	// For longer matches, show first 4 and last 4 chars
	return match[:4] + "..." + match[len(match)-4:]
}

// AddPattern adds a custom pattern to the scanner
func (s *Scanner) AddPattern(pattern *Pattern) {
	if pattern != nil {
		s.config.Patterns = append(s.config.Patterns, pattern)
	}
}

// RemovePattern removes a pattern by name
func (s *Scanner) RemovePattern(name string) bool {
	for i, pattern := range s.config.Patterns {
		if pattern.Name == name {
			s.config.Patterns = append(s.config.Patterns[:i], s.config.Patterns[i+1:]...)
			return true
		}
	}
	return false
}

// GetPattern returns a pattern by name
func (s *Scanner) GetPattern(name string) *Pattern {
	for _, pattern := range s.config.Patterns {
		if pattern.Name == name {
			return pattern
		}
	}
	return nil
}

// CompilePattern compiles a regex pattern and adds it to the scanner
func (s *Scanner) CompilePattern(name, pattern string, severity Severity, category Category, description string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	s.AddPattern(&Pattern{
		Name:        name,
		Regex:       re,
		Severity:    severity,
		Category:    category,
		Description: description,
	})

	return nil
}
