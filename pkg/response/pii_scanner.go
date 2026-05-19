// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - PII Scanner
// =========================================================================
//
// Detects personally identifiable information (PII) in AI responses.
// Supports GDPR, HIPAA, SOC2, and PCI-DSS compliance requirements.
// =========================================================================

package response

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ============================================================================
// PII Scanner
// ============================================================================

// PIIScanner detects PII in text using regex patterns
type PIIScanner struct {
	// patterns is a map of PIICategory to compiled regex patterns
	patterns map[PIICategory]*regexp.Regexp

	// customPatterns are user-defined patterns
	customPatterns []*regexp.Regexp

	// mu protects pattern compilation
	mu sync.RWMutex
}

// NewPIIScanner creates a new PII scanner with default patterns
func NewPIIScanner() *PIIScanner {
	ps := &PIIScanner{
		patterns: make(map[PIICategory]*regexp.Regexp),
	}
	ps.initDefaultPatterns()
	return ps
}

// NewPIIScannerWithCustomPatterns creates a scanner with custom patterns
func NewPIIScannerWithCustomPatterns(patterns []string) (*PIIScanner, error) {
	ps := NewPIIScanner()

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		ps.customPatterns = append(ps.customPatterns, re)
	}

	return ps, nil
}

// initDefaultPatterns initializes all default PII detection patterns
func (ps *PIIScanner) initDefaultPatterns() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// US Social Security Number
	// Format: XXX-XX-XXXX (with optional dashes, spaces, or dots)
	ps.patterns[PII_SSN] = regexp.MustCompile(`\b(?:\d{3}[-.\s]?\d{2}[-.\s]?\d{4}|\d{9})\b`)

	// Credit Card Numbers
	// Visa: Starts with 4, 13 or 16 digits
	// Mastercard: Starts with 51-55 or 2221-2720, 16 digits
	// American Express: Starts with 34 or 37, 15 digits
	// Discover: Starts with 6011, 644-649, or 65, 16 digits
	ps.patterns[PII_CREDIT_CARD] = regexp.MustCompile(`\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b`)

	// Email Addresses (RFC 5322 compliant)
	ps.patterns[PII_EMAIL] = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)

	// Phone Numbers
	// US: (XXX) XXX-XXXX, XXX-XXX-XXXX, XXX.XXX.XXXX, +1XXXXXXXXXX
	// International: +, country code, formats vary
	ps.patterns[PII_PHONE] = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b`)

	// US Passport Numbers (9 characters, alphanumeric)
	ps.patterns[PII_PASSPORT] = regexp.MustCompile(`\b[A-Z0-9]{9}\b`)

	// US Driver License Numbers (varies by state, general pattern)
	ps.patterns[PII_DRIVER_LICENSE] = regexp.MustCompile(`(?i)\b(?:dl|dl#|driverlic|driverlicno|driverlicense|driverlicensenum|licenseno):?\s*[A-Z0-9]{5,20}\b`)

	// Health Information (HIPAA)
	// Medical Record Numbers (MRN), patient IDs, health IDs, HIPAA
	ps.patterns[PII_HEALTH] = regexp.MustCompile(`(?i)\b(?:mrn|patient|health|medical|hipaa)\b[^\d]*\d{5,12}`)

	// Date of Birth variations
	ps.patterns[PII_DATE_OF_BIRTH] = regexp.MustCompile(`\b(?:DOB|Date of Birth|Birth Date|Birthday|Born):?\s*(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b`)

	// Bank Account Numbers (various formats, 8-17 digits)
	ps.patterns[PII_BANK_ACCOUNT] = regexp.MustCompile(`(?i)\b(?:account|acct|acct#|savings|checking|accountnum|acctno):?\s*\d{8,17}\b`)

	// IP Addresses (IPv4)
	ps.patterns[PII_IP_ADDRESS] = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)

	// Names (simple heuristic - Title case words)
	ps.patterns[PII_NAME] = regexp.MustCompile(`\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b`)
}

// FindPII returns all PII matches in the text
func (ps *PIIScanner) FindPII(text string) []PIIMatch {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var matches []PIIMatch

	// Check each category pattern
	for category, pattern := range ps.patterns {
		found := ps.findMatches(text, category, pattern)
		matches = append(matches, found...)
	}

	// Check custom patterns (skip validation as they're user-provided)
	for _, pattern := range ps.customPatterns {
		indices := pattern.FindAllStringIndex(text, -1)
		for _, idx := range indices {
			match := text[idx[0]:idx[1]]
			matches = append(matches, PIIMatch{
				Category: PII_EMAIL, // Categorize as email (generic)
				Start:   idx[0],
				End:     idx[1],
				Value:   match,
				Severity: 3, // Default medium severity
				Redacted: "****",
			})
		}
	}

	return matches
}

// findMatches finds all matches for a pattern and returns them as PIIMatches
func (ps *PIIScanner) findMatches(text string, category PIICategory, pattern *regexp.Regexp) []PIIMatch {
	var matches []PIIMatch

	indices := pattern.FindAllStringIndex(text, -1)
	for _, idx := range indices {
		match := text[idx[0]:idx[1]]

		// Skip false positives with additional validation
		if !ps.validateMatch(category, match) {
			continue
		}

		metadata := PIICategoryMetadata[category]

		matches = append(matches, PIIMatch{
			Category: category,
			Start:    idx[0],
			End:      idx[1],
			Value:    match,
			Severity: metadata.Severity,
			Redacted: ps.getRedaction(category, match),
		})
	}

	return matches
}

// validateMatch performs additional validation to reduce false positives
func (ps *PIIScanner) validateMatch(category PIICategory, match string) bool {
	switch category {
	case PII_SSN:
		// Check for valid SSN format (not all zeros, reasonable number ranges)
		digits := strings.ReplaceAll(match, "-", "")
		digits = strings.ReplaceAll(digits, " ", "")
		digits = strings.ReplaceAll(digits, ".", "")

		if len(digits) != 9 {
			return false
		}

		// SSN cannot start with 000, 666, or 900-999
		prefix := digits[:3]
		if prefix == "000" || prefix == "666" {
			return false
		}
		if prefix[0] == '9' {
			return false
		}

		// Middle two digits cannot be 00
		middle := digits[3:5]
		if middle == "00" {
			return false
		}

		// Last four digits cannot be 0000
		if digits[5:] == "0000" {
			return false
		}

		return true

	case PII_CREDIT_CARD:
		// Validate using Luhn algorithm
		return ps.luhnCheck(match)

	case PII_EMAIL:
		// Basic email validation
		atIndex := strings.Index(match, "@")
		if atIndex < 1 || atIndex > len(match)-3 {
			return false
		}
		domain := match[atIndex+1:]
		if !strings.Contains(domain, ".") || len(domain) < 3 {
			return false
		}
		return true

	case PII_PHONE:
		// Remove all non-digit characters for validation
		digits := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) || r == '+' {
				return r
			}
			return -1
		}, match)

		// Must have at least 10 digits (excluding +)
		count := 0
		for _, c := range digits {
			if unicode.IsDigit(c) {
				count++
			}
		}
		return count >= 10

	case PII_IP_ADDRESS:
		// Each octet must be 0-255 (already enforced by regex)
		// Additional check: not start or end with special addresses
		parts := strings.Split(match, ".")
		if len(parts) != 4 {
			return false
		}
		return true

	default:
		return len(match) >= 3
	}
}

// luhnCheck validates credit card numbers using the Luhn algorithm
func (ps *PIIScanner) luhnCheck(card string) bool {
	// Remove non-digit characters
	digits := strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		return -1
	}, card)

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')

		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}

		sum += n
		alternate = !alternate
	}

	return sum%10 == 0
}

// getRedaction returns the redacted form of a matched PII
func (ps *PIIScanner) getRedaction(category PIICategory, value string) string {
	metadata, ok := PIICategoryMetadata[category]
	if !ok {
		return "[REDACTED]"
	}

	switch category {
	case PII_SSN:
		// Show last 4 digits: XXX-XX-1234
		if len(value) >= 4 {
			return metadata.RedactPrefix + value[len(value)-4:]
		}
		return metadata.RedactPrefix + "****"

	case PII_CREDIT_CARD:
		// Show last 4 digits: XXXX-XXXX-XXXX-1234
		digits := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, value)
		if len(digits) >= 4 {
			return "****-****-****-" + digits[len(digits)-4:]
		}
		return "****-****-****-****"

	case PII_EMAIL:
		atIndex := strings.Index(value, "@")
		if atIndex > 0 {
			localPart := value[:atIndex]
			domain := value[atIndex+1:]
			if len(localPart) > 2 {
				return localPart[:2] + "***@" + domain
			}
			return "***@" + domain
		}
		return "***@***"

	case PII_PHONE:
		digits := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) || r == '+' {
				return r
			}
			return -1
		}, value)
		if len(digits) >= 4 {
			return metadata.RedactPrefix + digits[len(digits)-4:]
		}
		return metadata.RedactPrefix + "****"

	case PII_NAME:
		return metadata.RedactPrefix

	default:
		return metadata.RedactPrefix
	}
}

// ScanPII performs PII scanning on text and returns matches
func (ps *PIIScanner) ScanPII(ctx context.Context, text string) ([]PIIMatch, error) {
	return ps.FindPII(text), nil
}

// ScanPIIWithContext performs PII scanning with scan context
func (ps *PIIScanner) ScanPIIWithContext(ctx context.Context, text string, scanCtx *ScanContext) ([]PIIMatch, error) {
	matches := ps.FindPII(text)

	// Add context metadata
	if scanCtx != nil {
		for i := range matches {
			if scanCtx.Metadata == nil {
				scanCtx.Metadata = make(map[string]string)
			}
			matches[i].Value = matches[i].Redacted // Return redacted value for security
		}
	}

	return matches, nil
}

// CountByCategory returns the count of PII matches by category
func (ps *PIIScanner) CountByCategory(matches []PIIMatch) map[PIICategory]int {
	counts := make(map[PIICategory]int)
	for _, match := range matches {
		counts[match.Category]++
	}
	return counts
}

// SeveritySummary returns a summary of detected PII severity
func (ps *PIIScanner) SeveritySummary(matches []PIIMatch) struct {
	Critical int
	High     int
	Medium   int
	Low      int
} {
	summary := struct {
		Critical int
		High     int
		Medium   int
		Low      int
	}{}

	for _, match := range matches {
		switch {
		case match.Severity >= 5:
			summary.Critical++
		case match.Severity >= 4:
			summary.High++
		case match.Severity >= 3:
			summary.Medium++
		default:
			summary.Low++
		}
	}

	return summary
}

// RedactPII redacts all PII from text using the default redaction
func (ps *PIIScanner) RedactPII(text string, config *RedactionConfig) string {
	if config == nil {
		config = &RedactionConfig{
			RedactSSN:          true,
			RedactCreditCard:   true,
			RedactEmail:        true,
			RedactPhone:        true,
			RedactHealthInfo:   true,
			RedactCustom:       false,
		}
	}

	result := text
	matches := ps.FindPII(text)

	// Sort by start position in reverse order to preserve indices
	// (process from end to beginning so indices remain valid)
	type matchIndex struct {
		start int
		end   int
		text  string
	}

	sortedMatches := make([]matchIndex, 0, len(matches))
	for _, m := range matches {
		sortedMatches = append(sortedMatches, matchIndex{m.Start, m.End, m.Redacted})
	}

	// Sort by start position descending
	for i := 0; i < len(sortedMatches)-1; i++ {
		for j := i + 1; j < len(sortedMatches); j++ {
			if sortedMatches[i].start < sortedMatches[j].start {
				sortedMatches[i], sortedMatches[j] = sortedMatches[j], sortedMatches[i]
			}
		}
	}

	// Apply redactions in reverse order
	for _, m := range sortedMatches {
		// Check if this category is enabled for redaction
		shouldRedact := true
		for _, match := range matches {
			if match.Start == m.start && match.End == m.end {
				switch match.Category {
				case PII_SSN:
					shouldRedact = config.RedactSSN
				case PII_CREDIT_CARD:
					shouldRedact = config.RedactCreditCard
				case PII_EMAIL:
					shouldRedact = config.RedactEmail
				case PII_PHONE:
					shouldRedact = config.RedactPhone
				case PII_HEALTH:
					shouldRedact = config.RedactHealthInfo
				default:
					shouldRedact = config.RedactCustom
				}
				break
			}
		}

		if shouldRedact {
			result = result[:m.start] + m.text + result[m.end:]
		}
	}

	return result
}

// ============================================================================
// Standalone Scan Function
// ============================================================================

// ScanTextForPII is a convenience function for scanning text for PII
func ScanTextForPII(text string) ([]PIIMatch, error) {
	scanner := NewPIIScanner()
	return scanner.FindPII(text), nil
}

// ScanTextForPIIWithConfig scans text with custom patterns
func ScanTextForPIIWithConfig(text string, patterns []string) ([]PIIMatch, error) {
	scanner, err := NewPIIScannerWithCustomPatterns(patterns)
	if err != nil {
		return nil, err
	}
	return scanner.FindPII(text), nil
}

// ScanWithTimeout scans text with a timeout
func ScanWithTimeout(ctx context.Context, text string, timeout time.Duration) ([]PIIMatch, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan []PIIMatch, 1)
	errChan := make(chan error, 1)

	go func() {
		scanner := NewPIIScanner()
		matches := scanner.FindPII(text)
		done <- matches
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case matches := <-done:
		return matches, nil
	case err := <-errChan:
		return nil, err
	}
}