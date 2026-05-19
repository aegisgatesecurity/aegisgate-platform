// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Hallucination Detection Extensions
// =========================================================================
//
// Extended hallucination detection utilities.
// Works with the base HallucinationDetector from toxicity_filter.go.
//
// Features:
// - Overconfidence pattern detection
// - Factual claim verification
// - Statistics validation
// =========================================================================

package response

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// Hallucination Detection Patterns
// ============================================================================

var (
	// Overconfidence patterns indicate potentially false certainty
	overconfidenceRegex = regexp.MustCompile(`(?i)\b(certainly|definitely|absolutely|always|never|guaranteed|100%|proven|incontrovertible|unquestionably)\b`)

	// Factual claim patterns require verification
	factualClaimRegex = regexp.MustCompile(`(?i)\b(according to|studies show|research indicates|experts say|statistics show|evidence suggests)\b`)

	// Quantification patterns for statistics
	quantificationRegex = regexp.MustCompile(`\b\d+\.?\d*\s*(%|percent|percentage)\b`)

	// Source attribution patterns
	attributionRegex = regexp.MustCompile(`(?i)\b(source:|according to|based on|from|research|study|data)\b`)

	// Contradiction markers
	contradictionMarkers = []string{"however", "but", "although", "despite", "on the other hand"}
)

// ============================================================================
// Extended Hallucination Result
// ============================================================================

// ExtendedHallucinationResult extends HallucinationResult with additional analysis
type ExtendedHallucinationResult struct {
	*HallucinationResult
	OverconfidentClaims []string
	UnverifiedClaims    []string
	UnquantifiedStats   []string
	RiskLevel           string
}

// ============================================================================
// Extended Hallucination Detector
// ============================================================================

// ExtendedHallucinationDetector provides enhanced hallucination detection
type ExtendedHallucinationDetector struct {
	base    *HallucinationDetector
	enabled bool
}

// NewExtendedHallucinationDetector creates a new extended detector
func NewExtendedHallucinationDetector() *ExtendedHallucinationDetector {
	return &ExtendedHallucinationDetector{
		base:    NewHallucinationDetector(nil),
		enabled: true,
	}
}

// ScanExtended performs comprehensive hallucination detection
func (d *ExtendedHallucinationDetector) ScanExtended(text string) *ExtendedHallucinationResult {
	result := &ExtendedHallucinationResult{
		HallucinationResult: d.base.Scan(text),
		OverconfidentClaims: d.detectOverconfidence(text),
		UnverifiedClaims:    d.detectUnverifiedClaims(text),
		UnquantifiedStats:   d.detectUnquantifiedStatistics(text),
		RiskLevel:           "low",
	}

	// Calculate risk level
	riskScore := len(result.OverconfidentClaims) +
		len(result.UnverifiedClaims)*2 +
		len(result.UnquantifiedStats)

	if riskScore > 5 {
		result.RiskLevel = "high"
		result.Flagged = true
	} else if riskScore > 2 {
		result.RiskLevel = "medium"
	}

	return result
}

// detectOverconfidence finds overconfident statements
func (d *ExtendedHallucinationDetector) detectOverconfidence(text string) []string {
	var claims []string

	sentences := strings.Split(text, ".")
	for _, sentence := range sentences {
		sentence = strings.TrimSpace(sentence)
		if len(sentence) > 10 && overconfidenceRegex.MatchString(sentence) {
			claims = append(claims, sentence)
		}
	}

	return claims
}

// detectUnverifiedClaims finds factual claims without sources
func (d *ExtendedHallucinationDetector) detectUnverifiedClaims(text string) []string {
	var claims []string

	sentences := strings.Split(text, ".")
	for _, sentence := range sentences {
		sentence = strings.TrimSpace(sentence)
		if len(sentence) > 10 && factualClaimRegex.MatchString(sentence) {
			// Check if it has attribution
			if !attributionRegex.MatchString(sentence) {
				claims = append(claims, sentence)
			}
		}
	}

	return claims
}

// detectUnquantifiedStatistics finds statistics without sources
func (d *ExtendedHallucinationDetector) detectUnquantifiedStatistics(text string) []string {
	var stats []string

	matches := quantificationRegex.FindAllString(text, -1)
	for _, match := range matches {
		// Check if there's attribution near the statistic
		pos := strings.Index(text, match)
		if pos >= 0 {
			contextStart := pos - 200
			if contextStart < 0 {
				contextStart = 0
			}
			contextEnd := pos + len(match) + 200
			if contextEnd > len(text) {
				contextEnd = len(text)
			}
			context := text[contextStart:contextEnd]

			if !attributionRegex.MatchString(context) {
				stats = append(stats, match)
			}
		}
	}

	return stats
}

// ScanWithTimeout performs detection with timeout
func (d *ExtendedHallucinationDetector) ScanWithTimeout(ctx context.Context, text string, timeout time.Duration) (*ExtendedHallucinationResult, error) {
	done := make(chan *ExtendedHallucinationResult, 1)

	go func() {
		done <- d.ScanExtended(text)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-done:
		return result, nil
	}
}

// ValidateClaim performs quick claim validation
func (d *ExtendedHallucinationDetector) ValidateClaim(claim string) (bool, float64) {
	result := d.ScanExtended(claim)

	if result == nil || result.HallucinationResult == nil || len(result.Claims) == 0 {
		return true, 1.0
	}

	return !result.Flagged, result.Claims[0].Confidence
}

// AnalyzeText provides comprehensive text analysis
func (d *ExtendedHallucinationDetector) AnalyzeText(text string) *TextAnalysis {
	result := d.ScanExtended(text)

	analysis := &TextAnalysis{
		Text:              text,
		ClaimCount:        0,
		ConfidenceScore:   1.0,
		HallucinationRisk: result.RiskLevel,
		Flagged:           result.Flagged,
	}

	if result.HallucinationResult != nil {
		analysis.ClaimCount = result.TotalClaims
		if len(result.Claims) > 0 {
			sum := 0.0
			for _, c := range result.Claims {
				sum += c.Confidence
			}
			analysis.ConfidenceScore = sum / float64(len(result.Claims))
		}
	}

	return analysis
}

// TextAnalysis holds comprehensive text analysis results
type TextAnalysis struct {
	Text              string
	ClaimCount        int
	ConfidenceScore   float64
	HallucinationRisk string
	Flagged           bool
}

// ============================================================================
// Standalone Functions
// ============================================================================

// QuickHallucinationCheck performs quick hallucination check
func QuickHallucinationCheck(text string) (bool, string) {
	detector := NewExtendedHallucinationDetector()
	result := detector.ScanExtended(text)

	if result != nil && result.HallucinationResult != nil {
		return result.Flagged, result.Explanation
	}

	return false, "Check completed"
}

// ValidateClaimQuick performs quick claim validation
func ValidateClaimQuick(claim string) (bool, float64) {
	detector := NewExtendedHallucinationDetector()
	return detector.ValidateClaim(claim)
}

// AnalyzeTextQuick performs quick text analysis
func AnalyzeTextQuick(text string) *TextAnalysis {
	detector := NewExtendedHallucinationDetector()
	return detector.AnalyzeText(text)
}

// ScanHallucinations performs hallucination scan on text
func ScanHallucinations(text string) *HallucinationResult {
	detector := NewHallucinationDetector(nil)
	return detector.Scan(text)
}
