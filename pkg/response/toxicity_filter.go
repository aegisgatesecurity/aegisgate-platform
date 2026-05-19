// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Toxicity Filter
// =========================================================================

package response

import (
	"regexp"
	"strings"
	"sync"
)

// ToxicityFilter filters harmful content in responses
type ToxicityFilter struct {
	categories map[ToxicityCategory]*regexp.Regexp
	mu         sync.RWMutex
}

// NewToxicityFilter creates a toxicity filter with default patterns
func NewToxicityFilter() *ToxicityFilter {
	tf := &ToxicityFilter{
		categories: make(map[ToxicityCategory]*regexp.Regexp),
	}
	tf.initDefaultPatterns()
	return tf
}

func (tf *ToxicityFilter) initDefaultPatterns() {
	tf.mu.Lock()
	defer tf.mu.Unlock()

	// Violence patterns
	tf.categories[TOXICITY_VIOLENCE] = regexp.MustCompile(`(?i)\b(kill|murder|assassinate|execute|strangle|poison|shoot|stab|slit|dismember)\b`)

	// Weapons patterns
	tf.categories[TOXICITY_WEAPONS] = regexp.MustCompile(`(?i)\b(bomb|explosive|grenade|machine\s*gun|ak-47|ar-15|ricin|anthrax)\b`)

	// Illegal activity patterns
	tf.categories[TOXICITY_ILLEGAL] = regexp.MustCompile(`(?i)\b(crack\s*cocaine|heroin|meth|manufacture\s*drug|illegal\s*weapon)\b`)

	// Self-harm patterns
	tf.categories[TOXICITY_SELF_HARM] = regexp.MustCompile(`(?i)\b(suicide|self-harm|cut\s*myself|kill\s*myself|end\s*my\s*life)\b`)

	// Harassment patterns
	tf.categories[TOXICITY_HARASSMENT] = regexp.MustCompile(`(?i)\b(you\s+are\s+(stupid|dumb|ugly|worthless|inferior))\b`)
}

// Scan scans text for toxic content
func (tf *ToxicityFilter) Scan(text string) *ToxicityResult {
	tf.mu.RLock()
	defer tf.mu.RUnlock()

	result := &ToxicityResult{
		Categories: []ToxicityCategory{},
		Severity:   0,
		Filtered:   false,
	}

	for category, pattern := range tf.categories {
		if pattern.MatchString(text) {
			result.Categories = append(result.Categories, category)
			result.Severity = 5
			result.Filtered = true
		}
	}

	if len(result.Categories) > 0 {
		result.Explanation = "Harmful content detected: " + strings.Join(supportedCategoryStrings(result.Categories), ", ")
	}

	return result
}

// supportedCategoryStrings converts categories to readable strings
func supportedCategoryStrings(cats []ToxicityCategory) []string {
	result := []string{}
	for _, c := range cats {
		switch c {
		case TOXICITY_VIOLENCE:
			result = append(result, "violent content")
		case TOXICITY_WEAPONS:
			result = append(result, "weapons content")
		case TOXICITY_ILLEGAL:
			result = append(result, "illegal activity")
		case TOXICITY_SELF_HARM:
			result = append(result, "self-harm content")
		case TOXICITY_HARASSMENT:
			result = append(result, "harassment")
		}
	}
	return result
}

// ============================================================================
// Hallucination Detector
// ============================================================================

// HallucinationDetector detects potential hallucinations in responses
type HallucinationDetector struct {
	config *HallucinationConfig
	mu     sync.RWMutex
}

// NewHallucinationDetector creates a hallucination detector
func NewHallucinationDetector(config *HallucinationConfig) *HallucinationDetector {
	if config == nil {
		config = &HallucinationConfig{
			ConfidenceThreshold: 0.7,
			EnableFactChecking:  false,
			VerifyAttributions:  false,
		}
	}
	return &HallucinationDetector{
		config: config,
	}
}

// Scan scans text for potential hallucinations
func (hd *HallucinationDetector) Scan(text string) *HallucinationResult {
	hd.mu.RLock()
	defer hd.mu.RUnlock()

	result := &HallucinationResult{
		Flagged:              false,
		Claims:               []Claim{},
		TotalClaims:          0,
		HighConfidenceClaims: 0,
	}

	// Simple heuristic: look for overconfident language
	confidentPhrases := []string{
		"definitely", "absolutely", "certainly", "guaranteed",
		"always", "never", "everyone", "no one",
	}

	claimCount := 0
	for _, phrase := range confidentPhrases {
		if strings.Contains(strings.ToLower(text), phrase) {
			claimCount++
		}
	}

	// Check for numbers/statistics without attribution
	statPattern := regexp.MustCompile(`\b\d+%?\s+(people|users|users?|percent|%)`)
	matches := statPattern.FindAllString(text, -1)
	for _, m := range matches {
		result.Claims = append(result.Claims, Claim{
			Text:       m,
			Confidence: 0.5, // Lower confidence without source
			Verified:   nil,
		})
	}

	result.TotalClaims = len(result.Claims)
	result.Flagged = claimCount > 3 && result.TotalClaims > 2

	if result.Flagged {
		result.Explanation = "Potential overconfident claims detected without attribution"
	}

	return result
}
