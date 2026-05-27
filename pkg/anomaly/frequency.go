package anomaly

import (
	"strings"
	"unicode"
)

// CharacterFingerprint represents character frequency distribution and ratios.
type CharacterFingerprint struct {
	// Distribution map: character -> frequency (0.0-1.0)
	Distribution map[rune]float64

	// Metrics
	AlphanumericRatio float64 // [a-zA-Z0-9] / total
	SpecialCharRatio  float64 // [!@#$%^...*] / total
	WhitespaceRatio   float64 // [\s\t\n] / total
	UppercaseRatio    float64 // [A-Z] / total
	LowercaseRatio    float64 // [a-z] / total
	DigitRatio        float64 // [0-9] / total
	PunctuationRatio  float64 // [.,!?;:...] / total
	Base64Score       float64 // Is character set valid Base64? (0.0-1.0)
	HexScore          float64 // Is character set valid hex? (0.0-1.0)

	// Structural metrics
	AverageRunLength float64 // Average length of consecutive same-type chars
	UniqueCharRatio  float64 // Unique chars / total chars
}

// FingerprintBaseline represents expected patterns for different content types.
type FingerprintBaseline struct {
	English CharacterFingerprint
	Code    CharacterFingerprint
	JSON    CharacterFingerprint
	Base64  CharacterFingerprint
	Hex     CharacterFingerprint
	Natural CharacterFingerprint // General natural language
}

// Analyze returns a fingerprint for the input data.
func Analyze(data []byte) CharacterFingerprint {
	if len(data) == 0 {
		return CharacterFingerprint{}
	}

	fp := CharacterFingerprint{
		Distribution: make(map[rune]float64),
	}

	// Count characters
	charCount := make(map[rune]int)
	totalRunes := 0

	for _, b := range data {
		r := rune(b)
		charCount[r]++
		totalRunes++
	}

	// Calculate distribution
	for r, count := range charCount {
		fp.Distribution[r] = float64(count) / float64(len(data))
	}

	// Calculate ratios
	var alphanum, special, whitespace, upper, lower, digit, punct float64

	for r := range charCount {
		c := float64(charCount[r]) / float64(len(data))

		switch {
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			alphanum += c
			if unicode.IsUpper(r) {
				upper += c
			}
			if unicode.IsLower(r) {
				lower += c
			}
			if unicode.IsNumber(r) {
				digit += c
			}
		case unicode.IsSpace(r) || r == '\t' || r == '\n' || r == '\r':
			whitespace += c
		case unicode.IsPunct(r):
			punct += c
		default:
			// Control characters and other
			if !unicode.IsLetter(r) && !unicode.IsNumber(r) && !unicode.IsSpace(r) {
				special += c
			}
		}
	}

	fp.AlphanumericRatio = alphanum
	fp.SpecialCharRatio = special
	fp.WhitespaceRatio = whitespace
	fp.UppercaseRatio = upper
	fp.LowercaseRatio = lower
	fp.DigitRatio = digit
	fp.PunctuationRatio = punct

	// Calculate encoding scores
	fp.Base64Score = CalculateBase64Score(data)
	fp.HexScore = CalculateHexScore(data)

	// Calculate structural metrics
	fp.UniqueCharRatio = float64(len(charCount)) / float64(len(data))
	fp.AverageRunLength = calculateAverageRunLength(data)

	return fp
}

// AnalyzeString is a convenience wrapper for string input.
func AnalyzeString(s string) CharacterFingerprint {
	return Analyze([]byte(s))
}

// CompareWithBaseline scores similarity to a baseline fingerprint.
// Returns value 0.0-1.0 where 1.0 = perfect match.
func (f CharacterFingerprint) CompareWithBaseline(baseline CharacterFingerprint) float64 {
	// Weighted comparison of key metrics
	weights := map[string]float64{
		"alphanumeric": 0.15,
		"uppercase":    0.10,
		"lowercase":    0.15,
		"digit":        0.15,
		"whitespace":   0.10,
		"punctuation":  0.10,
		"base64":       0.15,
		"hex":          0.10,
	}

	var score float64

	// Alphanumeric comparison
	score += weights["alphanumeric"] * (1.0 - absDiff(f.AlphanumericRatio, baseline.AlphanumericRatio))

	// Case ratio comparison (important for distinguishing)
	score += weights["uppercase"] * (1.0 - absDiff(f.UppercaseRatio, baseline.UppercaseRatio))
	score += weights["lowercase"] * (1.0 - absDiff(f.LowercaseRatio, baseline.LowercaseRatio))

	// Digit ratio comparison
	score += weights["digit"] * (1.0 - absDiff(f.DigitRatio, baseline.DigitRatio))

	// Whitespace ratio (distinguishes prose from data)
	score += weights["whitespace"] * (1.0 - absDiff(f.WhitespaceRatio, baseline.WhitespaceRatio))

	// Punctuation ratio
	score += weights["punctuation"] * (1.0 - absDiff(f.PunctuationRatio, baseline.PunctuationRatio))

	// Encoding scores (strong signal for secrets)
	if baseline.Base64Score > 0.8 {
		// Baseline expects Base64
		score += weights["base64"] * (1.0 - absDiff(f.Base64Score, baseline.Base64Score))
	} else if f.Base64Score > 0.9 {
		// Input is Base64 but baseline isn't
		score *= 0.7 // Penalty
	}

	if baseline.HexScore > 0.8 {
		// Baseline expects hex
		score += weights["hex"] * (1.0 - absDiff(f.HexScore, baseline.HexScore))
	}

	return clamp(score, 0.0, 1.0)
}

// GetCommonBaseline returns a baseline representing common content types.
func GetCommonBaseline(contentType string) CharacterFingerprint {
	switch strings.ToLower(contentType) {
	case "english", "prose", "text":
		return EnglishBaseline
	case "code", "source", "programming":
		return CodeBaseline
	case "json", "data", "structured":
		return JSONBaseline
	case "base64", "encoded":
		return Base64Baseline
	case "hex", "binary":
		return HexBaseline
	default:
		return NaturalBaseline
	}
}

// Predefined baselines for common content types
var (
	// EnglishBaseline represents typical English prose
	EnglishBaseline = CharacterFingerprint{
		AlphanumericRatio: 0.80,
		UppercaseRatio:    0.05,
		LowercaseRatio:    0.70,
		DigitRatio:        0.03,
		WhitespaceRatio:   0.15,
		PunctuationRatio:  0.05,
		Base64Score:       0.0,
		HexScore:          0.0,
		UniqueCharRatio:   0.40,
	}

	// CodeBaseline represents typical programming code
	CodeBaseline = CharacterFingerprint{
		AlphanumericRatio: 0.70,
		UppercaseRatio:    0.10,
		LowercaseRatio:    0.55,
		DigitRatio:        0.08,
		WhitespaceRatio:   0.15,
		PunctuationRatio:  0.15,
		Base64Score:       0.0,
		HexScore:          0.0,
		UniqueCharRatio:   0.50,
	}

	// JSONBaseline represents typical JSON data
	JSONBaseline = CharacterFingerprint{
		AlphanumericRatio: 0.60,
		UppercaseRatio:    0.05,
		LowercaseRatio:    0.50,
		DigitRatio:        0.20,
		WhitespaceRatio:   0.10,
		PunctuationRatio:  0.15, // {},:[]"
		Base64Score:       0.0,
		HexScore:          0.0,
		UniqueCharRatio:   0.35,
	}

	// Base64Baseline represents typical Base64 encoded content
	Base64Baseline = CharacterFingerprint{
		AlphanumericRatio: 1.0,
		UppercaseRatio:    0.40,
		LowercaseRatio:    0.40,
		DigitRatio:        0.20,
		WhitespaceRatio:   0.0,
		PunctuationRatio:  0.0,
		Base64Score:       1.0,
		HexScore:          0.0,
		UniqueCharRatio:   0.60,
	}

	// HexBaseline represents typical hexadecimal content
	HexBaseline = CharacterFingerprint{
		AlphanumericRatio: 1.0,
		UppercaseRatio:    0.50,
		LowercaseRatio:    0.50,
		DigitRatio:        0.50,
		WhitespaceRatio:   0.0,
		PunctuationRatio:  0.0,
		Base64Score:       0.0,
		HexScore:          1.0,
		UniqueCharRatio:   0.20,
	}

	// NaturalBaseline represents general natural language
	NaturalBaseline = CharacterFingerprint{
		AlphanumericRatio: 0.75,
		UppercaseRatio:    0.05,
		LowercaseRatio:    0.65,
		DigitRatio:        0.05,
		WhitespaceRatio:   0.15,
		PunctuationRatio:  0.05,
		Base64Score:       0.0,
		HexScore:          0.0,
		UniqueCharRatio:   0.35,
	}
)

// CalculateBase64Score returns score (0.0-1.0) for Base64 likelihood.
func CalculateBase64Score(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	validSet := make(map[rune]bool)
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" {
		validSet[c] = true
	}

	validCount := 0
	for _, b := range data { //nolint:gosec G115 - byte (0-255) always valid as rune
		if validSet[rune(b)] {
			validCount++
		}
	}

	return float64(validCount) / float64(len(data))
}

// CalculateHexScore returns score (0.0-1.0) for hex likelihood.
func CalculateHexScore(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	validCount := 0
	for _, b := range data {
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
			validCount++
		}
	}

	return float64(validCount) / float64(len(data))
}

// calculateAverageRunLength computes average length of consecutive same-type characters.
func calculateAverageRunLength(data []byte) float64 {
	if len(data) < 2 {
		return 1.0
	}

	var totalRuns, totalLength int
	currentType := classifyChar(data[0])
	currentRun := 1

	for i := 1; i < len(data); i++ {
		charType := classifyChar(data[i])
		if charType == currentType {
			currentRun++
		} else {
			totalRuns++
			totalLength += currentRun
			currentType = charType
			currentRun = 1
		}
	}

	if currentRun > 0 {
		totalRuns++
		totalLength += currentRun
	}

	if totalRuns == 0 {
		return 1.0
	}

	return float64(totalLength) / float64(totalRuns)
}

// classifyChar categorizes a byte for run-length analysis.
func classifyChar(b byte) int {
	if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
		return 1 // Letter
	}
	if b >= '0' && b <= '9' {
		return 2 // Digit
	}
	if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
		return 3 // Whitespace
	}
	return 4 // Other
}

// absDiff returns absolute difference between two floats.
func absDiff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}

// clamp ensures value is within bounds.
func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
