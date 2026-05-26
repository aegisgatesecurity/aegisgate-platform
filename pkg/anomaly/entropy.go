package anomaly

import (
	"math"
)

// EntropyThresholds defines classification boundaries for entropy scores.
type EntropyThresholds struct {
	// Low is entropy below this value indicates natural language (default: 2.0)
	Low float64
	// Medium is entropy below this value but above Low indicates mixed content (default: 4.0)
	Medium float64
	// High is entropy below this value but above Medium indicates likely token/secret (default: 6.0)
	High float64
	// VeryHigh indicates entropy above High value (default: 7.0)
	VeryHigh float64
}

// DefaultEntropyThresholds returns industry-standard entropy boundaries.
func DefaultEntropyThresholds() EntropyThresholds {
	return EntropyThresholds{
		Low:      2.0,
		Medium:   4.0,
		High:     6.0,
		VeryHigh: 7.0,
	}
}

// Score returns a normalized score (0.0-1.0) based on entropy value.
// Higher entropy = higher anomaly score.
func (t EntropyThresholds) Score(entropy float64) float64 {
	if entropy <= 0 {
		return 0.0
	}

	// Normalize to 0.0-1.0 range based on max theoretical entropy (8.0 for bytes)
	// and apply sigmoid-like scaling for better distribution
	normalized := entropy / 8.0

	// Apply scaling: linear from 0-6, then sigmoid for 6-8
	var scaled float64
	if entropy <= t.High {
		scaled = normalized
	} else {
		// Sigmoid transition for very high entropy
		excess := entropy - t.High
		sigmoid := 1.0 / (1.0 + math.Exp(-(excess-1.0)*2.0))
		scaled = (t.High / 8.0) + sigmoid*(1.0-t.High/8.0)
	}

	// Clamp to valid range
	if scaled > 1.0 {
		scaled = 1.0
	}

	return scaled
}

// Classification returns a human-readable classification of entropy.
func (t EntropyThresholds) Classification(entropy float64) string {
	switch {
	case entropy < t.Low:
		return "natural_language"
	case entropy < t.Medium:
		return "mixed_content"
	case entropy < t.High:
		return "likely_token"
	case entropy < t.VeryHigh:
		return "high_entropy"
	default:
		return "very_high_entropy"
	}
}

// ShannonEntropy calculates the Shannon entropy of a byte slice.
// Returns value in range [0.0, 8.0] where:
//   - 0.0 = constant (all same byte)
//   - 4.0 = balanced distribution
//   - 8.0 = uniform random distribution
//
// Higher values indicate more randomness, which may indicate:
//   - Encoded content (Base64, hex)
//   - Cryptographic keys or tokens
//   - Passwords or secrets
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	var entropy float64
	n := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / n
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ShannonEntropyString is a convenience wrapper for string input.
func ShannonEntropyString(s string) float64 {
	return ShannonEntropy([]byte(s))
}

// Base64Entropy calculates entropy after attempting to decode as Base64.
// Returns normalized score to allow comparison with raw entropy.
func Base64Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Calculate raw entropy first
	rawEntropy := ShannonEntropy(data)

	// Check if it looks like Base64
	base64Score := Base64Likeness(data)

	// Adjust score based on encoding likelihood
	// High entropy + Base64-like = very likely encoded secret
	if base64Score > 0.7 {
		return rawEntropy * 1.2 // Boost to indicate encoding
	}

	return rawEntropy
}

// Base64Likeness returns a score (0.0-1.0) indicating how likely
// the data is Base64 encoded.
func Base64Likeness(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count valid Base64 characters
	validChars := 0
	validSet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	for _, b := range data {
		isValid := false
		for _, valid := range validSet {
			if byte(valid) == b {
				isValid = true
				break
			}
		}
		if isValid {
			validChars++
		}
	}

	return float64(validChars) / float64(len(data))
}

// HexLikeness returns a score (0.0-1.0) indicating how likely
// the data is hexadecimal encoded.
func HexLikeness(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	validChars := 0
	for _, b := range data {
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
			validChars++
		}
	}

	return float64(validChars) / float64(len(data))
}

// EntropyBenchmark is used for performance testing.
type EntropyBenchmark struct{}

// NewEntropyBenchmark creates a new benchmark helper.
func NewEntropyBenchmark() *EntropyBenchmark {
	return &EntropyBenchmark{}
}

// Measure returns entropy with benchmarking metadata.
func (b *EntropyBenchmark) Measure(data []byte) (float64, int) {
	return ShannonEntropy(data), len(data)
}
