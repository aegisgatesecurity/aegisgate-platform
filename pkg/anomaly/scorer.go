package anomaly

import (
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// ScorerConfig defines weights and thresholds for anomaly scoring.
type ScorerConfig struct {
	// EntropyWeight is the weight for entropy component (default: 0.3)
	EntropyWeight float64
	// FrequencyWeight is the weight for frequency component (default: 0.3)
	FrequencyWeight float64
	// StructureWeight is the weight for structure component (default: 0.4)
	StructureWeight float64

	// AnomalyThreshold is the score above which content is considered anomalous (default: 0.7)
	AnomalyThreshold float64
	// AlertThreshold is the score above which an alert should be generated (default: 0.85)
	AlertThreshold float64
	// SuspiciousThreshold is the score above which content should be flagged (default: 0.5)
	SuspiciousThreshold float64

	// CustomBaselines enables use of custom baselines instead of defaults
	CustomBaselines bool
	// NaturalBaseline is used for frequency comparison when CustomBaselines is true
	NaturalBaseline CharacterFingerprint
	// Base64Baseline is used for encoded content detection
	Base64Baseline CharacterFingerprint
}

// DefaultScorerConfig returns production-safe defaults.
func DefaultScorerConfig() ScorerConfig {
	return ScorerConfig{
		EntropyWeight:       0.3,
		FrequencyWeight:     0.3,
		StructureWeight:     0.4,
		AnomalyThreshold:    0.7,
		AlertThreshold:      0.85,
		SuspiciousThreshold: 0.5,
	}
}

// AnomalyScore represents combined detection score from multiple signals.
type AnomalyScore struct {
	// Total is the weighted combined score (0.0-1.0)
	Total float64
	// Entropy is the entropy component score (0.0-1.0)
	Entropy float64
	// Frequency is the frequency analysis component score (0.0-1.0)
	Frequency float64
	// Structure is the structure analysis component score (0.0-1.0)
	Structure float64
	// Confidence indicates overall confidence in the score (0.0-1.0)
	Confidence float64
	// Flags contains detection flags for logging
	Flags []string
	// Classification is a human-readable classification
	Classification string
	// IsAnomalous indicates if score exceeds anomaly threshold
	IsAnomalous bool
	// IsSuspicious indicates if score exceeds suspicious threshold
	IsSuspicious bool
	// IsAlert indicates if score exceeds alert threshold
	IsAlert bool
	// IsProduction indicates if detected token is production key
	IsProduction bool
	// TokenType is the detected token type (if applicable)
	TokenType TokenType
	// ProcessingTime is how long the analysis took
	ProcessingTime time.Duration
}

// Score analyzes input data and returns combined anomaly score.
func Score(data []byte, config ScorerConfig) AnomalyScore {
	start := time.Now()

	result := AnomalyScore{
		ProcessingTime: time.Since(start),
	}

	if len(data) == 0 {
		return result
	}

	// Calculate entropy component
	entropyValue := ShannonEntropy(data)
	result.Entropy = EntropyThresholds(DefaultEntropyThresholds()).Score(entropyValue)

	// Calculate frequency component
	fingerprint := Analyze(data)
	var baseline CharacterFingerprint
	if config.CustomBaselines {
		baseline = config.NaturalBaseline
	} else {
		baseline = NaturalBaseline
	}
	result.Frequency = 1.0 - fingerprint.CompareWithBaseline(baseline)

	// Calculate structure component
	fingerprintBase64 := Base64Baseline
	result.Structure = 1.0 - fingerprint.CompareWithBaseline(fingerprintBase64)

	// Combine scores with weights
	result.Total = (result.Entropy * config.EntropyWeight) +
		(result.Frequency * config.FrequencyWeight) +
		(result.Structure * config.StructureWeight)

	// Calculate confidence (based on agreement between components)
	confidence := calculateConfidence(result.Entropy, result.Frequency, result.Structure)
	result.Confidence = confidence

	// Set thresholds
	result.IsSuspicious = result.Total >= config.SuspiciousThreshold
	result.IsAnomalous = result.Total >= config.AnomalyThreshold
	result.IsAlert = result.Total >= config.AlertThreshold

	// Classification
	result.Classification = classifyScore(result.Total)

	// Build flags
	result.Flags = buildScoreFlags(result)

	// Check if it looks like a known token type
	tokenScore := ScoreToken(string(data), config)
	if tokenScore.IsAnomalous {
		result.TokenType = tokenScore.TokenType
		result.IsProduction = tokenScore.IsProduction
		result.Flags = append(result.Flags, "known_token_type")
	}

	result.ProcessingTime = time.Since(start)

	return result
}

// ScoreToken specifically analyzes string tokens for known patterns.
func ScoreToken(token string, config ScorerConfig) AnomalyScore {
	start := time.Now()

	result := AnomalyScore{
		ProcessingTime: time.Since(start),
	}

	if token == "" {
		return result
	}

	// Classify token structure
	ts := Classify(token)

	// Entropy component
	entropyThresholds := EntropyThresholds(DefaultEntropyThresholds())
	result.Entropy = entropyThresholds.Score(ts.Entropy)

	// Frequency component (check against natural language)
	fingerprint := AnalyzeString(token)
	result.Frequency = 1.0 - fingerprint.CompareWithBaseline(NaturalBaseline)

	// Structure component (check if it's encoded or known format)
	var baseline CharacterFingerprint
	if ts.IsEncoded {
		if ts.Base64Score > ts.HexScore {
			baseline = Base64Baseline
		} else {
			baseline = HexBaseline
		}
	} else {
		baseline = NaturalBaseline
	}
	result.Structure = 1.0 - fingerprint.CompareWithBaseline(baseline)

	// Boost structure score for known token types
	if ts.Type != TokenTypeUnknown {
		result.Structure = max(result.Structure, 0.7)
	}

	// Combine scores
	result.Total = (result.Entropy * config.EntropyWeight) +
		(result.Frequency * config.FrequencyWeight) +
		(result.Structure * config.StructureWeight)

	// Confidence
	result.Confidence = calculateConfidence(result.Entropy, result.Frequency, result.Structure)

	// Thresholds
	result.IsSuspicious = result.Total >= config.SuspiciousThreshold
	result.IsAnomalous = result.Total >= config.AnomalyThreshold
	result.IsAlert = result.Total >= config.AlertThreshold

	// Classification
	result.Classification = classifyScore(result.Total)

	// Token metadata
	result.TokenType = ts.Type
	result.IsProduction = ts.IsProduction

	// Build flags
	result.Flags = ts.Flags
	if ts.Type != TokenTypeUnknown {
		result.Flags = append(result.Flags, "known_format")
	}
	if ts.Entropy > 5.0 {
		result.Flags = append(result.Flags, "high_entropy")
	}
	if result.IsProduction {
		result.Flags = append(result.Flags, "production_indicator")
	}

	result.ProcessingTime = time.Since(start)

	return result
}

// calculateConfidence determines confidence in the score based on component agreement.
func calculateConfidence(entropy, frequency, structure float64) float64 {
	// High confidence when components agree
	variance := absDiff(entropy, frequency) + absDiff(frequency, structure) + absDiff(entropy, structure)

	// Lower variance = higher confidence
	// Max variance is 3.0 (each component differs by ~1.0)
	confidence := 1.0 - (variance / 4.5)

	return max(confidence, 0.3) // Minimum 30% confidence
}

// classifyScore returns human-readable classification.
func classifyScore(score float64) string {
	switch {
	case score < 0.3:
		return "normal"
	case score < 0.5:
		return "low_suspicion"
	case score < 0.7:
		return "suspicious"
	case score < 0.85:
		return "likely_anomalous"
	default:
		return "highly_anomalous"
	}
}

// buildScoreFlags creates flags for logging.
func buildScoreFlags(result AnomalyScore) []string {
	var flags []string

	if result.IsAlert {
		flags = append(flags, "alert")
	} else if result.IsAnomalous {
		flags = append(flags, "anomaly")
	} else if result.IsSuspicious {
		flags = append(flags, "suspicious")
	}

	if result.TokenType != TokenTypeUnknown {
		flags = append(flags, "token:"+result.TokenType.String())
	}

	if result.IsProduction {
		flags = append(flags, "production")
	}

	if result.Confidence < 0.5 {
		flags = append(flags, "low_confidence")
	}

	return flags
}

// max returns the maximum of two floats.
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ScoreResult is a convenience type for scan results.
type ScoreResult struct {
	IsAnomalous bool
	Score       AnomalyScore
	ShouldBlock bool
	Reason      string
}

// Scan performs a complete scan and returns result.
func Scan(data []byte, config ScorerConfig) ScoreResult {
	score := Score(data, config)

	result := ScoreResult{
		IsAnomalous: score.IsAnomalous,
		Score:       score,
		ShouldBlock: false, // Anomaly never blocks alone
	}

	if score.IsAlert {
		result.ShouldBlock = true
		result.Reason = "High anomaly score with alert threshold exceeded"
	} else if score.IsAnomalous {
		result.Reason = "Anomaly detected, flagging for review"
	} else {
		result.Reason = "Normal content"
	}

	// Record anomaly events in the global ring buffer for evidence
	// packages. Only record anomalous/alert events (clean scans would
	// dominate the ring buffer volume without adding signal).
	if result.IsAnomalous || result.ShouldBlock {
		sev := logging.SeverityMedium
		if result.ShouldBlock {
			sev = logging.SeverityHigh
		}
		logging.Record(logging.Event{
			Type:     "anomaly_score",
			Severity: sev,
			Message:  fmt.Sprintf("score=%.3f %s", score.Total, result.Reason),
		})
	}

	return result
}

// ScanString is a convenience wrapper for string input.
func ScanString(s string, config ScorerConfig) ScoreResult {
	return Scan([]byte(s), config)
}

// ScanToken performs token-specific scanning.
func ScanToken(token string, config ScorerConfig) ScoreResult {
	score := ScoreToken(token, config)

	result := ScoreResult{
		IsAnomalous: score.IsAnomalous,
		Score:       score,
		ShouldBlock: false,
	}

	if score.IsAlert {
		result.ShouldBlock = true
		result.Reason = "Token alert threshold exceeded"
	} else if score.IsAnomalous {
		result.Reason = "Token anomaly detected"
	} else {
		result.Reason = "Normal token"
	}

	return result
}

// SeverityLevel represents the severity of an anomaly.
type SeverityLevel int

const (
	SeverityNormal SeverityLevel = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// GetSeverity returns the severity level for a score.
func (s AnomalyScore) GetSeverity() SeverityLevel {
	switch {
	case s.Total >= 0.9:
		return SeverityCritical
	case s.Total >= 0.8:
		return SeverityHigh
	case s.Total >= 0.6:
		return SeverityMedium
	case s.Total >= 0.4:
		return SeverityLow
	default:
		return SeverityNormal
	}
}

// IsHighSeverity returns true if score is high or critical.
func (s AnomalyScore) IsHighSeverity() bool {
	return s.GetSeverity() >= SeverityHigh
}

// String returns human-readable severity.
func (s SeverityLevel) String() string {
	switch s {
	case SeverityNormal:
		return "normal"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// IsKnownServiceToken checks if the score indicates a known service token.
func (s AnomalyScore) IsKnownServiceToken() bool {
	knownServices := []TokenType{
		TokenTypeOpenAIKey,
		TokenTypeGitHubToken,
		TokenTypeStripeKey,
		TokenTypeAWSKey,
		TokenTypeSlackToken,
		TokenTypeJWT,
	}

	for _, t := range knownServices {
		if s.TokenType == t {
			return true
		}
	}

	return false
}

// ContainsServicePrefix checks if the token contains a known service prefix.
func (s AnomalyScore) ContainsServicePrefix() bool {
	knownPrefixes := []string{"sk-", "ghp_", "sk_live_", "xoxb-", "AKIA", "eyJ"}

	for _, prefix := range knownPrefixes {
		for _, flag := range s.Flags {
			if strings.Contains(flag, prefix) {
				return true
			}
		}
	}

	return false
}
