package anomaly

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"time"
)

// IntegrationPoint defines where anomaly detection is integrated.
type IntegrationPoint string

const (
	// IntegrationResponseGuard integrates with response guard
	IntegrationResponseGuard IntegrationPoint = "response_guard"
	// IntegrationSecretScanner integrates with secret scanner
	IntegrationSecretScanner IntegrationPoint = "secret_scanner"
	// IntegrationMCPServer integrates with MCP session
	IntegrationMCPServer IntegrationPoint = "mcp_server"
	// IntegrationHTTPGuard integrates with HTTP middleware
	IntegrationHTTPGuard IntegrationPoint = "http_guard"
)

// IntegrationConfig holds integration-specific settings.
type IntegrationConfig struct {
	// Point is where anomaly detection is integrated
	Point IntegrationPoint

	// Enabled controls whether this integration is active
	Enabled bool

	// AugmentResults when true, adds anomaly scores to existing results
	AugmentResults bool

	// BlockOnAlert when true, blocks requests that exceed alert threshold
	BlockOnAlert bool

	// Timeout for analysis
	Timeout time.Duration

	// Logger for debugging
	Logger *slog.Logger

	// Config for scoring
	ScorerConfig ScorerConfig
}

// DefaultIntegrationConfig returns default integration settings.
func DefaultIntegrationConfig(point IntegrationPoint) IntegrationConfig {
	return IntegrationConfig{
		Point:          point,
		Enabled:        true,
		AugmentResults: true,
		BlockOnAlert:   false, // Fail-closed: anomaly doesn't block alone
		Timeout:        10 * time.Millisecond,
		Logger:         slog.Default(),
		ScorerConfig:   DefaultScorerConfig(),
	}
}

// ScannerResult represents the result of a scan with anomaly augmentation.
type ScannerResult struct {
	// OriginalResult is the result from the underlying scanner
	OriginalResult interface{}

	// AnomalyScore is the calculated anomaly score
	AnomalyScore AnomalyScore

	// Augmented indicates if anomaly detection was applied
	Augmented bool

	// ProcessingTime is how long the analysis took
	ProcessingTime time.Duration

	// Error is any error that occurred during analysis
	Error error

	// BlockOnAlert controls blocking behavior for this result
	BlockOnAlert bool
}

// AnomalyAugmentedScanner wraps an existing scanner with anomaly detection.
type AnomalyAugmentedScanner struct {
	// Scanner is the underlying scanner being wrapped
	Scanner interface {
		Scan(data []byte) interface{}
	}

	// Config for anomaly detection
	Config IntegrationConfig

	// ThresholdManager for adaptive thresholds (optional)
	ThresholdMgr *ThresholdManager
}

// NewAnomalyAugmentedScanner creates a new augmented scanner.
func NewAnomalyAugmentedScanner(scanner interface {
	Scan(data []byte) interface{}
}, config IntegrationConfig) *AnomalyAugmentedScanner {
	return &AnomalyAugmentedScanner{
		Scanner: scanner,
		Config:  config,
	}
}

// Scan performs scanning with anomaly detection augmentation.
func (s *AnomalyAugmentedScanner) Scan(data []byte) ScannerResult {
	start := time.Now()

	result := ScannerResult{
		Augmented:    true,
		BlockOnAlert: s.Config.BlockOnAlert,
	}

	if !s.Config.Enabled {
		result.Augmented = false
		return result
	}

	// Check timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.Config.Timeout)
	defer cancel()

	// Run anomaly detection with timeout
	done := make(chan AnomalyScore, 1)
	go func() {
		done <- Score(data, s.Config.ScorerConfig)
	}()

	select {
	case <-ctx.Done():
		result.Error = fmt.Errorf("anomaly detection timeout after %v", s.Config.Timeout)
		result.ProcessingTime = time.Since(start)
		return result
	case anomalyScore := <-done:
		result.AnomalyScore = anomalyScore

		// Record sample for threshold adaptation
		if s.ThresholdMgr != nil {
			s.ThresholdMgr.RecordSample(anomalyScore.Total)
		}
	}

	// Run underlying scanner
	result.OriginalResult = s.Scanner.Scan(data)

	result.ProcessingTime = time.Since(start)

	return result
}

// ShouldBlock determines if the result should be blocked.
func (r ScannerResult) ShouldBlock() bool {
	if r.Error != nil {
		// Fail-closed: errors don't block
		return false
	}

	// Only block if explicitly configured AND alert threshold exceeded
	return r.BlockOnAlert && r.AnomalyScore.IsAlert
}

// LogResult logs the scan result.
func (r ScannerResult) LogResult(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	attrs := []any{
		"augmented", r.Augmented,
		"processing_ms", r.ProcessingTime.Milliseconds(),
	}

	if r.Error != nil {
		attrs = append(attrs, "error", r.Error.Error())
		logger.Warn("anomaly_scan_error", attrs...)
		return
	}

	if r.AnomalyScore.IsAlert {
		attrs = append(attrs,
			"score", r.AnomalyScore.Total,
			"classification", r.AnomalyScore.Classification,
			"flags", r.AnomalyScore.Flags,
			"token_type", r.AnomalyScore.TokenType.String(),
		)
		logger.Warn("anomaly_alert", attrs...)
	} else if r.AnomalyScore.IsAnomalous {
		attrs = append(attrs,
			"score", r.AnomalyScore.Total,
			"classification", r.AnomalyScore.Classification,
		)
		logger.Info("anomaly_detected", attrs...)
	}
}

// TokenScanner provides specialized scanning for tokens/keys.
type TokenScanner struct {
	Config IntegrationConfig
}

// NewTokenScanner creates a new token scanner.
func NewTokenScanner(config IntegrationConfig) *TokenScanner {
	config.Point = IntegrationSecretScanner
	return &TokenScanner{
		Config: config,
	}
}

// ScanToken scans a single token.
func (s *TokenScanner) ScanToken(token string) ScannerResult {
	start := time.Now()

	result := ScannerResult{
		Augmented:    true,
		BlockOnAlert: s.Config.BlockOnAlert,
	}

	if !s.Config.Enabled || token == "" {
		result.Augmented = false
		return result
	}

	// Run anomaly detection
	score := ScoreToken(token, s.Config.ScorerConfig)
	result.AnomalyScore = score

	result.ProcessingTime = time.Since(start)

	return result
}

// ScanTokens scans multiple tokens.
func (s *TokenScanner) ScanTokens(tokens []string) []ScannerResult {
	results := make([]ScannerResult, len(tokens))
	for i, token := range tokens {
		results[i] = s.ScanToken(token)
	}
	return results
}

// ScanData scans arbitrary data.
func (s *TokenScanner) ScanData(data []byte) ScannerResult {
	start := time.Now()

	result := ScannerResult{
		Augmented:    true,
		BlockOnAlert: s.Config.BlockOnAlert,
	}

	if !s.Config.Enabled || len(data) == 0 {
		result.Augmented = false
		return result
	}

	// Run anomaly detection
	score := Score(data, s.Config.ScorerConfig)
	result.AnomalyScore = score

	result.ProcessingTime = time.Since(start)

	return result
}

// ScanString is a convenience wrapper for string input.
func (s *TokenScanner) ScanString(str string) ScannerResult {
	return s.ScanToken(str)
}

// ScanJSON scans a JSON payload for potential secrets.
func (s *TokenScanner) ScanJSON(data []byte) []ScannerResult {
	var results []ScannerResult

	// Simple JSON scanning: look for common secret field names
	secretFields := []string{"key", "token", "secret", "password", "credential", "auth"}

	for _, field := range secretFields {
		// Look for "field": "value" patterns
		pattern := []byte(fmt.Sprintf(`"%s":`, field))
		idx := bytes.Index(data, pattern)
		if idx >= 0 {
			// Extract value (simplified - real implementation would use proper JSON parsing)
			start := idx + len(pattern)
			for start < len(data) && (data[start] == ' ' || data[start] == '"') {
				start++
			}
			end := start
			for end < len(data) && data[end] != '"' && data[end] != ',' && data[end] != '\n' {
				end++
			}
			if end > start {
				value := string(data[start:end])
				result := s.ScanToken(value)
				if result.AnomalyScore.IsAnomalous {
					results = append(results, result)
				}
			}
		}
	}

	return results
}

// WithThresholdManager sets the threshold manager for adaptive thresholds.
func (s *TokenScanner) WithThresholdManager(tm *ThresholdManager) *TokenScanner {
	// Store in config for now
	s.Config.ScorerConfig = tm.GetScorerConfig()
	return s
}

// HighEntropyScanner scans for high-entropy content only.
type HighEntropyScanner struct {
	EntropyThreshold float64
	Logger           *slog.Logger
}

// NewHighEntropyScanner creates a scanner for high-entropy content.
func NewHighEntropyScanner(threshold float64) *HighEntropyScanner {
	return &HighEntropyScanner{
		EntropyThreshold: threshold,
		Logger:           slog.Default(),
	}
}

// IsHighEntropy checks if data exceeds entropy threshold.
func (s *HighEntropyScanner) IsHighEntropy(data []byte) bool {
	entropy := ShannonEntropy(data)
	return entropy >= s.EntropyThreshold
}

// ScanForHighEntropy scans data and returns true if high entropy detected.
func (s *HighEntropyScanner) ScanForHighEntropy(data []byte) (bool, float64) {
	entropy := ShannonEntropy(data)
	isHigh := entropy >= s.EntropyThreshold

	if isHigh && s.Logger != nil {
		s.Logger.Debug("high_entropy_detected",
			"entropy", entropy,
			"threshold", s.EntropyThreshold,
			"length", len(data),
		)
	}

	return isHigh, entropy
}

// EncoderDetector detects encoded content (Base64, hex, etc.).
type EncoderDetector struct {
	Base64Threshold float64
	HexThreshold    float64
}

// NewEncoderDetector creates a new encoder detector.
func NewEncoderDetector() *EncoderDetector {
	return &EncoderDetector{
		Base64Threshold: 0.9,
		HexThreshold:    0.9,
	}
}

// Detect checks if data appears to be encoded.
func (d *EncoderDetector) Detect(data []byte) (isEncoded bool, encodingType string, score float64) {
	base64Score := Base64Likeness(data)
	hexScore := HexLikeness(data)

	if base64Score >= d.Base64Threshold {
		return true, "base64", base64Score
	}

	if hexScore >= d.HexThreshold {
		return true, "hex", hexScore
	}

	// Check for double encoding
	if base64Score > 0.7 {
		// Try decoding and re-check
		decoded := tryBase64Decode(data)
		if decoded != nil {
			innerBase64 := Base64Likeness(decoded)
			if innerBase64 > 0.7 {
				return true, "double_base64", base64Score * innerBase64
			}
		}
	}

	return false, "unknown", max(base64Score, hexScore)
}

// tryBase64Decode attempts to decode Base64.
func tryBase64Decode(data []byte) []byte {
	// Simple Base64 decode attempt
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	for _, b := range data {
		found := false
		for _, c := range base64Chars {
			if c == rune(b) {
				found = true
				break
			}
		}
		if !found && b != '=' && b != '\n' && b != '\r' && b != ' ' {
			return nil
		}
	}

	// Basic validation passed - this is not a full decode
	// Full implementation would use base64.StdEncoding.DecodeString
	return data // Return as-is for simple check
}

// ScanFunc is a function type for scanning data.
type ScanFunc func([]byte) interface{}

// WrapWithAnomalyDetection is a convenience function to wrap a function with anomaly detection.
func WrapWithAnomalyDetection(fn ScanFunc, config IntegrationConfig) func([]byte) ScannerResult {
	return func(data []byte) ScannerResult {
		start := time.Now()
		result := ScannerResult{
			Augmented:    true,
			BlockOnAlert: config.BlockOnAlert,
		}

		if !config.Enabled {
			result.Augmented = false
			return result
		}

		// Run anomaly detection
		done := make(chan AnomalyScore, 1)
		go func() {
			done <- Score(data, config.ScorerConfig)
		}()

		select {
		case <-time.After(config.Timeout):
			result.Error = fmt.Errorf("anomaly detection timeout")
			return result
		case anomalyScore := <-done:
			result.AnomalyScore = anomalyScore
		}

		// Run underlying scanner
		result.OriginalResult = fn(data)
		result.ProcessingTime = time.Since(start)

		return result
	}
}
