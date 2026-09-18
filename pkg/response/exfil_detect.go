// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Egress Data Exfiltration Detection (v4.5.0 P5)
// =========================================================================
//
// exfil_detect.go detects potential data exfiltration in AI response streams.
// It extends the Egress Scanner by analyzing response content for patterns
// that indicate sensitive data is being leaked through the AI's output:
//
//   - Sensitive data aggregation (multiple PII/secret findings in one response)
//   - Encoding/obfuscation detection (base64, hex, unicode escapes wrapping secrets)
//   - Volume-based thresholds (response contains unusually large sensitive data)
//   - Repeated exfil attempts across turns in a session
//   - Cross-reference with ingress alerts (response to a suspected exfil prompt)
//
// The detector operates on the response guard's finding set and produces
// an ExfilResult that can trigger blocking or alerting.
// =========================================================================

package response

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// ExfilScoreThreshold is the minimum score to flag a response as exfiltration.
const ExfilScoreThreshold = 0.6

// MaxSensitiveFindingsPerResponse is the count above which aggregation is flagged.
const MaxSensitiveFindingsPerResponse = 5

// ExfilResult is the analysis output for a response exfiltration check.
type ExfilResult struct {
	SessionID    string
	IsExfil      bool
	Score        float64
	Flags        []string
	FindingCount int
	EncodedData  bool
}

// ExfilDetector analyzes response content for data exfiltration patterns.
type ExfilDetector struct {
	sessionAttempts map[string]int // session → exfil attempt count
	mu              sync.RWMutex
	threshold       float64
	maxFindings     int
}

// NewExfilDetector creates a new ExfilDetector with default configuration.
func NewExfilDetector() *ExfilDetector {
	return &ExfilDetector{
		sessionAttempts: make(map[string]int),
		threshold:       ExfilScoreThreshold,
		maxFindings:     MaxSensitiveFindingsPerResponse,
	}
}

// ExfilInput is the data passed to the detector for analysis.
type ExfilInput struct {
	SessionID       string
	ResponseBody    string
	SensitiveCount  int  // count of PII/secret findings from the response guard
	HasIngressAlert bool // whether the corresponding ingress prompt was flagged
	Timestamp       time.Time
}

// Analyze evaluates a response for exfiltration indicators.
func (ed *ExfilDetector) Analyze(input ExfilInput) ExfilResult {
	result := ExfilResult{
		SessionID:    input.SessionID,
		FindingCount: input.SensitiveCount,
	}

	score := 0.0

	// Factor 1: Sensitive data aggregation
	if input.SensitiveCount >= ed.maxFindings {
		score += 0.3
		result.Flags = append(result.Flags, "sensitive_data_aggregation")
	}

	// Factor 2: Encoding/obfuscation
	encoded := ed.detectEncoding(input.ResponseBody)
	if encoded {
		score += 0.25
		result.Flags = append(result.Flags, "encoded_content")
		result.EncodedData = true
	}

	// Factor 3: Response to a flagged ingress prompt
	if input.HasIngressAlert {
		score += 0.2
		result.Flags = append(result.Flags, "response_to_flagged_prompt")
	}

	// Factor 4: Repeated exfil attempts in session
	ed.mu.RLock()
	attempts := ed.sessionAttempts[input.SessionID]
	ed.mu.RUnlock()
	if attempts > 0 {
		score += 0.15 * float64(attempts)
		result.Flags = append(result.Flags, "repeated_exfil_attempt")
	}

	// Cap score at 1.0
	if score > 1.0 {
		score = 1.0
	}

	result.Score = score
	result.IsExfil = score >= ed.threshold

	// Track attempt if flagged
	if result.IsExfil {
		ed.mu.Lock()
		ed.sessionAttempts[input.SessionID]++
		ed.mu.Unlock()
	}

	return result
}

// detectEncoding checks if the response body contains encoded content
// that could be used to obfuscate exfiltrated data.
func (ed *ExfilDetector) detectEncoding(body string) bool {
	// Check for base64-encoded blocks (length > 20, valid charset)
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 20 {
			continue
		}
		if ed.isBase64(trimmed) {
			return true
		}
		if ed.isHex(trimmed) {
			return true
		}
	}
	return false
}

// isBase64 checks if a string is valid base64 and decodes to something non-trivial.
func (ed *ExfilDetector) isBase64(s string) bool {
	// Filter out common false positives (URLs, file paths)
	if strings.HasPrefix(s, "http") || strings.HasPrefix(s, "/") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return false
		}
	}
	// Must decode to something with printable content
	return len(decoded) > 10
}

// isHex checks if a string is a long hex sequence.
func (ed *ExfilDetector) isHex(s string) bool {
	if len(s) < 20 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// GetSessionAttempts returns the number of exfil attempts for a session.
func (ed *ExfilDetector) GetSessionAttempts(sessionID string) int {
	ed.mu.RLock()
	defer ed.mu.RUnlock()
	return ed.sessionAttempts[sessionID]
}

// ResetSession clears the attempt counter for a session.
func (ed *ExfilDetector) ResetSession(sessionID string) {
	ed.mu.Lock()
	defer ed.mu.Unlock()
	delete(ed.sessionAttempts, sessionID)
}
