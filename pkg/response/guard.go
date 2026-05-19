// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Response Guard
// =========================================================================
//
// Main entry point for AI Response Security scanning.
// Combines PII scanning, secret detection, token rate limiting,
// and toxicity filtering into a unified response guard.
// =========================================================================

package response

import (
	"context"
	"sync"
	"time"
)

// ============================================================================
// Response Guard
// ============================================================================

// ResponseGuard is the main response scanning middleware
type ResponseGuard struct {
	// config holds the guard configuration
	config *ResponseGuardConfig

	// piiScanner detects PII in responses
	piiScanner *PIIScanner

	// secretDetector detects secrets in responses
	secretDetector *SecretDetector

	// tokenLimiter tracks and limits token usage
	tokenLimiter *TokenLimiter

	// toxicityFilter filters harmful content
	toxicityFilter *ToxicityFilter

	// hallucinationDetector detects hallucinations
	hallucinationDetector *HallucinationDetector

	// mu protects concurrent access
	mu sync.RWMutex

	// clientUsage tracks per-client usage
	clientUsage map[string]*TokenUsage

	// enabled indicates if the guard is enabled
	enabled bool
}

// NewResponseGuard creates a new response guard with default configuration
func NewResponseGuard() *ResponseGuard {
	return NewResponseGuardWithConfig(DefaultResponseGuardConfig())
}

// NewResponseGuardWithConfig creates a response guard with custom configuration
func NewResponseGuardWithConfig(config *ResponseGuardConfig) *ResponseGuard {
	if config == nil {
		config = DefaultResponseGuardConfig()
	}

	rg := &ResponseGuard{
		config:         config,
		piiScanner:    NewPIIScanner(),
		secretDetector: NewSecretDetector(),
		tokenLimiter:  NewTokenLimiter(DefaultTokenLimiterConfig()),
		toxicityFilter: NewToxicityFilter(),
		clientUsage:   make(map[string]*TokenUsage),
		enabled:        true,
	}

	// Initialize hallucination detector if enabled
	if config.EnableHallucination {
		rg.hallucinationDetector = NewHallucinationDetector(nil)
	}

	return rg
}

// Scan performs a complete security scan on the response
func (rg *ResponseGuard) Scan(ctx context.Context, response string) (*ResponseScanResult, error) {
	return rg.ScanWithContext(ctx, response, nil)
}

// ScanWithContext performs response scanning with optional scan context
func (rg *ResponseGuard) ScanWithContext(ctx context.Context, response string, scanCtx *ScanContext) (*ResponseScanResult, error) {
	startTime := time.Now()
	result := &ResponseScanResult{
		Allowed:           true,
		Threats:           []Threat{},
		DetectedPII:      []PIICategory{},
		DetectedSecrets:  []string{},
		ScanTime:         startTime,
		ComplianceReports: make(map[string]ComplianceResult),
	}

	rg.mu.RLock()
	defer rg.mu.RUnlock()

	// Check if guard is disabled
	if !rg.enabled {
		result.Allowed = true
		result.LatencyMs = time.Since(startTime).Milliseconds()
		return result, nil
	}

	// 1. Scan for PII if enabled
	if rg.config.EnablePIIScanner {
		piiMatches := rg.piiScanner.FindPII(response)
		for _, match := range piiMatches {
			result.DetectedPII = append(result.DetectedPII, match.Category)
			result.Threats = append(result.Threats, Threat{
				Type:     "pii",
				Severity: match.Severity,
				Message:  string(match.Category) + " detected in response",
				Location: "response_body",
				Pattern:  string(match.Category),
				MatchStart: match.Start,
				MatchEnd:   match.End,
			})
		}
	}

	// 2. Scan for secrets if enabled
	if rg.config.EnableSecretDetection {
		secretMatches := rg.secretDetector.FindSecrets(response)
		for _, match := range secretMatches {
			result.DetectedSecrets = append(result.DetectedSecrets, match.Provider+":"+string(match.Category))
			result.Threats = append(result.Threats, Threat{
				Type:     "secret",
				Severity: match.Severity,
				Message:  match.Provider + " " + string(match.Category) + " detected in response",
				Location: "response_body",
				Pattern:  string(match.Category),
				MatchStart: match.Start,
				MatchEnd:   match.End,
			})
		}
	}

	// 3. Check token limits if enabled
	if rg.tokenLimiter != nil && scanCtx != nil {
		clientID := "default"
		if scanCtx != nil {
			clientID = scanCtx.ClientID
		}
		
		tokenCount := rg.tokenLimiter.CountTokens(response)
		result.Tokens = tokenCount
		
		allowed, reason := rg.tokenLimiter.AllowToken(clientID, tokenCount)
		if !allowed {
			result.Allowed = false
			result.BlockReason = reason
			result.Threats = append(result.Threats, Threat{
				Type:     "token_limit",
				Severity: 4,
				Message:  reason,
				Location: "response_size",
			})
		}
	} else {
		result.Tokens = rg.tokenLimiter.CountTokens(response)
	}

	// 4. Check toxicity if enabled
	if rg.config.EnableToxicityFilter && rg.toxicityFilter != nil {
		toxicityResult := rg.toxicityFilter.Scan(response)
		if toxicityResult.Filtered {
			result.Allowed = false
			result.BlockReason = "Toxic content detected: " + toxicityResult.Explanation
			result.Threats = append(result.Threats, Threat{
				Type:     "toxicity",
				Severity: toxicityResult.Severity,
				Message:  toxicityResult.Explanation,
				Location: "response_body",
			})
		}
	}

	// 5. Check hallucination if enabled
	if rg.config.EnableHallucination && rg.hallucinationDetector != nil {
		hallResult := rg.hallucinationDetector.Scan(response)
		if hallResult.Flagged {
			// Hallucinations are warnings, not blocks (unless strict mode)
			if rg.config.StrictMode {
				result.Allowed = false
				result.BlockReason = "Hallucination detected: " + hallResult.Explanation
			}
			result.Threats = append(result.Threats, Threat{
				Type:     "hallucination",
				Severity: 3,
				Message:  hallResult.Explanation,
				Location: "response_content",
			})
		}
	}

	// Determine if response should be blocked
	if rg.config.StrictMode && len(result.Threats) > 0 {
		result.Allowed = false
		if result.BlockReason == "" {
			result.BlockReason = "Strict mode: threats detected in response"
		}
	}

	// Add compliance reports
	rg.addComplianceReports(result)

	result.LatencyMs = time.Since(startTime).Milliseconds()
	return result, nil
}

// ScanWithConfig performs scanning with custom configuration
func (rg *ResponseGuard) ScanWithConfig(ctx context.Context, response string, config *ResponseGuardConfig) (*ResponseScanResult, error) {
	// Create a temporary guard with the custom config
	tempGuard := &ResponseGuard{
		config:          config,
		piiScanner:      rg.piiScanner,
		secretDetector:  rg.secretDetector,
		tokenLimiter:    rg.tokenLimiter,
		toxicityFilter:  rg.toxicityFilter,
		enabled:         true,
	}

	if config.EnableHallucination {
		tempGuard.hallucinationDetector = rg.hallucinationDetector
	}

	return tempGuard.ScanWithContext(ctx, response, nil)
}

// Enable enables the response guard
func (rg *ResponseGuard) Enable() {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.enabled = true
}

// Disable disables the response guard
func (rg *ResponseGuard) Disable() {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.enabled = false
}

// IsEnabled returns whether the guard is enabled
func (rg *ResponseGuard) IsEnabled() bool {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	return rg.enabled
}

// UpdateConfig updates the guard configuration
func (rg *ResponseGuard) UpdateConfig(config *ResponseGuardConfig) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.config = config
}

// GetConfig returns the current guard configuration
func (rg *ResponseGuard) GetConfig() *ResponseGuardConfig {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	return rg.config
}

// ResetUsage resets token usage for a client
func (rg *ResponseGuard) ResetUsage(clientID string) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	delete(rg.clientUsage, clientID)
}

// ResetAllUsage resets all client usage
func (rg *ResponseGuard) ResetAllUsage() {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.clientUsage = make(map[string]*TokenUsage)
}

// GetUsage returns token usage for a client
func (rg *ResponseGuard) GetUsage(clientID string) *TokenUsage {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	return rg.clientUsage[clientID]
}

// addComplianceReports adds compliance reports to the result
func (rg *ResponseGuard) addComplianceReports(result *ResponseScanResult) {
	// Check for GDPR-relevant PII
	hasEmail := false
	hasPhone := false
	hasAddress := false
	for _, pii := range result.DetectedPII {
		switch pii {
		case PII_EMAIL:
			hasEmail = true
		case PII_PHONE:
			hasPhone = true
		case PII_ADDRESS:
			hasAddress = true
		}
	}

	if hasEmail || hasPhone || hasAddress {
		result.ComplianceReports["GDPR"] = ComplianceResult{
			Compliant: false,
			Violations: []string{"PII detected in AI response (GDPR Article 22)"},
			Framework: "GDPR",
			Timestamp: time.Now(),
		}
	}

	// Check for HIPAA-relevant PII
	hasHealth := false
	hasDOB := false
	for _, pii := range result.DetectedPII {
		if pii == PII_HEALTH || pii == PII_DATE_OF_BIRTH {
			hasHealth = true
			hasDOB = true
		}
	}

	if hasHealth || hasDOB {
		result.ComplianceReports["HIPAA"] = ComplianceResult{
			Compliant: false,
			Violations: []string{"Protected health information detected (HIPAA)"},
			Framework: "HIPAA",
			Timestamp: time.Now(),
		}
	}

	// Check for PCI-DSS relevant data
	hasCC := false
	hasBank := false
	for _, pii := range result.DetectedPII {
		if pii == PII_CREDIT_CARD {
			hasCC = true
		}
		if pii == PII_BANK_ACCOUNT {
			hasBank = true
		}
	}

	if hasCC || hasBank {
		result.ComplianceReports["PCI-DSS"] = ComplianceResult{
			Compliant: false,
			Violations: []string{"Payment card data detected (PCI-DSS)"},
			Framework: "PCI-DSS",
			Timestamp: time.Now(),
		}
	}

	// Check for secret/API key leakage (SOC2)
	if len(result.DetectedSecrets) > 0 {
		result.ComplianceReports["SOC2"] = ComplianceResult{
			Compliant: false,
			Violations: []string{"Secret/API key detected in response (SOC2)"},
			Framework: "SOC2",
			Timestamp: time.Now(),
		}
	}

	// If no violations, mark as compliant
	if len(result.DetectedPII) == 0 && len(result.DetectedSecrets) == 0 && result.Allowed {
		result.ComplianceReports["SOC2"] = ComplianceResult{
			Compliant: true,
			Framework: "SOC2",
			Timestamp: time.Now(),
		}
	}
}

// ============================================================================
// PII Scanner Interface
// ============================================================================

// PIIScanner returns the PII scanner for direct access
func (rg *ResponseGuard) PIIScanner() *PIIScanner {
	return rg.piiScanner
}

// SecretDetector returns the secret detector for direct access
func (rg *ResponseGuard) SecretDetector() *SecretDetector {
	return rg.secretDetector
}

// TokenLimiter returns the token limiter for direct access
func (rg *ResponseGuard) TokenLimiter() *TokenLimiter {
	return rg.tokenLimiter
}

// ============================================================================
// Standalone Functions
// ============================================================================

// ScanResponse is a convenience function for quick response scanning
func ScanResponse(response string) (*ResponseScanResult, error) {
	guard := NewResponseGuard()
	return guard.Scan(context.Background(), response)
}

// ScanResponseStrict performs strict scanning (fails on any detection)
func ScanResponseStrict(response string) (*ResponseScanResult, error) {
	config := DefaultResponseGuardConfig()
	config.StrictMode = true
	guard := NewResponseGuardWithConfig(config)
	return guard.Scan(context.Background(), response)
}

// RedactResponse redacts all PII from a response
func RedactResponse(response string) string {
	scanner := NewPIIScanner()
	return scanner.RedactPII(response, nil)
}

// MaskResponse masks all secrets from a response
func MaskResponse(response string) string {
	return MaskSecrets(response)
}