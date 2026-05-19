// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Response Redactor
// =========================================================================
//
// Intelligent redaction of sensitive data from AI responses.
// Uses the existing PII scanner and secret detector.
// =========================================================================

package response

import (
	"context"
	"strings"
	"sync"
)

// ============================================================================
// Redaction Config
// ============================================================================

// RedactionStrategy defines how to replace sensitive data
type RedactionStrategy int

const (
	// StrategyPlaceholder replaces with generic placeholder
	StrategyPlaceholder RedactionStrategy = iota
	// StrategyAsterisks replaces with asterisks
	StrategyAsterisks
	// StrategyHash replaces with hash
	StrategyHash
)

// RedactorConfig configures redaction behavior
type RedactorConfig struct {
	// Strategy for redaction
	Strategy RedactionStrategy

	// ReplaceWith custom replacement string
	ReplaceWith string

	// Categories to redact
	RedactSSN        bool
	RedactEmail      bool
	RedactPhone      bool
	RedactCreditCard bool
	RedactAPIKey     bool
	RedactPassword   bool
	RedactToken      bool

	// Generate audit trail
	GenerateAudit bool
}

// DefaultRedactorConfig returns default configuration
func DefaultRedactorConfig() *RedactorConfig {
	return &RedactorConfig{
		Strategy:         StrategyPlaceholder,
		ReplaceWith:      "[REDACTED]",
		RedactSSN:        true,
		RedactEmail:      true,
		RedactPhone:      true,
		RedactCreditCard: true,
		RedactAPIKey:     true,
		RedactPassword:   true,
		RedactToken:      true,
		GenerateAudit:    false,
	}
}

// ============================================================================
// Redactor
// ============================================================================

// Redactor handles intelligent redaction
type Redactor struct {
	config   *RedactorConfig
	pii      *PIIScanner
	secrets  *SecretDetector
	mu       sync.RWMutex
	auditLog []AuditEntry
}

// AuditEntry records a redaction event
type AuditEntry struct {
	Original  string
	Redacted  string
	Category  string
	Position  int
	Length    int
	Timestamp string
}

// NewRedactor creates a new redactor
func NewRedactor() *Redactor {
	return &Redactor{
		config:  DefaultRedactorConfig(),
		pii:     NewPIIScanner(),
		secrets: NewSecretDetector(),
	}
}

// NewRedactorWithConfig creates with custom config
func NewRedactorWithConfig(config *RedactorConfig) *Redactor {
	if config == nil {
		config = DefaultRedactorConfig()
	}

	return &Redactor{
		config:  config,
		pii:     NewPIIScanner(),
		secrets: NewSecretDetector(),
	}
}

// ============================================================================
// Redaction Methods
// ============================================================================

// Redact redacts sensitive data from text
func (r *Redactor) Redact(text string) string {
	return r.RedactWithContext(context.Background(), text)
}

// RedactWithContext redacts with context for timeout support
func (r *Redactor) RedactWithContext(ctx context.Context, text string) string {
	if text == "" {
		return ""
	}

	result := text

	// Redact PII
	result = r.redactPII(result)

	// Redact Secrets
	result = r.redactSecrets(result)

	return result
}

// redactPII redacts PII based on config
func (r *Redactor) redactPII(text string) string {
	matches := r.pii.FindPII(text)

	result := text
	for _, match := range matches {
		shouldRedact := false

		switch match.Category {
		case PII_SSN:
			shouldRedact = r.config.RedactSSN
		case PII_EMAIL:
			shouldRedact = r.config.RedactEmail
		case PII_PHONE:
			shouldRedact = r.config.RedactPhone
		case PII_CREDIT_CARD:
			shouldRedact = r.config.RedactCreditCard
		}

		if shouldRedact {
			replacement := r.getReplacement(len(match.Value))
			result = strings.Replace(result, match.Value, replacement, -1)
		}
	}

	return result
}

// redactSecrets redacts secrets based on config
func (r *Redactor) redactSecrets(text string) string {
	matches := r.secrets.FindSecrets(text)

	result := text
	for _, match := range matches {
		shouldRedact := false

		switch match.Category {
		case SECRET_API_KEY, SECRET_AWS_KEY:
			shouldRedact = r.config.RedactAPIKey
		case SECRET_PASSWORD:
			shouldRedact = r.config.RedactPassword
		case SECRET_BEARER_TOKEN, SECRET_JWT:
			shouldRedact = r.config.RedactToken
		}

		if shouldRedact {
			replacement := r.getReplacement(len(match.Value))
			result = strings.Replace(result, match.Value, replacement, -1)
		}
	}

	return result
}

// getReplacement returns appropriate replacement
func (r *Redactor) getReplacement(length int) string {
	if r.config.ReplaceWith != "" {
		return r.config.ReplaceWith
	}

	switch r.config.Strategy {
	case StrategyPlaceholder:
		return "[REDACTED]"
	case StrategyAsterisks:
		return strings.Repeat("*", length)
	case StrategyHash:
		return "[HASH]"
	default:
		return "[REDACTED]"
	}
}

// ============================================================================
// Batch Processing
// ============================================================================

// RedactBatch redacts multiple texts
func (r *Redactor) RedactBatch(texts []string) []string {
	results := make([]string, len(texts))
	for i, text := range texts {
		results[i] = r.Redact(text)
	}
	return results
}

// RedactBatchWithContext processes with timeout
func (r *Redactor) RedactBatchWithContext(ctx context.Context, texts []string) ([]string, error) {
	results := make([]string, len(texts))
	for i, text := range texts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			results[i] = r.Redact(text)
		}
	}
	return results, nil
}

// ============================================================================
// Audit Methods
// ============================================================================

// GetAuditLog returns the audit log
func (r *Redactor) GetAuditLog() []AuditEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	log := make([]AuditEntry, len(r.auditLog))
	copy(log, r.auditLog)
	return log
}

// ClearAuditLog clears the audit log
func (r *Redactor) ClearAuditLog() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auditLog = []AuditEntry{}
}

// ============================================================================
// Utility Functions
// ============================================================================

// QuickRedact performs quick redaction with defaults
func QuickRedact(text string) string {
	redactor := NewRedactor()
	return redactor.Redact(text)
}

// RedactWithStrategy performs redaction with specific strategy
func RedactWithStrategy(text string, strategy RedactionStrategy, replaceWith string) string {
	redactor := NewRedactorWithConfig(&RedactorConfig{
		Strategy:    strategy,
		ReplaceWith: replaceWith,
	})
	return redactor.Redact(text)
}

// RedactPIIOnly redacts only PII
func (r *Redactor) RedactPIIOnly(text string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	original := r.config.RedactAPIKey
	r.config.RedactAPIKey = false
	r.config.RedactPassword = false
	r.config.RedactToken = false
	defer func() { r.config.RedactAPIKey = original }()

	return r.Redact(text)
}

// RedactSecretsOnly redacts only secrets
func (r *Redactor) RedactSecretsOnly(text string) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	originalSSN := r.config.RedactSSN
	originalEmail := r.config.RedactEmail
	originalPhone := r.config.RedactPhone
	originalCC := r.config.RedactCreditCard

	r.config.RedactSSN = false
	r.config.RedactEmail = false
	r.config.RedactPhone = false
	r.config.RedactCreditCard = false

	defer func() {
		r.config.RedactSSN = originalSSN
		r.config.RedactEmail = originalEmail
		r.config.RedactPhone = originalPhone
		r.config.RedactCreditCard = originalCC
	}()

	return r.Redact(text)
}

// GetStats returns redaction statistics
func (r *Redactor) GetStats() *RedactorStats {
	return &RedactorStats{
		TotalRedacted: len(r.auditLog),
	}
}

// RedactorStats holds redaction statistics
type RedactorStats struct {
	TotalRedacted int
}
