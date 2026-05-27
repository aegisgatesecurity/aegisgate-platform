// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Computer Use API (Claude) Security Types
// ============================================================================

package computeruse

import (
	"fmt"
	"time"
)

// ============================================================================
// Browser Activity Types
// ============================================================================

// BrowserAction represents an action taken in the browser
type BrowserAction struct {
	Type      string            `json:"type"`
	URL       string            `json:"url"`
	Element   string            `json:"element,omitempty"`
	X         int               `json:"x,omitempty"`
	Y         int               `json:"y,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	AgentID   string            `json:"agent_id"`
	SessionID string            `json:"session_id"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// NewBrowserAction creates a new browser action
func NewBrowserAction(actionType, url, agentID, sessionID string) *BrowserAction {
	return &BrowserAction{
		Type:      actionType,
		URL:       url,
		AgentID:   agentID,
		SessionID: sessionID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}
}

// Action types
const (
	ActionClick      = "click"
	ActionType       = "type"
	ActionNavigate   = "navigate"
	ActionScreenshot = "screenshot"
	ActionScroll     = "scroll"
	ActionHover      = "hover"
)

// ============================================================================
// Form Field Types
// ============================================================================

// FormField represents a form field detected in the browser
type FormField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	IsSensitive bool   `json:"is_sensitive"`
	Label       string `json:"label,omitempty"`
	X           int    `json:"x,omitempty"`
	Y           int    `json:"y,omitempty"`
}

// Sensitive field types
var sensitiveFieldTypes = map[string]bool{
	"password":    true,
	"credit_card": true,
	"ssn":         true,
	"cvv":         true,
	"pin":         true,
	"secret":      true,
	"api_key":     true,
	"private_key": true,
}

// IsSensitiveField checks if a field type is sensitive
func IsSensitiveField(fieldType string) bool {
	return sensitiveFieldTypes[fieldType]
}

// ============================================================================
// Guard Result Types
// ============================================================================

// GuardDecision represents the decision of a guard check
type GuardDecision string

const (
	DecisionAllow           GuardDecision = "allow"
	DecisionBlock           GuardDecision = "block"
	DecisionMask            GuardDecision = "mask"
	DecisionRequireApproval GuardDecision = "require_approval"
	DecisionLogOnly         GuardDecision = "log_only"
)

// GuardResult represents the result of a guard check
type GuardResult struct {
	Decision    GuardDecision
	Reason      string
	MatchedRule string
	Severity    string
	Metadata    map[string]string
}

// NewGuardResult creates a new guard result
func NewGuardResult(decision GuardDecision, reason, rule, severity string) *GuardResult {
	return &GuardResult{
		Decision:    decision,
		Reason:      reason,
		MatchedRule: rule,
		Severity:    severity,
		Metadata:    make(map[string]string),
	}
}

// Allow returns true if the decision is allow
func (r *GuardResult) Allow() bool {
	return r.Decision == DecisionAllow || r.Decision == DecisionMask
}

// Block returns true if the decision is block
func (r *GuardResult) Block() bool {
	return r.Decision == DecisionBlock
}

// ============================================================================
// Security Context
// ============================================================================

// SecurityContext contains security-relevant information
type SecurityContext struct {
	AgentID      string
	SessionID    string
	TrustScore   float64
	Capabilities []string
	Timestamp    time.Time
	Metadata     map[string]string
}

// NewSecurityContext creates a security context
func NewSecurityContext(agentID, sessionID string) *SecurityContext {
	return &SecurityContext{
		AgentID:   agentID,
		SessionID: sessionID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds computer use guard configuration
type Config struct {
	// URL validation
	URLAllowlist   []string
	URLDenylist    []string
	AllowByDefault bool

	// Rate limiting
	MaxClicksPerMinute      int
	MaxScreenshotsPerMinute int
	MaxKeystrokesPerMinute  int

	// Sensitive data protection
	BlockCreditCards  bool
	BlockSSN          bool
	BlockPasswords    bool
	MaskSessionTokens bool

	// Screenshot limits
	ScreenshotCooldownSeconds int

	// Click pattern detection
	ClickRateThreshold int // Max clicks per 10 seconds to be considered rapid

	// Form field protection
	BlockSensitiveFields bool
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		URLAllowlist:              []string{},
		URLDenylist:               []string{"localhost", "127.0.0.1", "0.0.0.0"},
		AllowByDefault:            true,
		MaxClicksPerMinute:        10,
		MaxScreenshotsPerMinute:   1,
		MaxKeystrokesPerMinute:    120,
		BlockCreditCards:          true,
		BlockSSN:                  true,
		BlockPasswords:            true,
		MaskSessionTokens:         true,
		ScreenshotCooldownSeconds: 60,
		ClickRateThreshold:        5,
		BlockSensitiveFields:      true,
	}
}

// ============================================================================
// Helper functions
// ============================================================================

func generateID() string {
	return fmt.Sprintf("cu_%d_%s", time.Now().UnixNano(), randomString(8))
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[int(time.Now().UnixNano())%len(charset)]
	}
	return string(b)
}
