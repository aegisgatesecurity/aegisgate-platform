// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Computer Use API (Claude) Security Guard
// ============================================================================

package computeruse

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Guard provides security scanning for Computer Use API
type Guard struct {
	cfg    *Config
	logger *slog.Logger
	mu     sync.RWMutex

	// Rate limiting
	clickRate      map[string]*rateBucket
	screenshotRate map[string]*rateBucket
	screenshotLast map[string]time.Time
	keystrokeRate  map[string]*rateBucket

	// Click pattern tracking
	recentClicks map[string][]time.Time

	// Blocked patterns
	sensitivePatterns []*regexp.Regexp
}

// rateBucket for rate limiting
type rateBucket struct {
	tokens     int
	lastRefill time.Time
	maxTokens  int
	refillRate int
}

// NewGuard creates a new Computer Use security guard
func NewGuard() *Guard {
	return NewGuardWithConfig(DefaultConfig())
}

// NewGuardWithConfig creates guard with custom configuration
func NewGuardWithConfig(cfg *Config) *Guard {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	g := &Guard{
		cfg:            cfg,
		logger:         slog.Default().With("component", "computer-use-guard"),
		clickRate:      make(map[string]*rateBucket),
		screenshotRate: make(map[string]*rateBucket),
		screenshotLast: make(map[string]time.Time),
		keystrokeRate:  make(map[string]*rateBucket),
		recentClicks:   make(map[string][]time.Time),
	}

	// Compile sensitive patterns
	g.sensitivePatterns = []*regexp.Regexp{
		regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`), // Credit card
		regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                      // SSN
		regexp.MustCompile(`(?i)(api[_-]?key[:=]\s*[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`(?i)(secret[:=]\s*[a-zA-Z0-9]{16,})`),
		regexp.MustCompile(`(?i)(bearer\s+[a-zA-Z0-9_-]{20,})`),
		regexp.MustCompile(`(?i)(session[_-]?token[:=]\s*[a-zA-Z0-9]{16,})`),
	}

	return g
}

// ============================================================================
// URL Validation
// ============================================================================

// GuardURL validates a URL against allowlist/denylist
func (g *Guard) GuardURL(ctx context.Context, url string, secCtx *SecurityContext) (*GuardResult, error) {
	if url == "" {
		return nil, fmt.Errorf("URL is empty")
	}

	// Check denylist first
	for _, blocked := range g.cfg.URLDenylist {
		if strings.Contains(strings.ToLower(url), strings.ToLower(blocked)) {
			return NewGuardResult(DecisionBlock, fmt.Sprintf("URL contains blocked domain: %s", blocked), "cu_url_denylist", "critical"), nil
		}
	}

	// If allowlist has entries, check against it
	if len(g.cfg.URLAllowlist) > 0 {
		allowed := false
		for _, allowedDomain := range g.cfg.URLAllowlist {
			if strings.Contains(strings.ToLower(url), strings.ToLower(allowedDomain)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return NewGuardResult(DecisionBlock, "URL not in allowlist", "cu_url_whitelist", "high"), nil
		}
	}

	return NewGuardResult(DecisionAllow, "URL allowed", "cu_url_allowed", "low"), nil
}

// ============================================================================
// Click Rate Limiting
// ============================================================================

// GuardClick validates a click action
func (g *Guard) GuardClick(ctx context.Context, action *BrowserAction, secCtx *SecurityContext) (*GuardResult, error) {
	if action == nil {
		return nil, fmt.Errorf("action is nil")
	}

	agentID := secCtx.AgentID
	if agentID == "" {
		agentID = action.AgentID
	}

	// Check rate limit
	if !g.checkClickRateLimit(agentID) {
		return NewGuardResult(DecisionBlock, "click rate limit exceeded", "cu_click_rate_limit", "high"), nil
	}

	// Check for rapid clicking pattern
	if g.detectRapidClicking(agentID) {
		return NewGuardResult(DecisionLogOnly, "rapid clicking detected", "cu_click_pattern", "medium"), nil
	}

	// Track click
	g.trackClick(agentID)

	return NewGuardResult(DecisionAllow, "click allowed", "cu_click_allowed", "low"), nil
}

// ============================================================================
// Screenshot Rate Limiting
// ============================================================================

// GuardScreenshot validates a screenshot action
func (g *Guard) GuardScreenshot(ctx context.Context, action *BrowserAction, secCtx *SecurityContext) (*GuardResult, error) {
	if action == nil {
		return nil, fmt.Errorf("action is nil")
	}

	agentID := secCtx.AgentID
	if agentID == "" {
		agentID = action.AgentID
	}

	// Check cooldown
	g.mu.Lock()
	lastTime, exists := g.screenshotLast[agentID]
	if exists {
		elapsed := time.Since(lastTime)
		if elapsed < time.Duration(g.cfg.ScreenshotCooldownSeconds)*time.Second {
			g.mu.Unlock()
			return NewGuardResult(DecisionBlock, fmt.Sprintf("screenshot cooldown active, wait %d seconds", g.cfg.ScreenshotCooldownSeconds-int(elapsed.Seconds())), "cu_screenshot_cooldown", "medium"), nil
		}
	}
	g.screenshotLast[agentID] = time.Now()
	g.mu.Unlock()

	// Check rate limit
	if !g.checkScreenshotRateLimit(agentID) {
		return NewGuardResult(DecisionBlock, "screenshot rate limit exceeded", "cu_screenshot_rate_limit", "high"), nil
	}

	return NewGuardResult(DecisionAllow, "screenshot allowed", "cu_screenshot_allowed", "low"), nil
}

// ============================================================================
// Keystroke Pattern Detection
// ============================================================================

// GuardKeystroke validates keystroke patterns
func (g *Guard) GuardKeystroke(ctx context.Context, content string, secCtx *SecurityContext) (*GuardResult, error) {
	agentID := secCtx.AgentID

	// Check rate limit
	if !g.checkKeystrokeRateLimit(agentID) {
		return NewGuardResult(DecisionBlock, "keystroke rate limit exceeded", "cu_keystroke_pattern", "medium"), nil
	}

	// Check for sensitive data in content
	for _, pattern := range g.sensitivePatterns {
		if pattern.MatchString(content) {
			return NewGuardResult(DecisionLogOnly, fmt.Sprintf("sensitive pattern detected in keystroke: %s", pattern.String()), "cu_keystroke_sensitive", "high"), nil
		}
	}

	return NewGuardResult(DecisionAllow, "keystroke allowed", "cu_keystroke_allowed", "low"), nil
}

// ============================================================================
// Form Field Protection
// ============================================================================

// GuardFormField validates a form field interaction
func (g *Guard) GuardFormField(ctx context.Context, field *FormField, value string, secCtx *SecurityContext) (*GuardResult, error) {
	if field == nil {
		return nil, fmt.Errorf("field is nil")
	}

	// Check if field is sensitive
	if field.IsSensitive || IsSensitiveField(field.Type) {
		if g.cfg.BlockSensitiveFields {
			return NewGuardResult(DecisionBlock, fmt.Sprintf("sensitive field blocked: %s", field.Type), "cu_form_field_block", "critical"), nil
		}
		return NewGuardResult(DecisionMask, "sensitive field will be masked", "cu_form_field_mask", "high"), nil
	}

	// Check value for sensitive data
	for _, pattern := range g.sensitivePatterns {
		if pattern.MatchString(value) {
			return NewGuardResult(DecisionLogOnly, "sensitive data detected in form field", "cu_form_sensitive_data", "high"), nil
		}
	}

	return NewGuardResult(DecisionAllow, "form field allowed", "cu_form_field_allowed", "low"), nil
}

// ============================================================================
// Sensitive Data Detection
// ============================================================================

// GuardSensitiveData scans content for sensitive data patterns
func (g *Guard) GuardSensitiveData(ctx context.Context, content string, secCtx *SecurityContext) (*GuardResult, error) {
	if content == "" {
		return NewGuardResult(DecisionAllow, "empty content", "cu_empty_content", "low"), nil
	}

	// Check credit card pattern
	if g.cfg.BlockCreditCards {
		ccPattern := regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`)
		if ccPattern.MatchString(content) {
			return NewGuardResult(DecisionBlock, "credit card number detected", "cu_credit_card_block", "critical"), nil
		}
	}

	// Check SSN pattern
	if g.cfg.BlockSSN {
		ssnPattern := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
		if ssnPattern.MatchString(content) {
			return NewGuardResult(DecisionBlock, "SSN detected", "cu_ssn_block", "critical"), nil
		}
	}

	// Check for password patterns
	if g.cfg.BlockPasswords {
		pwdPattern := regexp.MustCompile(`(?i)(password[:=]\s*\S{8,})`)
		if pwdPattern.MatchString(content) {
			return NewGuardResult(DecisionBlock, "password detected in content", "cu_password_block", "high"), nil
		}
	}

	// Check for API keys
	apiKeyPattern := regexp.MustCompile(`(?i)(api[_-]?key[:=]\s*[a-zA-Z0-9]{16,})`)
	if apiKeyPattern.MatchString(content) {
		return NewGuardResult(DecisionBlock, "API key detected", "cu_api_key_block", "critical"), nil
	}

	return NewGuardResult(DecisionAllow, "no sensitive data detected", "cu_sensitive_scan_pass", "low"), nil
}

// ============================================================================
// Helper Methods
// ============================================================================

func (g *Guard) checkClickRateLimit(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	bucket, exists := g.clickRate[agentID]
	if !exists {
		bucket = &rateBucket{
			tokens:     g.cfg.MaxClicksPerMinute,
			lastRefill: time.Now(),
			maxTokens:  g.cfg.MaxClicksPerMinute,
			refillRate: g.cfg.MaxClicksPerMinute,
		}
		g.clickRate[agentID] = bucket
	}

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refill := int(elapsed.Minutes()) * bucket.refillRate
	if refill > 0 {
		bucket.tokens = min(g.cfg.MaxClicksPerMinute, bucket.tokens+refill)
		bucket.lastRefill = now
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *Guard) checkScreenshotRateLimit(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	bucket, exists := g.screenshotRate[agentID]
	if !exists {
		bucket = &rateBucket{
			tokens:     g.cfg.MaxScreenshotsPerMinute,
			lastRefill: time.Now(),
			maxTokens:  g.cfg.MaxScreenshotsPerMinute,
			refillRate: 60,
		}
		g.screenshotRate[agentID] = bucket
	}

	// Refill tokens based on elapsed time.
	elapsed := time.Since(bucket.lastRefill)
	refill := int(elapsed.Seconds()) * bucket.refillRate / 60
	if refill > 0 {
		bucket.tokens = min(bucket.maxTokens, bucket.tokens+refill)
		bucket.lastRefill = time.Now()
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *Guard) checkKeystrokeRateLimit(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	bucket, exists := g.keystrokeRate[agentID]
	if !exists {
		bucket = &rateBucket{
			tokens:     g.cfg.MaxKeystrokesPerMinute,
			lastRefill: time.Now(),
			maxTokens:  g.cfg.MaxKeystrokesPerMinute,
			refillRate: g.cfg.MaxKeystrokesPerMinute,
		}
		g.keystrokeRate[agentID] = bucket
	}

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	refill := int(elapsed.Minutes()) * bucket.refillRate
	if refill > 0 {
		bucket.tokens = min(g.cfg.MaxKeystrokesPerMinute, bucket.tokens+refill)
		bucket.lastRefill = now
	}

	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (g *Guard) detectRapidClicking(agentID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	clicks, exists := g.recentClicks[agentID]
	if !exists {
		return false
	}

	now := time.Now()
	windowStart := now.Add(-10 * time.Second)

	// Count clicks in last 10 seconds
	recentCount := 0
	validClicks := make([]time.Time, 0)

	for _, click := range clicks {
		if click.After(windowStart) {
			recentCount++
			validClicks = append(validClicks, click)
		}
	}

	g.recentClicks[agentID] = validClicks

	return recentCount > g.cfg.ClickRateThreshold
}

func (g *Guard) trackClick(agentID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	clicks, exists := g.recentClicks[agentID]
	if !exists {
		clicks = make([]time.Time, 0)
	}

	clicks = append(clicks, time.Now())

	// Keep only last 100 clicks
	if len(clicks) > 100 {
		clicks = clicks[len(clicks)-100:]
	}

	g.recentClicks[agentID] = clicks
}
