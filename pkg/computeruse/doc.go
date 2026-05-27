// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Computer Use API (Claude) Security
// ============================================================================
//
// Security guards for Anthropic's Computer Use API - browser automation
// for Claude desktop interactions.
//
// Security Features
// - URL allowlist/denylist validation
// - Click rate limiting (10/min default)
// - Screenshot rate limiting (1/min with cooldown)
// - Keystroke pattern detection
// - Form field sensitive data protection
// - Credit card/SSN/password detection
// - API key/secret scanning
//
// Guardrail Summary
// | Guardrail | Pattern | Action |
// |-----------|---------|--------|
// | cu_url_whitelist | Allowed URLs only | BLOCK if off-list |
// | cu_url_denylist | Block dangerous URLs | BLOCK if on-list |
// | cu_click_rate_limit | Max 10 clicks/min | REJECT if exceeded |
// | cu_screenshot_limit | Max 1 screenshot/min | BLOCK if exceeded |
// | cu_keystroke_pattern | Detect rapid typing | WARN + LOG |
// | cu_form_field_block | Block sensitive fields | MASK if sensitive |
// | cu_credit_card_block | Detect credit card nums | MASK + ALERT |
// | cu_ssn_block | Detect SSN/SIN | MASK + ALERT |
// | cu_password_block | Detect passwords | LOG + WARN |
//
// Usage
// guard := computeruse.NewGuard()
// result, err := guard.GuardClick(ctx, action, secCtx)
//
// ============================================================================
package computeruse
