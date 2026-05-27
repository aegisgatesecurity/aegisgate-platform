// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Agent Protocol (ANP) Security
// ============================================================================
//
// This package provides security guards for Anthropic's Agent Protocol,
// enabling secure agent-to-agent communication via tasks, steps, and artifacts.
//
// # Security Features
//
// - Task validation with ECDSA signature verification
// - Contract-based capability enforcement
// - Rate limiting per agent and task
// - Prompt injection detection
// - Step chain integrity verification
// - Artifact security scanning (PII, secrets, exfiltration)
// - Message content filtering (toxicity, social engineering)
//
// # Guardrail Summary
//
// | Guardrail | Pattern | Action |
// |-----------|---------|--------|
// | anp_task_origin_check | Verify ECDSA signature | BLOCK if invalid |
// | anp_capability_check | Validate contract capabilities | BLOCK if unauthorized |
// | anp_rate_limit | 100 tasks/min per agent | REJECT if exceeded |
// | anp_injection_scan | Scan for prompt injection | BLOCK if detected |
// | anp_step_integrity | Verify step chain hash | BLOCK if tampered |
// | anp_output_scan | Scan step outputs | BLOCK if PII/secrets |
// | anp_artifact_pii | GDPR PII detection | REDACT or BLOCK |
// | anp_message_auth | HMAC verification | BLOCK if invalid |
// | anp_toxicity_scan | Content toxicity | BLOCK if toxic |
// | anp_exfil_check | Artifact name analysis | BLOCK if suspicious |
// | anp_dangerous_tool | Block terminal/file ops | BLOCK if unauthorized |
// | anp_social_engineering | Message content analysis | WARN + LOG |
//
// # Usage
//
//	guard := anp.NewGuard()
//	result, err := guard.GuardTask(ctx, task, secCtx)
//	if !result.Allow() {
//	    // Handle blocked task
//	}
//
// ============================================================================

package anp
