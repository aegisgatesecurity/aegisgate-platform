// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - AI Response Security Scanner
// =========================================================================
//
// Scans LLM responses for PII, secrets, toxicity, and hallucinations
// before they are returned to the calling agent or user. This is the
// 4th pillar of AegisGate's 6-pillar coverage.
//
// Components:
//   - guard.go:                  main entry point; combines PII scanning,
//                                secret detection, token rate limiting,
//                                and toxicity filtering
//   - pii_scanner.go:            PII detection (SSN, credit card, email, phone,
//                                address, DOB, passport, etc.) — supports
//                                GDPR, HIPAA, SOC2, PCI-DSS
//   - hallucination_detector.go: overconfidence pattern detection, factual
//                                claim verification, statistics validation
//   - toxicity_filter.go:        toxicity scoring, content moderation
//   - secret_scanner.go:         API key, AWS key, GitHub token, JWT detection
//
// Integration points:
//   - pkg/bridge:        scans responses from the LLM proxy
//   - pkg/mcpserver:     scans MCP server responses (mcp_response_guard.go)
//   - pkg/a2a:           scans A2A agent-to-agent responses
//   - pkg/acp:           scans ACP agent communication responses
//
// When a violation is detected, the response guard can:
//   - BLOCK:  reject the response (return 403 to the agent)
//   - REDACT: replace the PII/secret with XXX-XX-1234-style redaction markers
//   - AUDIT:  allow the response but log the violation to the audit pipeline
//
// Tier gating:
//   - Basic PII/secret scanning: all tiers (Community+)
//   - Hallucination detection:   Developer+
//   - Advanced toxicity:         Professional+
//   - Custom rules:              Enterprise
//
// =========================================================================

package response
