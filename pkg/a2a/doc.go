// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - A2A (Agent-to-Agent) Protocol Guard
// =========================================================================
//
// Agent-to-Agent (A2A) protocol guardrails middleware for AegisGate.
//
// A2A is the protocol for communication between AI agents. This package
// adds security scanning for A2A messages, protecting both agent
// responses and inter-agent requests.
//
// Key Security Features:
//   - HMAC-SHA256 message integrity verification
//   - mTLS for transport-layer authentication
//   - Capability-based access control (capabilities YAML)
//   - Rate limiting per agent
//   - Response security scanning (PII, secrets, toxicity, hallucination)
//   - Prompt injection detection in agent-to-agent messages
//
// Reference: https://github.com/aegisgatesecurity/aegisgate-platform
//            plans/THREAT-MODEL.md Section 2.4 (A2A STRIDE threats)
//
// =========================================================================

package a2a
