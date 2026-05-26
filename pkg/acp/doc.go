// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - ACP Protocol Guard
// =========================================================================
//
// Agent Client Protocol (ACP) security scanner for AegisGate.
//
// ACP is a protocol for communication between code editors and coding agents.
// This package adds security scanning for ACP messages, protecting both
// agent responses and client requests.
//
// Key Security Features:
//   - Message integrity verification (HMAC)
//   - Response content scanning (PII, secrets, toxicity)
//   - Capability-based access control
//   - Rate limiting per agent/client
//   - Input validation for ACP messages
//
// Protocol: https://agentclientprotocol.com/
//
// Embedded Schema: https://agentclientprotocol.com/schema/schema.json
//
// =========================================================================

package acp

import _ "embed"

// acpSchema contains the official ACP protocol JSON schema for validation
//
//go:embed schema.json
var acpSchema []byte
