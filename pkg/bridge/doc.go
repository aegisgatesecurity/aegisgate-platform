// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - LLM Bridge (AegisGuard ↔ AegisGate)
// =========================================================================
//
// The bridge package provides unified LLM security coverage by routing
// agent LLM API calls through AegisGate for additional security
// scanning, while maintaining transparent integration with AegisGuard's
// MCP architecture.
//
// Architecture:
//
//	AI Agent -> AegisGuard (MCP) -> Bridge -> AegisGate (HTTP Proxy) -> LLM Provider
//
// This package re-exports the AegisGuard bridge types and adds
// platform-level convenience constructors that wire the bridge to
// AegisGate's proxy. Most types in this file are type aliases
// (`type Foo = guardbridge.Foo`) to upstream/.
//
// Related packages:
//   - pkg/scanner:  security scanning interface (used by the bridge)
//   - pkg/response: response-side scanning (PII, secrets, toxicity)
//   - pkg/auth:     authentication for the proxy endpoint
//
// =========================================================================

package bridge
