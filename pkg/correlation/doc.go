// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// AegisGate Platform - Cross-Protocol Threat Correlation
// ============================================================================
//
// Security correlation engine that detects threats across multiple protocols:
// HTTP, MCP, A2A, ANP, and Computer Use API.
//
// Threat Patterns
// - mcp_error_injection: MCP error followed by A2A request
// - task_hijacking: A2A message triggers ANP task creation
// - browser_escalation: ANP task enables browser control
// - rate_anomaly: Coordinated attack across protocols
// - capability_creep: Agent uses more capabilities over time
//
// Usage
// engine := correlation.NewEngine()
// engine.RecordEvent(ctx, event)
// result, err := engine.Analyze(ctx, agentID, sessionID)
//
// Persistence (v3.8)
// Community/Developer tiers use InMemoryCorrelationStore (wraps Engine).
// Professional/Enterprise tiers use PostgresCorrelationStore (shared pgxpool).
// The CorrelationStore interface abstracts both backends:
//
//	store := correlation.NewInMemoryCorrelationStore(engine)
//	// or, for Professional/Enterprise:
//	store := correlation.NewPostgresCorrelationStore(pool)
//
// ============================================================================
package correlation
