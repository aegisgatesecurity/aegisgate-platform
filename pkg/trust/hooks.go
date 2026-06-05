// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Protocol Hooks (v3.2.0 Phase 4.4)
//
// hooks.go is the bridge between the per-session trust accumulator
// (pkg/trust.Manager, Phase 4.2) and the 4 protocol packages that
// produce behavior events:
//
//   - pkg/mcpserver (MCP connections)
//   - pkg/a2a (agent-to-agent messaging)
//   - pkg/proxy (HTTP proxy; in upstream/aegisgate/, separate module)
//   - pkg/response (response scanning guard)
//
// Rather than deeply integrating the trust.Manager into every
// protocol's request lifecycle (which would be invasive and
// risk regressions), this package provides a small, opt-in API
// that protocols call at well-defined points:
//
//   - Hooks:        records a behavior event into the matching
//                    trust session (started via StartSession or
//                    joined via JoinSession).
//   - StartSession: begins a new trust session for an agent.
//   - JoinSession:  re-attaches to an existing session (for
//                    protocols that handle multiple events per
//                    session, like a long-lived MCP connection).
//   - EndSession:   closes a session.
//
// Hooks are no-ops when no manager is configured (the
// zero-value Hooks{} is safe to use). This is the key design
// point: protocols can wire the Hooks struct unconditionally
// without a feature flag, and Phase 4.4 wiring just plugs in
// the manager at the platform bootstrap.
//
// v3.2.0 Phase 4.4.

package trust

import (
	"context"
	"errors"
	"sync"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// Hooks provides opt-in integration points for protocol packages
// to record behavior events into a trust session.
//
// The zero value is safe to use; all methods are no-ops when
// Manager is nil. This is the key design point: protocols can
// embed `trust.Hooks` and call hook methods unconditionally;
// the platform bootstrap is responsible for setting Manager.
type Hooks struct {
	// Manager is the trust session manager. nil -> all hooks are
	// no-ops (safe for testing, and for Pro+ feature-gating).
	Manager *Manager

	// ThresholdScore is the trust score below which a session is
	// flagged for audit. 0 = no threshold. Default 30.
	ThresholdScore float64

	mu sync.Mutex
}

// NewHooks creates a Hooks with the given manager and default
// threshold (30). Pass nil manager to get no-op hooks.
func NewHooks(manager *Manager) *Hooks {
	return &Hooks{Manager: manager, ThresholdScore: 30}
}

// SetManager updates the manager reference. Useful for late binding
// during platform startup. Thread-safe.
func (h *Hooks) SetManager(m *Manager) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Manager = m
}

// StartSession begins a new trust session for the given agent.
// Returns the session ID, or "" if no manager is configured.
func (h *Hooks) StartSession(ctx context.Context, agentID string, metadata map[string]string) string {
	h.mu.Lock()
	m := h.Manager
	h.mu.Unlock()
	if m == nil {
		return ""
	}
	var sess *Session
	var err error
	if len(metadata) > 0 {
		sess, err = m.StartWithMetadata(ctx, agentID, metadata)
	} else {
		sess, err = m.Start(ctx, agentID)
	}
	if err != nil || sess == nil {
		return ""
	}
	return sess.ID
}

// JoinSession returns the existing session ID for an (agent,
// sessionKey) pair, or starts a new one if none exists. This is
// for protocols that have their own session identifier (like an
// MCP connection ID) and want to keep the trust session aligned
// with that lifecycle rather than per-event.
//
// sessionKey is the protocol's own ID (e.g., the MCP connection
// ID). The returned string is the trust session ID, or "" if
// no manager.
func (h *Hooks) JoinSession(ctx context.Context, sessionKey, agentID string, metadata map[string]string) string {
	h.mu.Lock()
	m := h.Manager
	h.mu.Unlock()
	if m == nil {
		return ""
	}
	// Look for an existing trust session whose metadata carries
	// sessionKey. We do a linear scan of active sessions; for
	// large deployments, the Manager could index by key.
	for _, sess := range m.List(true) {
		if sess.Metadata["session_key"] == sessionKey && sess.AgentID == agentID {
			return sess.ID
		}
	}
	// None found; start a new one tagged with the protocol's key.
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["session_key"] = sessionKey
	return h.StartSession(ctx, agentID, metadata)
}

// EndSession closes the trust session. No-op if sessionID is ""
// or if no manager is configured.
func (h *Hooks) EndSession(ctx context.Context, sessionID string) {
	h.mu.Lock()
	m := h.Manager
	h.mu.Unlock()
	if m == nil || sessionID == "" {
		return
	}
	_, _ = m.End(ctx, sessionID)
}

// ---- event hooks ----

// CapabilityAllowed records that an agent was permitted to do
// something. capability is the protocol-level operation name
// (e.g., "tools/call", "mcp/tool", "a2a/send"). description is
// optional human-readable context.
func (h *Hooks) CapabilityAllowed(ctx context.Context, sessionID, capability, description string) {
	h.record(ctx, sessionID, score.EventCapabilityAllowed, capability, 1, description)
}

// CapabilityDenied records that an agent was denied an operation.
// Severity should be 1-3 for a normal denial, 4-7 for a policy
// violation, 8-10 for a security violation.
func (h *Hooks) CapabilityDenied(ctx context.Context, sessionID, capability, description string, severity int) {
	h.record(ctx, sessionID, score.EventCapabilityDenied, capability, severity, description)
}

// AnomalyDetected records that a behavior anomaly was detected.
// Severity 1-10.
func (h *Hooks) AnomalyDetected(ctx context.Context, sessionID, description string, severity int) {
	h.record(ctx, sessionID, score.EventAnomalyDetected, "", severity, description)
}

// CompliancePass records a compliance check that passed.
func (h *Hooks) CompliancePass(ctx context.Context, sessionID, framework, description string) {
	h.record(ctx, sessionID, score.EventCompliancePass, framework, 1, description)
}

// ComplianceFail records a compliance check that failed.
func (h *Hooks) ComplianceFail(ctx context.Context, sessionID, framework, description string) {
	h.record(ctx, sessionID, score.EventComplianceFail, framework, 5, description)
}

// ContractViolated records a contract enforcement violation.
func (h *Hooks) ContractViolated(ctx context.Context, sessionID, contract, description string) {
	h.record(ctx, sessionID, score.EventContractViolated, contract, 7, description)
}

// IdentityVerified records a successful identity verification
// (mTLS, OIDC, etc.).
func (h *Hooks) IdentityVerified(ctx context.Context, sessionID, mechanism string) {
	h.record(ctx, sessionID, score.EventIdentityVerified, mechanism, 1, "")
}

// IdentityFailed records a failed identity verification.
func (h *Hooks) IdentityFailed(ctx context.Context, sessionID, mechanism, description string) {
	h.record(ctx, sessionID, score.EventIdentityFailed, mechanism, 8, description)
}

// ErrorOccurred records an error during request processing.
func (h *Hooks) ErrorOccurred(ctx context.Context, sessionID, description string) {
	h.record(ctx, sessionID, score.EventError, "", 3, description)
}

// record is the internal forwarder.
func (h *Hooks) record(ctx context.Context, sessionID string, eventType score.EventType, capability string, severity int, description string) {
	h.mu.Lock()
	m := h.Manager
	h.mu.Unlock()
	if m == nil || sessionID == "" {
		return
	}
	_, _ = m.Record(ctx, sessionID, eventType, capability, severity, description)
}

// SessionScore returns the current trust score for a session, or
// (0, false) if no manager. Used by protocols to make
// per-request decisions (e.g., "lower the rate limit if score
// is dropping").
func (h *Hooks) SessionScore(ctx context.Context, sessionID string) (float64, bool) {
	h.mu.Lock()
	m := h.Manager
	h.mu.Unlock()
	if m == nil || sessionID == "" {
		return 0, false
	}
	score, err := m.Score(ctx, sessionID)
	if err != nil || score == nil {
		return 0, false
	}
	return score.Score, true
}

// IsBelowThreshold returns true if the session's current trust
// score is below the configured ThresholdScore. Returns false
// if no manager or no score.
func (h *Hooks) IsBelowThreshold(ctx context.Context, sessionID string) bool {
	s, ok := h.SessionScore(ctx, sessionID)
	if !ok {
		return false
	}
	threshold := h.ThresholdScore
	if threshold == 0 {
		threshold = 30
	}
	return s < threshold
}

// ValidateContext returns nil if the Hooks struct is properly
// configured. Returns ErrNilManager if Manager is nil. Used in
// startup checks to catch misconfiguration early.
func (h *Hooks) ValidateContext() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Manager == nil {
		return errors.New("trust Hooks: Manager is nil (no-op mode)")
	}
	return nil
}
