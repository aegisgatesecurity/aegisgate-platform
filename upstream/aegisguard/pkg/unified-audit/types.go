// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security - Unified Audit Package
//
// =========================================================================

package unified_audit

// EventType represents the type of audit event
type EventType string

const (
	EventAgentRegister   EventType = "agent:register"
	EventAgentUnregister EventType = "agent:unregister"
	EventAgentLogin      EventType = "agent:login"
	EventAgentLogout     EventType = "agent:logout"
)

// Source represents the product source of an event
type Source string

const (
	SourceAegisGate  Source = "aegisgate"
	SourceAegisGuard Source = "aegisguard"
	SourceUnknown    Source = "unknown"
)

// Event represents a unified audit event
type Event struct {
	EventID   string                 `json:"event_id"`
	EventType EventType              `json:"event_type"`
	Source    Source                 `json:"source"`
	Timestamp int64                  `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
