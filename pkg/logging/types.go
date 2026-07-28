// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================

package logging

import (
	"os"
	"time"
)

// Severity represents the severity level of a log event.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Event represents a security or log event to be formatted.
type Event struct {
	// Time is when the event occurred. Optional - if zero, the event
	// is treated as occurring at the time it was added to a ring buffer
	// (which sets Time to time.Now() at Add() time).
	Time time.Time `json:"time,omitempty"`
	// Unique identifier for this event
	ID string `json:"id"`
	// Event type (e.g., "auth", "request", "threat")
	Type string `json:"type"`
	// Action taken (block, allow, drop, throttle, etc.)
	Action string `json:"action,omitempty"`
	// Severity level
	Severity Severity `json:"severity"`
	// Human-readable message
	Message string `json:"message"`
	// Source IP address
	SourceIP string `json:"sourceIP,omitempty"`
	// Destination address
	Destination string `json:"destination,omitempty"`
	// User identifier
	User string `json:"user,omitempty"`
	// Client ID
	ClientID string `json:"clientID,omitempty"`
	// Threat type
	ThreatType string `json:"threatType,omitempty"`
	// Threat level
	ThreatLevel string `json:"threatLevel,omitempty"`
	// Pattern matched
	Pattern string `json:"pattern,omitempty"`
	// Compliance framework name
	ComplianceFramework string `json:"complianceFramework,omitempty"`
	// Compliance control ID
	ComplianceControl string `json:"complianceControl,omitempty"`
	// FrameworkRefs is a precomputed cross-framework reference map
	// for the detection tuple (Type, ThreatType, Pattern). Keys are
	// canonical framework IDs (e.g., "mitre_atlas", "nist_ai_rmf",
	// "owasp_llm", "cwe", "cve"); values are the cross-reference
	// IDs in that framework (e.g., ["T0024"] for MITRE ATLAS tactic
	// "Exploit Public-Facing Application"). Populated by the
	// FrameworkRefCache attached to logging.Record(); empty if no
	// mapping is known for this detection. Tier 1 (TODO-401).
	FrameworkRefs map[string][]string `json:"frameworkRefs,omitempty"`

	// TSA holds the RFC 3161 timestamp token data for this event.
	// When TSA timestamping is enabled (v3.5.0+), each audit event
	// receives a cryptographic proof-of-existence from an independent
	// Time Stamp Authority. This provides non-repudiation evidence
	// for compliance frameworks (FedRAMP AU-10/AU-11, ISO 27001
	// A.12.4.3, SOC 2 CC7.3). Populated by the TSARecordingWrapper
	// attached to the audit ring buffer; nil when TSA is disabled.
	// Tier 1 (TODO-401): audit event lifecycle.
	TSA *EventTSA `json:"tsa,omitempty"`
}

// EventTSA carries the RFC 3161 timestamp proof for an audit event.
// This is the serialized form of audit.AuditEventTSA, suitable for
// JSON storage in the ring buffer and persistence layer.
type EventTSA struct {
	// EventID is the unique identifier of the original audit event.
	EventID string `json:"eventId"`

	// DataHash is the SHA-256 hash of the original event data.
	DataHash []byte `json:"dataHash"`

	// Timestamp is the genTime from the RFC 3161 token (UTC).
	Timestamp time.Time `json:"timestamp"`

	// TSAEndpoint is the URL of the TSA that issued the token.
	TSAEndpoint string `json:"tsaEndpoint"`

	// Verified indicates whether the token was successfully verified
	// against the data hash at sign time.
	Verified bool `json:"verified"`
}

// Get* accessors expose Event fields through a small interface.
// The audit package's loggingEvent interface (pkg/audit/search.go)
// declares these methods so the search layer can be written
// against a minimal contract; with the methods below, logging.Event
// itself satisfies the interface, so the handler can decode JSON
// directly into []logging.Event without going through the
// loggingEventAdapter at the wire-format boundary. The adapter
// in pkg/audit/handler.go is still used on the in-process search
// path, where the search layer operates on []loggingEvent.
func (e Event) GetID() string       { return e.ID }
func (e Event) GetTime() time.Time  { return e.Time }
func (e Event) GetType() string     { return e.Type }
func (e Event) GetAction() string   { return e.Action }
func (e Event) GetSeverity() string { return string(e.Severity) }
func (e Event) GetUser() string     { return e.User }
func (e Event) GetMessage() string  { return e.Message }

// SyslogFormatter formats events as RFC 5424 syslog messages.
// It provides methods to convert AegisGate Events into structured
// RFC 5424 compliant syslog format.
type SyslogFormatter struct {
	// Facility is the syslog facility code (0-23)
	Facility int
	// AppName is the application name to include in syslog messages
	AppName string
	// Hostname is the hostname to include in syslog messages
	Hostname string
}

// NewSyslogFormatter creates a new SyslogFormatter with the given options.
func NewSyslogFormatter(facility int, appName, hostname string) *SyslogFormatter {
	if appName == "" {
		appName = "aegisgate"
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &SyslogFormatter{
		Facility: facility,
		AppName:  appName,
		Hostname: hostname,
	}
}
