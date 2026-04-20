// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================

package logging

import (
	"os"
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
}

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
