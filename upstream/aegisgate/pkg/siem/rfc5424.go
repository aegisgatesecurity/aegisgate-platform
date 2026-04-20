// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Copyright 2024 AegisGate
// RFC 5424 compliant syslog implementation
// Reference: https://datatracker.ietf.org/doc/html/rfc5424

package siem

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// RFC 5424 constants
const (
	RFC5424Version         = 1
	RFC5424NILVALUE        = "-"
	RFC5424TimestampFormat = "2006-01-02T15:04:05.000Z07:00" // RFC3339 with microseconds
	SyslogFacilityKern     = 0
	SyslogFacilityUser     = 1
	SyslogFacilityMail     = 2
	SyslogFacilityDaemon   = 3
	SyslogFacilityAuth     = 4
	SyslogFacilitySyslog   = 5
	SyslogFacilityLpr      = 6
	SyslogFacilityNews     = 7
	SsyslogFacilityUucp    = 8
	SyslogFacilityCron     = 9
	SyslogFacilityAuthPriv = 10
	SyslogFacilityFtp      = 11
	SyslogFacilityNTP      = 12
	SyslogFacilityAudit    = 13
	SyslogFacilityAlert    = 14
	SyslogFacilityClock    = 15
	SyslogFacilityLocal0   = 16
	SyslogFacilityLocal1   = 17
	SyslogFacilityLocal2   = 18
	SyslogFacilityLocal3   = 19
	SyslogFacilityLocal4   = 20
	SyslogFacilityLocal5   = 21
	SyslogFacilityLocal6   = 22
	SyslogFacilityLocal7   = 23
)

// Syslog severity levels per RFC 5424
const (
	SyslogSeverityEmergency     = 0 // System is unusable
	SyslogSeverityAlert         = 1 // Action must be taken immediately
	SyslogSeverityCritical      = 2 // Critical conditions
	SyslogSeverityError         = 3 // Error conditions
	SyslogSeverityWarning       = 4 // Warning conditions
	SyslogSeverityNotice        = 5 // Normal but significant
	SyslogSeverityInformational = 6 // Informational
	SyslogSeverityDebug         = 7 // Debug-level messages
)

// RFC5424MsgID represents the message identifier per RFC 5424 Section 6.2.7
type RFC5424MsgID string

// Standard MSGID values for AegisGate events
const (
	// Authentication events
	MSGIDAuthSuccess      RFC5424MsgID = "AUTH_SUCCESS"
	MSGIDAuthFailure      RFC5424MsgID = "AUTH_FAILURE"
	MSGIDAuthSessionStart RFC5424MsgID = "SESSION_START"
	MSGIDAuthSessionEnd   RFC5424MsgID = "SESSION_END"
	MSGIDAuthTokenRefresh RFC5424MsgID = "TOKEN_REFRESH"
	MSGIDAuthTokenRevoke  RFC5424MsgID = "TOKEN_REVOKE"
	MSGIDAuthLogout       RFC5424MsgID = "AUTH_LOGOUT"

	// Authorization events
	MSGIDAuthzSuccess RFC5424MsgID = "AUTHZ_SUCCESS"
	MSGIDAuthzFailure RFC5424MsgID = "AUTHZ_FAILURE"
	MSGIDAuthzDenied  RFC5424MsgID = "AUTHZ_DENIED"

	// Request handling
	MSGIDRequestAllowed   RFC5424MsgID = "REQUEST_ALLOWED"
	MSGIDRequestBlocked   RFC5424MsgID = "REQUEST_BLOCKED"
	MSGIDRequestDropped   RFC5424MsgID = "REQUEST_DROPPED"
	MSGIDRequestThrottled RFC5424MsgID = "REQUEST_THROTTLED"

	// Security events
	MSGIDThreatDetected    RFC5424MsgID = "THREAT_DETECTED"
	MSGIDIntrusionAttempt  RFC5424MsgID = "INTRUSION_ATTEMPT"
	MSGIDMalwareDetected   RFC5424MsgID = "MALWARE_DETECTED"
	MSGIDAnomalyDetected   RFC5424MsgID = "ANOMALY_DETECTED"
	MSGIDPolicyViolation   RFC5424MsgID = "POLICY_VIOLATION"
	MSGIDRateLimitExceeded RFC5424MsgID = "RATE_LIMIT_EXCEEDED"

	// Proxy events
	MSGIDProxyRequest  RFC5424MsgID = "PROXY_REQUEST"
	MSGIDProxyResponse RFC5424MsgID = "PROXY_RESPONSE"
	MSGIDProxyError    RFC5424MsgID = "PROXY_ERROR"
	MSGIDMITMDetected  RFC5424MsgID = "MITM_DETECTED"
	MSGIDTLSError      RFC5424MsgID = "TLS_ERROR"

	// Configuration events
	MSGIDConfigChange RFC5424MsgID = "CONFIG_CHANGE"
	MSGIDConfigLoad   RFC5424MsgID = "CONFIG_LOAD"
	MSGIDConfigError  RFC5424MsgID = "CONFIG_ERROR"
	MSGIDPolicyUpdate RFC5424MsgID = "POLICY_UPDATE"
	MSGIDPolicyDrift  RFC5424MsgID = "POLICY_DRIFT"

	// System events
	MSGIDSystemStart      RFC5424MsgID = "SYSTEM_START"
	MSGIDSystemStop       RFC5424MsgID = "SYSTEM_STOP"
	MSGIDSystemError      RFC5424MsgID = "SYSTEM_ERROR"
	MSGIDComponentFailure RFC5424MsgID = "COMPONENT_FAILURE"
	MSGIDHealthCheck      RFC5424MsgID = "HEALTH_CHECK"
	MSGIDMetricsPublish   RFC5424MsgID = "METRICS_PUBLISH"

	// Compliance events
	MSGIDComplianceViolation RFC5424MsgID = "COMPLIANCE_VIOLATION"
	MSGIDAuditLog            RFC5424MsgID = "AUDIT_LOG"
	MSGIDDataExport          RFC5424MsgID = "DATA_EXPORT"

	// Plugin events
	MSGIDPluginLoad   RFC5424MsgID = "PLUGIN_LOAD"
	MSGIDPluginUnload RFC5424MsgID = "PLUGIN_UNLOAD"
	MSGIDPluginError  RFC5424MsgID = "PLUGIN_ERROR"
)

// RFC5424StructuredDataID represents structured data element ID per RFC 5424 Section 6.3.1
type RFC5424StructuredDataID string

// Standard SD-ID values for AegisGate
const (
	SDIDAegisGate  RFC5424StructuredDataID = "aegisgate@32473"
	SDIDOrigin     RFC5424StructuredDataID = "origin@aegisgate"
	SDIDTarget     RFC5424StructuredDataID = "target@aegisgate"
	SDIDThreat     RFC5424StructuredDataID = "threat@aegisgate"
	SDIDCompliance RFC5424StructuredDataID = "compliance@aegisgate"
	SDIDMeta       RFC5424StructuredDataID = "meta@aegisgate"
)

// RFC5424StructuredDataParam represents SD-PARAM per RFC 5424 Section 6.3.2
type RFC5424StructuredDataParam struct {
	Name  string
	Value string
}

// RFC5424StructuredData represents structured data element per RFC 5424 Section 6.3
type RFC5424StructuredData struct {
	ID     RFC5424StructuredDataID
	Params []RFC5424StructuredDataParam
}

// NewRFC5424StructuredData creates a new structured data element
func NewRFC5424StructuredData(id RFC5424StructuredDataID) *RFC5424StructuredData {
	return &RFC5424StructuredData{
		ID:     id,
		Params: make([]RFC5424StructuredDataParam, 0),
	}
}

// AddParam adds a parameter to the structured data element
func (sd *RFC5424StructuredData) AddParam(name, value string) *RFC5424StructuredData {
	sd.Params = append(sd.Params, RFC5424StructuredDataParam{
		Name:  name,
		Value: value,
	})
	return sd
}

// Build builds the SD-ELEMENT string per RFC 5424
func (sd *RFC5424StructuredData) Build() string {
	if len(sd.Params) == 0 {
		return fmt.Sprintf("[%s]", sd.ID)
	}

	var b bytes.Buffer
	b.WriteString(fmt.Sprintf("[%s ", sd.ID))
	for i, p := range sd.Params {
		b.WriteString(fmt.Sprintf("%s=\"%s\"", p.Name, escapeSDParam(p.Value)))
		if i < len(sd.Params)-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString("]")
	return b.String()
}

// escapeSDParam escapes special characters in SD-PARAM value per RFC 5424 Section 6.3.3
func escapeSDParam(value string) string {
	// Per RFC 5424: escape backslash, quotes, and closing bracket
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "]", "\\]")
	return value
}

// RFC5424Message represents a complete RFC 5424 syslog message
type RFC5424Message struct {
	Priority       int                      // PRI (facility * 8 + severity)
	Version        int                      // VERSION (always 1)
	Timestamp      time.Time                // TIMESTAMP (RFC3339 or NILVALUE)
	Hostname       string                   // HOSTNAME or NILVALUE
	AppName        string                   // APP-NAME or NILVALUE
	ProcID         string                   // PROCID or NILVALUE
	MsgID          RFC5424MsgID             // MSGID or NILVALUE
	StructuredData []*RFC5424StructuredData // STRUCTURED-DATA
	Message        string                   // MSG
}

// NewRFC5424Message creates a new RFC 5424 message
func NewRFC5424Message(facility, severity int, msgID RFC5424MsgID) *RFC5424Message {
	hostname, _ := os.Hostname()
	procID := strconv.Itoa(os.Getpid())

	return &RFC5424Message{
		Priority:       facility*8 + severity,
		Version:        RFC5424Version,
		Timestamp:      time.Now().UTC(),
		Hostname:       hostname,
		AppName:        "aegisgate",
		ProcID:         procID,
		MsgID:          msgID,
		StructuredData: make([]*RFC5424StructuredData, 0),
		Message:        "",
	}
}

// AddStructuredData adds structured data to the message
func (m *RFC5424Message) AddStructuredData(sd *RFC5424StructuredData) *RFC5424Message {
	m.StructuredData = append(m.StructuredData, sd)
	return m
}

// SetTimestamp sets the timestamp, use NILVALUE if zero
func (m *RFC5424Message) SetTimestamp(t time.Time) *RFC5424Message {
	m.Timestamp = t
	return m
}

// SetHostname sets the hostname, use NILVALUE if empty
func (m *RFC5424Message) SetHostname(hostname string) *RFC5424Message {
	if hostname == "" {
		m.Hostname = RFC5424NILVALUE
	} else {
		m.Hostname = hostname
	}
	return m
}

// SetProcID sets the process ID, use NILVALUE if empty
func (m *RFC5424Message) SetProcID(procID string) *RFC5424Message {
	if procID == "" {
		m.ProcID = RFC5424NILVALUE
	} else {
		m.ProcID = procID
	}
	return m
}

// SetMessage sets the message content
func (m *RFC5424Message) SetMessage(msg string) *RFC5424Message {
	m.Message = msg
	return m
}

// Build builds the complete RFC 5424 message
func (m *RFC5424Message) Build() string {
	var b bytes.Buffer

	// PRI - priority value
	b.WriteString(fmt.Sprintf("<%d>", m.Priority))

	// VERSION
	b.WriteString(fmt.Sprintf("%d ", m.Version))

	// TIMESTAMP - RFC3339 or NILVALUE
	if m.Timestamp.IsZero() {
		b.WriteString(RFC5424NILVALUE + " ")
	} else {
		b.WriteString(m.Timestamp.Format(RFC5424TimestampFormat) + " ")
	}

	// HOSTNAME
	b.WriteString(m.Hostname + " ")

	// APP-NAME
	b.WriteString(m.AppName + " ")

	// PROCID
	b.WriteString(m.ProcID + " ")

	// MSGID
	b.WriteString(string(m.MsgID) + " ")

	// STRUCTURED-DATA
	if len(m.StructuredData) == 0 {
		b.WriteString("- ")
	} else {
		for _, sd := range m.StructuredData {
			b.WriteString(sd.Build() + " ")
		}
	}

	// MSG - the message content (can contain UTF-8)
	// Note: Per RFC 5424, MSG should be encoded if non-ASCII
	// For now, we assume UTF-8 which is common practice
	if m.Message != "" {
		// If message starts with BOM, remove it as RFC 5424 doesn't use BOM
		msg := strings.TrimPrefix(m.Message, "\ufeff")
		b.WriteString(msg)
	}

	return b.String()
}

// String is an alias for Build
func (m *RFC5424Message) String() string {
	return m.Build()
}

// ConvertEventToRFC5424 converts a AegisGate Event to RFC 5424 format
func (f *SyslogFormatter) ConvertEventToRFC5424(event *Event) *RFC5424Message {
	// Determine severity from event
	severity := f.mapEventToSeverity(event)

	// Determine MSGID from event type
	msgID := f.mapEventToMsgID(event)

	// Create base message
	msg := NewRFC5424Message(SyslogFacilityLocal0, severity, msgID)

	// Add structured data
	sd := f.buildStructuredDataForEvent(event)
	if sd != nil {
		msg.AddStructuredData(sd)
	}

	// Set message
	msg.SetMessage(event.Message)

	// Set hostname from event if present
	if event.SourceIP != "" {
		msg.SetHostname(event.SourceIP)
	}

	return msg
}

// mapEventToSeverity maps an Event to RFC 5424 severity
func (f *SyslogFormatter) mapEventToSeverity(event *Event) int {
	// Map event severity/level to RFC 5424 severity
	severityStr := string(event.Severity)
	switch strings.ToLower(severityStr) {
	case "emergency", "emerg", "crit", "critical", "fatal":
		return SyslogSeverityCritical
	case "alert":
		return SyslogSeverityAlert
	case "error", "err":
		return SyslogSeverityError
	case "warning", "warn":
		return SyslogSeverityWarning
	case "notice":
		return SyslogSeverityNotice
	case "info", "informational":
		return SyslogSeverityInformational
	case "debug", "trace", "verbose":
		return SyslogSeverityDebug
	default:
		return SyslogSeverityInformational
	}
}

// mapEventToMsgID maps an Event type to RFC 5424 MSGID
func (f *SyslogFormatter) mapEventToMsgID(event *Event) RFC5424MsgID {
	// Map based on event type
	switch strings.ToLower(event.Type) {
	// Authentication
	case "auth", "authentication", "login":
		if strings.Contains(strings.ToLower(event.Message), "fail") {
			return MSGIDAuthFailure
		}
		return MSGIDAuthSuccess

	// Authorization
	case "authz", "authorization", "permission", "access":
		if strings.Contains(strings.ToLower(event.Message), "denied") {
			return MSGIDAuthzDenied
		}
		return MSGIDAuthzSuccess

	// Request handling
	case "request", "http", "proxy":
		if event.Action == "block" || event.Action == "drop" {
			return MSGIDRequestBlocked
		}
		if event.Action == "throttle" || event.Action == "rate_limit" {
			return MSGIDRequestThrottled
		}
		return MSGIDRequestAllowed

	// Security threats
	case "threat", "attack", "malware", "intrusion", "injection", "xss", "csrf":
		return MSGIDThreatDetected
	case "anomaly", "unusual", "suspicious":
		return MSGIDAnomalyDetected
	case "policy", "violation":
		return MSGIDPolicyViolation
	case "rate_limit", "throttle":
		return MSGIDRateLimitExceeded

	// Proxy specific
	case "mitm", "man-in-the-middle", "certificate":
		return MSGIDMITMDetected
	case "tls", "ssl", "certificate_error":
		return MSGIDTLSError
	case "proxy_error":
		return MSGIDProxyError

	// Configuration
	case "config", "configuration":
		return MSGIDConfigChange
	case "policy_update":
		return MSGIDPolicyUpdate

	// System
	case "start", "system_start":
		return MSGIDSystemStart
	case "stop", "shutdown", "system_stop":
		return MSGIDSystemStop
	case "error", "system_error":
		return MSGIDSystemError
	case "health", "health_check":
		return MSGIDHealthCheck
	case "metrics":
		return MSGIDMetricsPublish

	// Compliance
	case "compliance", "audit":
		return MSGIDAuditLog

	// Default
	default:
		return MSGIDAuthzSuccess // Generic default
	}
}

// buildStructuredDataForEvent builds structured data for an event
func (f *SyslogFormatter) buildStructuredDataForEvent(event *Event) *RFC5424StructuredData {
	sd := NewRFC5424StructuredData(SDIDAegisGate)

	// Add common parameters
	if event.ID != "" {
		sd.AddParam("eventId", event.ID)
	}
	if event.Type != "" {
		sd.AddParam("eventType", event.Type)
	}
	if event.Action != "" {
		sd.AddParam("action", event.Action)
	}
	if event.SourceIP != "" {
		sd.AddParam("srcIp", event.SourceIP)
	}
	if event.Destination != "" {
		sd.AddParam("dstIp", event.Destination)
	}
	if event.User != "" {
		sd.AddParam("user", event.User)
	}
	if event.ClientID != "" {
		sd.AddParam("clientId", event.ClientID)
	}

	// Add threat-specific parameters if present
	if event.ThreatType != "" {
		sd.AddParam("threatType", event.ThreatType)
	}
	if event.ThreatLevel != "" {
		sd.AddParam("threatLevel", event.ThreatLevel)
	}
	if event.Pattern != "" {
		sd.AddParam("pattern", event.Pattern)
	}

	// Add compliance parameters
	if event.ComplianceFramework != "" {
		sd.AddParam("framework", event.ComplianceFramework)
	}
	if event.ComplianceControl != "" {
		sd.AddParam("control", event.ComplianceControl)
	}

	// Only return SD if it has parameters
	if len(sd.Params) == 0 {
		return nil
	}

	return sd
}

// FormatRFC5424 formats an event as RFC 5424 compliant syslog message
func (f *SyslogFormatter) FormatRFC5424(event *Event) (string, error) {
	msg := f.ConvertEventToRFC5424(event)
	return msg.Build(), nil
}

// FormatRFC5424WithTimestamp formats with a specific timestamp
func (f *SyslogFormatter) FormatRFC5424WithTimestamp(event *Event, timestamp time.Time) (string, error) {
	msg := f.ConvertEventToRFC5424(event)
	msg.SetTimestamp(timestamp)
	return msg.Build(), nil
}

// GetSupportedMSGIDs returns all supported MSGID values
func GetSupportedMSGIDs() []RFC5424MsgID {
	return []RFC5424MsgID{
		MSGIDAuthSuccess,
		MSGIDAuthFailure,
		MSGIDAuthSessionStart,
		MSGIDAuthSessionEnd,
		MSGIDAuthTokenRefresh,
		MSGIDAuthTokenRevoke,
		MSGIDAuthLogout,
		MSGIDAuthzSuccess,
		MSGIDAuthzFailure,
		MSGIDAuthzDenied,
		MSGIDRequestAllowed,
		MSGIDRequestBlocked,
		MSGIDRequestDropped,
		MSGIDRequestThrottled,
		MSGIDThreatDetected,
		MSGIDIntrusionAttempt,
		MSGIDMalwareDetected,
		MSGIDAnomalyDetected,
		MSGIDPolicyViolation,
		MSGIDRateLimitExceeded,
		MSGIDProxyRequest,
		MSGIDProxyResponse,
		MSGIDProxyError,
		MSGIDMITMDetected,
		MSGIDTLSError,
		MSGIDConfigChange,
		MSGIDConfigLoad,
		MSGIDConfigError,
		MSGIDPolicyUpdate,
		MSGIDPolicyDrift,
		MSGIDSystemStart,
		MSGIDSystemStop,
		MSGIDSystemError,
		MSGIDComponentFailure,
		MSGIDHealthCheck,
		MSGIDMetricsPublish,
		MSGIDComplianceViolation,
		MSGIDAuditLog,
		MSGIDDataExport,
		MSGIDPluginLoad,
		MSGIDPluginUnload,
		MSGIDPluginError,
	}
}
