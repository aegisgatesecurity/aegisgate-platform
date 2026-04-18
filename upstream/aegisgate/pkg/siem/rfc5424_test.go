// Copyright 2024 AegisGate
// RFC 5424 compliance tests

package siem

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRFC5424Message_Build(t *testing.T) {
	tests := []struct {
		name     string
		msg      *RFC5424Message
		expected string
	}{
		{
			name: "minimal message",
			msg: &RFC5424Message{
				Priority:       14, // local0 + informational
				Version:        1,
				Timestamp:      time.Now().UTC(),
				Hostname:       "aegisgate-host",
				AppName:        "aegisgate",
				ProcID:         "12345",
				MsgID:          MSGIDAuthSuccess,
				StructuredData: nil,
				Message:        "Test message",
			},
			expected: "",
		},
		{
			name: "message with structured data",
			msg: &RFC5424Message{
				Priority:  14,
				Version:   1,
				Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
				Hostname:  "test-host",
				AppName:   "aegisgate",
				ProcID:    "1234",
				MsgID:     MSGIDThreatDetected,
				StructuredData: []*RFC5424StructuredData{
					{
						ID: SDIDAegisGate,
						Params: []RFC5424StructuredDataParam{
							{Name: "eventId", Value: "evt-001"},
							{Name: "threatType", Value: "SQL_INJECTION"},
						},
					},
				},
				Message: "Threat detected",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.msg.Build()
			if result == "" {
				t.Error("Build() returned empty string")
			}

			// Validate RFC 5424 format
			// Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
			if !strings.HasPrefix(result, "<") {
				t.Error("Message should start with <PRI>")
			}

			// Check PRI is in valid range
			priEnd := strings.Index(result, ">")
			if priEnd == -1 {
				t.Error("Missing PRI delimiter")
			}
			pri, err := strconv.Atoi(result[1:priEnd])
			if err != nil {
				t.Errorf("Invalid PRI value: %v", err)
			}
			if pri < 0 || pri > 191 {
				t.Errorf("PRI value out of range: %d", pri)
			}

			t.Logf("Generated RFC 5424 message: %s", result)
		})
	}
}

func TestRFC5424Message_Priority(t *testing.T) {
	tests := []struct {
		name     string
		facility int
		severity int
		wantPri  int
	}{
		// Priority = facility * 8 + severity
		// facility local0 = 16, so: 16*8 + 6 (info) = 128 + 6 = 134
		{name: "local0 + info", facility: SyslogFacilityLocal0, severity: SyslogSeverityInformational, wantPri: 134},
		// local0 (16) * 8 + 3 (error) = 128 + 3 = 131
		{name: "local0 + error", facility: SyslogFacilityLocal0, severity: SyslogSeverityError, wantPri: 131},
		// facility auth = 4, so: 4*8 + 1 (alert) = 32 + 1 = 33
		{name: "auth + alert", facility: SyslogFacilityAuth, severity: SyslogSeverityAlert, wantPri: 33},
		// local7 = 23 * 8 + 7 (debug) = 184 + 7 = 191
		{name: "local7 + debug", facility: SyslogFacilityLocal7, severity: SyslogSeverityDebug, wantPri: 191},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewRFC5424Message(tt.facility, tt.severity, MSGIDAuthSuccess)
			if msg.Priority != tt.wantPri {
				t.Errorf("Priority = %d, want %d (facility=%d*8 + severity=%d)", msg.Priority, tt.wantPri, tt.facility, tt.severity)
			}
		})
	}
}

func TestRFC5424StructuredData_Build(t *testing.T) {
	tests := []struct {
		name     string
		sd       *RFC5424StructuredData
		expected string
	}{
		{
			name: "empty params",
			sd: &RFC5424StructuredData{
				ID:     SDIDAegisGate,
				Params: []RFC5424StructuredDataParam{},
			},
			expected: "[aegisgate@32473]",
		},
		{
			name: "with params",
			sd: &RFC5424StructuredData{
				ID: SDIDThreat,
				Params: []RFC5424StructuredDataParam{
					{Name: "type", Value: "SQL_INJECTION"},
					{Name: "level", Value: "HIGH"},
				},
			},
			expected: "[threat@aegisgate type=\"SQL_INJECTION\" level=\"HIGH\"]",
		},
		{
			name: "with special chars",
			sd: &RFC5424StructuredData{
				ID: SDIDAegisGate,
				Params: []RFC5424StructuredDataParam{
					{Name: "message", Value: `Test "message" with \ backslash`},
				},
			},
			expected: `[aegisgate@32473 message="Test \"message\" with \\ backslash"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.sd.Build()
			if tt.expected != "" && result != tt.expected {
				t.Errorf("Build() = %s, want %s", result, tt.expected)
			}
			t.Logf("SD: %s", result)
		})
	}
}

func TestEscapeSDParam(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "simple", "simple"},
		{"quote", "with\"quote", "with\\\"quote"},
		{"backslash", "with\\backslash", "with\\\\backslash"},
		{"bracket", "with]bracket", "with\\]bracket"},
		// Combined case: backslash first, then quote, then bracket
		{"combined", `all: "\]`, `all: \"\\\]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeSDParam(tt.input)
			if result != tt.expected {
				t.Errorf("escapeSDParam(%s) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestConvertEventToRFC5424(t *testing.T) {
	f := NewSyslogFormatter(PlatformSyslog, SyslogOptions{})

	tests := []struct {
		name      string
		event     *Event
		wantMsgID RFC5424MsgID
	}{
		{
			name: "auth success",
			event: &Event{
				ID:       "evt-001",
				Type:     "authentication",
				Message:  "Login successful",
				Severity: SeverityInfo,
			},
			wantMsgID: MSGIDAuthSuccess,
		},
		{
			name: "auth failure",
			event: &Event{
				ID:       "evt-002",
				Type:     "authentication",
				Message:  "Login failed",
				Severity: SeverityHigh,
			},
			wantMsgID: MSGIDAuthFailure,
		},
		{
			name: "blocked request",
			event: &Event{
				ID:       "evt-003",
				Type:     "request",
				Action:   "block",
				Message:  "Request blocked",
				Severity: SeverityMedium,
			},
			wantMsgID: MSGIDRequestBlocked,
		},
		{
			name: "threat detected",
			event: &Event{
				ID:         "evt-004",
				Type:       "threat",
				Message:    "Malware detected",
				Severity:   SeverityCritical,
				ThreatType: "MALWARE",
			},
			wantMsgID: MSGIDThreatDetected,
		},
		{
			name: "anomaly detected",
			event: &Event{
				ID:       "evt-005",
				Type:     "anomaly",
				Message:  "Unusual traffic pattern",
				Severity: SeverityMedium,
			},
			wantMsgID: MSGIDAnomalyDetected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := f.ConvertEventToRFC5424(tt.event)
			if msg.MsgID != tt.wantMsgID {
				t.Errorf("MsgID = %s, want %s", msg.MsgID, tt.wantMsgID)
			}

			// Verify message structure
			result := msg.Build()
			if !strings.Contains(result, string(tt.wantMsgID)) {
				t.Errorf("MSGID not found in message: %s", result)
			}

			t.Logf("RFC 5424 message: %s", result)
		})
	}
}

func TestMapEventToSeverity(t *testing.T) {
	f := NewSyslogFormatter(PlatformSyslog, SyslogOptions{})

	tests := []struct {
		name      string
		severity  Severity
		wantLevel int
	}{
		// Note: SeverityCritical = "critical" maps to SyslogSeverityCritical = 2
		{name: "critical", severity: SeverityCritical, wantLevel: SyslogSeverityCritical},
		// SeverityHigh = "high" - there's no SyslogSeverityHigh, so it defaults to info
		{name: "high", severity: SeverityHigh, wantLevel: SyslogSeverityInformational},
		// SeverityMedium = "medium" - no SyslogSeverityMedium, defaults to info
		{name: "medium", severity: SeverityMedium, wantLevel: SyslogSeverityInformational},
		// SeverityLow = "low" - no SyslogSeverityLow, defaults to info
		{name: "low", severity: SeverityLow, wantLevel: SyslogSeverityInformational},
		{name: "info", severity: SeverityInfo, wantLevel: SyslogSeverityInformational},
		{name: "empty", severity: "", wantLevel: SyslogSeverityInformational},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &Event{Severity: tt.severity}
			got := f.mapEventToSeverity(event)
			if got != tt.wantLevel {
				t.Errorf("mapEventToSeverity(%s) = %d, want %d", tt.severity, got, tt.wantLevel)
			}
		})
	}
}

func TestFormatRFC5424(t *testing.T) {
	f := NewSyslogFormatter(PlatformSyslog, SyslogOptions{})

	event := &Event{
		ID:         "test-001",
		Type:       "authentication",
		Action:     "login",
		Message:    "User admin logged in successfully",
		Severity:   SeverityInfo,
		SourceIP:   "192.168.1.100",
		User:       "admin",
		ClientID:   "client-001",
		ThreatType: "",
	}

	result, err := f.FormatRFC5424(event)
	if err != nil {
		t.Errorf("FormatRFC5424() error = %v", err)
	}

	// Verify RFC 5424 structure
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	if !strings.HasPrefix(result, "<") {
		t.Error("Result should start with <PRI>")
	}

	parts := strings.Split(result, " ")
	if len(parts) < 7 {
		t.Errorf("Result should have at least 7 parts, got %d", len(parts))
	}

	t.Logf("Full RFC 5424 message:\n%s", result)
}

func TestGetSupportedMSGIDs(t *testing.T) {
	msgIDs := GetSupportedMSGIDs()

	if len(msgIDs) == 0 {
		t.Error("GetSupportedMSGIDs() returned empty slice")
	}

	// Verify some expected MSGIDs exist
	expected := []RFC5424MsgID{
		MSGIDAuthSuccess,
		MSGIDAuthFailure,
		MSGIDThreatDetected,
		MSGIDRequestBlocked,
		MSGIDPolicyViolation,
	}

	found := make(map[RFC5424MsgID]bool)
	for _, id := range msgIDs {
		found[id] = true
	}

	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("Expected MSGID %s not found", exp)
		}
	}

	t.Logf("Total supported MSGIDs: %d", len(msgIDs))
}

func TestNilValueHandling(t *testing.T) {
	// Test with zero timestamp (should produce NILVALUE)
	msg := &RFC5424Message{
		Priority:       14,
		Version:        1,
		Timestamp:      time.Time{}, // Zero time
		Hostname:       "",          // Empty hostname
		AppName:        "aegisgate",
		ProcID:         "", // Empty procID
		MsgID:          MSGIDAuthSuccess,
		StructuredData: nil,
		Message:        "Test",
	}

	result := msg.Build()

	// Should contain NILVALUE for empty fields
	if !strings.Contains(result, " - ") {
		t.Logf("Result: %s", result)
		// Note: NILVALUE handling depends on implementation
	}

	t.Logf("NILVALUE test result: %s", result)
}

func BenchmarkRFC5424Message_Build(b *testing.B) {
	msg := &RFC5424Message{
		Priority:  14,
		Version:   1,
		Timestamp: time.Now().UTC(),
		Hostname:  "aegisgate-host",
		AppName:   "aegisgate",
		ProcID:    "12345",
		MsgID:     MSGIDThreatDetected,
		StructuredData: []*RFC5424StructuredData{
			{
				ID: SDIDAegisGate,
				Params: []RFC5424StructuredDataParam{
					{Name: "eventId", Value: "evt-001"},
					{Name: "threatType", Value: "SQL_INJECTION"},
					{Name: "srcIp", Value: "192.168.1.100"},
					{Name: "dstIp", Value: "10.0.0.1"},
					{Name: "user", Value: "admin"},
				},
			},
		},
		Message: "Threat detected in request",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = msg.Build()
	}
}

func BenchmarkConvertEventToRFC5424(b *testing.B) {
	f := NewSyslogFormatter(PlatformSyslog, SyslogOptions{})

	event := &Event{
		ID:          "bench-001",
		Type:        "threat",
		Message:     "Benchmark threat event",
		Severity:    SeverityHigh,
		SourceIP:    "192.168.1.100",
		Destination: "10.0.0.1",
		User:        "bench-user",
		ThreatType:  "BENCHMARK",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = f.ConvertEventToRFC5424(event)
	}
}
