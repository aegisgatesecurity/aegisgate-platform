package logging

import (
	"testing"
	"time"
)

// RFC5424StructuredData tests

func TestNewRFC5424StructuredData(t *testing.T) {
	data := NewRFC5424StructuredData(SDIDAegisGate)
	if data == nil {
		t.Fatal("NewRFC5424StructuredData returned nil")
	}
	if data.ID != SDIDAegisGate {
		t.Errorf("ID = %v, want %v", data.ID, SDIDAegisGate)
	}
}

func TestRFC5424StructuredData_AddParam(t *testing.T) {
	data := NewRFC5424StructuredData(SDIDAegisGate)
	data.AddParam("key1", "value1")
	data.AddParam("key2", "value2")

	if len(data.Params) != 2 {
		t.Errorf("Params length = %d, want 2", len(data.Params))
	}
}

func TestRFC5424StructuredData_Build(t *testing.T) {
	data := NewRFC5424StructuredData(SDIDAegisGate)
	data.AddParam("key", "value")

	result := data.Build()
	if result == "" {
		t.Error("Build returned empty string")
	}
	if result == "["+string(SDIDAegisGate)+"]" {
		t.Error("Build should include params")
	}
}

// RFC5424Message tests

func TestNewRFC5424Message(t *testing.T) {
	msg := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)
	if msg == nil {
		t.Fatal("NewRFC5424Message returned nil")
	}
	// Priority = facility * 8 + severity
	expectedPriority := SyslogFacilityLocal0*8 + SyslogSeverityInformational
	if msg.Priority != expectedPriority {
		t.Errorf("Priority = %d, want %d", msg.Priority, expectedPriority)
	}
	if msg.Version != RFC5424Version {
		t.Errorf("Version = %d, want %d", msg.Version, RFC5424Version)
	}
}

func TestRFC5424Message_Setters(t *testing.T) {
	msg := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)

	msg.SetTimestamp(time.Now())
	msg.SetHostname("testhost")
	msg.SetProcID("12345")
	msg.SetMessage("test message")

	if msg.Hostname != "testhost" {
		t.Errorf("Hostname = %v, want testhost", msg.Hostname)
	}
	if msg.ProcID != "12345" {
		t.Errorf("ProcID = %v, want 12345", msg.ProcID)
	}
	if msg.Message != "test message" {
		t.Errorf("Message = %v, want test message", msg.Message)
	}
}

func TestRFC5424Message_AddStructuredData(t *testing.T) {
	msg := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)
	data := NewRFC5424StructuredData(SDIDAegisGate)
	data.AddParam("key", "value")

	msg.AddStructuredData(data)

	if len(msg.StructuredData) != 1 {
		t.Errorf("StructuredData length = %d, want 1", len(msg.StructuredData))
	}
}

func TestRFC5424Message_Build(t *testing.T) {
	msg := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)
	msg.SetHostname("localhost")
	msg.SetTimestamp(time.Now().UTC())

	result := msg.Build()
	if result == "" {
		t.Error("Build returned empty string")
	}
	// Should contain priority angle brackets
	if result[0] != '<' {
		t.Error("Build output should start with '<'")
	}
}

func TestRFC5424Message_String(t *testing.T) {
	msg := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)
	msg.SetHostname("localhost")

	result := msg.String()
	if result == "" {
		t.Error("String returned empty string")
	}
}

// SyslogFormatter tests

func TestNewSyslogFormatter(t *testing.T) {
	formatter := NewSyslogFormatter(SyslogFacilityLocal0, "aegisgate", "localhost")
	if formatter == nil {
		t.Fatal("NewSyslogFormatter returned nil")
	}
	if formatter.Facility != SyslogFacilityLocal0 {
		t.Errorf("Facility = %d, want %d", formatter.Facility, SyslogFacilityLocal0)
	}
	if formatter.AppName != "aegisgate" {
		t.Errorf("AppName = %v, want aegisgate", formatter.AppName)
	}
	if formatter.Hostname != "localhost" {
		t.Errorf("Hostname = %v, want localhost", formatter.Hostname)
	}
}

func TestFormatter_ConvertEventToRFC5424(t *testing.T) {
	formatter := NewSyslogFormatter(SyslogFacilityLocal0, "aegisgate", "localhost")

	event := &Event{
		ID:       "test-123",
		Type:     "auth",
		Action:   "block",
		Severity: SeverityHigh,
		Message:  "Test message",
		SourceIP: "10.0.0.1",
		User:     "testuser",
	}

	result := formatter.ConvertEventToRFC5424(event)
	if result == nil {
		t.Error("ConvertEventToRFC5424 returned nil")
	}
}

func TestFormatter_FormatRFC5424(t *testing.T) {
	formatter := NewSyslogFormatter(SyslogFacilityLocal0, "aegisgate", "localhost")

	event := &Event{
		ID:       "test-456",
		Type:     "request",
		Severity: SeverityInfo,
		Message:  "Request allowed",
	}

	result, err := formatter.FormatRFC5424(event)
	if err != nil {
		t.Errorf("FormatRFC5424 returned error: %v", err)
	}
	if result == "" {
		t.Error("FormatRFC5424 returned empty string")
	}
}

func TestFormatter_FormatRFC5424WithTimestamp(t *testing.T) {
	formatter := NewSyslogFormatter(SyslogFacilityLocal0, "aegisgate", "localhost")

	event := &Event{
		ID:       "test-789",
		Type:     "threat",
		Severity: SeverityCritical,
		Message:  "Threat detected",
	}

	ts := time.Now().UTC()
	result, err := formatter.FormatRFC5424WithTimestamp(event, ts)
	if err != nil {
		t.Errorf("FormatRFC5424WithTimestamp returned error: %v", err)
	}
	if result == "" {
		t.Error("FormatRFC5424WithTimestamp returned empty string")
	}
}
