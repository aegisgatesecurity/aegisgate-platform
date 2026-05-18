// SPDX-License-Identifier: Apache-2.0
// =============================================================================
// AegisGate Logging Package — Coverage Tests for Uncovered Branches
// =============================================================================
// Target: 95%+ by covering error/edge paths in SyslogFormatter and RFC5424
// Run: go test -cover ./pkg/logging/...
// =============================================================================

package logging

import (
	"strings"
	"testing"
	"time"
)

// ---- Build() ----

func TestRFC5424StructuredData_Build_EmptyParams(t *testing.T) {
	// Cover: len(sd.Params) == 0 → returns "[id]" without params
	sd := NewRFC5424StructuredData(SDIDAegisGate)
	got := sd.Build()
	if !strings.HasPrefix(got, "[aegisgate@32473") {
		t.Errorf("expected SD-ID prefix, got: %s", got)
	}
	if !strings.HasSuffix(got, "]") {
		t.Errorf("expected closing bracket, got: %s", got)
	}
}

func TestRFC5424StructuredData_Build_WithEscapedCharacters(t *testing.T) {
	// Cover: escapeSDParam paths for \, ", ]
	sd := NewRFC5424StructuredData(SDIDAegisGate)
	sd.AddParam("path", `/home/user\"test]\file`)
	result := sd.Build()
	if !strings.Contains(result, `\\`) {
		t.Errorf("expected escaped backslash, got: %s", result)
	}
	if !strings.Contains(result, `\"`) {
		t.Errorf("expected escaped quote, got: %s", result)
	}
	if !strings.Contains(result, `\]`) {
		t.Errorf("expected escaped bracket, got: %s", result)
	}
}

// ---- SetHostname / SetProcID empty string → NILVALUE ----

func TestRFC5424Message_SetHostname_Empty(t *testing.T) {
	// Cover: hostname == "" → RFC5424NILVALUE
	m := &RFC5424Message{Hostname: "orig"}
	m.SetHostname("")
	if m.Hostname != RFC5424NILVALUE {
		t.Errorf("expected NILVALUE for empty hostname, got: %s", m.Hostname)
	}
}

func TestRFC5424Message_SetProcID_Empty(t *testing.T) {
	// Cover: procID == "" → RFC5424NILVALUE
	m := &RFC5424Message{ProcID: "123"}
	m.SetProcID("")
	if m.ProcID != RFC5424NILVALUE {
		t.Errorf("expected NILVALUE for empty procID, got: %s", m.ProcID)
	}
}

// ---- Build() message format ----

func TestRFC5424Message_Build_AllFields(t *testing.T) {
	// Cover: full Build with all fields set, non-zero timestamp
	m := NewRFC5424Message(2, 6, MSGIDAuthSuccess)
	m.SetHostname("testhost").
		SetProcID("456").
		SetMessage("test message").
		SetTimestamp(time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC))
	m.AddStructuredData(NewRFC5424StructuredData(SDIDAegisGate))
	result := m.Build()
	if !strings.Contains(result, "testhost") {
		t.Errorf("expected hostname in output, got: %s", result)
	}
	if !strings.Contains(result, "456") {
		t.Errorf("expected procID in output, got: %s", result)
	}
	if !strings.Contains(result, "test message") {
		t.Errorf("expected message in output, got: %s", result)
	}
}

// ---- mapEventToMsgID default branch ----

func TestSyslogFormatter_mapEventToMsgID_UnknownEventType(t *testing.T) {
	// Cover: default branch → MSGIDAuthzSuccess
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	testCases := []struct {
		typ    string
		msg    string
		action string
	}{
		{"unknown_type", "something happened", ""},
		{"", "", ""},
		{"custom", "custom event", ""},
		{"custom", "custom block", "block"},
		{"custom", "custom rate_limit", "rate_limit"},
		{"custom", "custom threat", "drop"},
		{"custom", "custom threat", "throttle"},
	}
	for _, tc := range testCases {
		e := &Event{Type: tc.typ, Message: tc.msg, Action: tc.action}
		got := f.mapEventToMsgID(e)
		if got != MSGIDAuthzSuccess {
			t.Errorf("type=%q msg=%q action=%q: expected MSGIDAuthzSuccess, got %v",
				tc.typ, tc.msg, tc.action, got)
		}
	}
}

func TestSyslogFormatter_mapEventToMsgID_RequestAllowed(t *testing.T) {
	// Cover: request/http allowed (not block/throttle/rate_limit/drop)
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	e := &Event{Type: "request", Action: "allow", Message: "allowed request"}
	got := f.mapEventToMsgID(e)
	if got != MSGIDRequestAllowed {
		t.Errorf("expected MSGIDRequestAllowed, got: %v", got)
	}
}

func TestSyslogFormatter_mapEventToMsgID_RequestDropped(t *testing.T) {
	// Cover: request blocked/dropped actions — both map to MSGIDRequestBlocked
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	for _, action := range []string{"drop", "block"} {
		e := &Event{Type: "http", Action: action}
		got := f.mapEventToMsgID(e)
		if got != MSGIDRequestBlocked {
			t.Errorf("action=%q: expected REQUEST_BLOCKED, got %v", action, got)
		}
	}
}

func TestSyslogFormatter_mapEventToMsgID_SecurityThreats(t *testing.T) {
	// Cover: threat/attack/malware/intrusion/anomaly/policy cases
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	testCases := []struct {
		typ  string
		want RFC5424MsgID
	}{
		{"threat", MSGIDThreatDetected},
		{"attack", MSGIDThreatDetected},
		{"malware", MSGIDThreatDetected},   // malware → threat (no specific case)
		{"intrusion", MSGIDThreatDetected}, // intrusion → threat (no specific case)
		{"injection", MSGIDThreatDetected},
		{"xss", MSGIDThreatDetected},
		{"csrf", MSGIDThreatDetected},
		{"anomaly", MSGIDAnomalyDetected},
		{"unusual", MSGIDAnomalyDetected},
		{"suspicious", MSGIDAnomalyDetected},
		{"policy", MSGIDPolicyViolation},
		{"violation", MSGIDPolicyViolation},
		{"rate_limit", MSGIDRateLimitExceeded},
		{"throttle", MSGIDRateLimitExceeded},
	}
	for _, tc := range testCases {
		e := &Event{Type: tc.typ}
		got := f.mapEventToMsgID(e)
		if got != tc.want {
			t.Errorf("type=%q: expected %v, got %v", tc.typ, tc.want, got)
		}
	}
}

func TestSyslogFormatter_mapEventToMsgID_ProxyAndTLS(t *testing.T) {
	// Cover: proxy/TLS event types
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	testCases := []struct {
		typ  string
		want RFC5424MsgID
	}{
		{"mitm", MSGIDMITMDetected},
		{"man-in-the-middle", MSGIDMITMDetected},
		{"certificate", MSGIDMITMDetected},
		{"tls", MSGIDTLSError},
		{"ssl", MSGIDTLSError},
		{"certificate_error", MSGIDTLSError},
		{"proxy_error", MSGIDProxyError},
	}
	for _, tc := range testCases {
		e := &Event{Type: tc.typ}
		got := f.mapEventToMsgID(e)
		if got != tc.want {
			t.Errorf("type=%q: expected %v, got %v", tc.typ, tc.want, got)
		}
	}
}

func TestSyslogFormatter_mapEventToMsgID_ConfigSystem(t *testing.T) {
	// Cover: config/system/health/metrics event types
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	testCases := []struct {
		typ  string
		want RFC5424MsgID
	}{
		{"config", MSGIDConfigChange},
		{"configuration", MSGIDConfigChange},
		{"policy_update", MSGIDPolicyUpdate},
		{"config_load", MSGIDAuthzSuccess}, // falls to default (known gap — no case for config_load)
		{"start", MSGIDSystemStart},
		{"system_start", MSGIDSystemStart},
		{"stop", MSGIDSystemStop},
		{"shutdown", MSGIDSystemStop},
		{"system_stop", MSGIDSystemStop},
		{"error", MSGIDSystemError},
		{"system_error", MSGIDSystemError},
		{"health", MSGIDHealthCheck},
		{"health_check", MSGIDHealthCheck},
		{"metrics", MSGIDMetricsPublish},
		{"compliance", MSGIDAuditLog},
		{"audit", MSGIDAuditLog},
	}
	for _, tc := range testCases {
		e := &Event{Type: tc.typ}
		got := f.mapEventToMsgID(e)
		if got != tc.want {
			t.Errorf("type=%q: expected %v, got %v", tc.typ, tc.want, got)
		}
	}
}

// ---- buildStructuredDataForEvent ----

func TestSyslogFormatter_buildStructuredDataForEvent_EmptyEvent(t *testing.T) {
	// Cover: event with no fields → returns nil (no params)
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	sd := f.buildStructuredDataForEvent(&Event{})
	if sd != nil {
		t.Errorf("expected nil for empty event, got: %+v", sd)
	}
}

func TestSyslogFormatter_buildStructuredDataForEvent_SomeFields(t *testing.T) {
	// Cover: event with partial fields → returns sd with params
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	sd := f.buildStructuredDataForEvent(&Event{
		ID:         "e1",
		Type:       "auth",
		Action:     "login",
		SourceIP:   "1.2.3.4",
		User:       "alice",
		ThreatType: "sql_injection",
	})
	if sd == nil {
		t.Fatal("expected non-nil SD for event with fields")
	}
	if len(sd.Params) == 0 {
		t.Fatal("expected params in SD")
	}
}

func TestSyslogFormatter_buildStructuredDataForEvent_ComplianceFields(t *testing.T) {
	// Cover: compliance framework/control fields
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	sd := f.buildStructuredDataForEvent(&Event{
		ComplianceFramework: "HIPAA",
		ComplianceControl:   "§164.312(d)",
	})
	if sd == nil {
		t.Fatal("expected non-nil SD for compliance event")
	}
	// Check params contain framework/control
	found := false
	for _, p := range sd.Params {
		if p.Name == "framework" || p.Name == "control" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected framework/control params, got: %+v", sd.Params)
	}
}

// ---- RFC5424Message.Build() with zero timestamp → NILVALUE ----

func TestRFC5424Message_Build_ZeroTimestamp(t *testing.T) {
	// Cover: m.Timestamp.IsZero() → writes NILVALUE "-"
	m := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)
	m.SetHostname("testhost")
	// Default timestamp from NewRFC5424Message is time.Now().UTC(), never zero.
	// Explicitly set to zero to cover the IsZero() branch
	m.Timestamp = time.Time{}
	result := m.Build()
	if !strings.Contains(result, "- ") {
		t.Errorf("expected NILVALUE for zero timestamp, got: %s", result)
	}
}

// ---- mapEventToMsgID: authz denied branch ----

func TestSyslogFormatter_mapEventToMsgID_AuthzDenied(t *testing.T) {
	// Cover: "authz"/"authorization"/"permission"/"access" with "denied" message → MSGIDAuthzDenied
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	for _, typ := range []string{"authz", "authorization", "permission", "access"} {
		e := &Event{Type: typ, Message: "access denied for user"}
		got := f.mapEventToMsgID(e)
		if got != MSGIDAuthzDenied {
			t.Errorf("type=%q: expected MSGIDAuthzDenied, got %v", typ, got)
		}
	}
}

// ---- mapEventToMsgID: authz success (not denied) ----

func TestSyslogFormatter_mapEventToMsgID_AuthzSuccess(t *testing.T) {
	// Cover: "authz"/"authorization"/"permission"/"access" without "denied" → MSGIDAuthzSuccess
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	for _, typ := range []string{"authz", "authorization", "permission", "access"} {
		e := &Event{Type: typ, Message: "access granted"}
		got := f.mapEventToMsgID(e)
		if got != MSGIDAuthzSuccess {
			t.Errorf("type=%q: expected MSGIDAuthzSuccess, got %v", typ, got)
		}
	}
}

// ---- buildStructuredDataForEvent: all field branches ----

func TestSyslogFormatter_buildStructuredDataForEvent_AllFields(t *testing.T) {
	// Cover: Destination, ClientID, ThreatLevel, Pattern branches in buildStructuredDataForEvent
	f := &SyslogFormatter{Facility: 2, AppName: "test"}
	sd := f.buildStructuredDataForEvent(&Event{
		ID:          "e1",
		Type:        "threat",
		Action:      "block",
		SourceIP:    "1.2.3.4",
		Destination: "5.6.7.8",
		User:        "alice",
		ClientID:    "client-abc",
		ThreatType:  "sql_injection",
		ThreatLevel: "high",
		Pattern:     "UNION SELECT",
	})
	if sd == nil {
		t.Fatal("expected non-nil SD for fully populated event")
	}
	// Verify all expected params exist
	paramNames := map[string]bool{}
	for _, p := range sd.Params {
		paramNames[p.Name] = true
	}
	for _, name := range []string{"eventId", "eventType", "action", "srcIp", "dstIp", "user", "clientId", "threatType", "threatLevel", "pattern"} {
		if !paramNames[name] {
			t.Errorf("missing param: %s", name)
		}
	}
}

// ---- Build() with BOM-prefixed message ----

func TestRFC5424Message_Build_BOMMessage(t *testing.T) {
	// Cover: message starting with BOM → BOM stripped
	m := NewRFC5424Message(SyslogFacilityLocal0, SyslogSeverityInformational, MSGIDAuthSuccess)
	m.SetHostname("testhost")
	m.SetMessage("\ufeffHello world")
	result := m.Build()
	if strings.Contains(result, "\ufeff") {
		t.Errorf("BOM should be stripped from message, got: %q", result)
	}
	if !strings.Contains(result, "Hello world") {
		t.Errorf("expected message content without BOM, got: %s", result)
	}
}

// ---- NewSyslogFormatter edge cases ----

func TestNewSyslogFormatter_EmptyAppName(t *testing.T) {
	// Cover: appName == "" → defaults to "aegisgate"
	f := NewSyslogFormatter(2, "", "host.example.com")
	if f.AppName != "aegisgate" {
		t.Errorf("expected default appName, got: %s", f.AppName)
	}
}

func TestNewSyslogFormatter_EmptyHostname(t *testing.T) {
	// Cover: hostname == "" → calls os.Hostname()
	f := NewSyslogFormatter(2, "myapp", "")
	if f.Hostname == "" {
		t.Errorf("expected hostname to be set, got empty")
	}
}

func TestNewSyslogFormatter_BothNonEmpty(t *testing.T) {
	// Cover: both values provided → used as-is
	f := NewSyslogFormatter(3, "customapp", "custom.host")
	if f.Facility != 3 {
		t.Errorf("expected facility 3, got: %d", f.Facility)
	}
	if f.AppName != "customapp" {
		t.Errorf("expected customapp, got: %s", f.AppName)
	}
	if f.Hostname != "custom.host" {
		t.Errorf("expected custom.host, got: %s", f.Hostname)
	}
}
