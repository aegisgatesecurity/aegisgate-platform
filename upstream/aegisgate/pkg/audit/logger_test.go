package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger()
	if logger == nil {
		t.Fatal("NewLogger() returned nil")
	}
}

func TestLoggerLogAction(t *testing.T) {
	logger := NewLogger()

	action := &Action{
		Type:      "tool_call",
		SessionID: "session-123",
		AgentID:   "agent-456",
		ToolName:  "file_read",
		Allowed:   true,
		Reason:    "",
		RiskScore: 30,
	}

	err := logger.LogAction(context.Background(), action)
	if err != nil {
		t.Fatalf("LogAction() error = %v", err)
	}
}

func TestLoggerLogSessionStart(t *testing.T) {
	logger := NewLogger()

	err := logger.LogSessionStart(context.Background(), "session-1", "agent-1")
	if err != nil {
		t.Fatalf("LogSessionStart() error = %v", err)
	}
}

func TestLoggerLogSessionEnd(t *testing.T) {
	logger := NewLogger()

	err := logger.LogSessionEnd(context.Background(), "session-1", "agent-1")
	if err != nil {
		t.Fatalf("LogSessionEnd() error = %v", err)
	}
}

func TestLoggerLogToolCall(t *testing.T) {
	logger := NewLogger()

	err := logger.LogToolCall(context.Background(), "file_read", "session-1", true, "")
	if err != nil {
		t.Fatalf("LogToolCall() error = %v", err)
	}

	err = logger.LogToolCall(context.Background(), "shell", "session-1", false, "Shell commands blocked")
	if err != nil {
		t.Fatalf("LogToolCall() denied error = %v", err)
	}
}

func TestLoggerLogPolicyDenial(t *testing.T) {
	logger := NewLogger()

	err := logger.LogPolicyDenial(context.Background(), "session-1", "shell_command", "Security policy violation")
	if err != nil {
		t.Fatalf("LogPolicyDenial() error = %v", err)
	}
}

func TestLoggerLogRiskAlert(t *testing.T) {
	logger := NewLogger()

	err := logger.LogRiskAlert(context.Background(), "session-1", "shell_command", 95)
	if err != nil {
		t.Fatalf("LogRiskAlert() error = %v", err)
	}
}

func TestLoggerClose(t *testing.T) {
	logger := NewLogger()

	err := logger.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLoggerGeneratesID(t *testing.T) {
	logger := NewLogger()

	// Action without ID should get one generated
	action := &Action{
		Type: "test_action",
	}

	err := logger.LogAction(context.Background(), action)
	if err != nil {
		t.Fatalf("LogAction() error = %v", err)
	}

	if action.ID == "" {
		t.Error("Action ID should be generated if empty")
	}

	if action.Timestamp.IsZero() {
		t.Error("Action Timestamp should be set if zero")
	}
}

func TestNewFormatter(t *testing.T) {
	formatter := NewFormatter("json")
	if formatter == nil {
		t.Fatal("NewFormatter() returned nil")
	}
	if formatter.format != "json" {
		t.Errorf("format = %s, want json", formatter.format)
	}
}

func TestFormatterFormatActionJSON(t *testing.T) {
	formatter := NewFormatter("json")

	action := &Action{
		ID:        "test-123",
		Type:      "tool_call",
		Timestamp: timeNow(),
	}

	data, err := formatter.FormatAction(action)
	if err != nil {
		t.Fatalf("FormatAction() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("Formatted action is not valid JSON: %v", err)
	}
}

func TestFormatterFormatActionCSV(t *testing.T) {
	formatter := NewFormatter("csv")

	action := &Action{
		ID:        "test-123",
		Type:      "tool_call",
		Timestamp: timeNow(),
	}

	data, err := formatter.FormatAction(action)
	if err != nil {
		t.Fatalf("FormatAction() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("FormatAction() should return data")
	}
}

func TestBoolToString(t *testing.T) {
	if boolToString(true) != "true" {
		t.Error("boolToString(true) should return 'true'")
	}
	if boolToString(false) != "false" {
		t.Error("boolToString(false) should return 'false'")
	}
}

func TestNewExporter(t *testing.T) {
	exporter := NewExporter("file", "json")
	if exporter == nil {
		t.Fatal("NewExporter() returned nil")
	}
	if exporter.target != "file" {
		t.Errorf("target = %s, want file", exporter.target)
	}
	if exporter.format != "json" {
		t.Errorf("format = %s, want json", exporter.format)
	}
}

func TestExporterExport(t *testing.T) {
	exporter := NewExporter("file", "json")

	action := &Action{
		ID:   "test-export",
		Type: "tool_call",
	}

	// Export should not error (just returns nil for unimplemented targets)
	err := exporter.Export(action)
	if err != nil {
		t.Errorf("Export() error = %v", err)
	}
}

// Helper to get current time for tests
func timeNow() time.Time {
	return time.Now()
}

func TestNewLoggerWithConfig(t *testing.T) {
	logger := NewLoggerWithConfig(100, 24*time.Hour)
	if logger.maxEntries != 100 {
		t.Errorf("maxEntries = %d, want 100", logger.maxEntries)
	}
	if logger.retention != 24*time.Hour {
		t.Errorf("retention = %v, want 24h", logger.retention)
	}
}

func TestLoggerQueryBySessionID(t *testing.T) {
	logger := NewLogger()

	logger.LogAction(context.Background(), &Action{Type: "tool_call", SessionID: "sess-1", Allowed: true})
	logger.LogAction(context.Background(), &Action{Type: "tool_call", SessionID: "sess-2", Allowed: true})
	logger.LogAction(context.Background(), &Action{Type: "tool_call", SessionID: "sess-1", Allowed: false})

	results := logger.Query(&QueryFilter{SessionID: "sess-1"})
	if len(results) != 2 {
		t.Errorf("Query by SessionID = %d results, want 2", len(results))
	}
}

func TestLoggerQueryByAgentID(t *testing.T) {
	logger := NewLogger()

	logger.LogAction(context.Background(), &Action{Type: "tool_call", AgentID: "agent-a", Allowed: true})
	logger.LogAction(context.Background(), &Action{Type: "tool_call", AgentID: "agent-b", Allowed: true})
	logger.LogAction(context.Background(), &Action{Type: "tool_call", AgentID: "agent-a", Allowed: true})

	results := logger.Query(&QueryFilter{AgentID: "agent-a"})
	if len(results) != 2 {
		t.Errorf("Query by AgentID = %d results, want 2", len(results))
	}
}

func TestLoggerQueryByToolName(t *testing.T) {
	logger := NewLogger()

	logger.LogToolCall(context.Background(), "file_read", "sess-1", true, "")
	logger.LogToolCall(context.Background(), "shell", "sess-1", false, "")
	logger.LogToolCall(context.Background(), "file_read", "sess-1", true, "")

	results := logger.Query(&QueryFilter{ToolName: "file_read"})
	if len(results) != 2 {
		t.Errorf("Query by ToolName = %d results, want 2", len(results))
	}
}

func TestLoggerQueryByAllowed(t *testing.T) {
	logger := NewLogger()

	logger.LogToolCall(context.Background(), "read", "sess-1", true, "")
	logger.LogToolCall(context.Background(), "shell", "sess-1", false, "")
	logger.LogToolCall(context.Background(), "write", "sess-1", true, "")

	allowed := true
	results := logger.Query(&QueryFilter{Allowed: &allowed})
	if len(results) != 2 {
		t.Errorf("Query by Allowed = %d results, want 2", len(results))
	}

	allowed = false
	results = logger.Query(&QueryFilter{Allowed: &allowed})
	if len(results) != 1 {
		t.Errorf("Query by !Allowed = %d results, want 1", len(results))
	}
}

func TestLoggerQueryByRiskScore(t *testing.T) {
	logger := NewLogger()

	logger.LogAction(context.Background(), &Action{Type: "tool_call", RiskScore: 30, Allowed: true})
	logger.LogAction(context.Background(), &Action{Type: "tool_call", RiskScore: 80, Allowed: true})
	logger.LogAction(context.Background(), &Action{Type: "tool_call", RiskScore: 50, Allowed: true})

	results := logger.Query(&QueryFilter{RiskAbove: 60})
	if len(results) != 1 {
		t.Errorf("Query by RiskAbove = %d results, want 1", len(results))
	}
}

func TestLoggerGetEntryCount(t *testing.T) {
	logger := NewLogger()

	if logger.GetEntryCount() != 0 {
		t.Error("Initial count should be 0")
	}

	logger.LogAction(context.Background(), &Action{Type: "test"})
	logger.LogAction(context.Background(), &Action{Type: "test"})

	if logger.GetEntryCount() != 2 {
		t.Errorf("EntryCount = %d, want 2", logger.GetEntryCount())
	}
}

func TestLoggerGetEntries(t *testing.T) {
	logger := NewLogger()

	logger.LogAction(context.Background(), &Action{Type: "test", ID: "act-1"})
	logger.LogAction(context.Background(), &Action{Type: "test", ID: "act-2"})

	entries := logger.GetEntries()
	if len(entries) != 2 {
		t.Errorf("GetEntries() = %d, want 2", len(entries))
	}
}

func TestLoggerClear(t *testing.T) {
	logger := NewLogger()

	logger.LogAction(context.Background(), &Action{Type: "test"})
	logger.LogAction(context.Background(), &Action{Type: "test"})

	logger.Clear()

	if logger.GetEntryCount() != 0 {
		t.Error("Clear() should reset count to 0")
	}
}

func TestLoggerCleanup(t *testing.T) {
	logger := NewLoggerWithConfig(100, time.Millisecond)

	// Add entries
	logger.LogAction(context.Background(), &Action{Type: "test", Timestamp: time.Now()})

	// Wait for expiry
	time.Sleep(10 * time.Millisecond)

	cleaned := logger.Cleanup()
	t.Logf("Cleaned %d expired entries", cleaned)

	// With 1ms retention, entry should be removed
	if logger.GetEntryCount() != 0 {
		t.Errorf("After cleanup, count = %d, want 0", logger.GetEntryCount())
	}
}

func TestLoggerMaxEntries(t *testing.T) {
	logger := NewLoggerWithConfig(3, 0)

	logger.LogAction(context.Background(), &Action{Type: "test", ID: "1"})
	logger.LogAction(context.Background(), &Action{Type: "test", ID: "2"})
	logger.LogAction(context.Background(), &Action{Type: "test", ID: "3"})
	logger.LogAction(context.Background(), &Action{Type: "test", ID: "4"})
	logger.LogAction(context.Background(), &Action{Type: "test", ID: "5"})

	if logger.GetEntryCount() != 3 {
		t.Errorf("MaxEntries exceeded, count = %d, want 3", logger.GetEntryCount())
	}
}

func TestLoggerQueryAllFields(t *testing.T) {
	logger := NewLogger()

	now := time.Now()
	
	logger.LogAction(context.Background(), &Action{
		Type:      "tool_call",
		SessionID: "sess-1",
		AgentID:   "agent-1",
		ToolName:  "file_read",
		RiskScore: 75,
		Allowed:   true,
		Timestamp: now,
	})

	fromTime := now.Add(-time.Hour)
	toTime := now.Add(time.Hour)
	riskAbove := 70

	results := logger.Query(&QueryFilter{
		SessionID:  "sess-1",
		AgentID:    "agent-1",
		ToolName:   "file_read",
		FromTime:   &fromTime,
		ToTime:     &toTime,
		RiskAbove:  riskAbove,
	})

	if len(results) != 1 {
		t.Errorf("Query with all filters = %d results, want 1", len(results))
	}
}

func TestLoggerQueryNoMatches(t *testing.T) {
	logger := NewLogger()

	logger.LogAction(context.Background(), &Action{Type: "tool_call", SessionID: "sess-1"})

	results := logger.Query(&QueryFilter{SessionID: "nonexistent"})
	if len(results) != 0 {
		t.Errorf("Query with no matches = %d, want 0", len(results))
	}
}
