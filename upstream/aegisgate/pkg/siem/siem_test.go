// Package siem provides unit tests for the SIEM integration package.
package siem

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Types and Constants Tests
// ============================================================================

func TestPlatformConstants(t *testing.T) {
	platforms := []Platform{
		PlatformSplunk,
		PlatformElasticsearch,
		PlatformQRadar,
		PlatformSentinel,
		PlatformSumoLogic,
		PlatformLogRhythm,
		PlatformCloudWatch,
		PlatformSecurityHub,
		PlatformArcSight,
		PlatformSyslog,
		PlatformCustom,
	}

	for _, p := range platforms {
		if string(p) == "" {
			t.Errorf("Platform constant should not be empty")
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	severityLevels := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}

	for _, s := range severityLevels {
		if string(s) == "" {
			t.Errorf("Severity constant should not be empty")
		}
	}
}

func TestEventCategoryConstants(t *testing.T) {
	categories := []EventCategory{
		CategoryAuthentication,
		CategoryAuthorization,
		CategoryAccess,
		CategoryThreat,
		CategoryVulnerability,
		CategoryCompliance,
		CategoryAudit,
		CategoryNetwork,
		CategoryApplication,
		CategoryDataLoss,
		CategoryMalware,
		CategoryPolicy,
	}

	for _, c := range categories {
		if string(c) == "" {
			t.Errorf("EventCategory constant should not be empty")
		}
	}
}

func TestFormatConstants(t *testing.T) {
	formats := []Format{
		FormatJSON,
		FormatCEF,
		FormatLEEF,
		FormatSyslog,
		FormatCSV,
	}

	for _, f := range formats {
		if string(f) == "" {
			t.Errorf("Format constant should not be empty")
		}
	}
}

// ============================================================================
// Event Tests
// ============================================================================

func TestEventJSON(t *testing.T) {
	event := &Event{
		ID:        "test-123",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  CategoryThreat,
		Type:      "blocked_request",
		Severity:  SeverityHigh,
		Message:   "SQL injection attempt blocked",
		Attributes: map[string]string{
			"source_ip":  "192.168.1.100",
			"request_id": "req-456",
		},
		Entities: []Entity{
			{Type: "ip", ID: "ip-1", Name: "Attacker IP", Value: "192.168.1.100"},
		},
		MITRE: &MITREMapping{
			Tactic:    "Initial Access",
			Technique: "T1190",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	var parsed Event
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	if parsed.ID != event.ID {
		t.Errorf("Expected ID %s, got %s", event.ID, parsed.ID)
	}
	if parsed.Category != event.Category {
		t.Errorf("Expected Category %s, got %s", event.Category, parsed.Category)
	}
	if parsed.Severity != event.Severity {
		t.Errorf("Expected Severity %s, got %s", event.Severity, parsed.Severity)
	}
	if parsed.MITRE == nil || parsed.MITRE.Tactic != event.MITRE.Tactic {
		t.Errorf("MITRE mapping not preserved")
	}
}

// ============================================================================
// Formatter Tests
// ============================================================================

func TestJSONFormatter(t *testing.T) {
	formatter := NewJSONFormatter(PlatformSplunk)

	event := &Event{
		ID:        "test-123",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  CategoryThreat,
		Type:      "blocked_request",
		Severity:  SeverityHigh,
		Message:   "SQL injection attempt blocked",
	}

	data, err := formatter.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(string(data), `"id":"test-123"`) {
		t.Errorf("JSON output missing expected content")
	}

	if formatter.ContentType() != "application/json" {
		t.Errorf("Expected ContentType application/json, got %s", formatter.ContentType())
	}

	if formatter.FileExtension() != ".json" {
		t.Errorf("Expected FileExtension .json, got %s", formatter.FileExtension())
	}
}

func TestJSONFormatterBatch(t *testing.T) {
	formatter := NewJSONFormatter(PlatformElasticsearch)

	events := []*Event{
		{ID: "event-1", Timestamp: time.Now(), Severity: SeverityInfo, Category: CategoryAudit, Message: "Test 1"},
		{ID: "event-2", Timestamp: time.Now(), Severity: SeverityLow, Category: CategoryAudit, Message: "Test 2"},
	}

	data, err := formatter.FormatBatch(events)
	if err != nil {
		t.Fatalf("FormatBatch failed: %v", err)
	}

	lines := strings.Count(string(data), "\n")
	if lines != 2 {
		t.Errorf("Expected 2 lines in batch output, got %d", lines)
	}
}

func TestCEFFormatter(t *testing.T) {
	formatter := NewCEFFormatter(PlatformArcSight, CEFOptions{
		Vendor:  "AegisGate",
		Product: "AI Security Gateway",
		Version: "1.0",
	})

	event := &Event{
		ID:        "cef-test-1",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  CategoryThreat,
		Type:      "sql_injection",
		Severity:  SeverityCritical,
		Message:   "SQL injection attack detected",
		Entities: []Entity{
			{Type: "src_ip", Value: "10.0.0.1"},
			{Type: "dst_ip", Value: "10.0.0.2"},
		},
		MITRE: &MITREMapping{
			Tactic:    "Initial Access",
			Technique: "T1190",
		},
	}

	data, err := formatter.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "CEF:0") {
		t.Errorf("CEF output missing header")
	}
	if !strings.Contains(output, "AegisGate") {
		t.Errorf("CEF output missing vendor")
	}
	if !strings.Contains(output, "sql_injection") {
		t.Errorf("CEF output missing event type")
	}
	if !strings.Contains(output, "src=10.0.0.1") {
		t.Errorf("CEF output missing source IP extension")
	}

	if formatter.ContentType() != "text/plain" {
		t.Errorf("Expected ContentType text/plain, got %s", formatter.ContentType())
	}

	if formatter.FileExtension() != ".cef" {
		t.Errorf("Expected FileExtension .cef, got %s", formatter.FileExtension())
	}
}

func TestLEEFFormatter(t *testing.T) {
	formatter := NewLEEFFormatter(PlatformQRadar, LEEFOptions{
		Vendor:  "AegisGate",
		Product: "AI Security Gateway",
		Version: "1.0",
	})

	event := &Event{
		ID:        "leef-test-1",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  CategoryAuthentication,
		Type:      "auth_failure",
		Severity:  SeverityMedium,
		Message:   "Authentication failure detected",
		Entities: []Entity{
			{Type: "src_ip", Value: "192.168.1.50"},
			{Type: "src_user", Value: "admin"},
		},
	}

	data, err := formatter.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "LEEF:2.0") {
		t.Errorf("LEEF output missing header")
	}
	if !strings.Contains(output, "AegisGate") {
		t.Errorf("LEEF output missing vendor")
	}
	if !strings.Contains(output, "auth_failure") {
		t.Errorf("LEEF output missing event type")
	}
	if !strings.Contains(output, "src=192.168.1.50") {
		t.Errorf("LEEF output missing source IP")
	}

	if formatter.FileExtension() != ".leef" {
		t.Errorf("Expected FileExtension .leef, got %s", formatter.FileExtension())
	}
}

func TestSyslogFormatter(t *testing.T) {
	formatter := NewSyslogFormatter(PlatformSyslog, SyslogOptions{
		Facility: 1,
		AppName:  "aegisgate",
		Hostname: "testhost",
	})

	event := &Event{
		ID:        "syslog-test-1",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Source:    "aegisgate",
		Category:  CategoryAudit,
		Type:      "config_change",
		Severity:  SeverityInfo,
		Message:   "Configuration updated",
		Attributes: map[string]string{
			"user": "admin",
		},
	}

	data, err := formatter.Format(event)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, "<") {
		t.Errorf("Syslog output missing priority")
	}
	if !strings.Contains(output, "testhost") {
		t.Errorf("Syslog output missing hostname")
	}
	if !strings.Contains(output, "aegisgate") {
		t.Errorf("Syslog output missing app name")
	}
	if !strings.Contains(output, "Configuration updated") {
		t.Errorf("Syslog output missing message")
	}

	if formatter.FileExtension() != ".log" {
		t.Errorf("Expected FileExtension .log, got %s", formatter.FileExtension())
	}
}

func TestCSVFormatter(t *testing.T) {
	formatter := NewCSVFormatter(PlatformCustom, []string{
		"id", "timestamp", "severity", "category", "message",
	})

	events := []*Event{
		{
			ID:        "csv-1",
			Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			Category:  CategoryAudit,
			Severity:  SeverityInfo,
			Message:   "Test message 1",
		},
		{
			ID:        "csv-2",
			Timestamp: time.Date(2024, 1, 15, 10, 31, 0, 0, time.UTC),
			Category:  CategoryThreat,
			Severity:  SeverityHigh,
			Message:   "Test message 2",
		},
	}

	data, err := formatter.FormatBatch(events)
	if err != nil {
		t.Fatalf("FormatBatch failed: %v", err)
	}

	output := string(data)
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 { // header + 2 data rows
		t.Errorf("Expected 3 lines (header + 2 rows), got %d", len(lines))
	}
	if !strings.Contains(lines[0], "id,timestamp,severity") {
		t.Errorf("CSV header missing expected columns")
	}
	if !strings.Contains(lines[1], "csv-1") {
		t.Errorf("First data row missing event ID")
	}
	if !strings.Contains(lines[2], "csv-2") {
		t.Errorf("Second data row missing event ID")
	}

	if formatter.ContentType() != "text/csv" {
		t.Errorf("Expected ContentType text/csv, got %s", formatter.ContentType())
	}
}

// ============================================================================
// Event Buffer Tests
// ============================================================================

func TestEventBuffer(t *testing.T) {
	buffer := NewEventBuffer(PlatformSplunk, 3)

	// Test Add
	event1 := &Event{ID: "1", Severity: SeverityInfo}
	event2 := &Event{ID: "2", Severity: SeverityInfo}
	event3 := &Event{ID: "3", Severity: SeverityInfo}

	if err := buffer.Add(event1); err != nil {
		t.Errorf("Add failed for event 1: %v", err)
	}
	if err := buffer.Add(event2); err != nil {
		t.Errorf("Add failed for event 2: %v", err)
	}
	if buffer.Size() != 2 {
		t.Errorf("Expected buffer size 2, got %d", buffer.Size())
	}

	// Test IsFull
	if buffer.IsFull() {
		t.Errorf("Buffer should not be full yet")
	}

	if err := buffer.Add(event3); err != nil {
		t.Errorf("Add failed for event 3: %v", err)
	}
	if !buffer.IsFull() {
		t.Errorf("Buffer should be full")
	}

	// Test overflow
	overflow := &Event{ID: "4", Severity: SeverityInfo}
	if err := buffer.Add(overflow); err == nil {
		t.Errorf("Expected error when adding to full buffer")
	}

	// Test Flush
	events := buffer.Flush()
	if len(events) != 3 {
		t.Errorf("Expected 3 events from flush, got %d", len(events))
	}
	if buffer.Size() != 0 {
		t.Errorf("Buffer should be empty after flush")
	}
}

func TestEventBufferBatch(t *testing.T) {
	buffer := NewEventBuffer(PlatformElasticsearch, 10)

	events := []*Event{
		{ID: "1", Severity: SeverityInfo},
		{ID: "2", Severity: SeverityInfo},
		{ID: "3", Severity: SeverityInfo},
	}

	if err := buffer.AddBatch(events); err != nil {
		t.Errorf("AddBatch failed: %v", err)
	}
	if buffer.Size() != 3 {
		t.Errorf("Expected buffer size 3, got %d", buffer.Size())
	}

	// Test batch that would overflow
	largeBatch := make([]*Event, 15)
	for i := range largeBatch {
		largeBatch[i] = &Event{ID: string(rune(i + 'a')), Severity: SeverityInfo}
	}
	if err := buffer.AddBatch(largeBatch); err == nil {
		t.Errorf("Expected error when batch would overflow buffer")
	}
}

// ============================================================================
// Error Tests
// ============================================================================

func TestSIEMError(t *testing.T) {
	err := NewError(PlatformSplunk, "send", "connection refused", true, nil)

	if err.Platform != PlatformSplunk {
		t.Errorf("Expected Platform Splunk, got %s", err.Platform)
	}
	if !err.Retryable {
		t.Errorf("Error should be retryable")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "splunk") {
		t.Errorf("Error message missing platform")
	}
	if !strings.Contains(errMsg, "send") {
		t.Errorf("Error message missing operation")
	}
}

func TestSIEMErrorWithCause(t *testing.T) {
	cause := context.DeadlineExceeded
	err := NewError(PlatformElasticsearch, "query", "timeout", true, cause)

	if err.Unwrap() != cause {
		t.Errorf("Unwrap should return the cause")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "context deadline exceeded") {
		t.Errorf("Error message should contain cause")
	}
}

// ============================================================================
// HTTP Client Tests
// ============================================================================

func TestHTTPClientDefault(t *testing.T) {
	client, err := NewHTTPClient(PlatformSplunk, TLSConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}

	if client.Client == nil {
		t.Errorf("HTTP client should not be nil")
	}
}

func TestHTTPClientWithTLS(t *testing.T) {
	client, err := NewHTTPClient(PlatformSplunk, TLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
		ServerName:         "test.example.com",
	})
	if err != nil {
		t.Fatalf("NewHTTPClient with TLS failed: %v", err)
	}

	if client.Client == nil {
		t.Errorf("HTTP client should not be nil")
	}
}

func TestHTTPClientDoRequest(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	client, err := NewHTTPClient(PlatformSplunk, TLSConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewHTTPClient failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	retryCfg := RetryConfig{
		Enabled:     true,
		MaxAttempts: 3,
	}

	resp, err := client.DoRequest(context.Background(), req, retryCfg)
	if err != nil {
		t.Errorf("DoRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// ============================================================================
// Event Filter Tests
// ============================================================================

func TestEventFilterMinSeverity(t *testing.T) {
	filter := NewEventFilter(FilterConfig{
		MinSeverity: SeverityMedium,
	})

	tests := []struct {
		severity Severity
		allowed  bool
	}{
		{SeverityCritical, true},
		{SeverityHigh, true},
		{SeverityMedium, true},
		{SeverityLow, false},
		{SeverityInfo, false},
	}

	for _, tt := range tests {
		event := &Event{Severity: tt.severity, Category: CategoryAudit}
		if filter.Allow(event) != tt.allowed {
			t.Errorf("Severity %s: expected allowed=%v", tt.severity, tt.allowed)
		}
	}
}

func TestEventFilterExcludeCategories(t *testing.T) {
	filter := NewEventFilter(FilterConfig{
		ExcludeCategories: []EventCategory{CategoryPolicy},
	})

	tests := []struct {
		category EventCategory
		allowed  bool
	}{
		{CategoryThreat, true},
		{CategoryAudit, true},
		{CategoryPolicy, false},
	}

	for _, tt := range tests {
		event := &Event{Category: tt.category, Severity: SeverityInfo}
		if filter.Allow(event) != tt.allowed {
			t.Errorf("Category %s: expected allowed=%v", tt.category, tt.allowed)
		}
	}
}

func TestEventFilterIncludeCategories(t *testing.T) {
	filter := NewEventFilter(FilterConfig{
		IncludeCategories: []EventCategory{CategoryThreat},
		MinSeverity:       SeverityLow,
	})

	tests := []struct {
		category EventCategory
		allowed  bool
	}{
		{CategoryThreat, true},
		{CategoryAudit, false},
		{CategoryCompliance, false},
	}

	for _, tt := range tests {
		event := &Event{Category: tt.category, Severity: SeverityMedium}
		if filter.Allow(event) != tt.allowed {
			t.Errorf("Category %s: expected allowed=%v", tt.category, tt.allowed)
		}
	}
}

func TestEventFilterExcludeTypes(t *testing.T) {
	filter := NewEventFilter(FilterConfig{
		ExcludeTypes: []string{"health_check", "heartbeat"},
	})

	tests := []struct {
		eventType string
		allowed   bool
	}{
		{"blocked_request", true},
		{"auth_failure", true},
		{"health_check", false},
		{"heartbeat", false},
	}

	for _, tt := range tests {
		event := &Event{Type: tt.eventType, Category: CategoryAudit, Severity: SeverityInfo}
		if filter.Allow(event) != tt.allowed {
			t.Errorf("Type %s: expected allowed=%v", tt.eventType, tt.allowed)
		}
	}
}

// ============================================================================
// Event Builder Tests
// ============================================================================

func TestEventBuilder(t *testing.T) {
	now := time.Now()
	event := NewEventBuilder().
		WithID("builder-test-1").
		WithTimestamp(now).
		WithSource("test-source").
		WithCategory(CategoryThreat).
		WithType("sqli_attempt").
		WithSeverity(SeverityCritical).
		WithMessage("SQL injection detected").
		WithAttribute("ip", "10.0.0.1").
		WithAttribute("user", "admin").
		WithEntity("ip", "ip-1", "Source IP", "10.0.0.1").
		WithMITRE("Initial Access", "T1190").
		WithCompliance("SOC2", "CC6.1").
		Build()

	if event.ID != "builder-test-1" {
		t.Errorf("Expected ID builder-test-1, got %s", event.ID)
	}
	if !event.Timestamp.Equal(now) {
		t.Errorf("Timestamp mismatch")
	}
	if event.Source != "test-source" {
		t.Errorf("Expected Source test-source, got %s", event.Source)
	}
	if event.Category != CategoryThreat {
		t.Errorf("Expected Category Threat, got %s", event.Category)
	}
	if event.Type != "sqli_attempt" {
		t.Errorf("Expected Type sqli_attempt, got %s", event.Type)
	}
	if event.Severity != SeverityCritical {
		t.Errorf("Expected Severity Critical, got %s", event.Severity)
	}
	if event.Message != "SQL injection detected" {
		t.Errorf("Expected Message 'SQL injection detected', got %s", event.Message)
	}
	if event.Attributes["ip"] != "10.0.0.1" {
		t.Errorf("Expected attribute ip=10.0.0.1")
	}
	if len(event.Entities) != 1 {
		t.Errorf("Expected 1 entity")
	}
	if event.MITRE == nil || event.MITRE.Tactic != "Initial Access" {
		t.Errorf("MITRE mapping missing or incorrect")
	}
	if len(event.Compliance) != 1 {
		t.Errorf("Expected 1 compliance mapping")
	}
}

func TestEventBuilderDefaults(t *testing.T) {
	event := NewEventBuilder().Build()

	if event.ID == "" {
		t.Errorf("ID should be auto-generated")
	}
	if event.Timestamp.IsZero() {
		t.Errorf("Timestamp should be set")
	}
	if event.Attributes == nil {
		t.Errorf("Attributes should be initialized")
	}
	if event.Entities == nil {
		t.Errorf("Entities should be initialized")
	}
}

// ============================================================================
// Manager Tests
// ============================================================================

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Global.AppName == "" {
		t.Errorf("Default AppName should be set")
	}
	if config.Global.DefaultSeverity == "" {
		t.Errorf("Default Severity should be set")
	}
	if config.Buffer.MaxSize == 0 {
		t.Errorf("Default Buffer MaxSize should be set")
	}
}

func TestDefaultPlatformConfig(t *testing.T) {
	tests := []struct {
		platform       Platform
		expectedFormat Format
	}{
		{PlatformSplunk, FormatJSON},
		{PlatformElasticsearch, FormatJSON},
		{PlatformQRadar, FormatLEEF},
		{PlatformArcSight, FormatCEF},
		{PlatformSyslog, FormatSyslog},
	}

	for _, tt := range tests {
		config := DefaultPlatformConfig(tt.platform)
		if config.Platform != tt.platform {
			t.Errorf("Expected platform %s, got %s", tt.platform, config.Platform)
		}
		if config.Format != tt.expectedFormat {
			t.Errorf("Platform %s: expected format %s, got %s", tt.platform, tt.expectedFormat, config.Format)
		}
		if !config.Enabled {
			t.Errorf("Platform %s: should be enabled by default", tt.platform)
		}
		if config.Retry.MaxAttempts == 0 {
			t.Errorf("Platform %s: retry max attempts should be set", tt.platform)
		}
	}
}

func TestManagerValidation(t *testing.T) {
	// Test with minimal config
	config := DefaultConfig()
	config.Platforms = nil // No platforms

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Test sending nil event
	err = manager.Send(nil)
	if err == nil {
		t.Errorf("Expected error for nil event")
	}

	// Test valid event
	event := &Event{
		ID:        "test-event",
		Timestamp: time.Now(),
		Source:    "test",
		Category:  CategoryAudit,
		Type:      "test",
		Severity:  SeverityInfo,
		Message:   "Test event",
	}

	// With no platforms configured, event should be accepted but filtered
	err = manager.Send(event)
	// No error expected because there are no platforms to send to
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestManagerApplyDefaults(t *testing.T) {
	config := DefaultConfig()
	config.Global.AppName = "test-app"
	config.Global.DefaultSeverity = SeverityMedium
	config.Global.AddHostname = true

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	event := &Event{
		ID:        "test",
		Timestamp: time.Now(),
		Category:  CategoryAudit,
		Type:      "test",
		Message:   "Test",
		// Source and Severity not set
	}

	_ = manager.validateEvent(event)
	manager.applyDefaults(event)

	if event.Source != "test-app" {
		t.Errorf("Expected source to be set to test-app, got %s", event.Source)
	}
	if event.Severity != SeverityMedium {
		t.Errorf("Expected severity to be set to medium, got %s", event.Severity)
	}
}

// ============================================================================
// Configuration Tests
// ============================================================================

func TestConfigJSON(t *testing.T) {
	config := Config{
		Global: GlobalConfig{
			AppName:         "aegisgate-test",
			Environment:     "testing",
			DefaultSeverity: SeverityInfo,
			IncludeRaw:      true,
			AddHostname:     false,
		},
		Filter: FilterConfig{
			MinSeverity:       SeverityLow,
			ExcludeTypes:      []string{"health_check"},
			IncludeCategories: []EventCategory{CategoryThreat},
		},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformSplunk,
				Enabled:  true,
				Format:   FormatJSON,
				Endpoint: "https://splunk.example.com:8088",
				Auth: AuthConfig{
					Type:   "api_key",
					APIKey: "test-token",
				},
			},
		},
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if parsed.Global.AppName != config.Global.AppName {
		t.Errorf("AppName mismatch")
	}
	if len(parsed.Platforms) != 1 {
		t.Errorf("Expected 1 platform")
	}
	if parsed.Platforms[0].Platform != PlatformSplunk {
		t.Errorf("Platform mismatch")
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestOrDefault(t *testing.T) {
	if orDefault("", "default") != "default" {
		t.Errorf("Expected default value for empty string")
	}
	if orDefault("value", "default") != "value" {
		t.Errorf("Expected original value for non-empty string")
	}
}

func TestOrDefaultInt(t *testing.T) {
	if orDefaultInt(0, 10) != 10 {
		t.Errorf("Expected default value for zero")
	}
	if orDefaultInt(5, 10) != 5 {
		t.Errorf("Expected original value for non-zero")
	}
}

func TestGetHostnameCustom(t *testing.T) {
	hostname := getHostname()
	if hostname == "" {
		t.Errorf("Hostname should not be empty")
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	if id1 == "" {
		t.Errorf("Generated ID should not be empty")
	}
	if id1 == id2 {
		t.Errorf("Generated IDs should be unique")
	}
	if len(id1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("Expected ID length 32, got %d", len(id1))
	}
}

// ============================================================================
// Severity Mapping Tests
// ============================================================================

func TestCEFSeverity(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "10"},
		{SeverityHigh, "8"},
		{SeverityMedium, "6"},
		{SeverityLow, "4"},
		{SeverityInfo, "2"},
	}

	for _, tt := range tests {
		result := cefSeverity(tt.severity)
		if result != tt.expected {
			t.Errorf("CEF severity for %s: expected %s, got %s", tt.severity, tt.expected, result)
		}
	}
}

func TestSyslogSeverity(t *testing.T) {
	tests := []struct {
		severity Severity
		maxValue int
	}{
		{SeverityCritical, 2}, // Critical
		{SeverityHigh, 3},     // Error
		{SeverityMedium, 4},   // Warning
		{SeverityLow, 5},      // Notice
		{SeverityInfo, 6},     // Informational
	}

	for _, tt := range tests {
		result := syslogSeverity(tt.severity)
		if result > tt.maxValue || result < 0 {
			t.Errorf("Syslog severity for %s: expected <= %d, got %d", tt.severity, tt.maxValue, result)
		}
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkJSONFormatter_Format(b *testing.B) {
	formatter := NewJSONFormatter(PlatformSplunk)
	event := &Event{
		ID:        "bench-test",
		Timestamp: time.Now(),
		Source:    "aegisgate",
		Category:  CategoryThreat,
		Type:      "blocked_request",
		Severity:  SeverityHigh,
		Message:   "Benchmark test event",
		Attributes: map[string]string{
			"ip":   "10.0.0.1",
			"user": "testuser",
			"path": "/api/test",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = formatter.Format(event)
	}
}

func BenchmarkCEFFormatter_Format(b *testing.B) {
	formatter := NewCEFFormatter(PlatformArcSight, CEFOptions{
		Vendor:  "AegisGate",
		Product: "AI Security Gateway",
		Version: "1.0",
	})
	event := &Event{
		ID:        "bench-test",
		Timestamp: time.Now(),
		Source:    "aegisgate",
		Category:  CategoryThreat,
		Type:      "sqli",
		Severity:  SeverityCritical,
		Message:   "SQL injection attempt blocked",
		Entities: []Entity{
			{Type: "src_ip", Value: "10.0.0.1"},
			{Type: "dst_ip", Value: "10.0.0.2"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = formatter.Format(event)
	}
}

func BenchmarkEventBuffer_Add(b *testing.B) {
	buffer := NewEventBuffer(PlatformSplunk, 100000)
	event := &Event{
		ID:        "bench",
		Timestamp: time.Now(),
		Severity:  SeverityInfo,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buffer.Add(event)
		if buffer.IsFull() {
			buffer.Flush()
		}
	}
}

func BenchmarkEventFilter_Allow(b *testing.B) {
	filter := NewEventFilter(FilterConfig{
		MinSeverity:       SeverityMedium,
		IncludeCategories: []EventCategory{CategoryThreat},
		ExcludeTypes:      []string{"health_check"},
	})
	event := &Event{
		Category: CategoryThreat,
		Type:     "blocked_request",
		Severity: SeverityHigh,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = filter.Allow(event)
	}
}

func BenchmarkEventBuilder_Build(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewEventBuilder().
			WithID("bench").
			WithTimestamp(time.Now()).
			WithSource("aegisgate").
			WithCategory(CategoryThreat).
			WithType("test").
			WithSeverity(SeverityHigh).
			WithMessage("Benchmark event").
			WithAttribute("ip", "10.0.0.1").
			WithMITRE("Initial Access", "T1190").
			Build()
	}
}
