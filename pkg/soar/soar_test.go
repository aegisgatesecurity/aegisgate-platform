package soar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestManager(endpoints map[Platform]string) (*Manager, map[Platform]*httptest.Server) {
	servers := make(map[Platform]*httptest.Server)
	configs := []PlatformConfig{}

	for platform, _ := range endpoints {
		// Placeholder; servers are set per-test
		_ = platform
	}

	cfg := Config{
		Global: GlobalConfig{
			AppName:       "aegisgate-test",
			Environment:   "test",
			MaxRetries:    2,
			RetryInterval: 10 * time.Millisecond,
		},
		Platforms: configs,
	}

	mgr := NewManager(cfg, nil)
	return mgr, servers
}

func testIncident() *Incident {
	return &Incident{
		ID:              "INC-001",
		Title:           "CJIS Access Control Violation",
		Description:     "Unauthorized access attempt to CJIS-protected data",
		Severity:        SeverityCritical,
		Status:          StatusTriggered,
		Source:          "aegisgate",
		Timestamp:       time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Framework:       "cjis",
		ControlID:       "CJIS-AC-001",
		ControlName:     "Access Control Policy",
		Details:         "User jane.doe attempted access from unapproved IP 10.0.0.99",
		Remediation:     "Revoke access and enforce MFA for CJIS systems",
		AffectedSystems: []string{"cjis-database", "auth-service"},
		Labels:          map[string]string{"env": "production", "team": "security"},
		DedupKey:        "aegisgate-cjis-CJIS-AC-001",
	}
}

// --- Manager creation and configuration ---

func TestNewManager(t *testing.T) {
	cfg := Config{
		Global: GlobalConfig{
			AppName:       "aegisgate",
			Environment:   "production",
			MaxRetries:    3,
			RetryInterval: 5 * time.Second,
		},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: "https://events.pagerduty.com/v2/enqueue",
				Auth:     AuthConfig{Type: "api_key", APIKey: "test-key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if !mgr.started {
		t.Log("manager should not be started before Start()")
	}
}

func TestNewManager_Defaults(t *testing.T) {
	cfg := Config{
		Global: GlobalConfig{},
	}
	mgr := NewManager(cfg, nil)
	if mgr.config.Global.MaxRetries != 3 {
		t.Errorf("expected default MaxRetries=3, got %d", mgr.config.Global.MaxRetries)
	}
	if mgr.config.Global.RetryInterval != 5*time.Second {
		t.Errorf("expected default RetryInterval=5s, got %v", mgr.config.Global.RetryInterval)
	}
}

func TestManager_StartStop(t *testing.T) {
	cfg := Config{
		Global:    GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{},
	}
	mgr := NewManager(cfg, nil)

	mgr.Start()
	if !mgr.started {
		t.Error("manager should be started")
	}

	health := mgr.HealthCheck()
	if !health.Started {
		t.Error("health check should report started")
	}

	mgr.Stop()
	if mgr.started {
		t.Error("manager should be stopped")
	}
}

func TestManager_SendIncidentNotStarted(t *testing.T) {
	cfg := Config{
		Global:    GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{},
	}
	mgr := NewManager(cfg, nil)
	// Don't call Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error when manager not started")
	}
	if !strings.Contains(err.Error(), "not started") {
		t.Errorf("expected 'not started' error, got: %v", err)
	}
}

// --- PagerDuty tests ---

func TestSendIncident_PagerDuty(t *testing.T) {
	var receivedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"status":"success","message":"Event processed"}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 2, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "routing-key-123"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	results := mgr.SendIncident(context.Background(), testIncident())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("unexpected error: %v", results[0].Error)
	}
	if results[0].HTTPStatus != http.StatusAccepted {
		t.Errorf("expected 202, got %d", results[0].HTTPStatus)
	}

	// Validate PagerDuty payload structure
	if receivedBody["routing_key"] != "routing-key-123" {
		t.Errorf("expected routing_key, got %v", receivedBody["routing_key"])
	}
	if receivedBody["event_action"] != "trigger" {
		t.Errorf("expected event_action=trigger, got %v", receivedBody["event_action"])
	}
	if receivedBody["dedup_key"] != "aegisgate-cjis-CJIS-AC-001" {
		t.Errorf("expected dedup_key, got %v", receivedBody["dedup_key"])
	}

	payload, ok := receivedBody["payload"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be map, got %T", receivedBody["payload"])
	}
	if payload["source"] != "aegisgate" {
		t.Errorf("expected source=aegisgate, got %v", payload["source"])
	}
	if payload["class"] != "compliance_violation" {
		t.Errorf("expected class=compliance_violation, got %v", payload["class"])
	}
	if payload["group"] != "cjis" {
		t.Errorf("expected group=cjis, got %v", payload["group"])
	}
	if payload["component"] != "CJIS-AC-001" {
		t.Errorf("expected component=CJIS-AC-001, got %v", payload["component"])
	}
	if payload["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %v", payload["severity"])
	}
}

func TestPagerDuty_StatusMappings(t *testing.T) {
	tests := []struct {
		status       IncidentStatus
		eventAction  string
	}{
		{StatusTriggered, "trigger"},
		{StatusAcknowledged, "acknowledge"},
		{StatusResolved, "resolve"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			var receivedBody map[string]interface{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				json.Unmarshal(body, &receivedBody)
				w.WriteHeader(http.StatusAccepted)
				fmt.Fprintf(w, `{"status":"success"}`)
			}))
			defer srv.Close()

			cfg := Config{
				Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
				Platforms: []PlatformConfig{
					{
						Platform: PlatformPagerDuty,
						Enabled:  true,
						Endpoint: srv.URL,
						Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
					},
				},
			}
			mgr := NewManager(cfg, nil)
			mgr.Start()

			inc := testIncident()
			inc.Status = tt.status
			results := mgr.SendIncident(context.Background(), inc)
			if results[0].Error != nil {
				t.Fatalf("unexpected error: %v", results[0].Error)
			}
			if receivedBody["event_action"] != tt.eventAction {
				t.Errorf("expected event_action=%s, got %v", tt.eventAction, receivedBody["event_action"])
			}
		})
	}
}

// --- Jira tests ---

func TestSendIncident_Jira(t *testing.T) {
	var receivedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		auth := r.Header.Get("Authorization")
		if auth == "" {
			t.Errorf("expected Authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":"10001","key":"AEG-42"}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 2, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformJira,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "jira-token"},
				Settings: map[string]interface{}{"project_key": "SEC"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	results := mgr.SendIncident(context.Background(), testIncident())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("unexpected error: %v", results[0].Error)
	}
	if results[0].HTTPStatus != http.StatusCreated {
		t.Errorf("expected 201, got %d", results[0].HTTPStatus)
	}

	fields, ok := receivedBody["fields"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected fields to be map, got %T", receivedBody["fields"])
	}
	if fields["summary"] != "[AegisGate] CJIS Access Control Violation" {
		t.Errorf("unexpected summary: %v", fields["summary"])
	}
	project, ok := fields["project"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected project to be map")
	}
	if project["key"] != "SEC" {
		t.Errorf("expected project key=SEC, got %v", project["key"])
	}
	priority, ok := fields["priority"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected priority to be map")
	}
	if priority["name"] != "Highest" {
		t.Errorf("expected priority=Highest, got %v", priority["name"])
	}
	labels, ok := fields["labels"].([]interface{})
	if !ok {
		t.Fatalf("expected labels to be array")
	}
	if len(labels) != 3 {
		t.Errorf("expected 3 labels, got %d", len(labels))
	}
}

func TestJira_BasicAuth(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformJira,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "basic", Username: "admin", Password: "secret"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformJira, testIncident())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(receivedAuth, "Basic ") {
		t.Errorf("expected Basic auth header, got %s", receivedAuth)
	}
}

// --- ServiceNow tests ---

func TestSendIncident_ServiceNow(t *testing.T) {
	var receivedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"result":{"sys_id":"abc123"}}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 2, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformServiceNow,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "basic", Username: "admin", Password: "pass"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	results := mgr.SendIncident(context.Background(), testIncident())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("unexpected error: %v", results[0].Error)
	}

	if receivedBody["short_description"] != "[AegisGate] CJIS Access Control Violation" {
		t.Errorf("unexpected short_description: %v", receivedBody["short_description"])
	}
	if receivedBody["category"] != "security" {
		t.Errorf("expected category=security, got %v", receivedBody["category"])
	}
	if receivedBody["subcategory"] != "compliance" {
		t.Errorf("expected subcategory=compliance, got %v", receivedBody["subcategory"])
	}
	if receivedBody["u_framework"] != "cjis" {
		t.Errorf("expected u_framework=cjis, got %v", receivedBody["u_framework"])
	}
	if receivedBody["u_control_id"] != "CJIS-AC-001" {
		t.Errorf("expected u_control_id=CJIS-AC-001, got %v", receivedBody["u_control_id"])
	}

	// Severity mapping: critical -> 1
	sev, ok := receivedBody["severity"].(float64)
	if !ok {
		t.Fatalf("expected severity to be number, got %T", receivedBody["severity"])
	}
	if int(sev) != 1 {
		t.Errorf("expected severity=1 for critical, got %d", int(sev))
	}
}

// --- Custom webhook tests ---

func TestSendIncident_Custom(t *testing.T) {
	var receivedBody map[string]interface{}
	var receivedSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Signature")
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"ok":true}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 2, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformCustom,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "hmac", HMACSecret: "my-secret"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	inc := testIncident()
	results := mgr.SendIncident(context.Background(), inc)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("unexpected error: %v", results[0].Error)
	}

	if receivedBody["source"] != "aegisgate" {
		t.Errorf("expected source=aegisgate, got %v", receivedBody["source"])
	}
	if receivedBody["framework"] != "cjis" {
		t.Errorf("expected framework=cjis, got %v", receivedBody["framework"])
	}

	// Verify HMAC signature
	if receivedSig == "" {
		t.Error("expected X-Signature header for HMAC auth")
	}
}

// --- HMAC signing tests ---

func TestSignHMAC(t *testing.T) {
	payload := []byte(`{"test":"data"}`)
	secret := "my-secret-key"

	result := signHMAC(payload, secret)

	// Verify against known HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	if result != expected {
		t.Errorf("HMAC mismatch: got %s, expected %s", result, expected)
	}
}

func TestSignHMAC_EmptySecret(t *testing.T) {
	payload := []byte("test")
	result := signHMAC(payload, "")
	if result == "" {
		t.Error("expected non-empty HMAC even with empty secret")
	}
}

func TestSignHMAC_DifferentPayloads(t *testing.T) {
	sig1 := signHMAC([]byte("payload1"), "secret")
	sig2 := signHMAC([]byte("payload2"), "secret")
	if sig1 == sig2 {
		t.Error("different payloads should produce different signatures")
	}
}

// --- Severity mapping tests ---

func TestMapSeverityPagerDuty(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "error"},
		{SeverityMedium, "warning"},
		{SeverityLow, "info"},
		{SeverityInfo, "info"},
		{Severity("unknown"), "info"},
	}
	for _, tt := range tests {
		result := mapSeverityPagerDuty(tt.severity)
		if result != tt.expected {
			t.Errorf("mapSeverityPagerDuty(%s) = %s, expected %s", tt.severity, result, tt.expected)
		}
	}
}

func TestMapSeverityJira(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "Highest"},
		{SeverityHigh, "High"},
		{SeverityMedium, "Medium"},
		{SeverityLow, "Low"},
		{SeverityInfo, "Lowest"},
		{Severity("unknown"), "Medium"},
	}
	for _, tt := range tests {
		result := mapSeverityJira(tt.severity)
		if result != tt.expected {
			t.Errorf("mapSeverityJira(%s) = %s, expected %s", tt.severity, result, tt.expected)
		}
	}
}

func TestMapSeverityServiceNow(t *testing.T) {
	tests := []struct {
		severity Severity
		expected int
	}{
		{SeverityCritical, 1},
		{SeverityHigh, 2},
		{SeverityMedium, 3},
		{SeverityLow, 4},
		{SeverityInfo, 4},
		{Severity("unknown"), 3},
	}
	for _, tt := range tests {
		result := mapSeverityServiceNow(tt.severity)
		if result != tt.expected {
			t.Errorf("mapSeverityServiceNow(%s) = %d, expected %d", tt.severity, result, tt.expected)
		}
	}
}

// --- Retry logic tests ---

func TestRetryLogic_ServerError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&attempts, 1)
		if count < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"status":"success"}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 3, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	results := mgr.SendIncident(context.Background(), testIncident())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error != nil {
		t.Fatalf("unexpected error after retry: %v", results[0].Error)
	}
	if results[0].HTTPStatus != http.StatusAccepted {
		t.Errorf("expected 202, got %d", results[0].HTTPStatus)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}
}

func TestRetryLogic_AllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 2, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error after all retries failed")
	}
}

func TestRetryLogic_ConnectionError(t *testing.T) {
	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: "http://127.0.0.1:1/impossible",
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error for unreachable endpoint")
	}
}

// --- Stats tracking tests ---

func TestStatsTracking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"status":"success"}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	mgr.SendIncident(context.Background(), testIncident())
	mgr.SendIncident(context.Background(), testIncident())

	stats := mgr.Stats()
	if stats.TotalSent != 2 {
		t.Errorf("expected TotalSent=2, got %d", stats.TotalSent)
	}
	if stats.TotalFailed != 0 {
		t.Errorf("expected TotalFailed=0, got %d", stats.TotalFailed)
	}
	pdStats, ok := stats.PlatformStats[PlatformPagerDuty]
	if !ok {
		t.Fatal("expected pagerduty stats")
	}
	if pdStats.Sent != 2 {
		t.Errorf("expected pagerduty Sent=2, got %d", pdStats.Sent)
	}
}

func TestStatsTracking_Failures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	mgr.SendIncident(context.Background(), testIncident())

	stats := mgr.Stats()
	if stats.TotalFailed == 0 {
		t.Error("expected at least one failure")
	}
}

// --- Health check tests ---

func TestHealthCheck(t *testing.T) {
	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: "https://events.pagerduty.com/v2/enqueue",
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
			{
				Platform: PlatformJira,
				Enabled:  false,
				Endpoint: "https://jira.example.com",
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	health := mgr.HealthCheck()
	if !health.Healthy {
		t.Error("expected healthy")
	}
	if !health.Started {
		t.Error("expected started")
	}
	if len(health.Platforms) != 2 {
		t.Errorf("expected 2 platforms in health, got %d", len(health.Platforms))
	}
	if health.Uptime == 0 {
		t.Error("expected non-zero uptime")
	}
}

// --- Deduplication key tests ---

func TestDedupKey_PagerDuty(t *testing.T) {
	var receivedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"status":"success"}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	inc := testIncident()
	inc.DedupKey = "custom-dedup-key-123"
	results := mgr.SendIncident(context.Background(), inc)
	if results[0].Error != nil {
		t.Fatalf("unexpected error: %v", results[0].Error)
	}

	if receivedBody["dedup_key"] != "custom-dedup-key-123" {
		t.Errorf("expected dedup_key=custom-dedup-key-123, got %v", receivedBody["dedup_key"])
	}
}

// --- Multi-platform tests ---

func TestSendIncident_MultiplePlatforms(t *testing.T) {
	var pdBody, jiraBody, snBody map[string]interface{}

	pdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &pdBody)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"status":"success"}`)
	}))
	defer pdSrv.Close()

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &jiraBody)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":"1","key":"AEG-1"}`)
	}))
	defer jiraSrv.Close()

	snSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &snBody)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"result":{"sys_id":"sn1"}}`)
	}))
	defer snSrv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{Platform: PlatformPagerDuty, Enabled: true, Endpoint: pdSrv.URL, Auth: AuthConfig{Type: "api_key", APIKey: "key"}},
			{Platform: PlatformJira, Enabled: true, Endpoint: jiraSrv.URL, Auth: AuthConfig{Type: "api_key", APIKey: "token"}},
			{Platform: PlatformServiceNow, Enabled: true, Endpoint: snSrv.URL, Auth: AuthConfig{Type: "basic", Username: "u", Password: "p"}},
			{Platform: PlatformCustom, Enabled: false, Endpoint: "http://unused"},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	results := mgr.SendIncident(context.Background(), testIncident())
	if len(results) != 3 {
		t.Fatalf("expected 3 results (3 enabled), got %d", len(results))
	}

	// Verify all succeeded
	for i, r := range results {
		if r.Error != nil {
			t.Errorf("result %d: unexpected error: %v", i, r.Error)
		}
	}

	// Verify each platform received correct payload type
	if pdBody["routing_key"] == nil {
		t.Error("PagerDuty payload missing routing_key")
	}
	if jiraBody["fields"] == nil {
		t.Error("Jira payload missing fields")
	}
	if snBody["short_description"] == nil {
		t.Error("ServiceNow payload missing short_description")
	}
}

func TestSendIncidentToPlatform_NotConfigured(t *testing.T) {
	cfg := Config{
		Global:    GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error for unconfigured platform")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("expected 'not configured' error, got: %v", err)
	}
}

func TestSendIncidentToPlatform_Disabled(t *testing.T) {
	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  false,
				Endpoint: "http://unused",
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error for disabled platform")
	}
	if !strings.Contains(err.Error(), "not enabled") {
		t.Errorf("expected 'not enabled' error, got: %v", err)
	}
}

// --- Context cancellation test ---

func TestSendIncident_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := mgr.SendIncidentToPlatform(ctx, PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error due to context cancellation")
	}
}

// --- Incident creation tests ---

func TestIncidentCreation(t *testing.T) {
	inc := testIncident()

	if inc.Source != "aegisgate" {
		t.Errorf("expected source=aegisgate, got %s", inc.Source)
	}
	if inc.Framework != "cjis" {
		t.Errorf("expected framework=cjis, got %s", inc.Framework)
	}
	if inc.ControlID != "CJIS-AC-001" {
		t.Errorf("expected control_id=CJIS-AC-001, got %s", inc.ControlID)
	}
	if len(inc.AffectedSystems) != 2 {
		t.Errorf("expected 2 affected systems, got %d", len(inc.AffectedSystems))
	}
	if inc.Labels["env"] != "production" {
		t.Errorf("expected env=production, got %s", inc.Labels["env"])
	}
}

// --- All severities across platforms ---

func TestAllSeverities_AllPlatforms(t *testing.T) {
	severities := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}

	for _, sev := range severities {
		inc := testIncident()
		inc.Severity = sev
		_ = inc // Just verifying the type works correctly

		// Verify mappings don't panic
		_ = mapSeverityPagerDuty(sev)
		_ = mapSeverityJira(sev)
		_ = mapSeverityServiceNow(sev)
	}
}

// --- Basic auth encoding test ---

func TestBasicAuth(t *testing.T) {
	result := basicAuth("admin", "secret")
	expected := "YWRtaW46c2VjcmV0" // base64("admin:secret")
	if result != expected {
		t.Errorf("basicAuth: got %s, expected %s", result, expected)
	}
}

// --- Client error (4xx) should not retry ---

func TestNoRetry_ClientError(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"bad request"}`)
	}))
	defer srv.Close()

	cfg := Config{
		Global: GlobalConfig{MaxRetries: 3, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: srv.URL,
				Auth:     AuthConfig{Type: "api_key", APIKey: "key"},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error for 400 response")
	}

	// 4xx should not retry, so only 1 attempt
	if atomic.LoadInt32(&attempts) != 1 {
		t.Errorf("expected 1 attempt for client error (no retry), got %d", atomic.LoadInt32(&attempts))
	}
}

// --- PagerDuty missing API key ---

func TestPagerDuty_MissingAPIKey(t *testing.T) {
	cfg := Config{
		Global: GlobalConfig{MaxRetries: 1, RetryInterval: 10 * time.Millisecond},
		Platforms: []PlatformConfig{
			{
				Platform: PlatformPagerDuty,
				Enabled:  true,
				Endpoint: "http://unused",
				Auth:     AuthConfig{Type: "api_key", APIKey: ""},
			},
		},
	}
	mgr := NewManager(cfg, nil)
	mgr.Start()

	_, err := mgr.SendIncidentToPlatform(context.Background(), PlatformPagerDuty, testIncident())
	if err == nil {
		t.Error("expected error for missing API key")
	}
	if !strings.Contains(err.Error(), "missing routing key") {
		t.Errorf("expected 'missing routing key' error, got: %v", err)
	}
}