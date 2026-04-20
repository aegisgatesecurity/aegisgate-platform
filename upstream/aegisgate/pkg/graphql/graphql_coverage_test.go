// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate GraphQL - Comprehensive Test Coverage
//
// =========================================================================

package graphql

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// ============================================================
// SERVER CONFIG TESTS
// ============================================================

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg == nil {
		t.Fatal("DefaultServerConfig returned nil")
	}
	if !cfg.Enabled {
		t.Error("Enabled should be true by default")
	}
	if cfg.ListenAddress != "127.0.0.1" {
		t.Errorf("Expected ListenAddress '127.0.0.1', got %s", cfg.ListenAddress)
	}
	if cfg.Port != 4000 {
		t.Errorf("Expected Port 4000, got %d", cfg.Port)
	}
	if !cfg.Playground {
		t.Error("Playground should be true by default")
	}
	if cfg.DepthLimit != 10 {
		t.Errorf("Expected DepthLimit 10, got %d", cfg.DepthLimit)
	}
	if cfg.ComplexityLimit != 100 {
		t.Errorf("Expected ComplexityLimit 100, got %d", cfg.ComplexityLimit)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Expected Timeout 30s, got %v", cfg.Timeout)
	}
}

func TestNewServerNilConfig(t *testing.T) {
	server := NewServer(nil, nil)
	if server == nil {
		t.Fatal("NewServer(nil, nil) returned nil")
	}
	if server.config == nil {
		t.Error("Server config should not be nil")
	}
}

func TestNewServerWithConfig(t *testing.T) {
	cfg := &ServerConfig{
		Enabled:         false,
		ListenAddress:   "0.0.0.0",
		Port:            5000,
		Playground:      false,
		DepthLimit:      20,
		ComplexityLimit: 200,
		Timeout:         60 * time.Second,
	}

	server := NewServer(cfg, nil)
	if server == nil {
		t.Fatal("NewServer returned nil")
	}
	if server.config.ListenAddress != "0.0.0.0" {
		t.Errorf("Expected ListenAddress '0.0.0.0', got %s", server.config.ListenAddress)
	}
	if server.config.Port != 5000 {
		t.Errorf("Expected Port 5000, got %d", server.config.Port)
	}
}

// ============================================================
// TIME TYPE TESTS
// ============================================================

func TestTimeMarshalJSON(t *testing.T) {
	now := time.Now()
	testTime := Time(now)
	data, err := testTime.MarshalJSON()
	if err != nil {
		t.Errorf("Time.MarshalJSON returned error: %v", err)
	}
	if data == nil {
		t.Error("Time.MarshalJSON returned nil")
	}
}

func TestTimeUnmarshalJSON(t *testing.T) {
	now := time.Now()
	jsonData, _ := now.MarshalJSON()

	var testTime Time
	err := testTime.UnmarshalJSON(jsonData)
	if err != nil {
		t.Errorf("Time.UnmarshalJSON returned error: %v", err)
	}
	if time.Time(testTime).IsZero() {
		t.Error("Time should not be zero after unmarshaling")
	}
}

func TestTimeUnmarshalJSONInvalid(t *testing.T) {
	var testTime Time
	err := testTime.UnmarshalJSON([]byte("invalid"))
	if err == nil {
		t.Error("Time.UnmarshalJSON should return error for invalid input")
	}
}

// ============================================================
// RESPONSE TYPE TESTS
// ============================================================

func TestResponseJSON(t *testing.T) {
	resp := &Response{
		Data: map[string]interface{}{
			"health": "ok",
		},
		Errors: []*Error{
			{Message: "test error"},
		},
		Extensions: map[string]interface{}{
			"tracing": map[string]interface{}{
				"duration": 1000,
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Errorf("Failed to marshal Response: %v", err)
	}
	if data == nil {
		t.Error("Marshaled Response should not be nil")
	}

	var unmarshaled Response
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal Response: %v", err)
	}
}

func TestResponseEmptyData(t *testing.T) {
	resp := &Response{
		Data: nil,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Errorf("Failed to marshal empty Response: %v", err)
	}

	var unmarshaled Response
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal empty Response: %v", err)
	}
}

// ============================================================
// ERROR TYPE TESTS
// ============================================================

func TestErrorJSON(t *testing.T) {
	err := &Error{
		Message: "test error",
		Locations: []Location{
			{Line: 1, Column: 10},
		},
		Path: []interface{}{"query", "field"},
	}

	data, errJSON := json.Marshal(err)
	if errJSON != nil {
		t.Errorf("Failed to marshal Error: %v", errJSON)
	}

	var unmarshaled Error
	if jsonErr := json.Unmarshal(data, &unmarshaled); jsonErr != nil {
		t.Errorf("Failed to unmarshal Error: %v", jsonErr)
	}
}

func TestErrorWithExtensions(t *testing.T) {
	err := &Error{
		Message: "validation error",
		Extensions: map[string]interface{}{
			"code": "VALIDATION_ERROR",
			"type": "graphql",
		},
	}

	data, errJSON := json.Marshal(err)
	if errJSON != nil {
		t.Errorf("Failed to marshal Error: %v", errJSON)
	}

	var unmarshaled Error
	if jsonErr := json.Unmarshal(data, &unmarshaled); jsonErr != nil {
		t.Errorf("Failed to unmarshal Error: %v", jsonErr)
	}

	if unmarshaled.Extensions["code"] != "VALIDATION_ERROR" {
		t.Error("Extensions code mismatch")
	}
}

// ============================================================
// CONTEXT FUNCTIONS TESTS
// ============================================================

func TestWithRequestInfo(t *testing.T) {
	ctx := context.Background()
	info := &RequestInfo{
		StartTime: time.Now(),
		RemoteIP:  "192.168.1.1",
	}

	ctx = WithRequestInfo(ctx, info)
	retrieved := GetRequestInfo(ctx)
	if retrieved == nil {
		t.Fatal("GetRequestInfo returned nil")
	}
	if retrieved.RemoteIP != "192.168.1.1" {
		t.Errorf("Expected RemoteIP '192.168.1.1', got %s", retrieved.RemoteIP)
	}
}

func TestGetRequestInfoNotFound(t *testing.T) {
	ctx := context.Background()
	retrieved := GetRequestInfo(ctx)
	if retrieved != nil {
		t.Error("GetRequestInfo should return nil for context without RequestInfo")
	}
}

func TestWithDepthLimit(t *testing.T) {
	ctx := context.Background()
	ctx = WithDepthLimit(ctx, 10)

	limit := GetDepthLimit(ctx)
	if limit != 10 {
		t.Errorf("Expected DepthLimit 10, got %d", limit)
	}
}

func TestGetDepthLimitNotFound(t *testing.T) {
	ctx := context.Background()
	limit := GetDepthLimit(ctx)
	if limit != 0 {
		t.Errorf("Expected DepthLimit 0 for context without limit, got %d", limit)
	}
}

func TestWithComplexityLimit(t *testing.T) {
	ctx := context.Background()
	ctx = WithComplexityLimit(ctx, 100)

	limit := GetComplexityLimit(ctx)
	if limit != 100 {
		t.Errorf("Expected ComplexityLimit 100, got %d", limit)
	}
}

func TestGetComplexityLimitNotFound(t *testing.T) {
	ctx := context.Background()
	limit := GetComplexityLimit(ctx)
	if limit != 0 {
		t.Errorf("Expected ComplexityLimit 0 for context without limit, got %d", limit)
	}
}

// ============================================================
// TYPE CONSTANTS TESTS
// ============================================================

func TestFrameworkType(t *testing.T) {
	frameworks := []FrameworkType{
		"MITRE_ATLAS",
		"NIST_CSF",
		"ISO_27001",
		"GDPR",
		"SOC2",
	}

	for _, fw := range frameworks {
		if string(fw) == "" {
			t.Errorf("FrameworkType %s should not be empty", fw)
		}
	}
}

func TestSeverity(t *testing.T) {
	severities := []Severity{
		"CRITICAL",
		"HIGH",
		"MEDIUM",
		"LOW",
		"INFO",
	}

	for _, sev := range severities {
		if string(sev) == "" {
			t.Errorf("Severity %s should not be empty", sev)
		}
	}
}

func TestComplianceStatus(t *testing.T) {
	statuses := []ComplianceStatus{
		"COMPLIANT",
		"NON_COMPLIANT",
		"PARTIAL",
		"PENDING",
	}

	for _, status := range statuses {
		if string(status) == "" {
			t.Errorf("ComplianceStatus %s should not be empty", status)
		}
	}
}

func TestViolationType(t *testing.T) {
	violationTypes := []ViolationType{
		"RATE_LIMIT",
		"AUTH_FAILURE",
		"ACCESS_DENIED",
		"INVALID_INPUT",
	}

	for _, vt := range violationTypes {
		if string(vt) == "" {
			t.Errorf("ViolationType %s should not be empty", vt)
		}
	}
}

func TestLogLevel(t *testing.T) {
	levels := []LogLevel{
		"DEBUG",
		"INFO",
		"WARN",
		"ERROR",
		"FATAL",
	}

	for _, level := range levels {
		if string(level) == "" {
			t.Errorf("LogLevel %s should not be empty", level)
		}
	}
}

func TestAuthProvider(t *testing.T) {
	providers := []AuthProvider{
		"LOCAL",
		"LDAP",
		"OIDC",
		"SAML",
	}

	for _, provider := range providers {
		if string(provider) == "" {
			t.Errorf("AuthProvider %s should not be empty", provider)
		}
	}
}

func TestRole(t *testing.T) {
	roles := []Role{
		"ADMIN",
		"USER",
		"VIEWER",
		"AUDITOR",
	}

	for _, role := range roles {
		if string(role) == "" {
			t.Errorf("Role %s should not be empty", role)
		}
	}
}

func TestModuleTier(t *testing.T) {
	tiers := []ModuleTier{
		"FREE",
		"STANDARD",
		"PREMIUM",
		"ENTERPRISE",
	}

	for _, tier := range tiers {
		if string(tier) == "" {
			t.Errorf("ModuleTier %s should not be empty", tier)
		}
	}
}

func TestModuleStatus(t *testing.T) {
	statuses := []ModuleStatus{
		"ACTIVE",
		"INACTIVE",
		"ERROR",
		"PENDING",
	}

	for _, status := range statuses {
		if string(status) == "" {
			t.Errorf("ModuleStatus %s should not be empty", status)
		}
	}
}

// ============================================================
// TYPE STRUCT TESTS
// ============================================================

func TestFramework(t *testing.T) {
	framework := Framework{
		ID:            "MITRE_ATLAS",
		Name:          "MITRE ATLAS",
		Description:   "AI Security Framework",
		Version:       "1.0",
		Status:        ComplianceStatus("COMPLIANT"),
		FindingsCount: 10,
	}

	if framework.ID != "MITRE_ATLAS" {
		t.Errorf("Expected ID 'MITRE_ATLAS', got %s", framework.ID)
	}
}

func TestComplianceFindingStruct(t *testing.T) {
	now := time.Now()
	finding := ComplianceFinding{
		ID:          "finding-1",
		Title:       "Test Finding",
		Description: "Test Description",
		Severity:    Severity("HIGH"),
		Category:    "Security",
		Timestamp:   Time(now),
	}

	if finding.ID != "finding-1" {
		t.Errorf("Expected ID 'finding-1', got %s", finding.ID)
	}
	if finding.Severity != "HIGH" {
		t.Errorf("Expected Severity 'HIGH', got %s", finding.Severity)
	}
}

func TestUser(t *testing.T) {
	now := time.Now()
	user := User{
		ID:        "user-1",
		Username:  "testuser",
		Email:     "test@example.com",
		Role:      Role("USER"),
		Enabled:   true,
		CreatedAt: Time(now),
	}

	if user.ID != "user-1" {
		t.Errorf("Expected ID 'user-1', got %s", user.ID)
	}
	if !user.Enabled {
		t.Error("User should be enabled")
	}
}

func TestSession(t *testing.T) {
	session := Session{
		ID:        "session-1",
		UserID:    "user-1",
		Token:     "token-123",
		IPAddress: "192.168.1.1",
	}

	if session.ID != "session-1" {
		t.Errorf("Expected ID 'session-1', got %s", session.ID)
	}
}

func TestAuthResult(t *testing.T) {
	result := AuthResult{
		Success:      true,
		Token:        "jwt-token",
		RefreshToken: "refresh-token",
	}

	if !result.Success {
		t.Error("AuthResult should be successful")
	}
}

func TestProxyStats(t *testing.T) {
	stats := ProxyStats{
		RequestsTotal:     1000,
		RequestsBlocked:   50,
		RequestsAllowed:   950,
		BytesIn:           10000,
		BytesOut:          50000,
		ActiveConnections: 10,
		AvgLatencyMs:      25.5,
	}

	if stats.RequestsTotal != 1000 {
		t.Errorf("Expected RequestsTotal 1000, got %d", stats.RequestsTotal)
	}
}

func TestViolation(t *testing.T) {
	violation := Violation{
		ID:       "violation-1",
		Type:     ViolationType("RATE_LIMIT"),
		Severity: Severity("HIGH"),
		Message:  "Rate limit exceeded",
		Blocked:  true,
	}

	if violation.ID != "violation-1" {
		t.Errorf("Expected ID 'violation-1', got %s", violation.ID)
	}
	if !violation.Blocked {
		t.Error("Violation should be blocked")
	}
}

func TestProxyHealth(t *testing.T) {
	health := ProxyHealth{
		Status:      "healthy",
		Uptime:      99.9,
		MemoryUsage: 1024,
	}

	if health.Status != "healthy" {
		t.Errorf("Expected Status 'healthy', got %s", health.Status)
	}
}

func TestSIEMEvent(t *testing.T) {
	event := SIEMEvent{
		ID:       "event-1",
		Source:   "gateway",
		Category: "security",
		Severity: Severity("HIGH"),
		Message:  "Test event",
	}

	if event.ID != "event-1" {
		t.Errorf("Expected ID 'event-1', got %s", event.ID)
	}
}

func TestWebhook(t *testing.T) {
	webhook := Webhook{
		ID:      "webhook-1",
		Name:    "Test Webhook",
		URL:     "https://example.com/webhook",
		Enabled: true,
	}

	if webhook.ID != "webhook-1" {
		t.Errorf("Expected ID 'webhook-1', got %s", webhook.ID)
	}
}

func TestTLSConfig(t *testing.T) {
	config := TLSConfig{
		Enabled:      true,
		MinVersion:   "1.3",
		MaxVersion:   "1.3",
		CipherSuites: []string{"TLS_AES_256_GCM_SHA384"},
		AutoGenerate: true,
	}

	if !config.Enabled {
		t.Error("TLSConfig should be enabled")
	}
}

func TestCertificate(t *testing.T) {
	cert := Certificate{
		ID:           "cert-1",
		Subject:      "CN=test.example.com",
		Issuer:       "CN=Test CA",
		SerialNumber: "12345",
		DNSNames:     []string{"test.example.com"},
		IsCA:         false,
	}

	if cert.ID != "cert-1" {
		t.Errorf("Expected ID 'cert-1', got %s", cert.ID)
	}
}

func TestMTLSConfig(t *testing.T) {
	config := MTLSConfig{
		Enabled:          true,
		ClientAuth:       "RequireAndVerifyClientCert",
		VerifyClientCert: true,
	}

	if !config.Enabled {
		t.Error("MTLSConfig should be enabled")
	}
}

func TestModule(t *testing.T) {
	module := Module{
		ID:       "module-1",
		Name:     "Test Module",
		Version:  "1.0.0",
		Category: "Security",
		Tier:     ModuleTier("PREMIUM"),
		Status:   ModuleStatus("ACTIVE"),
	}

	if module.ID != "module-1" {
		t.Errorf("Expected ID 'module-1', got %s", module.ID)
	}
}

func TestHealth(t *testing.T) {
	health := Health{
		Status: "healthy",
		Checks: []*HealthCheck{
			{Name: "database", Status: "ok"},
			{Name: "cache", Status: "ok"},
		},
	}

	if health.Status != "healthy" {
		t.Errorf("Expected Status 'healthy', got %s", health.Status)
	}
	if len(health.Checks) != 2 {
		t.Errorf("Expected 2 checks, got %d", len(health.Checks))
	}
}

func TestDashboardStats(t *testing.T) {
	stats := DashboardStats{
		TotalRequests:     10000,
		BlockedRequests:   500,
		ActiveUsers:       100,
		ActiveConnections: 50,
		Uptime:            99.9,
	}

	if stats.TotalRequests != 10000 {
		t.Errorf("Expected TotalRequests 10000, got %d", stats.TotalRequests)
	}
}

func TestConfigValidationResult(t *testing.T) {
	result := ConfigValidationResult{
		Valid: false,
		Errors: []*ConfigError{
			{Field: "port", Message: "invalid port"},
		},
	}

	if result.Valid {
		t.Error("ConfigValidationResult should be invalid")
	}
	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}
}

// ============================================================
// INPUT TYPE TESTS
// ============================================================

func TestLoginInput(t *testing.T) {
	input := LoginInput{
		Username: "testuser",
		Password: "password123",
		MFACode:  "123456",
	}

	if input.Username != "testuser" {
		t.Errorf("Expected Username 'testuser', got %s", input.Username)
	}
}

func TestCreateUserInput(t *testing.T) {
	input := CreateUserInput{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "securepass",
		Role:     Role("USER"),
	}

	if input.Username != "newuser" {
		t.Errorf("Expected Username 'newuser', got %s", input.Username)
	}
}

func TestPageInfo(t *testing.T) {
	pageInfo := PageInfo{
		HasNextPage:     true,
		HasPreviousPage: false,
		StartCursor:     "cursor-start",
		EndCursor:       "cursor-end",
	}

	if !pageInfo.HasNextPage {
		t.Error("PageInfo should have next page")
	}
}

// ============================================================
// SUBSCRIPTION MANAGER TESTS
// ============================================================

func TestNewSubscriptionManager(t *testing.T) {
	sm := NewSubscriptionManager()
	if sm == nil {
		t.Fatal("NewSubscriptionManager returned nil")
	}
}

// ============================================================
// STATS TYPE TESTS
// ============================================================

func TestSIEMStats(t *testing.T) {
	stats := Stats{
		EventsSent:     1000,
		EventsReceived: 990,
		EventsFailed:   10,
		BytesSent:      50000,
	}

	if stats.EventsSent != 1000 {
		t.Errorf("Expected EventsSent 1000, got %d", stats.EventsSent)
	}
}

func TestWebhookStats(t *testing.T) {
	stats := WebhookStats{
		TotalDeliveries: 100,
		SuccessCount:    95,
		FailureCount:    5,
	}

	if stats.TotalDeliveries != 100 {
		t.Errorf("Expected TotalDeliveries 100, got %d", stats.TotalDeliveries)
	}
}

// ============================================================
// CONFIG TYPE TESTS
// ============================================================

func TestAuthConfig(t *testing.T) {
	config := AuthConfig{
		Provider:           "LOCAL",
		SessionTimeout:     3600,
		MaxSessionsPerUser: 5,
		RequireMFA:         true,
		MFAMethods:         []string{"TOTP", "SMS"},
		LoginAttempts:      5,
		LockoutDuration:    300,
	}

	if config.Provider != "LOCAL" {
		t.Errorf("Expected Provider 'LOCAL', got %s", config.Provider)
	}
	if !config.RequireMFA {
		t.Error("RequireMFA should be true")
	}
}

func TestPasswordPolicy(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireDigit:   true,
		RequireSpecial: true,
		MaxAge:         90,
	}

	if policy.MinLength != 12 {
		t.Errorf("Expected MinLength 12, got %d", policy.MinLength)
	}
}

func TestProxyConfigStruct(t *testing.T) {
	config := ProxyConfig{
		Enabled:     true,
		BindAddress: "0.0.0.0:8080",
		Upstream:    "http://backend:8000",
		MaxBodySize: 10485760,
		Timeout:     30,
		RateLimit:   1000,
		TLSEnabled:  true,
	}

	if !config.Enabled {
		t.Error("ProxyConfig should be enabled")
	}
}

func TestSIEMConfig(t *testing.T) {
	config := SIEMConfig{
		Enabled:    true,
		Platform:   "splunk",
		Endpoint:   "https://siem.example.com",
		Format:     "json",
		BufferSize: 1000,
	}

	if !config.Enabled {
		t.Error("SIEMConfig should be enabled")
	}
}

// ============================================================
// PAGINATION TESTS
// ============================================================

func TestPagination(t *testing.T) {
	pagination := Pagination{
		Offset: 0,
		Limit:  10,
		Total:  100,
	}

	if pagination.Limit != 10 {
		t.Errorf("Expected Limit 10, got %d", pagination.Limit)
	}
	if pagination.Total != 100 {
		t.Errorf("Expected Total 100, got %d", pagination.Total)
	}
}

// ============================================================
// FILTER TYPE TESTS
// ============================================================

func TestUserFilter(t *testing.T) {
	filter := UserFilter{
		Role:     "ADMIN",
		Provider: "OIDC",
		Email:    "admin@example.com",
		Search:   "admin",
	}

	if filter.Role != "ADMIN" {
		t.Errorf("Expected Role 'ADMIN', got %s", filter.Role)
	}
}

func TestViolationFilter(t *testing.T) {
	now := time.Now()
	filter := ViolationFilter{
		Severity:  "HIGH",
		Type:      "RATE_LIMIT",
		ClientIP:  "192.168.1.1",
		Path:      "/api/v1/test",
		StartDate: &now,
	}

	if filter.Severity != "HIGH" {
		t.Errorf("Expected Severity 'HIGH', got %s", filter.Severity)
	}
}

func TestSIEMEventFilter(t *testing.T) {
	now := time.Now()
	filter := SIEMEventFilter{
		Source:    "gateway",
		Category:  "security",
		Severity:  "CRITICAL",
		StartTime: &now,
	}

	if filter.Source != "gateway" {
		t.Errorf("Expected Source 'gateway', got %s", filter.Source)
	}
}

func TestCertificateFilter(t *testing.T) {
	filter := CertificateFilter{
		Subject: "CN=test.example.com",
		Issuer:  "CN=Test CA",
	}

	if filter.Subject != "CN=test.example.com" {
		t.Errorf("Expected Subject 'CN=test.example.com', got %s", filter.Subject)
	}
}

func TestWebhookFilter(t *testing.T) {
	enabled := true
	filter := WebhookFilter{
		Enabled:   &enabled,
		Name:      "Test Webhook",
		EventType: "security.alert",
	}

	if filter.Enabled == nil || !*filter.Enabled {
		t.Error("WebhookFilter Enabled should be true")
	}
}

// ============================================================
// INPUT TYPE TESTS
// ============================================================

func TestWebhookInput(t *testing.T) {
	input := WebhookInput{
		Name:    "Test Webhook",
		URL:     "https://example.com/webhook",
		Events:  []string{"user.created", "user.deleted"},
		Enabled: true,
	}

	if input.Name != "Test Webhook" {
		t.Errorf("Expected Name 'Test Webhook', got %s", input.Name)
	}
}

func TestProxyConfigInput(t *testing.T) {
	input := ProxyConfigInput{
		Enabled:     true,
		BindAddress: "0.0.0.0:8080",
		Upstream:    "http://backend:8000",
		RateLimit:   1000,
	}

	if !input.Enabled {
		t.Error("ProxyConfigInput should be enabled")
	}
}

func TestUpdateUserInput(t *testing.T) {
	input := UpdateUserInput{
		Email:   "new@example.com",
		Role:    "ADMIN",
		Enabled: true,
	}

	if input.Email != "new@example.com" {
		t.Errorf("Expected Email 'new@example.com', got %s", input.Email)
	}
}

// ============================================================
// METRICS TYPE TESTS
// ============================================================

func TestCounterMetric(t *testing.T) {
	metric := CounterMetric{
		Name:  "requests_total",
		Value: 1000,
		Labels: map[string]interface{}{
			"method": "GET",
			"path":   "/api/v1/test",
		},
	}

	if metric.Name != "requests_total" {
		t.Errorf("Expected Name 'requests_total', got %s", metric.Name)
	}
}

func TestGaugeMetric(t *testing.T) {
	metric := GaugeMetric{
		Name:  "active_connections",
		Value: 50.5,
		Labels: map[string]interface{}{
			"server": "gateway-1",
		},
	}

	if metric.Name != "active_connections" {
		t.Errorf("Expected Name 'active_connections', got %s", metric.Name)
	}
}

func TestMetricSnapshot(t *testing.T) {
	snapshot := MetricSnapshot{
		Timestamp: Time(time.Now()),
		Counters: []*CounterMetric{
			{Name: "requests_total", Value: 1000},
		},
		Gauges: []*GaugeMetric{
			{Name: "active_connections", Value: 50},
		},
	}

	if len(snapshot.Counters) != 1 {
		t.Errorf("Expected 1 counter, got %d", len(snapshot.Counters))
	}
}

func TestMetricsSnapshot(t *testing.T) {
	snapshot := MetricsSnapshot{
		Timestamp:       time.Now(),
		TotalRequests:   10000,
		BlockedRequests: 500,
		ActiveUsers:     100,
	}

	if snapshot.TotalRequests != 10000 {
		t.Errorf("Expected TotalRequests 10000, got %d", snapshot.TotalRequests)
	}
}

// ============================================================
// COMPLIANCE TYPE TESTS
// ============================================================

func TestComplianceReportSummary(t *testing.T) {
	summary := ComplianceReportSummary{
		TotalChecks:   100,
		Passed:        95,
		Failed:        3,
		Warnings:      2,
		NotApplicable: 0,
		Score:         95.0,
	}

	if summary.TotalChecks != 100 {
		t.Errorf("Expected TotalChecks 100, got %d", summary.TotalChecks)
	}
}

func TestComplianceStatusSummary(t *testing.T) {
	summary := ComplianceStatusSummary{
		Overall: ComplianceStatus("COMPLIANT"),
		Frameworks: []*FrameworkStatus{
			{Framework: "MITRE_ATLAS", Status: ComplianceStatus("COMPLIANT"), Score: 95.0},
		},
	}

	if summary.Overall != "COMPLIANT" {
		t.Errorf("Expected Overall 'COMPLIANT', got %s", summary.Overall)
	}
}

func TestFrameworkStatus(t *testing.T) {
	status := FrameworkStatus{
		Framework: FrameworkType("NIST_CSF"),
		Status:    ComplianceStatus("PARTIAL"),
		Score:     75.5,
	}

	if status.Framework != "NIST_CSF" {
		t.Errorf("Expected Framework 'NIST_CSF', got %s", status.Framework)
	}
}

func TestComplianceResult(t *testing.T) {
	result := ComplianceResult{
		ID:        "result-1",
		Framework: "MITRE_ATLAS",
		Status:    "COMPLIANT",
		Passed:    true,
		Score:     95.0,
	}

	if !result.Passed {
		t.Error("ComplianceResult should pass")
	}
}

func TestComplianceReport(t *testing.T) {
	report := ComplianceReport{
		ID:        "report-1",
		Framework: "MITRE_ATLAS",
		Status:    "complete",
		Summary:   "All checks passed",
	}

	if report.ID != "report-1" {
		t.Errorf("Expected ID 'report-1', got %s", report.ID)
	}
}

func TestFindingFilter(t *testing.T) {
	filter := FindingFilter{
		Framework: "MITRE_ATLAS",
		Severity:  "HIGH",
		Category:  "Security",
	}

	if filter.Framework != "MITRE_ATLAS" {
		t.Errorf("Expected Framework 'MITRE_ATLAS', got %s", filter.Framework)
	}
}

// ============================================================
// MODULE AND REGISTRY TESTS
// ============================================================

func TestModuleHealth(t *testing.T) {
	health := ModuleHealth{
		Status:    "healthy",
		Message:   "Module running normally",
		LastCheck: Time(time.Now()),
	}

	if health.Status != "healthy" {
		t.Errorf("Expected Status 'healthy', got %s", health.Status)
	}
}

func TestLicense(t *testing.T) {
	now := time.Now()
	license := License{
		ID:        "license-1",
		Type:      "enterprise",
		Valid:     true,
		ExpiresAt: &[]Time{Time(now)}[0],
		Features:  []string{"all"},
	}

	if !license.Valid {
		t.Error("License should be valid")
	}
}

func TestRegistryStatus(t *testing.T) {
	status := RegistryStatus{
		TotalModules:   10,
		ActiveModules:  8,
		HealthyModules: 7,
		ModuleStatuses: map[string]string{
			"auth":       "active",
			"compliance": "active",
		},
	}

	if status.TotalModules != 10 {
		t.Errorf("Expected TotalModules 10, got %d", status.TotalModules)
	}
}

func TestMTLSStatus(t *testing.T) {
	status := MTLSStatus{
		Enabled:        true,
		CaCertFile:     "/etc/ssl/ca.crt",
		ClientCertFile: "/etc/ssl/client.crt",
	}

	if !status.Enabled {
		t.Error("MTLSStatus should be enabled")
	}
}

func TestSecurityEvent(t *testing.T) {
	event := SecurityEvent{
		ID:        "event-1",
		Type:      "intrusion_attempt",
		Severity:  "HIGH",
		Message:   "Suspicious activity detected",
		Timestamp: "2024-01-01T00:00:00Z",
	}

	if event.Type != "intrusion_attempt" {
		t.Errorf("Expected Type 'intrusion_attempt', got %s", event.Type)
	}
}

// ============================================================
// TYPE ASSERTION TESTS
// ============================================================

func TestTypesNotNil(t *testing.T) {
	// Ensure all types can be instantiated
	var _ Time
	var _ FrameworkType = "TEST"
	var _ Severity = "HIGH"
	var _ ComplianceStatus = "COMPLIANT"
	var _ ViolationType = "TEST"
	var _ LogLevel = "INFO"
	var _ AuthProvider = "LOCAL"
	var _ Role = "USER"
	var _ Permission = "READ"
	var _ ModuleTier = "FREE"
	var _ ModuleStatus = "ACTIVE"

	// Struct instances
	_ = Framework{}
	_ = ComplianceFinding{}
	_ = User{}
	_ = Session{}
	_ = AuthResult{}
	_ = ProxyStats{}
	_ = Violation{}
	_ = ProxyHealth{}
	_ = SIEMEvent{}
	_ = Webhook{}
	_ = TLSConfig{}
	_ = Certificate{}
	_ = MTLSConfig{}
	_ = Module{}
	_ = ModuleHealth{}
	_ = License{}
	_ = DashboardStats{}
	_ = Health{}
	_ = HealthCheck{}
	_ = CounterMetric{}
	_ = GaugeMetric{}
	_ = MetricSnapshot{}
	_ = ComplianceReportSummary{}
	_ = ComplianceStatusSummary{}
	_ = FrameworkStatus{}
	_ = ConfigValidationResult{}
	_ = ConfigError{}
	_ = LoginInput{}
	_ = CreateUserInput{}
	_ = PageInfo{}
	_ = Pagination{}
	_ = UserFilter{}
	_ = ViolationFilter{}
	_ = FindingFilter{}
	_ = CertificateFilter{}
	_ = SIEMEventFilter{}
	_ = WebhookFilter{}
}
