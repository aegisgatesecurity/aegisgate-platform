// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Service Tests
// =========================================================================

package grpc

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// ====================================================================
// Mock Backends for Testing
// ====================================================================

type mockAuthBackend struct{}

func (m *mockAuthBackend) Login(_ context.Context, username, password string) (string, int64, error) {
	return "mock_token_" + username, time.Now().Add(24 * time.Hour).Unix(), nil
}
func (m *mockAuthBackend) Logout(_ context.Context, token string) error              { return nil }
func (m *mockAuthBackend) ValidateToken(_ context.Context, token string) (bool, string, int64, error) {
	if token == "valid_token" {
		return true, "user123", time.Now().Add(24 * time.Hour).Unix(), nil
	}
	return false, "", 0, nil
}
func (m *mockAuthBackend) GetUser(_ context.Context, userID string) (*AuthUserInfo, error) {
	return &AuthUserInfo{ID: userID, Username: userID, Email: userID + "@test.com", Role: "admin", Enabled: true, CreatedAt: 1000}, nil
}
func (m *mockAuthBackend) ListUsers(_ context.Context) ([]*AuthUserInfo, error) {
	return []*AuthUserInfo{
		{ID: "u1", Username: "admin", Email: "admin@test.com", Role: "admin", Enabled: true, CreatedAt: 1000},
		{ID: "u2", Username: "viewer", Email: "viewer@test.com", Role: "viewer", Enabled: true, CreatedAt: 2000},
	}, nil
}
func (m *mockAuthBackend) CreateUser(_ context.Context, username, email, password, role string) (*AuthUserInfo, error) {
	return &AuthUserInfo{ID: username, Username: username, Email: email, Role: role, Enabled: true, CreatedAt: 3000}, nil
}
func (m *mockAuthBackend) UpdateUser(_ context.Context, userID, username, email, role string, enabled bool) (*AuthUserInfo, error) {
	return &AuthUserInfo{ID: userID, Username: username, Email: email, Role: role, Enabled: enabled, CreatedAt: 4000}, nil
}
func (m *mockAuthBackend) DeleteUser(_ context.Context, userID string) error { return nil }
func (m *mockAuthBackend) GetSessions(_ context.Context) ([]*AuthSessionInfo, error) {
	return []*AuthSessionInfo{
		{ID: "s1", UserID: "u1", Token: "t1", ExpiresAt: 9000, CreatedAt: 8000, LastActivity: 8500, IPAddress: "127.0.0.1"},
	}, nil
}
func (m *mockAuthBackend) GetAuthConfig(_ context.Context) (*AuthConfig, error) {
	return &AuthConfig{SessionDurationSec: 86400, MaxSessions: 5, EnableMFA: false, LoginAttempts: 5, LockoutDurationSec: 300, PasswordMinLength: 8}, nil
}

type mockComplianceBackend struct{}

func (m *mockComplianceBackend) GetFrameworks(_ context.Context) ([]*ComplianceFrameworkInfo, error) {
	return []*ComplianceFrameworkInfo{
		{ID: "fedramp", Name: "FedRAMP", Description: "Federal Risk and Authorization Management Program"},
		{ID: "soc2", Name: "SOC 2", Description: "Service Organization Control 2"},
	}, nil
}
func (m *mockComplianceBackend) GetStatus(_ context.Context) (*ComplianceOverallStatus, error) {
	return &ComplianceOverallStatus{
		OverallStatus: ComplianceStatusPass,
		Frameworks: []*FrameworkStatusInfo{
			{Framework: "fedramp", Status: ComplianceStatusPass, Score: 95.5},
			{Framework: "soc2", Status: ComplianceStatusPass, Score: 98.0},
		},
	}, nil
}
func (m *mockComplianceBackend) RunCheck(_ context.Context, framework string) (*ComplianceCheckResult, error) {
	return &ComplianceCheckResult{
		ID: "check_" + framework, Framework: framework, Status: ComplianceStatusPass,
		Summary: &ComplianceSummary{TotalChecks: 100, Passed: 95, Failed: 3, Warnings: 2, Score: 95.0},
	}, nil
}
func (m *mockComplianceBackend) GetFindings(_ context.Context) ([]*ComplianceFindingInfo, error) {
	return []*ComplianceFindingInfo{
		{ID: "f1", Title: "Finding 1", Description: "Test finding", Severity: FindingSeverityMedium, Category: "security", Framework: "fedramp", Timestamp: 1000},
	}, nil
}
func (m *mockComplianceBackend) GenerateReport(_ context.Context, framework string) (*ComplianceReportResult, error) {
	return &ComplianceReportResult{
		ID: "report_" + framework, Framework: framework, Timestamp: 2000, Status: ComplianceStatusPass,
		Summary: &ComplianceSummary{TotalChecks: 100, Passed: 95, Failed: 3, Score: 95.0},
	}, nil
}

type mockProxyBackend struct {
	enabled bool
}

func (m *mockProxyBackend) GetStats(_ context.Context) (*ProxyStatsInfo, error) {
	return &ProxyStatsInfo{RequestsTotal: 1000, RequestsBlocked: 50, RequestsAllowed: 950, BytesIn: 10000, BytesOut: 20000, ActiveConnections: 5, AvgLatencyMs: 12.5, P99LatencyMs: 45.0, Errors: 2}, nil
}
func (m *mockProxyBackend) GetHealth(_ context.Context) (*ProxyHealthInfo, error) {
	return &ProxyHealthInfo{Status: "healthy", Uptime: 86400.0, MemoryUsage: 50000000, Goroutines: 42}, nil
}
func (m *mockProxyBackend) GetConfig(_ context.Context) (*ProxyConfigInfo, error) {
	return &ProxyConfigInfo{Enabled: true, Host: "0.0.0.0", Port: 8080, TLSEnabled: true, RateLimit: 100, RateLimitBurst: 150, CORSEnabled: true, CORSOrigins: []string{"*"}}, nil
}
func (m *mockProxyBackend) IsEnabled(_ context.Context) (bool, error) { return m.enabled, nil }
func (m *mockProxyBackend) Enable(_ context.Context) error              { m.enabled = true; return nil }
func (m *mockProxyBackend) Disable(_ context.Context) error              { m.enabled = false; return nil }
func (m *mockProxyBackend) GetViolations(_ context.Context, _ []ViolationSeverity, _ int32) ([]*ViolationInfo, error) {
	return []*ViolationInfo{{ID: "v1", Type: ViolationTypeSQLInjection, Severity: ViolationSeverityCritical, Message: "SQL injection attempt", ClientIP: "10.0.0.1", Method: "POST", Path: "/api/data", Blocked: true, Timestamp: 1000}}, nil
}
func (m *mockProxyBackend) ClearViolations(_ context.Context) error { return nil }

type mockSIEMBackend struct{}

func (m *mockSIEMBackend) GetConfig(_ context.Context) (*SIEMConfigInfo, error) {
	return &SIEMConfigInfo{Enabled: true, BatchSize: 100, BatchInterval: 30, RetryAttempts: 3, RetryInterval: 5}, nil
}
func (m *mockSIEMBackend) GetStats(_ context.Context) (*SIEMStatsInfo, error) {
	return &SIEMStatsInfo{EventsSent: 5000, EventsDropped: 10, EventsQueued: 50, LastSendTime: 1000, LastError: ""}, nil
}
func (m *mockSIEMBackend) GetEvents(_ context.Context, limit int32) ([]*SIEMEventInfo, error) {
	return []*SIEMEventInfo{{ID: "e1", Timestamp: 1000, Source: "proxy", Category: "security", Type: "violation", Severity: EventSeverityHigh, Message: "test event", Entity: "10.0.0.1"}}, nil
}
func (m *mockSIEMBackend) SendEvent(_ context.Context, source, category, eventType string, severity EventSeverity, message, entity string) error {
	return nil
}
func (m *mockSIEMBackend) TestConnection(_ context.Context, platform string) (bool, string, error) {
	return true, "Connection test successful", nil
}

type mockWebhookBackend struct{}

func (m *mockWebhookBackend) ListWebhooks(_ context.Context) ([]*WebhookDetail, error) {
	return []*WebhookDetail{{ID: "wh1", Name: "alert-hook", URL: "https://example.com/webhook", Events: []string{"violation", "alert"}, Enabled: true}}, nil
}
func (m *mockWebhookBackend) GetWebhook(_ context.Context, id string) (*WebhookDetail, error) {
	return &WebhookDetail{ID: id, Name: "alert-hook", URL: "https://example.com/webhook", Events: []string{"violation"}, Enabled: true}, nil
}
func (m *mockWebhookBackend) CreateWebhook(_ context.Context, name, url string, events []string, enabled bool) (*WebhookDetail, error) {
	return &WebhookDetail{ID: "wh_new", Name: name, URL: url, Events: events, Enabled: enabled}, nil
}
func (m *mockWebhookBackend) UpdateWebhook(_ context.Context, id, name, url string, events []string, enabled bool) (*WebhookDetail, error) {
	return &WebhookDetail{ID: id, Name: name, URL: url, Events: events, Enabled: enabled}, nil
}
func (m *mockWebhookBackend) DeleteWebhook(_ context.Context, id string) error  { return nil }
func (m *mockWebhookBackend) EnableWebhook(_ context.Context, id string) (*WebhookDetail, error) {
	return &WebhookDetail{ID: id, Name: "hook", URL: "https://example.com", Events: []string{"*"}, Enabled: true}, nil
}
func (m *mockWebhookBackend) DisableWebhook(_ context.Context, id string) (*WebhookDetail, error) {
	return &WebhookDetail{ID: id, Name: "hook", URL: "https://example.com", Events: []string{"*"}, Enabled: false}, nil
}
func (m *mockWebhookBackend) TestWebhook(_ context.Context, id string) (bool, string, error) {
	return true, "Webhook test successful", nil
}
func (m *mockWebhookBackend) GetStats(_ context.Context) (*WebhookStatsInfo, error) {
	return &WebhookStatsInfo{TotalWebhooks: 5, ActiveWebhooks: 3, DeliveriesTotal: 100, DeliveriesSuccess: 95, DeliveriesFailed: 5}, nil
}

type mockMetricsBackend struct{}

func (m *mockMetricsBackend) GetHealth(_ context.Context) (*HealthInfo, error) {
	return &HealthInfo{Status: "healthy", Checks: []*HealthCheck{{Name: "system", Status: "healthy", Message: "All systems operational"}}}, nil
}
func (m *mockMetricsBackend) GetStats(_ context.Context) (*SystemStatsInfo, error) {
	return &SystemStatsInfo{TotalRequests: 10000, BlockedRequests: 500, ActiveUsers: 50, ActiveConnections: 25, Uptime: 86400.0}, nil
}
func (m *mockMetricsBackend) GetUptime(_ context.Context) (float64, error) { return 86400.0, nil }

type mockTLSBackend struct{}

func (m *mockTLSBackend) GetConfig(_ context.Context) (*TLSConfigInfo, error) {
	return &TLSConfigInfo{Enabled: true, CertFile: "/etc/aegisgate/cert.pem", KeyFile: "/etc/aegisgate/key.pem", AutoGenerate: true, MinVersion: "1.3"}, nil
}
func (m *mockTLSBackend) GetCertificates(_ context.Context) ([]*CertificateDetail, error) {
	return []*CertificateDetail{{Subject: "aegisgate.local", Issuer: "AegisGate CA", NotBefore: 1000, NotAfter: 2000, Fingerprint: "sha256:abc123"}}, nil
}
func (m *mockTLSBackend) GenerateCertificate(_ context.Context, commonName, organization string, validityDays int32) (*CertificateDetail, error) {
	return &CertificateDetail{Subject: commonName, Issuer: organization + " CA", NotBefore: 1000, NotAfter: 2000, Fingerprint: "sha256:new123"}, nil
}
func (m *mockTLSBackend) GetMTLSConfig(_ context.Context) (*MTLSConfigInfo, error) {
	return &MTLSConfigInfo{Enabled: false, CACertFile: "/etc/aegisgate/ca.pem", ClientCertFile: "/etc/aegisgate/client.pem", ClientKeyFile: "/etc/aegisgate/client-key.pem"}, nil
}

// ====================================================================
// Server Lifecycle Tests
// ====================================================================

func TestNewGRPCServer(t *testing.T) {
	logger := slog.Default()
	deps := Dependencies{
		Auth:       &mockAuthBackend{},
		Compliance: &mockComplianceBackend{},
		Proxy:      &mockProxyBackend{},
		SIEM:       &mockSIEMBackend{},
		Webhook:    &mockWebhookBackend{},
		Metrics:    &mockMetricsBackend{},
		TLS:        &mockTLSBackend{},
	}

	server, err := NewGRPCServer(deps, logger)
	if err != nil {
		t.Fatalf("NewGRPCServer returned error: %v", err)
	}
	if server == nil {
		t.Fatal("NewGRPCServer returned nil server")
	}
}

func TestNewGRPCServer_NilDeps(t *testing.T) {
	logger := slog.Default()
	deps := Dependencies{} // All nil — services should be Unimplemented

	server, err := NewGRPCServer(deps, logger)
	if err != nil {
		t.Fatalf("NewGRPCServer with nil deps returned error: %v", err)
	}
	if server == nil {
		t.Fatal("NewGRPCServer with nil deps returned nil server")
	}
}

func TestNewGRPCServer_NilLogger(t *testing.T) {
	deps := Dependencies{
		Auth: &mockAuthBackend{},
	}

	server, err := NewGRPCServer(deps, nil)
	if err != nil {
		t.Fatalf("NewGRPCServer with nil logger returned error: %v", err)
	}
	if server == nil {
		t.Fatal("NewGRPCServer with nil logger returned nil server")
	}
}

func TestServiceCount(t *testing.T) {
	if ServiceCount() != 7 {
		t.Errorf("ServiceCount() = %d, want 7", ServiceCount())
	}
}

func TestMethodCount(t *testing.T) {
	// 10 (auth) + 8 (proxy) + 5 (compliance) + 5 (siem) + 9 (webhook) + 9 (core) + 4 (tls) = 50
	if MethodCount() != 50 {
		t.Errorf("MethodCount() = %d, want 50", MethodCount())
	}
}

// ====================================================================
// Server Start/Stop Tests
// ====================================================================

func TestServeAndGracefulStop(t *testing.T) {
	logger := slog.Default()
	deps := Dependencies{
		Auth: &mockAuthBackend{},
	}
	server, err := NewGRPCServer(deps, logger)
	if err != nil {
		t.Fatalf("NewGRPCServer: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	_ = lis.Addr() // ensure listener is bound

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(lis)
	}()

	// Give server time to start.
	time.Sleep(100 * time.Millisecond)

	// Graceful stop with timeout.
	GracefulStop(server, 2*time.Second)

	// Verify server stopped.
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("Server stopped with: %v (expected)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("GracefulStop timed out")
	}
}

func TestGracefulStopNil(t *testing.T) {
	// Should not panic on nil.
	GracefulStop(nil, 1*time.Second)
}

// ====================================================================
// Health Check Test (via real gRPC connection)
// ====================================================================

func TestHealthCheck(t *testing.T) {
	logger := slog.Default()
	deps := Dependencies{
		Auth: &mockAuthBackend{},
	}
	server, err := NewGRPCServer(deps, logger)
	if err != nil {
		t.Fatalf("NewGRPCServer: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	go server.Serve(lis)
	defer server.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	resp, err := healthClient.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health check: %v", err)
	}

	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("Health status = %v, want SERVING", resp.Status)
	}
}

// ====================================================================
// Auth Service Tests (Direct)
// ====================================================================

func TestAuthService_Login(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.Login(ctx, &LoginRequest{Username: "admin", Password: "pass"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !resp.Success {
		t.Error("Login should succeed")
	}
	if resp.Token == "" {
		t.Error("Login should return a token")
	}
}

func TestAuthService_Login_EmptyUsername(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.Login(ctx, &LoginRequest{Username: "", Password: "pass"})
	if err == nil {
		t.Error("Expected error for empty username")
	}
}

func TestAuthService_ValidateToken(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ValidateToken(ctx, &ValidateTokenRequest{Token: "valid_token"})
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if !resp.Valid {
		t.Error("Valid token should be valid")
	}

	resp, err = svc.ValidateToken(ctx, &ValidateTokenRequest{Token: ""})
	if err != nil {
		t.Fatalf("ValidateToken empty: %v", err)
	}
	if resp.Valid {
		t.Error("Empty token should be invalid")
	}
}

func TestAuthService_ListUsers(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ListUsers(ctx, &ListUsersRequest{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Errorf("ListUsers returned %d users, want 2", len(resp.Users))
	}
}

func TestAuthService_CreateUser(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.CreateUser(ctx, &CreateUserRequest{Username: "newuser", Email: "new@test.com", Password: "pass", Role: "viewer"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if resp.User == nil {
		t.Error("CreateUser should return a user")
	}
}

func TestAuthService_CreateUser_EmptyUsername(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, &CreateUserRequest{Username: "", Password: "pass"})
	if err == nil {
		t.Error("Expected error for empty username")
	}
}

func TestAuthService_GetAuthConfig(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetAuthConfig(ctx, &GetAuthConfigRequest{})
	if err != nil {
		t.Fatalf("GetAuthConfig: %v", err)
	}
	if resp.SessionTimeout != 86400 {
		t.Errorf("SessionTimeout = %d, want 86400", resp.SessionTimeout)
	}
	if resp.PasswordMinLength != 8 {
		t.Errorf("PasswordMinLength = %d, want 8", resp.PasswordMinLength)
	}
}

// ====================================================================
// Compliance Service Tests
// ====================================================================

func TestComplianceService_GetFrameworks(t *testing.T) {
	svc := NewComplianceService(&mockComplianceBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetFrameworks(ctx, &GetFrameworksRequest{})
	if err != nil {
		t.Fatalf("GetFrameworks: %v", err)
	}
	if len(resp.Frameworks) != 2 {
		t.Errorf("GetFrameworks returned %d frameworks, want 2", len(resp.Frameworks))
	}
}

func TestComplianceService_GetStatus(t *testing.T) {
	svc := NewComplianceService(&mockComplianceBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetStatus(ctx, &GetComplianceStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.Overall != ComplianceStatusPass {
		t.Errorf("Overall status = %v, want PASS", resp.Overall)
	}
}

func TestComplianceService_RunCheck(t *testing.T) {
	svc := NewComplianceService(&mockComplianceBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.RunCheck(ctx, &RunComplianceCheckRequest{Framework: "fedramp"})
	if err != nil {
		t.Fatalf("RunCheck: %v", err)
	}
	if resp.Framework != "fedramp" {
		t.Errorf("Framework = %s, want fedramp", resp.Framework)
	}
}

func TestComplianceService_RunCheck_EmptyFramework(t *testing.T) {
	svc := NewComplianceService(&mockComplianceBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.RunCheck(ctx, &RunComplianceCheckRequest{Framework: ""})
	if err == nil {
		t.Error("Expected error for empty framework")
	}
}

// ====================================================================
// Proxy Service Tests
// ====================================================================

func TestProxyService_GetStats(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetStats(ctx, &GetProxyStatsRequest{})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if resp.RequestsTotal != 1000 {
		t.Errorf("RequestsTotal = %d, want 1000", resp.RequestsTotal)
	}
}

func TestProxyService_IsEnabled(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{enabled: true}, slog.Default())
	ctx := context.Background()

	resp, err := svc.IsEnabled(ctx, &IsProxyEnabledRequest{})
	if err != nil {
		t.Fatalf("IsEnabled: %v", err)
	}
	if !resp.Enabled {
		t.Error("Expected proxy to be enabled")
	}
}

// ====================================================================
// Core Service Tests
// ====================================================================

func TestCoreService_GetVersion(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetVersion(ctx, &GetVersionRequest{})
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if resp.Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestCoreService_ListModules(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ListModules(ctx, &ListModulesRequest{})
	if err != nil {
		t.Fatalf("ListModules: %v", err)
	}
	if len(resp.Modules) != 7 {
		t.Errorf("ListModules returned %d modules, want 7", len(resp.Modules))
	}
}

func TestCoreService_GetModule(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetModule(ctx, &GetModuleRequest{ModuleId: "proxy"})
	if err != nil {
		t.Fatalf("GetModule: %v", err)
	}
	if resp.Module == nil || resp.Module.Id != "proxy" {
		t.Error("GetModule should return proxy module")
	}
}

func TestCoreService_GetModule_NotFound(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.GetModule(ctx, &GetModuleRequest{ModuleId: "nonexistent"})
	if err == nil {
		t.Error("Expected error for nonexistent module")
	}
}

func TestCoreService_GetModule_EmptyID(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.GetModule(ctx, &GetModuleRequest{ModuleId: ""})
	if err == nil {
		t.Error("Expected error for empty module ID")
	}
}

// ====================================================================
// SIEM Service Tests
// ====================================================================

func TestSIEMService_GetConfig(t *testing.T) {
	svc := NewSIEMService(&mockSIEMBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetConfig(ctx, &GetSIEMConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !resp.Enabled {
		t.Error("SIEM should be enabled")
	}
	if resp.BatchSize != 100 {
		t.Errorf("BatchSize = %d, want 100", resp.BatchSize)
	}
}

func TestSIEMService_SendEvent(t *testing.T) {
	svc := NewSIEMService(&mockSIEMBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.SendEvent(ctx, &SendSIEMEventRequest{Source: "proxy", Category: "security", Type: "violation", Severity: EventSeverityHigh, Message: "test"})
	if err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if !resp.Success {
		t.Error("SendEvent should succeed")
	}
}

func TestSIEMService_SendEvent_EmptySource(t *testing.T) {
	svc := NewSIEMService(&mockSIEMBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.SendEvent(ctx, &SendSIEMEventRequest{Source: ""})
	if err == nil {
		t.Error("Expected error for empty source")
	}
}

// ====================================================================
// Webhook Service Tests
// ====================================================================

func TestWebhookService_ListWebhooks(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ListWebhooks(ctx, &ListWebhooksRequest{})
	if err != nil {
		t.Fatalf("ListWebhooks: %v", err)
	}
	if len(resp.Webhooks) != 1 {
		t.Errorf("ListWebhooks returned %d webhooks, want 1", len(resp.Webhooks))
	}
}

func TestWebhookService_CreateWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.CreateWebhook(ctx, &CreateWebhookRequest{Name: "test", Url: "https://example.com", Events: []string{"alert"}, Enabled: true})
	if err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}
	if resp.Webhook == nil {
		t.Error("CreateWebhook should return a webhook")
	}
}

func TestWebhookService_CreateWebhook_EmptyName(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.CreateWebhook(ctx, &CreateWebhookRequest{Name: "", Url: "https://example.com"})
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestWebhookService_GetStats(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetStats(ctx, &GetWebhookStatsRequest{})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if resp.TotalWebhooks != 5 {
		t.Errorf("TotalWebhooks = %d, want 5", resp.TotalWebhooks)
	}
}

// ====================================================================
// TLS Service Tests
// ====================================================================

func TestTLSSvc_GetConfig(t *testing.T) {
	svc := NewTLSSvc(&mockTLSBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetConfig(ctx, &GetTLSConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !resp.Enabled {
		t.Error("TLS should be enabled")
	}
	if resp.MinVersion != "1.3" {
		t.Errorf("MinVersion = %s, want 1.3", resp.MinVersion)
	}
}

func TestTLSSvc_GetCertificates(t *testing.T) {
	svc := NewTLSSvc(&mockTLSBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetCertificates(ctx, &GetCertificatesRequest{})
	if err != nil {
		t.Fatalf("GetCertificates: %v", err)
	}
	if len(resp.Certificates) != 1 {
		t.Errorf("GetCertificates returned %d certs, want 1", len(resp.Certificates))
	}
}

func TestTLSSvc_GenerateCertificate(t *testing.T) {
	svc := NewTLSSvc(&mockTLSBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GenerateCertificate(ctx, &GenerateCertificateRequest{CommonName: "test.local", Organization: "TestOrg", ValidityDays: 365})
	if err != nil {
		t.Fatalf("GenerateCertificate: %v", err)
	}
	if !resp.Success {
		t.Error("GenerateCertificate should succeed")
	}
}

func TestTLSSvc_GenerateCertificate_EmptyCN(t *testing.T) {
	svc := NewTLSSvc(&mockTLSBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.GenerateCertificate(ctx, &GenerateCertificateRequest{CommonName: ""})
	if err == nil {
		t.Error("Expected error for empty common name")
	}
}

// ====================================================================
// Interceptor Tests
// ====================================================================

func TestUnaryInterceptor(t *testing.T) {
	logger := slog.Default()
	interceptor := unaryLoggingInterceptor(logger)
	if interceptor == nil {
		t.Fatal("unaryLoggingInterceptor returned nil")
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test/Test",
	}

	resp, err := interceptor(context.Background(), "request", info, handler)
	if err != nil {
		t.Errorf("interceptor error: %v", err)
	}
	if resp != "response" {
		t.Errorf("expected response, got %v", resp)
	}
}

func TestStreamInterceptor(t *testing.T) {
	logger := slog.Default()
	interceptor := streamLoggingInterceptor(logger)
	if interceptor == nil {
		t.Fatal("streamLoggingInterceptor returned nil")
	}
}

func TestRecoveryInterceptor(t *testing.T) {
	logger := slog.Default()
	interceptor := unaryRecoveryInterceptor(logger)
	if interceptor == nil {
		t.Fatal("unaryRecoveryInterceptor returned nil")
	}

	// Test that a handler that panics is recovered.
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		panic("test panic")
	}

	info := &grpc.UnaryServerInfo{
		FullMethod: "/test/PanicTest",
	}

	resp, err := interceptor(context.Background(), "request", info, handler)
	if err == nil {
		t.Error("Expected error from panic recovery")
	}
	if resp != nil {
		t.Errorf("Expected nil response from panic, got %v", resp)
	}
}

// ====================================================================
// Version Info Tests
// ====================================================================

func TestVersionDefaults(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

func TestParseHealthStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected grpc_health_v1.HealthCheckResponse_ServingStatus
	}{
		{"healthy", grpc_health_v1.HealthCheckResponse_SERVING},
		{"serving", grpc_health_v1.HealthCheckResponse_SERVING},
		{"ok", grpc_health_v1.HealthCheckResponse_SERVING},
		{"up", grpc_health_v1.HealthCheckResponse_SERVING},
		{"degraded", grpc_health_v1.HealthCheckResponse_SERVING},
		{"unhealthy", grpc_health_v1.HealthCheckResponse_NOT_SERVING},
		{"down", grpc_health_v1.HealthCheckResponse_NOT_SERVING},
		{"error", grpc_health_v1.HealthCheckResponse_NOT_SERVING},
		{"unknown_status", grpc_health_v1.HealthCheckResponse_SERVICE_UNKNOWN},
	}

	for _, tc := range tests {
		result := ParseHealthStatus(tc.input)
		if result != tc.expected {
			t.Errorf("ParseHealthStatus(%q) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

// ====================================================================
// Backend Nil Safety Tests
// ====================================================================

func TestAuthService_WithNilBackend(t *testing.T) {
	// UnimplementedAuthServiceServer should return Unimplemented for all RPCs.
	svc := &UnimplementedAuthServiceServer{}
	ctx := context.Background()

	_, err := svc.Login(ctx, &LoginRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

func TestProxyService_WithNilBackend(t *testing.T) {
	svc := &UnimplementedProxyServiceServer{}
	ctx := context.Background()

	_, err := svc.GetStats(ctx, &GetProxyStatsRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

func TestComplianceService_WithNilBackend(t *testing.T) {
	svc := &UnimplementedComplianceServiceServer{}
	ctx := context.Background()

	_, err := svc.GetFrameworks(ctx, &GetFrameworksRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

func TestSIEMService_WithNilBackend(t *testing.T) {
	svc := &UnimplementedSIEMServiceServer{}
	ctx := context.Background()

	_, err := svc.GetConfig(ctx, &GetSIEMConfigRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

func TestWebhookService_WithNilBackend(t *testing.T) {
	svc := &UnimplementedWebhookServiceServer{}
	ctx := context.Background()

	_, err := svc.ListWebhooks(ctx, &ListWebhooksRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

func TestCoreService_WithNilBackend(t *testing.T) {
	svc := &UnimplementedCoreServiceServer{}
	ctx := context.Background()

	_, err := svc.GetHealth(ctx, &GetHealthRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

func TestTLSSvc_WithNilBackend(t *testing.T) {
	svc := &UnimplementedTLSSvcServer{}
	ctx := context.Background()

	_, err := svc.GetConfig(ctx, &GetTLSConfigRequest{})
	if err == nil {
		t.Error("Expected Unimplemented error")
	}
}

// ====================================================================
// Health Server Direct Registration Test
// ====================================================================

func TestHealthServerRegistration(t *testing.T) {
	server := grpc.NewServer()
	hs := health.NewServer()
	grpc_health_v1.RegisterHealthServer(server, hs)

	hs.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	hs.SetServingStatus("grpc.AuthService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Verify the health server is registered and responds.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	go server.Serve(lis)
	defer server.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	client := grpc_health_v1.NewHealthClient(conn)
	resp, err := client.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health check: %v", err)
	}
	if resp.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Errorf("Overall health = %v, want SERVING", resp.Status)
	}
}

// ====================================================================
// FormatToken Test
// ====================================================================

func TestFormatToken(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "***short"},
		{"abcdefghijklmnopqrstuvwxyz", "***wxyz"},
		{"valid_token_123456", "***3456"},
	}

	for _, tc := range tests {
		result := FormatToken(tc.input)
		if result != tc.expected {
			t.Errorf("FormatToken(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}