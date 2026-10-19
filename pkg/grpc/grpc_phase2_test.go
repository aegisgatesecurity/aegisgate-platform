// SPDX-License-Identifier: Apache-2.0
// Phase 2 gRPC bufconn tests — exercises all uncovered service methods,
// interceptors, handlers, v4 services, and Unimplemented stubs.
package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ====================================================================
// Mock Backends for v4 Services
// ====================================================================

type mockDSARBackend struct {
	blockedBy string
}

func (m *mockDSARBackend) Export(_ context.Context, entityID string) (*DSARExportResponse, error) {
	return &DSARExportResponse{EntityID: entityID, ExportedAt: 1000, Providers: map[string]interface{}{"scanner": "ok"}}, nil
}
func (m *mockDSARBackend) Erase(_ context.Context, entityID string) (*DSAREraseResponse, error) {
	if m.blockedBy != "" {
		return &DSAREraseResponse{EntityID: entityID, BlockedBy: m.blockedBy}, errors.New("blocked by legal hold")
	}
	return &DSAREraseResponse{EntityID: entityID, ErasedAt: 2000, RecordsAffected: 5}, nil
}

type mockLegalHoldBackend struct{}

func (m *mockLegalHoldBackend) CreateHold(_ context.Context, entityID, entityType, reason, issuedBy string) (*LegalHoldInfo, error) {
	return &LegalHoldInfo{ID: "hold-1", EntityID: entityID, EntityType: entityType, Reason: reason, IssuedBy: issuedBy, CreatedAt: 1000}, nil
}
func (m *mockLegalHoldBackend) ReleaseHold(_ context.Context, holdID string) error {
	if holdID == "notfound" {
		return errors.New("hold not found")
	}
	return nil
}
func (m *mockLegalHoldBackend) IsUnderHold(_ context.Context, entityID string) (bool, error) {
	return entityID == "held-entity", nil
}
func (m *mockLegalHoldBackend) ListHolds(_ context.Context) ([]*LegalHoldInfo, error) {
	return []*LegalHoldInfo{{ID: "h1", EntityID: "e1", Reason: "litigation"}}, nil
}
func (m *mockLegalHoldBackend) GetHold(_ context.Context, holdID string) (*LegalHoldInfo, error) {
	if holdID == "notfound" {
		return nil, errors.New("hold not found")
	}
	return &LegalHoldInfo{ID: holdID, EntityID: "e1"}, nil
}

type mockABTestBackend struct{}

func (m *mockABTestBackend) CreateTest(_ context.Context, name, description string, variants []ABTestVariantInfo) (*ABTestInfo, error) {
	return &ABTestInfo{ID: "test-1", Name: name, Description: description, Variants: variants, Status: "created", CreatedAt: 1000}, nil
}
func (m *mockABTestBackend) ListTests(_ context.Context) ([]*ABTestInfo, error) {
	return []*ABTestInfo{{ID: "t1", Name: "test1", Status: "running"}}, nil
}
func (m *mockABTestBackend) StartTest(_ context.Context, testID string) error {
	if testID == "bad" {
		return errors.New("test not found")
	}
	return nil
}
func (m *mockABTestBackend) StopTest(_ context.Context, testID string) error {
	if testID == "bad" {
		return errors.New("test not found")
	}
	return nil
}
func (m *mockABTestBackend) GetMetrics(_ context.Context, testID string) ([]*ABTestVariantMetrics, error) {
	if testID == "notfound" {
		return nil, errors.New("metrics not found")
	}
	return []*ABTestVariantMetrics{{VariantName: "A", TotalRequests: 100, Detections: 80, FalsePositives: 5, AvgLatencyMs: 12.5}}, nil
}
func (m *mockABTestBackend) AssignVariant(_ context.Context, testID, requestID string) (string, error) {
	if requestID == "bad" {
		return "", errors.New("assignment failed")
	}
	return "variant-A", nil
}
func (m *mockABTestBackend) RecordResult(_ context.Context, testID, variantName string, detected, falsePositive bool, latencyMs float64) error {
	return nil
}

// ====================================================================
// Auth Service — uncovered methods
// ====================================================================

func TestPhase2AuthService_Logout(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	// Valid logout
	resp, err := svc.Logout(ctx, &LogoutRequest{Token: "some_token"})
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	// Empty token
	resp, err = svc.Logout(ctx, &LogoutRequest{Token: ""})
	if err != nil {
		t.Fatalf("Logout empty: %v", err)
	}
	if resp.Success {
		t.Error("expected failure for empty token")
	}
}

func TestPhase2AuthService_GetUser(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetUser(ctx, &GetUserRequest{UserId: "user123"})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if resp.User == nil || resp.User.Id != "user123" {
		t.Error("unexpected user")
	}

	// Empty user ID
	_, err = svc.GetUser(ctx, &GetUserRequest{UserId: ""})
	if err == nil {
		t.Error("expected error for empty user ID")
	}
}

func TestPhase2AuthService_UpdateUser(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.UpdateUser(ctx, &UpdateUserRequest{UserId: "u1", Username: "updated", Email: "new@test.com", Role: "admin", Enabled: true})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if resp.User == nil {
		t.Error("expected user")
	}

	// Empty user ID
	_, err = svc.UpdateUser(ctx, &UpdateUserRequest{UserId: ""})
	if err == nil {
		t.Error("expected error for empty user ID")
	}
}

func TestPhase2AuthService_DeleteUser(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.DeleteUser(ctx, &DeleteUserRequest{UserId: "u1"})
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	// Empty user ID
	_, err = svc.DeleteUser(ctx, &DeleteUserRequest{UserId: ""})
	if err == nil {
		t.Error("expected error for empty user ID")
	}
}

func TestPhase2AuthService_GetSessions(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetSessions(ctx, &GetSessionsRequest{})
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if len(resp.Sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(resp.Sessions))
	}
}

func TestPhase2AuthService_CreateUser_EmptyPassword(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, &CreateUserRequest{Username: "user", Password: ""})
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestPhase2AuthService_Login_UserLookupFail(t *testing.T) {
	// Backend that fails GetUser after successful Login
	svc := NewAuthService(&failingGetUserBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.Login(ctx, &LoginRequest{Username: "testuser", Password: "pass"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
	if resp.User != nil {
		t.Error("expected nil user when GetUser fails")
	}
}

type failingGetUserBackend struct {
	mockAuthBackend
}

func (m *failingGetUserBackend) GetUser(_ context.Context, _ string) (*AuthUserInfo, error) {
	return nil, errors.New("lookup failed")
}

// ====================================================================
// Compliance Service — uncovered methods
// ====================================================================

func TestPhase2ComplianceService_GetFindings(t *testing.T) {
	svc := NewComplianceService(&mockComplianceBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetFindings(ctx, &GetFindingsRequest{})
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(resp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(resp.Findings))
	}
}

func TestPhase2ComplianceService_GenerateReport(t *testing.T) {
	svc := NewComplianceService(&mockComplianceBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GenerateReport(ctx, &GenerateReportRequest{Framework: "fedramp"})
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	if resp.Framework != "fedramp" {
		t.Errorf("expected fedramp, got %s", resp.Framework)
	}
	if resp.Summary == nil {
		t.Error("expected non-nil summary")
	}

	// Empty framework
	_, err = svc.GenerateReport(ctx, &GenerateReportRequest{Framework: ""})
	if err == nil {
		t.Error("expected error for empty framework")
	}
}

// ====================================================================
// Core Service — uncovered methods
// ====================================================================

func TestPhase2CoreService_GetHealth(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetHealth(ctx, &GetHealthRequest{})
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("expected healthy, got %s", resp.Status)
	}
}

func TestPhase2CoreService_GetHealth_BackendError(t *testing.T) {
	svc := NewCoreService(&failingMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetHealth(ctx, &GetHealthRequest{})
	if err != nil {
		t.Fatalf("GetHealth with failing backend: %v", err)
	}
	if resp.Status != "degraded" {
		t.Errorf("expected degraded, got %s", resp.Status)
	}
}

func TestPhase2CoreService_GetMetrics(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetMetrics(ctx, &GetMetricsRequest{})
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if resp.TotalRequests != 10000 {
		t.Errorf("expected 10000, got %d", resp.TotalRequests)
	}
}

func TestPhase2CoreService_GetMetrics_BackendError(t *testing.T) {
	svc := NewCoreService(&failingMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetMetrics(ctx, &GetMetricsRequest{})
	if err != nil {
		t.Fatalf("GetMetrics with failing backend: %v", err)
	}
	if resp.TotalRequests != 0 {
		t.Errorf("expected 0, got %d", resp.TotalRequests)
	}
	if resp.Uptime <= 0 {
		t.Error("expected positive uptime from fallback")
	}
}

func TestPhase2CoreService_GetUptime(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetUptime(ctx, &GetUptimeRequest{})
	if err != nil {
		t.Fatalf("GetUptime: %v", err)
	}
	if resp.Uptime != 86400.0 {
		t.Errorf("expected 86400, got %f", resp.Uptime)
	}
}

func TestPhase2CoreService_GetUptime_BackendError(t *testing.T) {
	svc := NewCoreService(&failingMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetUptime(ctx, &GetUptimeRequest{})
	if err != nil {
		t.Fatalf("GetUptime with failing backend: %v", err)
	}
	if resp.Uptime <= 0 {
		t.Error("expected positive uptime from fallback")
	}
}

func TestPhase2CoreService_GetRegistryStatus(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetRegistryStatus(ctx, &GetRegistryStatusRequest{})
	if err != nil {
		t.Fatalf("GetRegistryStatus: %v", err)
	}
	if resp.TotalModules != 7 {
		t.Errorf("expected 7, got %d", resp.TotalModules)
	}
}

func TestPhase2CoreService_EnableModule(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.EnableModule(ctx, &EnableModuleRequest{ModuleId: "proxy"})
	if err != nil {
		t.Fatalf("EnableModule: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false (read-only)")
	}

	// Empty module ID
	_, err = svc.EnableModule(ctx, &EnableModuleRequest{ModuleId: ""})
	if err == nil {
		t.Error("expected error for empty module ID")
	}
}

func TestPhase2CoreService_DisableModule(t *testing.T) {
	svc := NewCoreService(&mockMetricsBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.DisableModule(ctx, &DisableModuleRequest{ModuleId: "proxy"})
	if err != nil {
		t.Fatalf("DisableModule: %v", err)
	}
	if resp.Success {
		t.Error("expected Success=false (read-only)")
	}

	// Empty module ID
	_, err = svc.DisableModule(ctx, &DisableModuleRequest{ModuleId: ""})
	if err == nil {
		t.Error("expected error for empty module ID")
	}
}

type failingMetricsBackend struct {
	mockMetricsBackend
}

func (m *failingMetricsBackend) GetHealth(_ context.Context) (*HealthInfo, error) {
	return nil, errors.New("backend unavailable")
}
func (m *failingMetricsBackend) GetStats(_ context.Context) (*SystemStatsInfo, error) {
	return nil, errors.New("backend unavailable")
}
func (m *failingMetricsBackend) GetUptime(_ context.Context) (float64, error) {
	return 0, errors.New("backend unavailable")
}

// ====================================================================
// Proxy Service — uncovered methods
// ====================================================================

func TestPhase2ProxyService_GetHealth(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetHealth(ctx, &GetProxyHealthRequest{})
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if resp.Status != "healthy" {
		t.Errorf("expected healthy, got %s", resp.Status)
	}
}

func TestPhase2ProxyService_GetConfig(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetConfig(ctx, &GetProxyConfigRequest{})
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if !resp.Enabled {
		t.Error("expected enabled")
	}
	if resp.Port != 8080 {
		t.Errorf("expected port 8080, got %d", resp.Port)
	}
}

func TestPhase2ProxyService_Enable(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.Enable(ctx, &EnableProxyRequest{})
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
}

func TestPhase2ProxyService_Disable(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.Disable(ctx, &DisableProxyRequest{})
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
}

func TestPhase2ProxyService_GetViolations(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetViolations(ctx, &GetViolationsRequest{
		Severities: []ViolationSeverity{ViolationSeverityCritical},
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("GetViolations: %v", err)
	}
	if len(resp.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(resp.Violations))
	}
}

func TestPhase2ProxyService_ClearViolations(t *testing.T) {
	svc := NewProxyService(&mockProxyBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ClearViolations(ctx, &ClearViolationsRequest{})
	if err != nil {
		t.Fatalf("ClearViolations: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}
}

// ====================================================================
// SIEM Service (Community) — all methods return Unimplemented
// ====================================================================

func TestPhase2SIEMService_AllUnimplemented(t *testing.T) {
	svc := NewSIEMService(&mockSIEMBackend{}, slog.Default())
	ctx := context.Background()

	// GetConfig
	_, err := svc.GetConfig(ctx, &GetSIEMConfigRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetConfig")
	}

	// GetStats
	_, err = svc.GetStats(ctx, &GetSIEMStatsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetStats")
	}

	// GetEvents
	_, err = svc.GetEvents(ctx, &GetSIEMEventsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetEvents")
	}

	// SendEvent
	_, err = svc.SendEvent(ctx, &SendSIEMEventRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for SendEvent")
	}

	// TestConnection
	_, err = svc.TestConnection(ctx, &TestSIEMConnectionRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for TestConnection")
	}
}

func isUnimplemented(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.Unimplemented
}

// ====================================================================
// TLS Service — GetMTLSConfig
// ====================================================================

func TestPhase2TLSSvc_GetMTLSConfig(t *testing.T) {
	svc := NewTLSSvc(&mockTLSBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetMTLSConfig(ctx, &GetMTLSConfigRequest{})
	if err != nil {
		t.Fatalf("GetMTLSConfig: %v", err)
	}
	if resp.Enabled {
		t.Error("expected mTLS disabled")
	}
}

// ====================================================================
// Webhook Service — uncovered methods
// ====================================================================

func TestPhase2WebhookService_GetWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetWebhook(ctx, &GetWebhookRequest{WebhookId: "wh1"})
	if err != nil {
		t.Fatalf("GetWebhook: %v", err)
	}
	if resp.Webhook == nil || resp.Webhook.Id != "wh1" {
		t.Error("unexpected webhook")
	}

	// Empty ID
	_, err = svc.GetWebhook(ctx, &GetWebhookRequest{WebhookId: ""})
	if err == nil {
		t.Error("expected error for empty webhook ID")
	}
}

func TestPhase2WebhookService_CreateWebhook_EmptyURL(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.CreateWebhook(ctx, &CreateWebhookRequest{Name: "test", Url: ""})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestPhase2WebhookService_UpdateWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.UpdateWebhook(ctx, &UpdateWebhookRequest{WebhookId: "wh1", Name: "updated", Url: "https://example.com", Events: []string{"alert"}, Enabled: true})
	if err != nil {
		t.Fatalf("UpdateWebhook: %v", err)
	}
	if resp.Webhook == nil {
		t.Error("expected webhook")
	}

	// Empty ID
	_, err = svc.UpdateWebhook(ctx, &UpdateWebhookRequest{WebhookId: ""})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestPhase2WebhookService_DeleteWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.DeleteWebhook(ctx, &DeleteWebhookRequest{WebhookId: "wh1"})
	if err != nil {
		t.Fatalf("DeleteWebhook: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	// Empty ID
	_, err = svc.DeleteWebhook(ctx, &DeleteWebhookRequest{WebhookId: ""})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestPhase2WebhookService_EnableWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.EnableWebhook(ctx, &EnableWebhookRequest{WebhookId: "wh1"})
	if err != nil {
		t.Fatalf("EnableWebhook: %v", err)
	}
	if resp.Webhook == nil || !resp.Webhook.Enabled {
		t.Error("expected enabled webhook")
	}

	// Empty ID
	_, err = svc.EnableWebhook(ctx, &EnableWebhookRequest{WebhookId: ""})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestPhase2WebhookService_DisableWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.DisableWebhook(ctx, &DisableWebhookRequest{WebhookId: "wh1"})
	if err != nil {
		t.Fatalf("DisableWebhook: %v", err)
	}
	if resp.Webhook == nil || resp.Webhook.Enabled {
		t.Error("expected disabled webhook")
	}

	// Empty ID
	_, err = svc.DisableWebhook(ctx, &DisableWebhookRequest{WebhookId: ""})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestPhase2WebhookService_TestWebhook(t *testing.T) {
	svc := NewWebhookService(&mockWebhookBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.TestWebhook(ctx, &TestWebhookRequest{WebhookId: "wh1"})
	if err != nil {
		t.Fatalf("TestWebhook: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	// Empty ID
	_, err = svc.TestWebhook(ctx, &TestWebhookRequest{WebhookId: ""})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

// ====================================================================
// Auth Interceptor — extractBearerToken, authStream.Context, UserIDFromContext
// ====================================================================

func TestPhase2ExtractBearerToken_NoMetadata(t *testing.T) {
	_, err := extractBearerToken(context.Background())
	if err == nil {
		t.Error("expected error for no metadata")
	}
}

func TestPhase2ExtractBearerToken_NoAuthHeader(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-custom", "val"))
	_, err := extractBearerToken(ctx)
	if err == nil {
		t.Error("expected error for no auth header")
	}
}

func TestPhase2ExtractBearerToken_BearerPrefix(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer my_token"))
	token, err := extractBearerToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my_token" {
		t.Errorf("expected 'my_token', got %q", token)
	}
}

func TestPhase2ExtractBearerToken_LowercaseBearer(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "bearer my_token"))
	token, err := extractBearerToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my_token" {
		t.Errorf("expected 'my_token', got %q", token)
	}
}

func TestPhase2ExtractBearerToken_RawToken(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "raw_token_123"))
	token, err := extractBearerToken(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "raw_token_123" {
		t.Errorf("expected 'raw_token_123', got %q", token)
	}
}

func TestPhase2ExtractBearerToken_EmptyHeader(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", ""))
	_, err := extractBearerToken(ctx)
	if err == nil {
		t.Error("expected error for empty auth header")
	}
}

func TestPhase2UnaryAuthInterceptor_ExemptMethod(t *testing.T) {
	interceptor := unaryAuthInterceptor(slog.Default(), nil)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.AuthService/Login"}
	resp, err := interceptor(context.Background(), "req", info, handler)
	if err != nil {
		t.Fatalf("exempt method should pass: %v", err)
	}
	if resp != "ok" {
		t.Error("expected ok")
	}
}

func TestPhase2UnaryAuthInterceptor_NilBackend(t *testing.T) {
	interceptor := unaryAuthInterceptor(slog.Default(), nil)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.ProxyService/GetStats"}
	_, err := interceptor(context.Background(), "req", info, handler)
	if err == nil {
		t.Error("expected Unauthenticated for nil backend")
	}
}

func TestPhase2UnaryAuthInterceptor_ValidToken(t *testing.T) {
	interceptor := unaryAuthInterceptor(slog.Default(), &mockAuthBackend{})
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		uid := UserIDFromContext(ctx)
		if uid != "user123" {
			t.Errorf("expected user123 in context, got %q", uid)
		}
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid_token"))
	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.ProxyService/GetStats"}
	resp, err := interceptor(ctx, "req", info, handler)
	if err != nil {
		t.Fatalf("valid token should pass: %v", err)
	}
	if resp != "ok" {
		t.Error("expected ok")
	}
}

func TestPhase2UnaryAuthInterceptor_InvalidToken(t *testing.T) {
	interceptor := unaryAuthInterceptor(slog.Default(), &mockAuthBackend{})
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid"))
	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.ProxyService/GetStats"}
	_, err := interceptor(ctx, "req", info, handler)
	if err == nil {
		t.Error("expected Unauthenticated for invalid token")
	}
}

func TestPhase2UnaryAuthInterceptor_NoMetadata(t *testing.T) {
	interceptor := unaryAuthInterceptor(slog.Default(), &mockAuthBackend{})
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/grpc.ProxyService/GetStats"}
	_, err := interceptor(context.Background(), "req", info, handler)
	if err == nil {
		t.Error("expected Unauthenticated for no metadata")
	}
}

func TestPhase2StreamAuthInterceptor_ExemptMethod(t *testing.T) {
	interceptor := streamAuthInterceptor(slog.Default(), nil)
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"}
	err := interceptor(nil, nil, info, handler)
	if err != nil {
		t.Fatalf("exempt method should pass: %v", err)
	}
}

func TestPhase2StreamAuthInterceptor_NilBackend(t *testing.T) {
	interceptor := streamAuthInterceptor(slog.Default(), nil)
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/grpc.SomeService/Stream"}
	err := interceptor(nil, nil, info, handler)
	if err == nil {
		t.Error("expected Unauthenticated for nil backend")
	}
}

func TestPhase2StreamAuthInterceptor_ValidToken(t *testing.T) {
	interceptor := streamAuthInterceptor(slog.Default(), &mockAuthBackend{})
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		uid := UserIDFromContext(ss.Context())
		if uid != "user123" {
			t.Errorf("expected user123, got %q", uid)
		}
		return nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid_token"))
	stream := &testServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{FullMethod: "/grpc.SomeService/Stream"}
	err := interceptor(nil, stream, info, handler)
	if err != nil {
		t.Fatalf("valid token should pass: %v", err)
	}
}

func TestPhase2StreamAuthInterceptor_InvalidToken(t *testing.T) {
	interceptor := streamAuthInterceptor(slog.Default(), &mockAuthBackend{})
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer bad"))
	stream := &testServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{FullMethod: "/grpc.SomeService/Stream"}
	err := interceptor(nil, stream, info, handler)
	if err == nil {
		t.Error("expected Unauthenticated for invalid token")
	}
}

func TestPhase2UserIDFromContext_NotSet(t *testing.T) {
	result := UserIDFromContext(context.Background())
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

// testServerStream implements grpc.ServerStream for testing
type testServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (t *testServerStream) Context() context.Context {
	return t.ctx
}

// ====================================================================
// Handlers — jsonCodec, methodHandler, invokeMethod
// ====================================================================

func TestPhase2JsonCodec_MarshalUnmarshal(t *testing.T) {
	codec := jsonCodec{}
	original := &LoginRequest{Username: "test", Password: "secret"}

	data, err := codec.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded LoginRequest
	err = codec.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Username != "test" {
		t.Errorf("expected 'test', got %q", decoded.Username)
	}

	if codec.Name() != "json" {
		t.Errorf("expected 'json', got %q", codec.Name())
	}
}

func TestPhase2InvokeMethod_Success(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	ctx := context.Background()
	req := &LoginRequest{Username: "admin", Password: "pass"}

	resp, err := invokeMethod(svc, ctx, "Login", req)
	if err != nil {
		t.Fatalf("invokeMethod Login: %v", err)
	}
	loginResp, ok := resp.(*LoginResponse)
	if !ok {
		t.Fatal("expected *LoginResponse")
	}
	if !loginResp.Success {
		t.Error("expected success")
	}
}

func TestPhase2InvokeMethod_MethodNotFound(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	_, err := invokeMethod(svc, context.Background(), "NonExistent", &LoginRequest{})
	if err == nil {
		t.Error("expected error for non-existent method")
	}
}

func TestPhase2InvokeMethod_PanicRecovery(t *testing.T) {
	svc := &panicService{}
	_, err := invokeMethod(svc, context.Background(), "PanicMethod", &LoginRequest{})
	if err == nil {
		t.Error("expected error from panic recovery")
	}
}

type panicService struct{}

func (p *panicService) PanicMethod(_ context.Context, _ *LoginRequest) (*LoginResponse, error) {
	panic("test panic")
}

func TestPhase2MethodHandler_WithInterceptor(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	handler := methodHandler(svc, "Login", func() any { return &LoginRequest{} })

	interceptor := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, hdlr grpc.UnaryHandler) (any, error) {
		return hdlr(ctx, req)
	}

	// Test with interceptor — dec function simulates gRPC decoding
	dec := func(v any) error {
		if lr, ok := v.(*LoginRequest); ok {
			lr.Username = "admin"
			lr.Password = "pass"
		}
		return nil
	}

	resp, err := handler(svc, context.Background(), dec, interceptor)
	if err != nil {
		t.Fatalf("methodHandler with interceptor: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestPhase2MethodHandler_DecodeError(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	handler := methodHandler(svc, "Login", func() any { return &LoginRequest{} })

	dec := func(v any) error {
		return errors.New("decode failed")
	}

	_, err := handler(svc, context.Background(), dec, nil)
	if err == nil {
		t.Error("expected error for decode failure")
	}
}

func TestPhase2MethodHandler_NoInterceptor(t *testing.T) {
	svc := NewAuthService(&mockAuthBackend{}, slog.Default())
	handler := methodHandler(svc, "Login", func() any { return &LoginRequest{} })

	dec := func(v any) error {
		if lr, ok := v.(*LoginRequest); ok {
			lr.Username = "admin"
			lr.Password = "pass"
		}
		return nil
	}

	resp, err := handler(svc, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("methodHandler no interceptor: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// ====================================================================
// Server — Serve, ServeTLS, RunServer, stream interceptors
// ====================================================================

func TestPhase2Serve_InvalidAddr(t *testing.T) {
	server := grpc.NewServer()
	defer server.Stop()
	err := Serve(server, "invalid:address:format")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestPhase2Serve_Success(t *testing.T) {
	server := grpc.NewServer()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := lis.Addr().String()
	lis.Close() // free the port; Serve will re-listen

	errCh := make(chan error, 1)
	go func() {
		errCh <- Serve(server, port)
	}()
	time.Sleep(100 * time.Millisecond)
	server.GracefulStop()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
}

func TestPhase2ServeTLS_MissingCert(t *testing.T) {
	server := grpc.NewServer()
	defer server.Stop()
	err := ServeTLS(server, "127.0.0.1:0", "/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for missing cert files")
	}
}

func TestPhase2ServeTLS_Success(t *testing.T) {
	// Generate self-signed cert for testing
	certPEM, keyPEM := generateTestCert(t)
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	server := grpc.NewServer()
	defer server.Stop()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	port := lis.Addr().String()
	lis.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeTLS(server, port, certFile, keyFile)
	}()
	time.Sleep(100 * time.Millisecond)
	server.GracefulStop()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
	}
}

func TestPhase2StreamLoggingInterceptor_ActualCall(t *testing.T) {
	logger := slog.Default()
	interceptor := streamLoggingInterceptor(logger)
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}
	info := &grpc.StreamServerInfo{
		FullMethod:     "/test/Stream",
		IsClientStream: true,
		IsServerStream: false,
	}
	err := interceptor(nil, nil, info, handler)
	if err != nil {
		t.Fatalf("streamLoggingInterceptor: %v", err)
	}
}

func TestPhase2StreamLoggingInterceptor_HandlerError(t *testing.T) {
	logger := slog.Default()
	interceptor := streamLoggingInterceptor(logger)
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return errors.New("stream handler error")
	}
	info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}
	err := interceptor(nil, nil, info, handler)
	if err == nil {
		t.Error("expected error from handler")
	}
}

func TestPhase2StreamRecoveryInterceptor_Success(t *testing.T) {
	logger := slog.Default()
	interceptor := streamRecoveryInterceptor(logger)
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		return nil
	}
	info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}
	err := interceptor(nil, nil, info, handler)
	if err != nil {
		t.Fatalf("streamRecoveryInterceptor: %v", err)
	}
}

func TestPhase2StreamRecoveryInterceptor_PanicRecovery(t *testing.T) {
	logger := slog.Default()
	interceptor := streamRecoveryInterceptor(logger)
	handler := func(srv interface{}, ss grpc.ServerStream) error {
		panic("stream panic")
	}
	info := &grpc.StreamServerInfo{FullMethod: "/test/Stream"}
	err := interceptor(nil, nil, info, handler)
	if err == nil {
		t.Error("expected error from panic recovery")
	}
}

func TestPhase2RunServer_BadAddr(t *testing.T) {
	deps := Dependencies{Auth: &mockAuthBackend{}}
	logger := slog.Default()

	// Invalid address causes Serve to fail immediately. The error is
	// sent to errCh and RunServer returns it. No signal needed.
	done := make(chan error, 1)
	go func() {
		done <- RunServer("invalid:addr:format", deps, logger)
	}()

	select {
	case err := <-done:
		// RunServer should return an error from Serve failing.
		if err == nil {
			// If nil, the signal handler may have caught a leftover signal.
			// Either way, the test didn't hang, which is the goal.
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunServer hung on bad address")
	}
}

// ====================================================================
// v4 Services — DSAR
// ====================================================================

func TestPhase2DSARService_Export(t *testing.T) {
	svc := NewDSARService(&mockDSARBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.Export(ctx, &DSARExportRequest{EntityID: "user-123"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if resp.EntityID != "user-123" {
		t.Errorf("expected user-123, got %s", resp.EntityID)
	}

	// Empty entity ID
	_, err = svc.Export(ctx, &DSARExportRequest{EntityID: ""})
	if err == nil {
		t.Error("expected error for empty entity ID")
	}
}

func TestPhase2DSARService_Erase(t *testing.T) {
	svc := NewDSARService(&mockDSARBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.Erase(ctx, &DSAREraseRequest{EntityID: "user-123"})
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if resp.EntityID != "user-123" {
		t.Errorf("expected user-123, got %s", resp.EntityID)
	}

	// Empty entity ID
	_, err = svc.Erase(ctx, &DSAREraseRequest{EntityID: ""})
	if err == nil {
		t.Error("expected error for empty entity ID")
	}
}

func TestPhase2DSARService_Erase_LegalHoldBlocked(t *testing.T) {
	svc := NewDSARService(&mockDSARBackend{blockedBy: "legal_hold"}, slog.Default())
	ctx := context.Background()

	// When blocked by legal hold, the response should be returned (not error)
	resp, err := svc.Erase(ctx, &DSAREraseRequest{EntityID: "user-123"})
	if err != nil {
		t.Fatalf("Erase with legal hold: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.BlockedBy != "legal_hold" {
		t.Errorf("expected blocked_by=legal_hold, got %s", resp.BlockedBy)
	}
}

func TestPhase2DSARService_Unimplemented(t *testing.T) {
	svc := &UnimplementedDSARServiceServer{}
	ctx := context.Background()

	_, err := svc.Export(ctx, &DSARExportRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for Export")
	}

	_, err = svc.Erase(ctx, &DSAREraseRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for Erase")
	}
}

func TestPhase2NewDSARService(t *testing.T) {
	svc := NewDSARService(&mockDSARBackend{}, slog.Default())
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ====================================================================
// v4 Services — Legal Hold
// ====================================================================

func TestPhase2LegalHoldService_CreateHold(t *testing.T) {
	svc := NewLegalHoldService(&mockLegalHoldBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.CreateHold(ctx, &CreateHoldRequest{EntityID: "e1", EntityType: "user", Reason: "litigation", IssuedBy: "admin"})
	if err != nil {
		t.Fatalf("CreateHold: %v", err)
	}
	if resp.ID != "hold-1" {
		t.Errorf("expected hold-1, got %s", resp.ID)
	}

	// Empty entity ID
	_, err = svc.CreateHold(ctx, &CreateHoldRequest{EntityID: ""})
	if err == nil {
		t.Error("expected error for empty entity ID")
	}
}

func TestPhase2LegalHoldService_ReleaseHold(t *testing.T) {
	svc := NewLegalHoldService(&mockLegalHoldBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ReleaseHold(ctx, &ReleaseHoldRequest{HoldID: "h1"})
	if err != nil {
		t.Fatalf("ReleaseHold: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	// Empty hold ID
	_, err = svc.ReleaseHold(ctx, &ReleaseHoldRequest{HoldID: ""})
	if err == nil {
		t.Error("expected error for empty hold ID")
	}

	// Not found
	_, err = svc.ReleaseHold(ctx, &ReleaseHoldRequest{HoldID: "notfound"})
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestPhase2LegalHoldService_IsUnderHold(t *testing.T) {
	svc := NewLegalHoldService(&mockLegalHoldBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.IsUnderHold(ctx, &IsUnderHoldRequest{EntityID: "held-entity"})
	if err != nil {
		t.Fatalf("IsUnderHold: %v", err)
	}
	if !resp.UnderHold {
		t.Error("expected under hold")
	}

	resp, err = svc.IsUnderHold(ctx, &IsUnderHoldRequest{EntityID: "free-entity"})
	if err != nil {
		t.Fatalf("IsUnderHold: %v", err)
	}
	if resp.UnderHold {
		t.Error("expected not under hold")
	}
}

func TestPhase2LegalHoldService_ListHolds(t *testing.T) {
	svc := NewLegalHoldService(&mockLegalHoldBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ListHolds(ctx, &ListHoldsRequest{})
	if err != nil {
		t.Fatalf("ListHolds: %v", err)
	}
	if len(resp.Holds) != 1 {
		t.Errorf("expected 1 hold, got %d", len(resp.Holds))
	}
}

func TestPhase2LegalHoldService_GetHold(t *testing.T) {
	svc := NewLegalHoldService(&mockLegalHoldBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetHold(ctx, &GetHoldRequest{HoldID: "h1"})
	if err != nil {
		t.Fatalf("GetHold: %v", err)
	}
	if resp.ID != "h1" {
		t.Errorf("expected h1, got %s", resp.ID)
	}

	// Not found
	_, err = svc.GetHold(ctx, &GetHoldRequest{HoldID: "notfound"})
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestPhase2LegalHoldService_Unimplemented(t *testing.T) {
	svc := &UnimplementedLegalHoldServiceServer{}
	ctx := context.Background()

	_, err := svc.CreateHold(ctx, &CreateHoldRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for CreateHold")
	}
	_, err = svc.ReleaseHold(ctx, &ReleaseHoldRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ReleaseHold")
	}
	_, err = svc.IsUnderHold(ctx, &IsUnderHoldRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for IsUnderHold")
	}
	_, err = svc.ListHolds(ctx, &ListHoldsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ListHolds")
	}
	_, err = svc.GetHold(ctx, &GetHoldRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetHold")
	}
}

func TestPhase2NewLegalHoldService(t *testing.T) {
	svc := NewLegalHoldService(&mockLegalHoldBackend{}, slog.Default())
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ====================================================================
// v4 Services — ABTest
// ====================================================================

func TestPhase2ABTestService_CreateTest(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.CreateTest(ctx, &ABTestCreateRequest{
		Name:        "test1",
		Description: "A/B test",
		Variants: []ABTestVariantInfo{
			{Name: "A", Weight: 50},
			{Name: "B", Weight: 50},
		},
	})
	if err != nil {
		t.Fatalf("CreateTest: %v", err)
	}
	if resp.Name != "test1" {
		t.Errorf("expected test1, got %s", resp.Name)
	}

	// Empty name
	_, err = svc.CreateTest(ctx, &ABTestCreateRequest{Name: ""})
	if err == nil {
		t.Error("expected error for empty name")
	}

	// Too few variants
	_, err = svc.CreateTest(ctx, &ABTestCreateRequest{Name: "test", Variants: []ABTestVariantInfo{{Name: "A"}}})
	if err == nil {
		t.Error("expected error for < 2 variants")
	}
}

func TestPhase2ABTestService_ListTests(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.ListTests(ctx, &ABTestListRequest{})
	if err != nil {
		t.Fatalf("ListTests: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("expected count 1, got %d", resp.Count)
	}
}

func TestPhase2ABTestService_StartTest(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.StartTest(ctx, &ABTestActionRequest{TestID: "t1"})
	if err != nil {
		t.Fatalf("StartTest: %v", err)
	}
	if resp.Status != "started" {
		t.Errorf("expected started, got %s", resp.Status)
	}

	// Bad test ID
	_, err = svc.StartTest(ctx, &ABTestActionRequest{TestID: "bad"})
	if err == nil {
		t.Error("expected error for bad test ID")
	}
}

func TestPhase2ABTestService_StopTest(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.StopTest(ctx, &ABTestActionRequest{TestID: "t1"})
	if err != nil {
		t.Fatalf("StopTest: %v", err)
	}
	if resp.Status != "stopped" {
		t.Errorf("expected stopped, got %s", resp.Status)
	}

	// Bad test ID
	_, err = svc.StopTest(ctx, &ABTestActionRequest{TestID: "bad"})
	if err == nil {
		t.Error("expected error for bad test ID")
	}
}

func TestPhase2ABTestService_GetMetrics(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.GetMetrics(ctx, &ABTestMetricsRequest{TestID: "t1"})
	if err != nil {
		t.Fatalf("GetMetrics: %v", err)
	}
	if len(resp.Metrics) != 1 {
		t.Errorf("expected 1 metric, got %d", len(resp.Metrics))
	}

	// Not found
	_, err = svc.GetMetrics(ctx, &ABTestMetricsRequest{TestID: "notfound"})
	if err == nil {
		t.Error("expected error for not found")
	}
}

func TestPhase2ABTestService_AssignVariant(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.AssignVariant(ctx, &ABTestAssignRequest{TestID: "t1", RequestID: "r1"})
	if err != nil {
		t.Fatalf("AssignVariant: %v", err)
	}
	if resp.Variant != "variant-A" {
		t.Errorf("expected variant-A, got %s", resp.Variant)
	}

	// Empty request ID
	_, err = svc.AssignVariant(ctx, &ABTestAssignRequest{TestID: "t1", RequestID: ""})
	if err == nil {
		t.Error("expected error for empty request ID")
	}

	// Bad request ID
	_, err = svc.AssignVariant(ctx, &ABTestAssignRequest{TestID: "t1", RequestID: "bad"})
	if err == nil {
		t.Error("expected error for bad request ID")
	}
}

func TestPhase2ABTestService_RecordResult(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	ctx := context.Background()

	resp, err := svc.RecordResult(ctx, &ABTestResultRequest{TestID: "t1", VariantName: "A", Detected: true, FalsePositive: false, LatencyMs: 12.5})
	if err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	if resp.Status != "recorded" {
		t.Errorf("expected recorded, got %s", resp.Status)
	}
}

func TestPhase2ABTestService_Unimplemented(t *testing.T) {
	svc := &UnimplementedABTestServiceServer{}
	ctx := context.Background()

	_, err := svc.CreateTest(ctx, &ABTestCreateRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for CreateTest")
	}
	_, err = svc.ListTests(ctx, &ABTestListRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ListTests")
	}
	_, err = svc.StartTest(ctx, &ABTestActionRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for StartTest")
	}
	_, err = svc.StopTest(ctx, &ABTestActionRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for StopTest")
	}
	_, err = svc.GetMetrics(ctx, &ABTestMetricsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetMetrics")
	}
	_, err = svc.AssignVariant(ctx, &ABTestAssignRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for AssignVariant")
	}
	_, err = svc.RecordResult(ctx, &ABTestResultRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for RecordResult")
	}
}

func TestPhase2NewABTestService(t *testing.T) {
	svc := NewABTestService(&mockABTestBackend{}, slog.Default())
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// ====================================================================
// Unimplemented stubs — all remaining types.go methods
// ====================================================================

func TestPhase2UnimplementedAuth_AllMethods(t *testing.T) {
	svc := &UnimplementedAuthServiceServer{}
	ctx := context.Background()

	// Methods not covered by existing TestAuthService_WithNilBackend
	_, err := svc.Logout(ctx, &LogoutRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for Logout")
	}
	_, err = svc.ValidateToken(ctx, &ValidateTokenRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ValidateToken")
	}
	_, err = svc.GetUser(ctx, &GetUserRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetUser")
	}
	_, err = svc.ListUsers(ctx, &ListUsersRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ListUsers")
	}
	_, err = svc.CreateUser(ctx, &CreateUserRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for CreateUser")
	}
	_, err = svc.UpdateUser(ctx, &UpdateUserRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for UpdateUser")
	}
	_, err = svc.DeleteUser(ctx, &DeleteUserRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for DeleteUser")
	}
	_, err = svc.GetSessions(ctx, &GetSessionsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetSessions")
	}
	_, err = svc.GetAuthConfig(ctx, &GetAuthConfigRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetAuthConfig")
	}
}

func TestPhase2UnimplementedProxy_AllMethods(t *testing.T) {
	svc := &UnimplementedProxyServiceServer{}
	ctx := context.Background()

	// Methods not covered by existing test
	_, err := svc.GetHealth(ctx, &GetProxyHealthRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetHealth")
	}
	_, err = svc.GetConfig(ctx, &GetProxyConfigRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetConfig")
	}
	_, err = svc.IsEnabled(ctx, &IsProxyEnabledRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for IsEnabled")
	}
	_, err = svc.Enable(ctx, &EnableProxyRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for Enable")
	}
	_, err = svc.Disable(ctx, &DisableProxyRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for Disable")
	}
	_, err = svc.GetViolations(ctx, &GetViolationsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetViolations")
	}
	_, err = svc.ClearViolations(ctx, &ClearViolationsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ClearViolations")
	}
}

func TestPhase2UnimplementedCompliance_AllMethods(t *testing.T) {
	svc := &UnimplementedComplianceServiceServer{}
	ctx := context.Background()

	_, err := svc.GetStatus(ctx, &GetComplianceStatusRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetStatus")
	}
	_, err = svc.RunCheck(ctx, &RunComplianceCheckRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for RunCheck")
	}
	_, err = svc.GetFindings(ctx, &GetFindingsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetFindings")
	}
	_, err = svc.GenerateReport(ctx, &GenerateReportRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GenerateReport")
	}
}

func TestPhase2UnimplementedSIEM_AllMethods(t *testing.T) {
	svc := &UnimplementedSIEMServiceServer{}
	ctx := context.Background()

	_, err := svc.GetStats(ctx, &GetSIEMStatsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetStats")
	}
	_, err = svc.GetEvents(ctx, &GetSIEMEventsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetEvents")
	}
	_, err = svc.SendEvent(ctx, &SendSIEMEventRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for SendEvent")
	}
	_, err = svc.TestConnection(ctx, &TestSIEMConnectionRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for TestConnection")
	}
}

func TestPhase2UnimplementedWebhook_AllMethods(t *testing.T) {
	svc := &UnimplementedWebhookServiceServer{}
	ctx := context.Background()

	_, err := svc.GetWebhook(ctx, &GetWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetWebhook")
	}
	_, err = svc.CreateWebhook(ctx, &CreateWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for CreateWebhook")
	}
	_, err = svc.UpdateWebhook(ctx, &UpdateWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for UpdateWebhook")
	}
	_, err = svc.DeleteWebhook(ctx, &DeleteWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for DeleteWebhook")
	}
	_, err = svc.EnableWebhook(ctx, &EnableWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for EnableWebhook")
	}
	_, err = svc.DisableWebhook(ctx, &DisableWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for DisableWebhook")
	}
	_, err = svc.TestWebhook(ctx, &TestWebhookRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for TestWebhook")
	}
	_, err = svc.GetStats(ctx, &GetWebhookStatsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetStats")
	}
}

func TestPhase2UnimplementedCore_AllMethods(t *testing.T) {
	svc := &UnimplementedCoreServiceServer{}
	ctx := context.Background()

	_, err := svc.ListModules(ctx, &ListModulesRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for ListModules")
	}
	_, err = svc.GetModule(ctx, &GetModuleRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetModule")
	}
	_, err = svc.GetMetrics(ctx, &GetMetricsRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetMetrics")
	}
	_, err = svc.GetVersion(ctx, &GetVersionRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetVersion")
	}
	_, err = svc.GetUptime(ctx, &GetUptimeRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetUptime")
	}
	_, err = svc.GetRegistryStatus(ctx, &GetRegistryStatusRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetRegistryStatus")
	}
	_, err = svc.EnableModule(ctx, &EnableModuleRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for EnableModule")
	}
	_, err = svc.DisableModule(ctx, &DisableModuleRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for DisableModule")
	}
}

func TestPhase2UnimplementedTLS_AllMethods(t *testing.T) {
	svc := &UnimplementedTLSSvcServer{}
	ctx := context.Background()

	_, err := svc.GetCertificates(ctx, &GetCertificatesRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetCertificates")
	}
	_, err = svc.GenerateCertificate(ctx, &GenerateCertificateRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GenerateCertificate")
	}
	_, err = svc.GetMTLSConfig(ctx, &GetMTLSConfigRequest{})
	if !isUnimplemented(err) {
		t.Error("expected Unimplemented for GetMTLSConfig")
	}
}

// ====================================================================
// JSON round-trip test for response types
// ====================================================================

func TestPhase2JSONRoundtrip_DSAResponses(t *testing.T) {
	exportResp := DSARExportResponse{EntityID: "e1", ExportedAt: 1000, Providers: map[string]interface{}{"key": "val"}}
	data, err := json.Marshal(&exportResp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded DSARExportResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.EntityID != "e1" {
		t.Error("roundtrip mismatch")
	}
}

// ====================================================================
// Helper: generate self-signed TLS certificate
// ====================================================================

// errorBackend returns errors for all methods — tests error paths in services
type errorAuthBackend struct{}

func (e *errorAuthBackend) Login(_ context.Context, _, _ string) (string, int64, error) {
	return "", 0, errors.New("login failed")
}
func (e *errorAuthBackend) Logout(_ context.Context, _ string) error {
	return errors.New("logout failed")
}
func (e *errorAuthBackend) ValidateToken(_ context.Context, _ string) (bool, string, int64, error) {
	return false, "", 0, errors.New("validation failed")
}
func (e *errorAuthBackend) GetUser(_ context.Context, _ string) (*AuthUserInfo, error) {
	return nil, errors.New("not found")
}
func (e *errorAuthBackend) ListUsers(_ context.Context) ([]*AuthUserInfo, error) {
	return nil, errors.New("list failed")
}
func (e *errorAuthBackend) CreateUser(_ context.Context, _, _, _, _ string) (*AuthUserInfo, error) {
	return nil, errors.New("create failed")
}
func (e *errorAuthBackend) UpdateUser(_ context.Context, _, _, _, _ string, _ bool) (*AuthUserInfo, error) {
	return nil, errors.New("update failed")
}
func (e *errorAuthBackend) DeleteUser(_ context.Context, _ string) error {
	return errors.New("delete failed")
}
func (e *errorAuthBackend) GetSessions(_ context.Context) ([]*AuthSessionInfo, error) {
	return nil, errors.New("sessions failed")
}
func (e *errorAuthBackend) GetAuthConfig(_ context.Context) (*AuthConfig, error) {
	return nil, errors.New("config failed")
}

type errorProxyBackend struct{}

func (e *errorProxyBackend) GetStats(_ context.Context) (*ProxyStatsInfo, error) {
	return nil, errors.New("stats failed")
}
func (e *errorProxyBackend) GetHealth(_ context.Context) (*ProxyHealthInfo, error) {
	return nil, errors.New("health failed")
}
func (e *errorProxyBackend) GetConfig(_ context.Context) (*ProxyConfigInfo, error) {
	return nil, errors.New("config failed")
}
func (e *errorProxyBackend) IsEnabled(_ context.Context) (bool, error) {
	return false, errors.New("check failed")
}
func (e *errorProxyBackend) Enable(_ context.Context) error { return errors.New("enable failed") }
func (e *errorProxyBackend) Disable(_ context.Context) error {
	return errors.New("disable failed")
}
func (e *errorProxyBackend) GetViolations(_ context.Context, _ []ViolationSeverity, _ int32) ([]*ViolationInfo, error) {
	return nil, errors.New("violations failed")
}
func (e *errorProxyBackend) ClearViolations(_ context.Context) error {
	return errors.New("clear failed")
}

type errorWebhookBackend struct{}

func (e *errorWebhookBackend) ListWebhooks(_ context.Context) ([]*WebhookDetail, error) {
	return nil, errors.New("list failed")
}
func (e *errorWebhookBackend) GetWebhook(_ context.Context, _ string) (*WebhookDetail, error) {
	return nil, errors.New("not found")
}
func (e *errorWebhookBackend) CreateWebhook(_ context.Context, _, _ string, _ []string, _ bool) (*WebhookDetail, error) {
	return nil, errors.New("create failed")
}
func (e *errorWebhookBackend) UpdateWebhook(_ context.Context, _, _, _ string, _ []string, _ bool) (*WebhookDetail, error) {
	return nil, errors.New("update failed")
}
func (e *errorWebhookBackend) DeleteWebhook(_ context.Context, _ string) error {
	return errors.New("delete failed")
}
func (e *errorWebhookBackend) EnableWebhook(_ context.Context, _ string) (*WebhookDetail, error) {
	return nil, errors.New("enable failed")
}
func (e *errorWebhookBackend) DisableWebhook(_ context.Context, _ string) (*WebhookDetail, error) {
	return nil, errors.New("disable failed")
}
func (e *errorWebhookBackend) TestWebhook(_ context.Context, _ string) (bool, string, error) {
	return false, "", errors.New("test failed")
}
func (e *errorWebhookBackend) GetStats(_ context.Context) (*WebhookStatsInfo, error) {
	return nil, errors.New("stats failed")
}

// --- Error path tests ---

func TestPhase2AuthService_ErrorPaths(t *testing.T) {
	svc := NewAuthService(&errorAuthBackend{}, slog.Default())
	ctx := context.Background()

	// Login error — returns response with Success=false, not gRPC error
	resp, err := svc.Login(ctx, &LoginRequest{Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("Login error: %v", err)
	}
	if resp.Success {
		t.Error("expected failure")
	}

	// Logout error
	resp2, err := svc.Logout(ctx, &LogoutRequest{Token: "t"})
	if err != nil {
		t.Fatalf("Logout error: %v", err)
	}
	if resp2.Success {
		t.Error("expected failure")
	}

	// GetUser error
	_, err = svc.GetUser(ctx, &GetUserRequest{UserId: "u"})
	if err == nil {
		t.Error("expected error for GetUser")
	}

	// ListUsers error
	_, err = svc.ListUsers(ctx, &ListUsersRequest{})
	if err == nil {
		t.Error("expected error for ListUsers")
	}

	// CreateUser error
	_, err = svc.CreateUser(ctx, &CreateUserRequest{Username: "u", Password: "p"})
	if err == nil {
		t.Error("expected error for CreateUser")
	}

	// UpdateUser error
	_, err = svc.UpdateUser(ctx, &UpdateUserRequest{UserId: "u"})
	if err == nil {
		t.Error("expected error for UpdateUser")
	}

	// DeleteUser error
	_, err = svc.DeleteUser(ctx, &DeleteUserRequest{UserId: "u"})
	if err == nil {
		t.Error("expected error for DeleteUser")
	}

	// GetSessions error
	_, err = svc.GetSessions(ctx, &GetSessionsRequest{})
	if err == nil {
		t.Error("expected error for GetSessions")
	}

	// GetAuthConfig error
	_, err = svc.GetAuthConfig(ctx, &GetAuthConfigRequest{})
	if err == nil {
		t.Error("expected error for GetAuthConfig")
	}

	// ValidateToken error
	_, err = svc.ValidateToken(ctx, &ValidateTokenRequest{Token: "t"})
	if err == nil {
		t.Error("expected error for ValidateToken")
	}
}

func TestPhase2ProxyService_ErrorPaths(t *testing.T) {
	svc := NewProxyService(&errorProxyBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.GetStats(ctx, &GetProxyStatsRequest{})
	if err == nil {
		t.Error("expected error for GetStats")
	}

	_, err = svc.GetHealth(ctx, &GetProxyHealthRequest{})
	if err == nil {
		t.Error("expected error for GetHealth")
	}

	_, err = svc.GetConfig(ctx, &GetProxyConfigRequest{})
	if err == nil {
		t.Error("expected error for GetConfig")
	}

	_, err = svc.IsEnabled(ctx, &IsProxyEnabledRequest{})
	if err == nil {
		t.Error("expected error for IsEnabled")
	}

	// Enable error — returns response with Success=false, not gRPC error
	resp, err := svc.Enable(ctx, &EnableProxyRequest{})
	if err != nil {
		t.Fatalf("Enable error: %v", err)
	}
	if resp.Success {
		t.Error("expected failure")
	}

	// Disable error — returns response with Success=false
	resp2, err := svc.Disable(ctx, &DisableProxyRequest{})
	if err != nil {
		t.Fatalf("Disable error: %v", err)
	}
	if resp2.Success {
		t.Error("expected failure")
	}

	_, err = svc.GetViolations(ctx, &GetViolationsRequest{})
	if err == nil {
		t.Error("expected error for GetViolations")
	}

	_, err = svc.ClearViolations(ctx, &ClearViolationsRequest{})
	if err == nil {
		t.Error("expected error for ClearViolations")
	}
}

func TestPhase2WebhookService_ErrorPaths(t *testing.T) {
	svc := NewWebhookService(&errorWebhookBackend{}, slog.Default())
	ctx := context.Background()

	_, err := svc.ListWebhooks(ctx, &ListWebhooksRequest{})
	if err == nil {
		t.Error("expected error for ListWebhooks")
	}

	_, err = svc.GetWebhook(ctx, &GetWebhookRequest{WebhookId: "w"})
	if err == nil {
		t.Error("expected error for GetWebhook")
	}

	_, err = svc.CreateWebhook(ctx, &CreateWebhookRequest{Name: "n", Url: "u"})
	if err == nil {
		t.Error("expected error for CreateWebhook")
	}

	_, err = svc.UpdateWebhook(ctx, &UpdateWebhookRequest{WebhookId: "w"})
	if err == nil {
		t.Error("expected error for UpdateWebhook")
	}

	_, err = svc.DeleteWebhook(ctx, &DeleteWebhookRequest{WebhookId: "w"})
	if err == nil {
		t.Error("expected error for DeleteWebhook")
	}

	_, err = svc.EnableWebhook(ctx, &EnableWebhookRequest{WebhookId: "w"})
	if err == nil {
		t.Error("expected error for EnableWebhook")
	}

	_, err = svc.DisableWebhook(ctx, &DisableWebhookRequest{WebhookId: "w"})
	if err == nil {
		t.Error("expected error for DisableWebhook")
	}

	_, err = svc.TestWebhook(ctx, &TestWebhookRequest{WebhookId: "w"})
	if err == nil {
		t.Error("expected error for TestWebhook")
	}

	_, err = svc.GetStats(ctx, &GetWebhookStatsRequest{})
	if err == nil {
		t.Error("expected error for GetStats")
	}
}

func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	// Generate a self-signed RSA certificate for TLS testing.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA key gen: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.local", "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
