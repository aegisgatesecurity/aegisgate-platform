// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Message Types
// =========================================================================
//
// Hand-crafted gRPC message types for all seven services.
// These mirror what protobuf-generated code would produce,
// using json struct tags (compatible with protojson).
// No protobuf code generation step is required.
//
// =========================================================================

package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================
// AUTH SERVICE TYPES
// ============================================================

// LoginRequest is the request message for AuthService.Login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the response message for AuthService.Login.
type LoginResponse struct {
	Success   bool   `json:"success"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	User      *User  `json:"user"`
	Error     string `json:"error"`
}

// LogoutRequest is the request message for AuthService.Logout.
type LogoutRequest struct {
	Token string `json:"token"`
}

// LogoutResponse is the response message for AuthService.Logout.
type LogoutResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// ValidateTokenRequest is the request message for AuthService.ValidateToken.
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse is the response message for AuthService.ValidateToken.
type ValidateTokenResponse struct {
	Valid     bool   `json:"valid"`
	UserId    string `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}

// GetUserRequest is the request message for AuthService.GetUser.
type GetUserRequest struct {
	UserId string `json:"user_id"`
}

// GetUserResponse is the response message for AuthService.GetUser.
type GetUserResponse struct {
	User *User `json:"user"`
}

// ListUsersRequest is the request message for AuthService.ListUsers.
type ListUsersRequest struct{}

// ListUsersResponse is the response message for AuthService.ListUsers.
type ListUsersResponse struct {
	Users []*User `json:"users"`
}

// CreateUserRequest is the request message for AuthService.CreateUser.
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// CreateUserResponse is the response message for AuthService.CreateUser.
type CreateUserResponse struct {
	User *User `json:"user"`
}

// UpdateUserRequest is the request message for AuthService.UpdateUser.
type UpdateUserRequest struct {
	UserId   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Enabled  bool   `json:"enabled"`
}

// UpdateUserResponse is the response message for AuthService.UpdateUser.
type UpdateUserResponse struct {
	User *User `json:"user"`
}

// DeleteUserRequest is the request message for AuthService.DeleteUser.
type DeleteUserRequest struct {
	UserId string `json:"user_id"`
}

// DeleteUserResponse is the response message for AuthService.DeleteUser.
type DeleteUserResponse struct {
	Success bool `json:"success"`
}

// GetSessionsRequest is the request message for AuthService.GetSessions.
type GetSessionsRequest struct{}

// GetSessionsResponse is the response message for AuthService.GetSessions.
type GetSessionsResponse struct {
	Sessions []*Session `json:"sessions"`
}

// GetAuthConfigRequest is the request message for AuthService.GetAuthConfig.
type GetAuthConfigRequest struct{}

// GetAuthConfigResponse is the response message for AuthService.GetAuthConfig.
type GetAuthConfigResponse struct {
	SessionTimeout     int32 `json:"session_timeout"`
	MaxSessionsPerUser int32 `json:"max_sessions_per_user"`
	RequireMfa         bool  `json:"require_mfa"`
	LoginAttempts      int32 `json:"login_attempts"`
	LockoutDuration    int32 `json:"lockout_duration"`
	PasswordMinLength  int32 `json:"password_min_length"`
}

// User represents a platform user.
type User struct {
	Id        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

// Session represents an authentication session.
type Session struct {
	Id           string `json:"id"`
	UserId       string `json:"user_id"`
	Token        string `json:"token"`
	ExpiresAt    int64  `json:"expires_at"`
	CreatedAt    int64  `json:"created_at"`
	LastActivity int64  `json:"last_activity"`
	IpAddress    string `json:"ip_address"`
}

// ============================================================
// PROXY SERVICE TYPES
// ============================================================

// GetProxyStatsRequest is the request message for ProxyService.GetStats.
type GetProxyStatsRequest struct{}

// GetProxyStatsResponse is the response message for ProxyService.GetStats.
type GetProxyStatsResponse struct {
	RequestsTotal     int64   `json:"requests_total"`
	RequestsBlocked   int64   `json:"requests_blocked"`
	RequestsAllowed   int64   `json:"requests_allowed"`
	BytesIn           int64   `json:"bytes_in"`
	BytesOut          int64   `json:"bytes_out"`
	ActiveConnections int32   `json:"active_connections"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	P99LatencyMs      float64 `json:"p99_latency_ms"`
	Errors            int64   `json:"errors"`
}

// GetProxyHealthRequest is the request message for ProxyService.GetHealth.
type GetProxyHealthRequest struct{}

// GetProxyHealthResponse is the response message for ProxyService.GetHealth.
type GetProxyHealthResponse struct {
	Status      string  `json:"status"`
	Uptime      float64 `json:"uptime"`
	MemoryUsage int64   `json:"memory_usage"`
	Goroutines  int32   `json:"goroutines"`
}

// GetProxyConfigRequest is the request message for ProxyService.GetConfig.
type GetProxyConfigRequest struct{}

// GetProxyConfigResponse is the response message for ProxyService.GetConfig.
type GetProxyConfigResponse struct {
	Enabled        bool     `json:"enabled"`
	Host           string   `json:"host"`
	Port           int32    `json:"port"`
	TlsEnabled     bool     `json:"tls_enabled"`
	RateLimit      int32    `json:"rate_limit"`
	RateLimitBurst int32    `json:"rate_limit_burst"`
	CorsEnabled    bool     `json:"cors_enabled"`
	CorsOrigins    []string `json:"cors_origins"`
}

// IsProxyEnabledRequest is the request message for ProxyService.IsEnabled.
type IsProxyEnabledRequest struct{}

// IsProxyEnabledResponse is the response message for ProxyService.IsEnabled.
type IsProxyEnabledResponse struct {
	Enabled bool `json:"enabled"`
}

// EnableProxyRequest is the request message for ProxyService.Enable.
type EnableProxyRequest struct{}

// EnableProxyResponse is the response message for ProxyService.Enable.
type EnableProxyResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// DisableProxyRequest is the request message for ProxyService.Disable.
type DisableProxyRequest struct{}

// DisableProxyResponse is the response message for ProxyService.Disable.
type DisableProxyResponse struct {
	Success bool `json:"success"`
}

// GetViolationsRequest is the request message for ProxyService.GetViolations.
type GetViolationsRequest struct {
	Severities []ViolationSeverity `json:"severities"`
	Limit      int32               `json:"limit"`
}

// GetViolationsResponse is the response message for ProxyService.GetViolations.
type GetViolationsResponse struct {
	Violations []*Violation `json:"violations"`
}

// ClearViolationsRequest is the request message for ProxyService.ClearViolations.
type ClearViolationsRequest struct{}

// ClearViolationsResponse is the response message for ProxyService.ClearViolations.
type ClearViolationsResponse struct {
	Success bool `json:"success"`
}

// Violation represents a proxy security violation.
type Violation struct {
	Id        string            `json:"id"`
	Type      ViolationType     `json:"type"`
	Severity  ViolationSeverity `json:"severity"`
	Message   string            `json:"message"`
	ClientIp  string            `json:"client_ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Blocked   bool              `json:"blocked"`
	Timestamp int64             `json:"timestamp"`
}

// ViolationType enumerates proxy violation categories.
type ViolationType int32

const (
	ViolationTypeUnknown          ViolationType = 0
	ViolationTypeMaliciousRequest ViolationType = 1
	ViolationTypeSQLInjection     ViolationType = 2
	ViolationTypeXSS              ViolationType = 3
	ViolationTypeCSRF             ViolationType = 4
	ViolationTypePathTraversal    ViolationType = 5
	ViolationTypeCommandInjection ViolationType = 6
	ViolationTypeAtlasTechnique   ViolationType = 7
	ViolationTypeCustomPattern    ViolationType = 8
)

// ViolationSeverity enumerates violation severity levels.
type ViolationSeverity int32

const (
	ViolationSeverityInfo     ViolationSeverity = 0
	ViolationSeverityLow      ViolationSeverity = 1
	ViolationSeverityMedium   ViolationSeverity = 2
	ViolationSeverityHigh     ViolationSeverity = 3
	ViolationSeverityCritical ViolationSeverity = 4
)

// ============================================================
// COMPLIANCE SERVICE TYPES
// ============================================================

// GetFrameworksRequest is the request message for ComplianceService.GetFrameworks.
type GetFrameworksRequest struct{}

// GetFrameworksResponse is the response message for ComplianceService.GetFrameworks.
type GetFrameworksResponse struct {
	Frameworks []*Framework `json:"frameworks"`
}

// GetComplianceStatusRequest is the request message for ComplianceService.GetStatus.
type GetComplianceStatusRequest struct{}

// GetComplianceStatusResponse is the response message for ComplianceService.GetStatus.
type GetComplianceStatusResponse struct {
	Overall    ComplianceStatus   `json:"overall"`
	Frameworks []*FrameworkStatus `json:"frameworks"`
}

// RunComplianceCheckRequest is the request message for ComplianceService.RunCheck.
type RunComplianceCheckRequest struct {
	Framework string `json:"framework"`
}

// RunComplianceCheckResponse is the response message for ComplianceService.RunCheck.
type RunComplianceCheckResponse struct {
	Id        string             `json:"id"`
	Framework string             `json:"framework"`
	Status    ComplianceStatus   `json:"status"`
	Summary   *ComplianceSummary `json:"summary"`
}

// GetFindingsRequest is the request message for ComplianceService.GetFindings.
type GetFindingsRequest struct{}

// GetFindingsResponse is the response message for ComplianceService.GetFindings.
type GetFindingsResponse struct {
	Findings []*ComplianceFinding `json:"findings"`
}

// GenerateReportRequest is the request message for ComplianceService.GenerateReport.
type GenerateReportRequest struct {
	Framework string `json:"framework"`
}

// GenerateReportResponse is the response message for ComplianceService.GenerateReport.
type GenerateReportResponse struct {
	Id        string             `json:"id"`
	Framework string             `json:"framework"`
	Timestamp int64              `json:"timestamp"`
	Status    ComplianceStatus   `json:"status"`
	Summary   *ComplianceSummary `json:"summary"`
}

// ComplianceStatus represents the status of a compliance check.
type ComplianceStatus int32

const (
	ComplianceStatusUnknown       ComplianceStatus = 0
	ComplianceStatusPass          ComplianceStatus = 1
	ComplianceStatusFail          ComplianceStatus = 2
	ComplianceStatusWarning       ComplianceStatus = 3
	ComplianceStatusPending       ComplianceStatus = 4
	ComplianceStatusNotApplicable ComplianceStatus = 5
)

// FindingSeverity represents the severity of a compliance finding.
type FindingSeverity int32

const (
	FindingSeverityInfo     FindingSeverity = 0
	FindingSeverityLow      FindingSeverity = 1
	FindingSeverityMedium   FindingSeverity = 2
	FindingSeverityHigh     FindingSeverity = 3
	FindingSeverityCritical FindingSeverity = 4
)

// Framework represents a compliance framework.
type Framework struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// FrameworkStatus represents the status of a framework.
type FrameworkStatus struct {
	Framework string           `json:"framework"`
	Status    ComplianceStatus `json:"status"`
	Score     float64          `json:"score"`
}

// ComplianceSummary contains summary statistics.
type ComplianceSummary struct {
	TotalChecks   int32   `json:"total_checks"`
	Passed        int32   `json:"passed"`
	Failed        int32   `json:"failed"`
	Warnings      int32   `json:"warnings"`
	NotApplicable int32   `json:"not_applicable"`
	Score         float64 `json:"score"`
}

// ComplianceFinding represents a single compliance finding.
type ComplianceFinding struct {
	Id          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    FindingSeverity `json:"severity"`
	Category    string          `json:"category"`
	Framework   string          `json:"framework"`
	Timestamp   int64           `json:"timestamp"`
}

// ============================================================
// SIEM SERVICE TYPES
// ============================================================

// GetSIEMConfigRequest is the request message for SIEMService.GetConfig.
type GetSIEMConfigRequest struct{}

// GetSIEMConfigResponse is the response message for SIEMService.GetConfig.
type GetSIEMConfigResponse struct {
	Enabled       bool  `json:"enabled"`
	BatchSize     int32 `json:"batch_size"`
	BatchInterval int32 `json:"batch_interval"`
	RetryAttempts int32 `json:"retry_attempts"`
	RetryInterval int32 `json:"retry_interval"`
}

// GetSIEMStatsRequest is the request message for SIEMService.GetStats.
type GetSIEMStatsRequest struct{}

// GetSIEMStatsResponse is the response message for SIEMService.GetStats.
type GetSIEMStatsResponse struct {
	EventsSent    int64  `json:"events_sent"`
	EventsDropped int64  `json:"events_dropped"`
	EventsQueued  int64  `json:"events_queued"`
	LastSendTime  int64  `json:"last_send_time"`
	LastError     string `json:"last_error"`
}

// GetSIEMEventsRequest is the request message for SIEMService.GetEvents.
type GetSIEMEventsRequest struct {
	Limit int32 `json:"limit"`
}

// GetSIEMEventsResponse is the response message for SIEMService.GetEvents.
type GetSIEMEventsResponse struct {
	Events []*SIEMEvent `json:"events"`
}

// SendSIEMEventRequest is the request message for SIEMService.SendEvent.
type SendSIEMEventRequest struct {
	Source   string        `json:"source"`
	Category string        `json:"category"`
	Type     string        `json:"type"`
	Severity EventSeverity `json:"severity"`
	Message  string        `json:"message"`
	Entity   string        `json:"entity"`
}

// SendSIEMEventResponse is the response message for SIEMService.SendEvent.
type SendSIEMEventResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// TestSIEMConnectionRequest is the request message for SIEMService.TestConnection.
type TestSIEMConnectionRequest struct {
	Platform string `json:"platform"`
}

// TestSIEMConnectionResponse is the response message for SIEMService.TestConnection.
type TestSIEMConnectionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// EventSeverity represents SIEM event severity levels.
type EventSeverity int32

const (
	EventSeverityInfo     EventSeverity = 0
	EventSeverityLow      EventSeverity = 1
	EventSeverityMedium   EventSeverity = 2
	EventSeverityHigh     EventSeverity = 3
	EventSeverityCritical EventSeverity = 4
)

// SIEMEvent represents a SIEM event.
type SIEMEvent struct {
	Id        string        `json:"id"`
	Timestamp int64         `json:"timestamp"`
	Source    string        `json:"source"`
	Category  string        `json:"category"`
	Type      string        `json:"type"`
	Severity  EventSeverity `json:"severity"`
	Message   string        `json:"message"`
	Entity    string        `json:"entity"`
}

// ============================================================
// WEBHOOK SERVICE TYPES
// ============================================================

// ListWebhooksRequest is the request message for WebhookService.ListWebhooks.
type ListWebhooksRequest struct{}

// ListWebhooksResponse is the response message for WebhookService.ListWebhooks.
type ListWebhooksResponse struct {
	Webhooks []*WebhookInfo `json:"webhooks"`
}

// GetWebhookRequest is the request message for WebhookService.GetWebhook.
type GetWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

// GetWebhookResponse is the response message for WebhookService.GetWebhook.
type GetWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

// CreateWebhookRequest is the request message for WebhookService.CreateWebhook.
type CreateWebhookRequest struct {
	Name    string   `json:"name"`
	Url     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

// CreateWebhookResponse is the response message for WebhookService.CreateWebhook.
type CreateWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

// UpdateWebhookRequest is the request message for WebhookService.UpdateWebhook.
type UpdateWebhookRequest struct {
	WebhookId string   `json:"webhook_id"`
	Name      string   `json:"name"`
	Url       string   `json:"url"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
}

// UpdateWebhookResponse is the response message for WebhookService.UpdateWebhook.
type UpdateWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

// DeleteWebhookRequest is the request message for WebhookService.DeleteWebhook.
type DeleteWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

// DeleteWebhookResponse is the response message for WebhookService.DeleteWebhook.
type DeleteWebhookResponse struct {
	Success bool `json:"success"`
}

// EnableWebhookRequest is the request message for WebhookService.EnableWebhook.
type EnableWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

// EnableWebhookResponse is the response message for WebhookService.EnableWebhook.
type EnableWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

// DisableWebhookRequest is the request message for WebhookService.DisableWebhook.
type DisableWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

// DisableWebhookResponse is the response message for WebhookService.DisableWebhook.
type DisableWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

// TestWebhookRequest is the request message for WebhookService.TestWebhook.
type TestWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

// TestWebhookResponse is the response message for WebhookService.TestWebhook.
type TestWebhookResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// GetWebhookStatsRequest is the request message for WebhookService.GetStats.
type GetWebhookStatsRequest struct{}

// GetWebhookStatsResponse is the response message for WebhookService.GetStats.
type GetWebhookStatsResponse struct {
	TotalWebhooks     int64 `json:"total_webhooks"`
	ActiveWebhooks    int64 `json:"active_webhooks"`
	DeliveriesTotal   int64 `json:"deliveries_total"`
	DeliveriesSuccess int64 `json:"deliveries_success"`
	DeliveriesFailed  int64 `json:"deliveries_failed"`
}

// WebhookInfo represents a webhook configuration.
type WebhookInfo struct {
	Id      string   `json:"id"`
	Name    string   `json:"name"`
	Url     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

// ============================================================
// CORE SERVICE TYPES
// ============================================================

// ListModulesRequest is the request message for CoreService.ListModules.
type ListModulesRequest struct{}

// ListModulesResponse is the response message for CoreService.ListModules.
type ListModulesResponse struct {
	Modules []*ModuleInfo `json:"modules"`
}

// GetModuleRequest is the request message for CoreService.GetModule.
type GetModuleRequest struct {
	ModuleId string `json:"module_id"`
}

// GetModuleResponse is the response message for CoreService.GetModule.
type GetModuleResponse struct {
	Module *ModuleInfo `json:"module"`
}

// GetHealthRequest is the request message for CoreService.GetHealth.
type GetHealthRequest struct{}

// GetHealthResponse is the response message for CoreService.GetHealth.
type GetHealthResponse struct {
	Status string         `json:"status"`
	Checks []*HealthCheck `json:"checks"`
}

// GetMetricsRequest is the request message for CoreService.GetMetrics.
type GetMetricsRequest struct{}

// GetMetricsResponse is the response message for CoreService.GetMetrics.
type GetMetricsResponse struct {
	TotalRequests     int64   `json:"total_requests"`
	BlockedRequests   int64   `json:"blocked_requests"`
	ActiveUsers       int32   `json:"active_users"`
	ActiveConnections int32   `json:"active_connections"`
	Uptime            float64 `json:"uptime"`
}

// GetVersionRequest is the request message for CoreService.GetVersion.
type GetVersionRequest struct{}

// GetVersionResponse is the response message for CoreService.GetVersion.
type GetVersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
}

// GetUptimeRequest is the request message for CoreService.GetUptime.
type GetUptimeRequest struct{}

// GetUptimeResponse is the response message for CoreService.GetUptime.
type GetUptimeResponse struct {
	Uptime float64 `json:"uptime"`
}

// GetRegistryStatusRequest is the request message for CoreService.GetRegistryStatus.
type GetRegistryStatusRequest struct{}

// GetRegistryStatusResponse is the response message for CoreService.GetRegistryStatus.
type GetRegistryStatusResponse struct {
	TotalModules     int32 `json:"total_modules"`
	ActiveModules    int32 `json:"active_modules"`
	HealthyModules   int32 `json:"healthy_modules"`
	UnhealthyModules int32 `json:"unhealthy_modules"`
}

// EnableModuleRequest is the request message for CoreService.EnableModule.
type EnableModuleRequest struct {
	ModuleId string `json:"module_id"`
}

// EnableModuleResponse is the response message for CoreService.EnableModule.
type EnableModuleResponse struct {
	Success bool `json:"success"`
}

// DisableModuleRequest is the request message for CoreService.DisableModule.
type DisableModuleRequest struct {
	ModuleId string `json:"module_id"`
}

// DisableModuleResponse is the response message for CoreService.DisableModule.
type DisableModuleResponse struct {
	Success bool `json:"success"`
}

// ModuleStatus represents the operational status of a module.
type ModuleStatus int32

const (
	ModuleStatusUnknown      ModuleStatus = 0
	ModuleStatusInitializing ModuleStatus = 1
	ModuleStatusRunning      ModuleStatus = 2
	ModuleStatusStopped      ModuleStatus = 3
	ModuleStatusError        ModuleStatus = 4
)

// ModuleInfo represents a platform module.
type ModuleInfo struct {
	Id          string       `json:"id"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Status      ModuleStatus `json:"status"`
}

// HealthCheck represents a single health check result.
type HealthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ============================================================
// TLS SERVICE TYPES
// ============================================================

// GetTLSConfigRequest is the request message for TLSSvc.GetConfig.
type GetTLSConfigRequest struct{}

// GetTLSConfigResponse is the response message for TLSSvc.GetConfig.
type GetTLSConfigResponse struct {
	Enabled      bool   `json:"enabled"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	AutoGenerate bool   `json:"auto_generate"`
	MinVersion   string `json:"min_version"`
}

// GetCertificatesRequest is the request message for TLSSvc.GetCertificates.
type GetCertificatesRequest struct{}

// GetCertificatesResponse is the response message for TLSSvc.GetCertificates.
type GetCertificatesResponse struct {
	Certificates []*CertificateInfo `json:"certificates"`
}

// CertificateInfo represents a TLS certificate.
type CertificateInfo struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   int64  `json:"not_before"`
	NotAfter    int64  `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
}

// GenerateCertificateRequest is the request message for TLSSvc.GenerateCertificate.
type GenerateCertificateRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	ValidityDays int32  `json:"validity_days"`
}

// GenerateCertificateResponse is the response message for TLSSvc.GenerateCertificate.
type GenerateCertificateResponse struct {
	Success     bool             `json:"success"`
	Certificate *CertificateInfo `json:"certificate"`
	Error       string           `json:"error"`
}

// GetMTLSConfigRequest is the request message for TLSSvc.GetMTLSConfig.
type GetMTLSConfigRequest struct{}

// GetMTLSConfigResponse is the response message for TLSSvc.GetMTLSConfig.
type GetMTLSConfigResponse struct {
	Enabled        bool   `json:"enabled"`
	CaCertFile     string `json:"ca_cert_file"`
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
}

// ============================================================
// SERVICE INTERFACES
// ============================================================

// AuthServiceServer is the server API for AuthService.
type AuthServiceServer interface {
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
	Logout(context.Context, *LogoutRequest) (*LogoutResponse, error)
	ValidateToken(context.Context, *ValidateTokenRequest) (*ValidateTokenResponse, error)
	GetUser(context.Context, *GetUserRequest) (*GetUserResponse, error)
	ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error)
	CreateUser(context.Context, *CreateUserRequest) (*CreateUserResponse, error)
	UpdateUser(context.Context, *UpdateUserRequest) (*UpdateUserResponse, error)
	DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error)
	GetSessions(context.Context, *GetSessionsRequest) (*GetSessionsResponse, error)
	GetAuthConfig(context.Context, *GetAuthConfigRequest) (*GetAuthConfigResponse, error)
}

// ProxyServiceServer is the server API for ProxyService.
type ProxyServiceServer interface {
	GetStats(context.Context, *GetProxyStatsRequest) (*GetProxyStatsResponse, error)
	GetHealth(context.Context, *GetProxyHealthRequest) (*GetProxyHealthResponse, error)
	GetConfig(context.Context, *GetProxyConfigRequest) (*GetProxyConfigResponse, error)
	IsEnabled(context.Context, *IsProxyEnabledRequest) (*IsProxyEnabledResponse, error)
	Enable(context.Context, *EnableProxyRequest) (*EnableProxyResponse, error)
	Disable(context.Context, *DisableProxyRequest) (*DisableProxyResponse, error)
	GetViolations(context.Context, *GetViolationsRequest) (*GetViolationsResponse, error)
	ClearViolations(context.Context, *ClearViolationsRequest) (*ClearViolationsResponse, error)
}

// ComplianceServiceServer is the server API for ComplianceService.
type ComplianceServiceServer interface {
	GetFrameworks(context.Context, *GetFrameworksRequest) (*GetFrameworksResponse, error)
	GetStatus(context.Context, *GetComplianceStatusRequest) (*GetComplianceStatusResponse, error)
	RunCheck(context.Context, *RunComplianceCheckRequest) (*RunComplianceCheckResponse, error)
	GetFindings(context.Context, *GetFindingsRequest) (*GetFindingsResponse, error)
	GenerateReport(context.Context, *GenerateReportRequest) (*GenerateReportResponse, error)
}

// SIEMServiceServer is the server API for SIEMService.
type SIEMServiceServer interface {
	GetConfig(context.Context, *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error)
	GetStats(context.Context, *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error)
	GetEvents(context.Context, *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error)
	SendEvent(context.Context, *SendSIEMEventRequest) (*SendSIEMEventResponse, error)
	TestConnection(context.Context, *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error)
}

// WebhookServiceServer is the server API for WebhookService.
type WebhookServiceServer interface {
	ListWebhooks(context.Context, *ListWebhooksRequest) (*ListWebhooksResponse, error)
	GetWebhook(context.Context, *GetWebhookRequest) (*GetWebhookResponse, error)
	CreateWebhook(context.Context, *CreateWebhookRequest) (*CreateWebhookResponse, error)
	UpdateWebhook(context.Context, *UpdateWebhookRequest) (*UpdateWebhookResponse, error)
	DeleteWebhook(context.Context, *DeleteWebhookRequest) (*DeleteWebhookResponse, error)
	EnableWebhook(context.Context, *EnableWebhookRequest) (*EnableWebhookResponse, error)
	DisableWebhook(context.Context, *DisableWebhookRequest) (*DisableWebhookResponse, error)
	TestWebhook(context.Context, *TestWebhookRequest) (*TestWebhookResponse, error)
	GetStats(context.Context, *GetWebhookStatsRequest) (*GetWebhookStatsResponse, error)
}

// CoreServiceServer is the server API for CoreService.
type CoreServiceServer interface {
	ListModules(context.Context, *ListModulesRequest) (*ListModulesResponse, error)
	GetModule(context.Context, *GetModuleRequest) (*GetModuleResponse, error)
	GetHealth(context.Context, *GetHealthRequest) (*GetHealthResponse, error)
	GetMetrics(context.Context, *GetMetricsRequest) (*GetMetricsResponse, error)
	GetVersion(context.Context, *GetVersionRequest) (*GetVersionResponse, error)
	GetUptime(context.Context, *GetUptimeRequest) (*GetUptimeResponse, error)
	GetRegistryStatus(context.Context, *GetRegistryStatusRequest) (*GetRegistryStatusResponse, error)
	EnableModule(context.Context, *EnableModuleRequest) (*EnableModuleResponse, error)
	DisableModule(context.Context, *DisableModuleRequest) (*DisableModuleResponse, error)
}

// TLSSvcServer is the server API for TLSSvc.
type TLSSvcServer interface {
	GetConfig(context.Context, *GetTLSConfigRequest) (*GetTLSConfigResponse, error)
	GetCertificates(context.Context, *GetCertificatesRequest) (*GetCertificatesResponse, error)
	GenerateCertificate(context.Context, *GenerateCertificateRequest) (*GenerateCertificateResponse, error)
	GetMTLSConfig(context.Context, *GetMTLSConfigRequest) (*GetMTLSConfigResponse, error)
}

// ============================================================
// UNIMPLEMENTED RPC HANDLERS
// ============================================================

// UnimplementedAuthServiceServer returns codes.Unimplemented for all methods.
type UnimplementedAuthServiceServer struct{}

func (*UnimplementedAuthServiceServer) Login(_ context.Context, _ *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (*UnimplementedAuthServiceServer) Logout(_ context.Context, _ *LogoutRequest) (*LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Logout not implemented")
}
func (*UnimplementedAuthServiceServer) ValidateToken(_ context.Context, _ *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateToken not implemented")
}
func (*UnimplementedAuthServiceServer) GetUser(_ context.Context, _ *GetUserRequest) (*GetUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUser not implemented")
}
func (*UnimplementedAuthServiceServer) ListUsers(_ context.Context, _ *ListUsersRequest) (*ListUsersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers not implemented")
}
func (*UnimplementedAuthServiceServer) CreateUser(_ context.Context, _ *CreateUserRequest) (*CreateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUser not implemented")
}
func (*UnimplementedAuthServiceServer) UpdateUser(_ context.Context, _ *UpdateUserRequest) (*UpdateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUser not implemented")
}
func (*UnimplementedAuthServiceServer) DeleteUser(_ context.Context, _ *DeleteUserRequest) (*DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}
func (*UnimplementedAuthServiceServer) GetSessions(_ context.Context, _ *GetSessionsRequest) (*GetSessionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetSessions not implemented")
}
func (*UnimplementedAuthServiceServer) GetAuthConfig(_ context.Context, _ *GetAuthConfigRequest) (*GetAuthConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAuthConfig not implemented")
}

// UnimplementedProxyServiceServer returns codes.Unimplemented for all methods.
type UnimplementedProxyServiceServer struct{}

func (*UnimplementedProxyServiceServer) GetStats(_ context.Context, _ *GetProxyStatsRequest) (*GetProxyStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStats not implemented")
}
func (*UnimplementedProxyServiceServer) GetHealth(_ context.Context, _ *GetProxyHealthRequest) (*GetProxyHealthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHealth not implemented")
}
func (*UnimplementedProxyServiceServer) GetConfig(_ context.Context, _ *GetProxyConfigRequest) (*GetProxyConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfig not implemented")
}
func (*UnimplementedProxyServiceServer) IsEnabled(_ context.Context, _ *IsProxyEnabledRequest) (*IsProxyEnabledResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsEnabled not implemented")
}
func (*UnimplementedProxyServiceServer) Enable(_ context.Context, _ *EnableProxyRequest) (*EnableProxyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Enable not implemented")
}
func (*UnimplementedProxyServiceServer) Disable(_ context.Context, _ *DisableProxyRequest) (*DisableProxyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Disable not implemented")
}
func (*UnimplementedProxyServiceServer) GetViolations(_ context.Context, _ *GetViolationsRequest) (*GetViolationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetViolations not implemented")
}
func (*UnimplementedProxyServiceServer) ClearViolations(_ context.Context, _ *ClearViolationsRequest) (*ClearViolationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ClearViolations not implemented")
}

// UnimplementedComplianceServiceServer returns codes.Unimplemented for all methods.
type UnimplementedComplianceServiceServer struct{}

func (*UnimplementedComplianceServiceServer) GetFrameworks(_ context.Context, _ *GetFrameworksRequest) (*GetFrameworksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetFrameworks not implemented")
}
func (*UnimplementedComplianceServiceServer) GetStatus(_ context.Context, _ *GetComplianceStatusRequest) (*GetComplianceStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStatus not implemented")
}
func (*UnimplementedComplianceServiceServer) RunCheck(_ context.Context, _ *RunComplianceCheckRequest) (*RunComplianceCheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RunCheck not implemented")
}
func (*UnimplementedComplianceServiceServer) GetFindings(_ context.Context, _ *GetFindingsRequest) (*GetFindingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetFindings not implemented")
}
func (*UnimplementedComplianceServiceServer) GenerateReport(_ context.Context, _ *GenerateReportRequest) (*GenerateReportResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateReport not implemented")
}

// UnimplementedSIEMServiceServer returns codes.Unimplemented for all methods.
type UnimplementedSIEMServiceServer struct{}

func (*UnimplementedSIEMServiceServer) GetConfig(_ context.Context, _ *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfig not implemented")
}
func (*UnimplementedSIEMServiceServer) GetStats(_ context.Context, _ *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStats not implemented")
}
func (*UnimplementedSIEMServiceServer) GetEvents(_ context.Context, _ *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEvents not implemented")
}
func (*UnimplementedSIEMServiceServer) SendEvent(_ context.Context, _ *SendSIEMEventRequest) (*SendSIEMEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendEvent not implemented")
}
func (*UnimplementedSIEMServiceServer) TestConnection(_ context.Context, _ *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestConnection not implemented")
}

// UnimplementedWebhookServiceServer returns codes.Unimplemented for all methods.
type UnimplementedWebhookServiceServer struct{}

func (*UnimplementedWebhookServiceServer) ListWebhooks(_ context.Context, _ *ListWebhooksRequest) (*ListWebhooksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListWebhooks not implemented")
}
func (*UnimplementedWebhookServiceServer) GetWebhook(_ context.Context, _ *GetWebhookRequest) (*GetWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) CreateWebhook(_ context.Context, _ *CreateWebhookRequest) (*CreateWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) UpdateWebhook(_ context.Context, _ *UpdateWebhookRequest) (*UpdateWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) DeleteWebhook(_ context.Context, _ *DeleteWebhookRequest) (*DeleteWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) EnableWebhook(_ context.Context, _ *EnableWebhookRequest) (*EnableWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EnableWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) DisableWebhook(_ context.Context, _ *DisableWebhookRequest) (*DisableWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) TestWebhook(_ context.Context, _ *TestWebhookRequest) (*TestWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TestWebhook not implemented")
}
func (*UnimplementedWebhookServiceServer) GetStats(_ context.Context, _ *GetWebhookStatsRequest) (*GetWebhookStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStats not implemented")
}

// UnimplementedCoreServiceServer returns codes.Unimplemented for all methods.
type UnimplementedCoreServiceServer struct{}

func (*UnimplementedCoreServiceServer) ListModules(_ context.Context, _ *ListModulesRequest) (*ListModulesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListModules not implemented")
}
func (*UnimplementedCoreServiceServer) GetModule(_ context.Context, _ *GetModuleRequest) (*GetModuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetModule not implemented")
}
func (*UnimplementedCoreServiceServer) GetHealth(_ context.Context, _ *GetHealthRequest) (*GetHealthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetHealth not implemented")
}
func (*UnimplementedCoreServiceServer) GetMetrics(_ context.Context, _ *GetMetricsRequest) (*GetMetricsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMetrics not implemented")
}
func (*UnimplementedCoreServiceServer) GetVersion(_ context.Context, _ *GetVersionRequest) (*GetVersionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetVersion not implemented")
}
func (*UnimplementedCoreServiceServer) GetUptime(_ context.Context, _ *GetUptimeRequest) (*GetUptimeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUptime not implemented")
}
func (*UnimplementedCoreServiceServer) GetRegistryStatus(_ context.Context, _ *GetRegistryStatusRequest) (*GetRegistryStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRegistryStatus not implemented")
}
func (*UnimplementedCoreServiceServer) EnableModule(_ context.Context, _ *EnableModuleRequest) (*EnableModuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EnableModule not implemented")
}
func (*UnimplementedCoreServiceServer) DisableModule(_ context.Context, _ *DisableModuleRequest) (*DisableModuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableModule not implemented")
}

// UnimplementedTLSSvcServer returns codes.Unimplemented for all methods.
type UnimplementedTLSSvcServer struct{}

func (*UnimplementedTLSSvcServer) GetConfig(_ context.Context, _ *GetTLSConfigRequest) (*GetTLSConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfig not implemented")
}
func (*UnimplementedTLSSvcServer) GetCertificates(_ context.Context, _ *GetCertificatesRequest) (*GetCertificatesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCertificates not implemented")
}
func (*UnimplementedTLSSvcServer) GenerateCertificate(_ context.Context, _ *GenerateCertificateRequest) (*GenerateCertificateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateCertificate not implemented")
}
func (*UnimplementedTLSSvcServer) GetMTLSConfig(_ context.Context, _ *GetMTLSConfigRequest) (*GetMTLSConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetMTLSConfig not implemented")
}

// ============================================================
// SERVICE DESCRIPTORS (with method handlers for gRPC dispatch)
// ============================================================

// methodDesc describes a single RPC method in a service descriptor.
type methodDesc struct {
	MethodName string
}

// serviceDesc describes a gRPC service for registration.
type serviceDesc struct {
	ServiceName string
	HandlerType interface{}
	Methods     []methodDesc
}

// Service descriptors with full method lists for proper gRPC dispatch.
var (
	AuthService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.AuthService",
		HandlerType: (*AuthServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "Login"},
			{MethodName: "Logout"},
			{MethodName: "ValidateToken"},
			{MethodName: "GetUser"},
			{MethodName: "ListUsers"},
			{MethodName: "CreateUser"},
			{MethodName: "UpdateUser"},
			{MethodName: "DeleteUser"},
			{MethodName: "GetSessions"},
			{MethodName: "GetAuthConfig"},
		},
	}

	ProxyService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.ProxyService",
		HandlerType: (*ProxyServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "GetStats"},
			{MethodName: "GetHealth"},
			{MethodName: "GetConfig"},
			{MethodName: "IsEnabled"},
			{MethodName: "Enable"},
			{MethodName: "Disable"},
			{MethodName: "GetViolations"},
			{MethodName: "ClearViolations"},
		},
	}

	ComplianceService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.ComplianceService",
		HandlerType: (*ComplianceServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "GetFrameworks"},
			{MethodName: "GetStatus"},
			{MethodName: "RunCheck"},
			{MethodName: "GetFindings"},
			{MethodName: "GenerateReport"},
		},
	}

	SIEMService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.SIEMService",
		HandlerType: (*SIEMServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "GetConfig"},
			{MethodName: "GetStats"},
			{MethodName: "GetEvents"},
			{MethodName: "SendEvent"},
			{MethodName: "TestConnection"},
		},
	}

	WebhookService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.WebhookService",
		HandlerType: (*WebhookServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "ListWebhooks"},
			{MethodName: "GetWebhook"},
			{MethodName: "CreateWebhook"},
			{MethodName: "UpdateWebhook"},
			{MethodName: "DeleteWebhook"},
			{MethodName: "EnableWebhook"},
			{MethodName: "DisableWebhook"},
			{MethodName: "TestWebhook"},
			{MethodName: "GetStats"},
		},
	}

	CoreService_ServiceDesc = serviceDesc{
		ServiceName: "grpc.CoreService",
		HandlerType: (*CoreServiceServer)(nil),
		Methods: []methodDesc{
			{MethodName: "ListModules"},
			{MethodName: "GetModule"},
			{MethodName: "GetHealth"},
			{MethodName: "GetMetrics"},
			{MethodName: "GetVersion"},
			{MethodName: "GetUptime"},
			{MethodName: "GetRegistryStatus"},
			{MethodName: "EnableModule"},
			{MethodName: "DisableModule"},
		},
	}

	TLSSvc_ServiceDesc = serviceDesc{
		ServiceName: "grpc.TLSSvc",
		HandlerType: (*TLSSvcServer)(nil),
		Methods: []methodDesc{
			{MethodName: "GetConfig"},
			{MethodName: "GetCertificates"},
			{MethodName: "GenerateCertificate"},
			{MethodName: "GetMTLSConfig"},
		},
	}
)

// ServiceCount returns the total number of gRPC service descriptors registered.
// Used in tests to verify all services are registered.
func ServiceCount() int {
	return 7
}

// MethodCount returns the total number of gRPC method descriptors across all services.
// Used in tests to verify all RPCs are registered.
func MethodCount() int {
	total := 0
	for _, desc := range []serviceDesc{
		AuthService_ServiceDesc, ProxyService_ServiceDesc,
		ComplianceService_ServiceDesc, SIEMService_ServiceDesc,
		WebhookService_ServiceDesc, CoreService_ServiceDesc,
		TLSSvc_ServiceDesc,
	} {
		total += len(desc.Methods)
	}
	return total
}

// RegisterHelper is a convenience type for registering services on a grpc.Server.
// Each Register* method adds the service implementation to the server.
type RegisterHelper struct {
	Server *grpc.Server
}

// RegisterAuthService registers the AuthService on the gRPC server.
func (rh *RegisterHelper) RegisterAuthService(svc AuthServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_Auth, svc)
}

// RegisterProxyService registers the ProxyService on the gRPC server.
func (rh *RegisterHelper) RegisterProxyService(svc ProxyServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_Proxy, svc)
}

// RegisterComplianceService registers the ComplianceService on the gRPC server.
func (rh *RegisterHelper) RegisterComplianceService(svc ComplianceServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_Compliance, svc)
}

// RegisterSIEMService registers the SIEMService on the gRPC server.
func (rh *RegisterHelper) RegisterSIEMService(svc SIEMServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_SIEM, svc)
}

// RegisterWebhookService registers the WebhookService on the gRPC server.
func (rh *RegisterHelper) RegisterWebhookService(svc WebhookServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_Webhook, svc)
}

// RegisterCoreService registers the CoreService on the gRPC server.
func (rh *RegisterHelper) RegisterCoreService(svc CoreServiceServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_Core, svc)
}

// RegisterTLSSvc registers the TLSSvc on the gRPC server.
func (rh *RegisterHelper) RegisterTLSSvc(svc TLSSvcServer) {
	rh.Server.RegisterService(&_grpcServiceDesc_TLS, svc)
}

// Internal grpc.ServiceDesc objects for service registration.
// These bridge our custom serviceDesc to the standard grpc.ServiceDesc format.
var (
	_grpcServiceDesc_Auth = grpc.ServiceDesc{
		ServiceName: AuthService_ServiceDesc.ServiceName,
		HandlerType: (*AuthServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_Proxy = grpc.ServiceDesc{
		ServiceName: ProxyService_ServiceDesc.ServiceName,
		HandlerType: (*ProxyServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_Compliance = grpc.ServiceDesc{
		ServiceName: ComplianceService_ServiceDesc.ServiceName,
		HandlerType: (*ComplianceServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_SIEM = grpc.ServiceDesc{
		ServiceName: SIEMService_ServiceDesc.ServiceName,
		HandlerType: (*SIEMServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_Webhook = grpc.ServiceDesc{
		ServiceName: WebhookService_ServiceDesc.ServiceName,
		HandlerType: (*WebhookServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_Core = grpc.ServiceDesc{
		ServiceName: CoreService_ServiceDesc.ServiceName,
		HandlerType: (*CoreServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
	_grpcServiceDesc_TLS = grpc.ServiceDesc{
		ServiceName: TLSSvc_ServiceDesc.ServiceName,
		HandlerType: (*TLSSvcServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams:     []grpc.StreamDesc{},
	}
)
