// Package grpc provides gRPC API types for AegisGate
package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ============================================================
// TYPE DEFINITIONS (would be generated from api.proto)
// ============================================================

// Auth Types
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Success   bool   `json:"success"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	User      *User  `json:"user"`
	Error     string `json:"error"`
}

type LogoutRequest struct {
	Token string `json:"token"`
}

type LogoutResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

type ValidateTokenRequest struct {
	Token string `json:"token"`
}

type ValidateTokenResponse struct {
	Valid     bool   `json:"valid"`
	UserId    string `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type GetUserRequest struct {
	UserId string `json:"user_id"`
}

type GetUserResponse struct {
	User *User `json:"user"`
}

type ListUsersRequest struct{}

type ListUsersResponse struct {
	Users []*User `json:"users"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type CreateUserResponse struct {
	User *User `json:"user"`
}

type UpdateUserRequest struct {
	UserId   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Enabled  bool   `json:"enabled"`
}

type UpdateUserResponse struct {
	User *User `json:"user"`
}

type DeleteUserRequest struct {
	UserId string `json:"user_id"`
}

type DeleteUserResponse struct {
	Success bool `json:"success"`
}

type GetSessionsRequest struct{}

type GetSessionsResponse struct {
	Sessions []*Session `json:"sessions"`
}

type GetAuthConfigRequest struct{}

type GetAuthConfigResponse struct {
	SessionTimeout     int32 `json:"session_timeout"`
	MaxSessionsPerUser int32 `json:"max_sessions_per_user"`
	RequireMfa         bool  `json:"require_mfa"`
	LoginAttempts      int32 `json:"login_attempts"`
	LockoutDuration    int32 `json:"lockout_duration"`
	PasswordMinLength  int32 `json:"password_min_length"`
}

type User struct {
	Id        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

type Session struct {
	Id           string `json:"id"`
	UserId       string `json:"user_id"`
	Token        string `json:"token"`
	ExpiresAt    int64  `json:"expires_at"`
	CreatedAt    int64  `json:"created_at"`
	LastActivity int64  `json:"last_activity"`
	IpAddress    string `json:"ip_address"`
}

// Proxy Types
type GetProxyStatsRequest struct{}

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

type GetProxyHealthRequest struct{}

type GetProxyHealthResponse struct {
	Status      string  `json:"status"`
	Uptime      float64 `json:"uptime"`
	MemoryUsage int64   `json:"memory_usage"`
	Goroutines  int32   `json:"goroutines"`
}

type GetProxyConfigRequest struct{}

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

type IsProxyEnabledRequest struct{}

type IsProxyEnabledResponse struct {
	Enabled bool `json:"enabled"`
}

type EnableProxyRequest struct{}

type EnableProxyResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

type DisableProxyRequest struct{}

type DisableProxyResponse struct {
	Success bool `json:"success"`
}

type GetViolationsRequest struct {
	Severities []ViolationSeverity `json:"severities"`
	Limit      int32               `json:"limit"`
}

type GetViolationsResponse struct {
	Violations []*Violation `json:"violations"`
}

type ClearViolationsRequest struct{}

type ClearViolationsResponse struct {
	Success bool `json:"success"`
}

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

type ViolationType int32
type ViolationSeverity int32

const (
	ViolationTypeUnknown ViolationType = iota
	ViolationTypeMaliciousRequest
	ViolationTypeSQLInjection
	ViolationTypeXSS
	ViolationTypeCSRF
	ViolationTypePathTraversal
	ViolationTypeCommandInjection
	ViolationTypeAtlasTechnique
	ViolationTypeCustomPattern
)

const (
	ViolationSeverityInfo ViolationSeverity = iota
	ViolationSeverityLow
	ViolationSeverityMedium
	ViolationSeverityHigh
	ViolationSeverityCritical
)

// Compliance Types
type GetFrameworksRequest struct{}

type GetFrameworksResponse struct {
	Frameworks []*Framework `json:"frameworks"`
}

type GetComplianceStatusRequest struct{}

type GetComplianceStatusResponse struct {
	Overall    ComplianceStatus   `json:"overall"`
	Frameworks []*FrameworkStatus `json:"frameworks"`
}

type RunComplianceCheckRequest struct {
	Framework string `json:"framework"`
}

type RunComplianceCheckResponse struct {
	Id        string             `json:"id"`
	Framework string             `json:"framework"`
	Status    ComplianceStatus   `json:"status"`
	Summary   *ComplianceSummary `json:"summary"`
}

type GetFindingsRequest struct{}

type GetFindingsResponse struct {
	Findings []*ComplianceFinding `json:"findings"`
}

type GenerateReportRequest struct {
	Framework string `json:"framework"`
}

type GenerateReportResponse struct {
	Id        string             `json:"id"`
	Framework string             `json:"framework"`
	Timestamp int64              `json:"timestamp"`
	Status    ComplianceStatus   `json:"status"`
	Summary   *ComplianceSummary `json:"summary"`
}

type ComplianceStatus int32

// ComplianceStatus values
const (
	ComplianceStatus_UNKNOWN        ComplianceStatus = 0
	ComplianceStatus_PASS           ComplianceStatus = 1
	ComplianceStatus_FAIL           ComplianceStatus = 2
	ComplianceStatus_WARNING        ComplianceStatus = 3
	ComplianceStatus_PENDING        ComplianceStatus = 4
	ComplianceStatus_NOT_APPLICABLE ComplianceStatus = 5
)

type FindingSeverity int32

// FindingSeverity values
const (
	FindingSeverity_UNKNOWN  FindingSeverity = 0
	FindingSeverity_INFO     FindingSeverity = 1
	FindingSeverity_LOW      FindingSeverity = 2
	FindingSeverity_MEDIUM   FindingSeverity = 3
	FindingSeverity_HIGH     FindingSeverity = 4
	FindingSeverity_CRITICAL FindingSeverity = 5
)

const (
	ComplianceStatusUnknown ComplianceStatus = iota
	ComplianceStatusPass
	ComplianceStatusFail
	ComplianceStatusWarning
	ComplianceStatusPending
	ComplianceStatusNotApplicable
)

const (
	FindingSeverityInfo FindingSeverity = iota
	FindingSeverityLow
	FindingSeverityMedium
	FindingSeverityHigh
	FindingSeverityCritical
)

type Framework struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type FrameworkStatus struct {
	Framework ComplianceStatus `json:"framework"`
	Status    ComplianceStatus `json:"status"`
	Score     float64          `json:"score"`
}

type ComplianceSummary struct {
	TotalChecks   int32   `json:"total_checks"`
	Passed        int32   `json:"passed"`
	Failed        int32   `json:"failed"`
	Warnings      int32   `json:"warnings"`
	NotApplicable int32   `json:"not_applicable"`
	Score         float64 `json:"score"`
}

type ComplianceFinding struct {
	Id          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    FindingSeverity `json:"severity"`
	Category    string          `json:"category"`
	Framework   string          `json:"framework"`
	Timestamp   int64           `json:"timestamp"`
}

// SIEM Types
type GetSIEMConfigRequest struct{}

type GetSIEMConfigResponse struct {
	Enabled       bool  `json:"enabled"`
	BatchSize     int32 `json:"batch_size"`
	BatchInterval int32 `json:"batch_interval"`
	RetryAttempts int32 `json:"retry_attempts"`
	RetryInterval int32 `json:"retry_interval"`
}

type GetSIEMStatsRequest struct{}

type GetSIEMStatsResponse struct {
	EventsSent    int64  `json:"events_sent"`
	EventsDropped int64  `json:"events_dropped"`
	EventsQueued  int64  `json:"events_queued"`
	LastSendTime  int64  `json:"last_send_time"`
	LastError     string `json:"last_error"`
}

type GetSIEMEventsRequest struct {
	Limit int32 `json:"limit"`
}

type GetSIEMEventsResponse struct {
	Events []*SIEMEvent `json:"events"`
}

type SendSIEMEventRequest struct {
	Source   string        `json:"source"`
	Category string        `json:"category"`
	Type     string        `json:"type"`
	Severity EventSeverity `json:"severity"`
	Message  string        `json:"message"`
	Entity   string        `json:"entity"`
}

type SendSIEMEventResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

type TestSIEMConnectionRequest struct {
	Platform string `json:"platform"`
}

type TestSIEMConnectionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type EventSeverity int32

const (
	EventSeverityInfo EventSeverity = iota
	EventSeverityLow
	EventSeverityMedium
	EventSeverityHigh
	EventSeverityCritical
)

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

// Webhook Types
type ListWebhooksRequest struct{}

type ListWebhooksResponse struct {
	Webhooks []*WebhookInfo `json:"webhooks"`
}

type GetWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

type GetWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

type CreateWebhookRequest struct {
	Name    string   `json:"name"`
	Url     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

type CreateWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

type UpdateWebhookRequest struct {
	WebhookId string   `json:"webhook_id"`
	Name      string   `json:"name"`
	Url       string   `json:"url"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
}

type UpdateWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

type DeleteWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

type DeleteWebhookResponse struct {
	Success bool `json:"success"`
}

type EnableWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

type EnableWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

type DisableWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

type DisableWebhookResponse struct {
	Webhook *WebhookInfo `json:"webhook"`
}

type TestWebhookRequest struct {
	WebhookId string `json:"webhook_id"`
}

type TestWebhookResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type GetWebhookStatsRequest struct{}

type GetWebhookStatsResponse struct {
	TotalWebhooks     int64 `json:"total_webhooks"`
	ActiveWebhooks    int64 `json:"active_webhooks"`
	DeliveriesTotal   int64 `json:"deliveries_total"`
	DeliveriesSuccess int64 `json:"deliveries_success"`
	DeliveriesFailed  int64 `json:"deliveries_failed"`
}

type WebhookInfo struct {
	Id      string   `json:"id"`
	Name    string   `json:"name"`
	Url     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

// Core Types
type ListModulesRequest struct{}

type ListModulesResponse struct {
	Modules []*ModuleInfo `json:"modules"`
}

type GetModuleRequest struct {
	ModuleId string `json:"module_id"`
}

type GetModuleResponse struct {
	Module *ModuleInfo `json:"module"`
}

type GetHealthRequest struct{}

type GetHealthResponse struct {
	Status string         `json:"status"`
	Checks []*HealthCheck `json:"checks"`
}

type GetMetricsRequest struct{}

type GetMetricsResponse struct {
	TotalRequests     int64   `json:"total_requests"`
	BlockedRequests   int64   `json:"blocked_requests"`
	ActiveUsers       int32   `json:"active_users"`
	ActiveConnections int32   `json:"active_connections"`
	Uptime            float64 `json:"uptime"`
}

type GetVersionRequest struct{}

type GetVersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
	GitCommit string `json:"git_commit"`
}

type GetUptimeRequest struct{}

type GetUptimeResponse struct {
	Uptime float64 `json:"uptime"`
}

type GetRegistryStatusRequest struct{}

type GetRegistryStatusResponse struct {
	TotalModules     int32 `json:"total_modules"`
	ActiveModules    int32 `json:"active_modules"`
	HealthyModules   int32 `json:"healthy_modules"`
	UnhealthyModules int32 `json:"unhealthy_modules"`
}

type EnableModuleRequest struct {
	ModuleId string `json:"module_id"`
}

type EnableModuleResponse struct {
	Success bool `json:"success"`
}

type DisableModuleRequest struct {
	ModuleId string `json:"module_id"`
}

type DisableModuleResponse struct {
	Success bool `json:"success"`
}

type ModuleStatus int32
type ModuleInfo struct {
	Id          string       `json:"id"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Status      ModuleStatus `json:"status"`
}

const (
	ModuleStatusUnknown ModuleStatus = iota
	ModuleStatusInitializing
	ModuleStatusRunning
	ModuleStatusStopped
	ModuleStatusError
)

type HealthCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// TLS Types
type GetTLSConfigRequest struct{}

type GetTLSConfigResponse struct {
	Enabled      bool   `json:"enabled"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	AutoGenerate bool   `json:"auto_generate"`
	MinVersion   string `json:"min_version"`
}

type GetCertificatesRequest struct{}

type GetCertificatesResponse struct {
	Certificates []*CertificateInfo `json:"certificates"`
}

type CertificateInfo struct {
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotBefore   int64  `json:"not_before"`
	NotAfter    int64  `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
}

type GenerateCertificateRequest struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	ValidityDays int32  `json:"validity_days"`
}

type GenerateCertificateResponse struct {
	Success     bool             `json:"success"`
	Certificate *CertificateInfo `json:"certificate"`
	Error       string           `json:"error"`
}

type GetMTLSConfigRequest struct{}

type GetMTLSConfigResponse struct {
	Enabled        bool   `json:"enabled"`
	CaCertFile     string `json:"ca_cert_file"`
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
}

// ============================================================
// SERVICE INTERFACES
// ============================================================

// TLSSvcServer is the server API for TLSSvc
type TLSSvcServer interface {
	GetConfig(context.Context, *GetTLSConfigRequest) (*GetTLSConfigResponse, error)
	GetCertificates(context.Context, *GetCertificatesRequest) (*GetCertificatesResponse, error)
	GenerateCertificate(context.Context, *GenerateCertificateRequest) (*GenerateCertificateResponse, error)
	GetMTLSConfig(context.Context, *GetMTLSConfigRequest) (*GetMTLSConfigResponse, error)
}

// AuthServiceServer is the server API for AuthService
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

// ProxyServiceServer is the server API for ProxyService
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

// ComplianceServiceServer is the server API for ComplianceService
type ComplianceServiceServer interface {
	GetFrameworks(context.Context, *GetFrameworksRequest) (*GetFrameworksResponse, error)
	GetStatus(context.Context, *GetComplianceStatusRequest) (*GetComplianceStatusResponse, error)
	RunCheck(context.Context, *RunComplianceCheckRequest) (*RunComplianceCheckResponse, error)
	GetFindings(context.Context, *GetFindingsRequest) (*GetFindingsResponse, error)
	GenerateReport(context.Context, *GenerateReportRequest) (*GenerateReportResponse, error)
}

// SIEMServiceServer is the server API for SIEMService
type SIEMServiceServer interface {
	GetConfig(context.Context, *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error)
	GetStats(context.Context, *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error)
	GetEvents(context.Context, *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error)
	SendEvent(context.Context, *SendSIEMEventRequest) (*SendSIEMEventResponse, error)
	TestConnection(context.Context, *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error)
}

// WebhookServiceServer is the server API for WebhookService
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

// CoreServiceServer is the server API for CoreService
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

// ============================================================
// UNIMPLEMENTED STUBS
// ============================================================

type UnimplementedTLSSvcServer struct{}

func (*UnimplementedTLSSvcServer) GetConfig(ctx context.Context, req *GetTLSConfigRequest) (*GetTLSConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedTLSSvcServer) GetCertificates(ctx context.Context, req *GetCertificatesRequest) (*GetCertificatesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedTLSSvcServer) GenerateCertificate(ctx context.Context, req *GenerateCertificateRequest) (*GenerateCertificateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedTLSSvcServer) GetMTLSConfig(ctx context.Context, req *GetMTLSConfigRequest) (*GetMTLSConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

type UnimplementedAuthServiceServer struct{}

func (*UnimplementedAuthServiceServer) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) Logout(ctx context.Context, req *LogoutRequest) (*LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) ValidateToken(ctx context.Context, req *ValidateTokenRequest) (*ValidateTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) GetUser(ctx context.Context, req *GetUserRequest) (*GetUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) ListUsers(ctx context.Context, req *ListUsersRequest) (*ListUsersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) CreateUser(ctx context.Context, req *CreateUserRequest) (*CreateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) UpdateUser(ctx context.Context, req *UpdateUserRequest) (*UpdateUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) DeleteUser(ctx context.Context, req *DeleteUserRequest) (*DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) GetSessions(ctx context.Context, req *GetSessionsRequest) (*GetSessionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedAuthServiceServer) GetAuthConfig(ctx context.Context, req *GetAuthConfigRequest) (*GetAuthConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

type UnimplementedProxyServiceServer struct{}

func (*UnimplementedProxyServiceServer) GetStats(ctx context.Context, req *GetProxyStatsRequest) (*GetProxyStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) GetHealth(ctx context.Context, req *GetProxyHealthRequest) (*GetProxyHealthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) GetConfig(ctx context.Context, req *GetProxyConfigRequest) (*GetProxyConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) IsEnabled(ctx context.Context, req *IsProxyEnabledRequest) (*IsProxyEnabledResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) Enable(ctx context.Context, req *EnableProxyRequest) (*EnableProxyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) Disable(ctx context.Context, req *DisableProxyRequest) (*DisableProxyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) GetViolations(ctx context.Context, req *GetViolationsRequest) (*GetViolationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedProxyServiceServer) ClearViolations(ctx context.Context, req *ClearViolationsRequest) (*ClearViolationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

type UnimplementedComplianceServiceServer struct{}

func (*UnimplementedComplianceServiceServer) GetFrameworks(ctx context.Context, req *GetFrameworksRequest) (*GetFrameworksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedComplianceServiceServer) GetStatus(ctx context.Context, req *GetComplianceStatusRequest) (*GetComplianceStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedComplianceServiceServer) RunCheck(ctx context.Context, req *RunComplianceCheckRequest) (*RunComplianceCheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedComplianceServiceServer) GetFindings(ctx context.Context, req *GetFindingsRequest) (*GetFindingsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedComplianceServiceServer) GenerateReport(ctx context.Context, req *GenerateReportRequest) (*GenerateReportResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

type UnimplementedSIEMServiceServer struct{}

func (*UnimplementedSIEMServiceServer) GetConfig(ctx context.Context, req *GetSIEMConfigRequest) (*GetSIEMConfigResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedSIEMServiceServer) GetStats(ctx context.Context, req *GetSIEMStatsRequest) (*GetSIEMStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedSIEMServiceServer) GetEvents(ctx context.Context, req *GetSIEMEventsRequest) (*GetSIEMEventsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedSIEMServiceServer) SendEvent(ctx context.Context, req *SendSIEMEventRequest) (*SendSIEMEventResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedSIEMServiceServer) TestConnection(ctx context.Context, req *TestSIEMConnectionRequest) (*TestSIEMConnectionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

type UnimplementedWebhookServiceServer struct{}

func (*UnimplementedWebhookServiceServer) ListWebhooks(ctx context.Context, req *ListWebhooksRequest) (*ListWebhooksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) GetWebhook(ctx context.Context, req *GetWebhookRequest) (*GetWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) CreateWebhook(ctx context.Context, req *CreateWebhookRequest) (*CreateWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) UpdateWebhook(ctx context.Context, req *UpdateWebhookRequest) (*UpdateWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) DeleteWebhook(ctx context.Context, req *DeleteWebhookRequest) (*DeleteWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) EnableWebhook(ctx context.Context, req *EnableWebhookRequest) (*EnableWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) DisableWebhook(ctx context.Context, req *DisableWebhookRequest) (*DisableWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) TestWebhook(ctx context.Context, req *TestWebhookRequest) (*TestWebhookResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedWebhookServiceServer) GetStats(ctx context.Context, req *GetWebhookStatsRequest) (*GetWebhookStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

type UnimplementedCoreServiceServer struct{}

func (*UnimplementedCoreServiceServer) ListModules(ctx context.Context, req *ListModulesRequest) (*ListModulesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) GetModule(ctx context.Context, req *GetModuleRequest) (*GetModuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) GetHealth(ctx context.Context, req *GetHealthRequest) (*GetHealthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) GetMetrics(ctx context.Context, req *GetMetricsRequest) (*GetMetricsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) GetVersion(ctx context.Context, req *GetVersionRequest) (*GetVersionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) GetUptime(ctx context.Context, req *GetUptimeRequest) (*GetUptimeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) GetRegistryStatus(ctx context.Context, req *GetRegistryStatusRequest) (*GetRegistryStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) EnableModule(ctx context.Context, req *EnableModuleRequest) (*EnableModuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}
func (*UnimplementedCoreServiceServer) DisableModule(ctx context.Context, req *DisableModuleRequest) (*DisableModuleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

// ============================================================
// GRPC REGISTRATION HELPERS
// ============================================================

// RegisterAuthServiceServer registers the AuthService to the provided grpc.Server
func RegisterAuthServiceServer(s *grpc.Server, srv AuthServiceServer) {
	s.RegisterService(&AuthService_ServiceDesc, srv)
}

// RegisterProxyServiceServer registers the ProxyService to the provided grpc.Server
func RegisterProxyServiceServer(s *grpc.Server, srv ProxyServiceServer) {
	s.RegisterService(&ProxyService_ServiceDesc, srv)
}

// RegisterComplianceServiceServer registers the ComplianceService to the provided grpc.Server
func RegisterComplianceServiceServer(s *grpc.Server, srv ComplianceServiceServer) {
	s.RegisterService(&ComplianceService_ServiceDesc, srv)
}

// RegisterSIEMServiceServer registers the SIEMService to the provided grpc.Server
func RegisterSIEMServiceServer(s *grpc.Server, srv SIEMServiceServer) {
	s.RegisterService(&SIEMService_ServiceDesc, srv)
}

// RegisterWebhookServiceServer registers the WebhookService to the provided grpc.Server
func RegisterWebhookServiceServer(s *grpc.Server, srv WebhookServiceServer) {
	s.RegisterService(&WebhookService_ServiceDesc, srv)
}

// RegisterCoreServiceServer registers the CoreService to the provided grpc.Server
func RegisterCoreServiceServer(s *grpc.Server, srv CoreServiceServer) {
	s.RegisterService(&CoreService_ServiceDesc, srv)
}

// Service descriptors (simplified)
var (
	AuthService_ServiceDesc = grpc.ServiceDesc{
		ServiceName: "grpc.AuthService",
		HandlerType: (*AuthServiceServer)(nil),
	}

	ProxyService_ServiceDesc = grpc.ServiceDesc{
		ServiceName: "grpc.ProxyService",
		HandlerType: (*ProxyServiceServer)(nil),
	}

	ComplianceService_ServiceDesc = grpc.ServiceDesc{
		ServiceName: "grpc.ComplianceService",
		HandlerType: (*ComplianceServiceServer)(nil),
	}

	SIEMService_ServiceDesc = grpc.ServiceDesc{
		ServiceName: "grpc.SIEMService",
		HandlerType: (*SIEMServiceServer)(nil),
	}

	WebhookService_ServiceDesc = grpc.ServiceDesc{
		ServiceName: "grpc.WebhookService",
		HandlerType: (*WebhookServiceServer)(nil),
	}

	CoreService_ServiceDesc = grpc.ServiceDesc{
		ServiceName: "grpc.CoreService",
		HandlerType: (*CoreServiceServer)(nil),
	}
)
