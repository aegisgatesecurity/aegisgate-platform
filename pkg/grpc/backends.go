// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — gRPC Backend Interfaces
// =========================================================================
//
// Backend interfaces decouple the gRPC service layer from platform internals.
// Each interface exposes only the methods needed by its corresponding gRPC
// service, enabling dependency injection and testability.
//
// The main binary (cmd/aegisgate-platform) provides adapters that wrap
// platform packages (auth, compliance, proxy, siem, metrics, tls) to
// satisfy these interfaces.
//
// =========================================================================

package grpc

import (
	"context"
)

// ====================================================================
// AuthBackend provides user and session operations for AuthService.
// ====================================================================

// AuthBackend is the interface for authentication and user management.
type AuthBackend interface {
	// Login authenticates a user and returns a session token.
	Login(ctx context.Context, username, password string) (token string, expiresAt int64, err error)
	// Logout invalidates a session token.
	Logout(ctx context.Context, token string) error
	// ValidateToken checks if a token is valid and returns the user ID and expiry.
	ValidateToken(ctx context.Context, token string) (valid bool, userID string, expiresAt int64, err error)
	// GetUser retrieves a user by ID.
	GetUser(ctx context.Context, userID string) (*AuthUserInfo, error)
	// ListUsers lists all users.
	ListUsers(ctx context.Context) ([]*AuthUserInfo, error)
	// CreateUser creates a new user.
	CreateUser(ctx context.Context, username, email, password, role string) (*AuthUserInfo, error)
	// UpdateUser updates an existing user.
	UpdateUser(ctx context.Context, userID, username, email, role string, enabled bool) (*AuthUserInfo, error)
	// DeleteUser deletes a user.
	DeleteUser(ctx context.Context, userID string) error
	// GetSessions returns active sessions.
	GetSessions(ctx context.Context) ([]*AuthSessionInfo, error)
	// GetAuthConfig returns authentication configuration.
	GetAuthConfig(ctx context.Context) (*AuthConfig, error)
}

// AuthUserInfo represents a user returned by the auth backend.
type AuthUserInfo struct {
	ID        string
	Username  string
	Email     string
	Role      string
	Enabled   bool
	CreatedAt int64
}

// AuthSessionInfo represents a session returned by the auth backend.
type AuthSessionInfo struct {
	ID           string
	UserID       string
	Token        string
	ExpiresAt    int64
	CreatedAt    int64
	LastActivity int64
	IPAddress    string
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	SessionDurationSec int32
	MaxSessions        int32
	EnableMFA          bool
	LoginAttempts      int32
	LockoutDurationSec int32
	PasswordMinLength  int32
}

// ====================================================================
// ComplianceBackend provides compliance operations.
// ====================================================================

// ComplianceBackend is the interface for compliance management.
type ComplianceBackend interface {
	// GetFrameworks returns the list of active compliance frameworks.
	GetFrameworks(ctx context.Context) ([]*ComplianceFrameworkInfo, error)
	// GetStatus returns the overall compliance status.
	GetStatus(ctx context.Context) (*ComplianceOverallStatus, error)
	// RunCheck runs a compliance check for a specific framework.
	RunCheck(ctx context.Context, framework string) (*ComplianceCheckResult, error)
	// GetFindings returns compliance findings.
	GetFindings(ctx context.Context) ([]*ComplianceFindingInfo, error)
	// GenerateReport generates a compliance report for a framework.
	GenerateReport(ctx context.Context, framework string) (*ComplianceReportResult, error)
}

// ComplianceFrameworkInfo represents a compliance framework.
type ComplianceFrameworkInfo struct {
	ID          string
	Name        string
	Description string
}

// ComplianceOverallStatus represents the overall compliance posture.
type ComplianceOverallStatus struct {
	OverallStatus ComplianceStatus
	Frameworks    []*FrameworkStatusInfo
}

// FrameworkStatusInfo represents a framework's compliance status.
type FrameworkStatusInfo struct {
	Framework string
	Status    ComplianceStatus
	Score     float64
}

// ComplianceCheckResult is the result of running a compliance check.
type ComplianceCheckResult struct {
	ID        string
	Framework string
	Status    ComplianceStatus
	Summary   *ComplianceSummary
}

// ComplianceFindingInfo represents a compliance finding.
type ComplianceFindingInfo struct {
	ID          string
	Title       string
	Description string
	Severity    FindingSeverity
	Category    string
	Framework   string
	Timestamp   int64
}

// ComplianceReportResult is the result of generating a compliance report.
type ComplianceReportResult struct {
	ID        string
	Framework string
	Timestamp int64
	Status    ComplianceStatus
	Summary   *ComplianceSummary
}

// ====================================================================
// ProxyBackend provides proxy operations.
// ====================================================================

// ProxyBackend is the interface for proxy management.
type ProxyBackend interface {
	// GetStats returns proxy statistics.
	GetStats(ctx context.Context) (*ProxyStatsInfo, error)
	// GetHealth returns proxy health status.
	GetHealth(ctx context.Context) (*ProxyHealthInfo, error)
	// GetConfig returns proxy configuration.
	GetConfig(ctx context.Context) (*ProxyConfigInfo, error)
	// IsEnabled returns whether the proxy is enabled.
	IsEnabled(ctx context.Context) (bool, error)
	// Enable enables the proxy.
	Enable(ctx context.Context) error
	// Disable disables the proxy.
	Disable(ctx context.Context) error
	// GetViolations returns proxy violations.
	GetViolations(ctx context.Context, severities []ViolationSeverity, limit int32) ([]*ViolationInfo, error)
	// ClearViolations clears all proxy violations.
	ClearViolations(ctx context.Context) error
}

// ProxyStatsInfo holds proxy statistics.
type ProxyStatsInfo struct {
	RequestsTotal     int64
	RequestsBlocked   int64
	RequestsAllowed   int64
	BytesIn           int64
	BytesOut          int64
	ActiveConnections int
	AvgLatencyMs      float64
	P99LatencyMs      float64
	Errors            int64
}

// ProxyHealthInfo holds proxy health status.
type ProxyHealthInfo struct {
	Status      string
	Uptime      float64
	MemoryUsage int64
	Goroutines  int32
}

// ProxyConfigInfo holds proxy configuration.
type ProxyConfigInfo struct {
	Enabled        bool
	Host           string
	Port           int
	TLSEnabled     bool
	RateLimit      int32
	RateLimitBurst int32
	CORSEnabled    bool
	CORSOrigins    []string
}

// ViolationInfo represents a proxy violation.
type ViolationInfo struct {
	ID        string
	Type      ViolationType
	Severity  ViolationSeverity
	Message   string
	ClientIP  string
	Method    string
	Path      string
	Blocked   bool
	Timestamp int64
}

// ====================================================================
// SIEMBackend provides SIEM operations.
// ====================================================================

// SIEMBackend is the interface for SIEM integration.
type SIEMBackend interface {
	// GetConfig returns SIEM configuration.
	GetConfig(ctx context.Context) (*SIEMConfigInfo, error)
	// GetStats returns SIEM statistics.
	GetStats(ctx context.Context) (*SIEMStatsInfo, error)
	// GetEvents returns recent SIEM events.
	GetEvents(ctx context.Context, limit int32) ([]*SIEMEventInfo, error)
	// SendEvent sends an event to SIEM.
	SendEvent(ctx context.Context, source, category, eventType string, severity EventSeverity, message, entity string) error
	// TestConnection tests the SIEM connection.
	TestConnection(ctx context.Context, platform string) (bool, string, error)
}

// SIEMConfigInfo holds SIEM configuration.
type SIEMConfigInfo struct {
	Enabled       bool
	BatchSize     int32
	BatchInterval int32
	RetryAttempts int32
	RetryInterval int32
}

// SIEMStatsInfo holds SIEM statistics.
type SIEMStatsInfo struct {
	EventsSent    int64
	EventsDropped int64
	EventsQueued  int64
	LastSendTime  int64
	LastError     string
}

// SIEMEventInfo represents a SIEM event.
type SIEMEventInfo struct {
	ID        string
	Timestamp int64
	Source    string
	Category  string
	Type      string
	Severity  EventSeverity
	Message   string
	Entity    string
}

// ====================================================================
// WebhookBackend provides webhook operations.
// ====================================================================

// WebhookBackend is the interface for webhook management.
type WebhookBackend interface {
	// ListWebhooks lists all webhooks.
	ListWebhooks(ctx context.Context) ([]*WebhookDetail, error)
	// GetWebhook gets a webhook by ID.
	GetWebhook(ctx context.Context, id string) (*WebhookDetail, error)
	// CreateWebhook creates a new webhook.
	CreateWebhook(ctx context.Context, name, url string, events []string, enabled bool) (*WebhookDetail, error)
	// UpdateWebhook updates an existing webhook.
	UpdateWebhook(ctx context.Context, id, name, url string, events []string, enabled bool) (*WebhookDetail, error)
	// DeleteWebhook deletes a webhook.
	DeleteWebhook(ctx context.Context, id string) error
	// EnableWebhook enables a webhook.
	EnableWebhook(ctx context.Context, id string) (*WebhookDetail, error)
	// DisableWebhook disables a webhook.
	DisableWebhook(ctx context.Context, id string) (*WebhookDetail, error)
	// TestWebhook tests a webhook delivery.
	TestWebhook(ctx context.Context, id string) (bool, string, error)
	// GetStats returns webhook statistics.
	GetStats(ctx context.Context) (*WebhookStatsInfo, error)
}

// WebhookDetail holds webhook configuration and metadata.
type WebhookDetail struct {
	ID      string
	Name    string
	URL     string
	Events  []string
	Enabled bool
}

// WebhookStatsInfo holds webhook statistics.
type WebhookStatsInfo struct {
	TotalWebhooks     int64
	ActiveWebhooks    int64
	DeliveriesTotal   int64
	DeliveriesSuccess int64
	DeliveriesFailed  int64
}

// ====================================================================
// MetricsBackend provides metrics and health operations.
// ====================================================================

// MetricsBackend is the interface for system metrics and health.
type MetricsBackend interface {
	// GetHealth returns system health status.
	GetHealth(ctx context.Context) (*HealthInfo, error)
	// GetStats returns system statistics.
	GetStats(ctx context.Context) (*SystemStatsInfo, error)
	// GetUptime returns system uptime in seconds.
	GetUptime(ctx context.Context) (float64, error)
}

// HealthInfo holds health check results.
type HealthInfo struct {
	Status string
	Checks []*HealthCheck
}

// SystemStatsInfo holds system statistics.
type SystemStatsInfo struct {
	TotalRequests     int64
	BlockedRequests   int64
	ActiveUsers       int64
	ActiveConnections int64
	Uptime            float64
}

// ====================================================================
// TLSBackend provides TLS/mTLS operations.
// ====================================================================

// TLSBackend is the interface for TLS configuration management.
type TLSBackend interface {
	// GetConfig returns TLS configuration.
	GetConfig(ctx context.Context) (*TLSConfigInfo, error)
	// GetCertificates returns all certificates.
	GetCertificates(ctx context.Context) ([]*CertificateDetail, error)
	// GenerateCertificate generates a new certificate.
	GenerateCertificate(ctx context.Context, commonName, organization string, validityDays int32) (*CertificateDetail, error)
	// GetMTLSConfig returns mTLS configuration.
	GetMTLSConfig(ctx context.Context) (*MTLSConfigInfo, error)
}

// TLSConfigInfo holds TLS configuration.
type TLSConfigInfo struct {
	Enabled      bool
	CertFile     string
	KeyFile      string
	AutoGenerate bool
	MinVersion   string
}

// CertificateDetail holds certificate information.
type CertificateDetail struct {
	Subject     string
	Issuer      string
	NotBefore   int64
	NotAfter    int64
	Fingerprint string
}

// MTLSConfigInfo holds mTLS configuration.
type MTLSConfigInfo struct {
	Enabled        bool
	CACertFile     string
	ClientCertFile string
	ClientKeyFile  string
}
