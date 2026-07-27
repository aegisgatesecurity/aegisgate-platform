package graphql

import (
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/sso"
)

// ============================================================================
// Type Aliases for External Packages (to match resolver.go expectations)
// ============================================================================

// sso.Provider - alias for sso.SSOProvider (the sso package uses SSOProvider)
type Provider = sso.SSOProvider

// sso.ProviderType - alias for sso.SSOProvider (used as provider type)
type ProviderType = sso.SSOProvider

// sso.SSOProviderType - alias for sso.SSOProvider
type SSOProviderType = sso.SSOProvider

// siem.Stats - create a stats type for SIEM (the package doesn't have this)
type Stats struct {
	EventsSent     int64 `json:"events_sent"`
	EventsReceived int64 `json:"events_received"`
	EventsFailed   int64 `json:"events_failed"`
	BytesSent      int64 `json:"bytes_sent"`
}

// SIEMStats is an alias for Stats (for resolver.go compatibility)
type SIEMStats = Stats

// ============================================================================
// Pagination and Filter Types (for GraphQL resolvers)
// ============================================================================

// Pagination represents pagination parameters
type Pagination struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
	Total  int `json:"total"`
}

// UserFilter represents filter parameters for user queries
type UserFilter struct {
	Role     string
	Provider string
	Email    string
	Search   string
}

// ViolationFilter represents filter parameters for violation queries
type ViolationFilter struct {
	Severity  string
	Type      string
	ClientIP  string
	Path      string
	StartDate *time.Time
	EndDate   *time.Time
}

// ============================================================================
// Config Types (for module configuration)
// ============================================================================

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Provider           string          `json:"provider"`
	SessionTimeout     int             `json:"session_timeout"`
	MaxSessionsPerUser int             `json:"max_sessions_per_user"`
	RequireMFA         bool            `json:"require_mfa"`
	MFAMethods         []string        `json:"mfa_methods"`
	PasswordPolicy     *PasswordPolicy `json:"password_policy"`
	LoginAttempts      int             `json:"login_attempts"`
	LockoutDuration    int             `json:"lockout_duration"`
	Providers          []string        `json:"providers"`
}

// PasswordPolicy - local type for GraphQL
type PasswordPolicy struct {
	MinLength      int  `json:"min_length"`
	RequireUpper   bool `json:"require_upper"`
	RequireLower   bool `json:"require_lower"`
	RequireDigit   bool `json:"require_digit"`
	RequireSpecial bool `json:"require_special"`
	MaxAge         int  `json:"max_age"`
}

// SSOProvider - local type for GraphQL (not to be confused with sso.SSOProvider)
type SSOProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// ProxyConfig represents proxy configuration
type ProxyConfig struct {
	Enabled     bool   `json:"enabled"`
	BindAddress string `json:"bind_address"`
	Upstream    string `json:"upstream"`
	MaxBodySize int64  `json:"max_body_size"`
	Timeout     int    `json:"timeout"`
	RateLimit   int    `json:"rate_limit"`
	TLSEnabled  bool   `json:"tls_enabled"`
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	ID        string               `json:"id"`
	Framework string               `json:"framework"`
	Timestamp time.Time            `json:"timestamp"`
	Status    string               `json:"status"`
	Summary   string               `json:"summary"`
	Findings  []compliance.Finding `json:"findings"`
}

// FindingFilter represents filter parameters for compliance findings
type FindingFilter struct {
	Framework string
	Severity  string
	Category  string
}

// ComplianceFindingConnection represents a paginated list of findings
type ComplianceFindingConnection struct {
	Edges      []FindingEdge `json:"edges"`
	PageInfo   PageInfo      `json:"page_info"`
	TotalCount int           `json:"total_count"`
}

// FindingEdge represents an edge in the finding connection
type FindingEdge struct {
	Node   compliance.Finding `json:"node"`
	Cursor string             `json:"cursor"`
}

// SIEMConfig represents SIEM configuration
type SIEMConfig struct {
	Enabled    bool   `json:"enabled"`
	Platform   string `json:"platform"`
	Endpoint   string `json:"endpoint"`
	Format     string `json:"format"`
	BufferSize int    `json:"buffer_size"`
}

// WebhookStats represents webhook statistics
type WebhookStats struct {
	TotalDeliveries int64     `json:"total_deliveries"`
	SuccessCount    int64     `json:"success_count"`
	FailureCount    int64     `json:"failure_count"`
	LastDelivery    time.Time `json:"last_delivery"`
	LastError       string    `json:"last_error"`
}

// DashboardData represents dashboard data for the UI
type DashboardData struct {
	TotalRequests   int64   `json:"total_requests"`
	BlockedRequests int64   `json:"blocked_requests"`
	ActiveUsers     int     `json:"active_users"`
	ComplianceScore float64 `json:"compliance_score"`
}

// ComplianceResult represents the result of a compliance check
type ComplianceResult struct {
	ID        string               `json:"id"`
	Framework string               `json:"framework"`
	Status    string               `json:"status"`
	Passed    bool                 `json:"passed"`
	Score     float64              `json:"score"`
	Timestamp time.Time            `json:"timestamp"`
	Findings  []compliance.Finding `json:"findings"`
}

// Config represents a configuration
type Config struct {
	Name  string
	Value interface{}
}

// TestResult represents a test result (for test configuration)
type TestResult struct {
	Passed  bool
	Message string
}

// ConfigInput represents input for configuring modules
type ConfigInput struct {
	Name  string
	Value interface{}
}

// TimeRange represents a time range for queries
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// CertificateFilter represents filter parameters for certificate queries
type CertificateFilter struct {
	Subject    string
	Issuer     string
	Expiration *time.Time
}

// SIEMEventFilter represents filter parameters for SIEM events
type SIEMEventFilter struct {
	Source    string
	Category  string
	Severity  string
	StartTime *time.Time
	EndTime   *time.Time
}

// WebhookFilter represents filter parameters for webhooks
type WebhookFilter struct {
	Enabled   *bool
	Name      string
	EventType string
}

// ProxyConfigInput represents input for configuring the proxy
type ProxyConfigInput struct {
	Enabled     bool
	BindAddress string
	Upstream    string
	RateLimit   int
}

// UpdateUserInput represents input for updating a user
type UpdateUserInput struct {
	Email   string
	Role    string
	Enabled bool
}

// WebhookInput represents input for creating/updating a webhook
type WebhookInput struct {
	Name    string
	URL     string
	Events  []string
	Enabled bool
}

// MetricsSnapshot represents a snapshot of system metrics
type MetricsSnapshot struct {
	Timestamp       time.Time `json:"timestamp"`
	TotalRequests   int64     `json:"total_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	ActiveUsers     int       `json:"active_users"`
}

// RegistryStatus represents the status of the module registry
type RegistryStatus struct {
	TotalModules   int               `json:"total_modules"`
	ActiveModules  int               `json:"active_modules"`
	HealthyModules int               `json:"healthy_modules"`
	ModuleStatuses map[string]string `json:"module_statuses"`
}

// MTLSStatus represents mTLS configuration status
type MTLSStatus struct {
	Enabled        bool   `json:"enabled"`
	CaCertFile     string `json:"ca_cert_file"`
	ClientCertFile string `json:"client_cert_file"`
}

// SecurityEvent represents a security event for subscriptions
type SecurityEvent struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// ComplianceFindingEdge represents an edge in compliance findings
type ComplianceFindingEdge struct {
	Node   compliance.Finding `json:"node"`
	Cursor string             `json:"cursor"`
}
