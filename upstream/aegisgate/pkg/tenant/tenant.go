// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package tenant

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
	"github.com/aegisgatesecurity/aegisgate/pkg/resilience"
)

// AuditLevel is an alias for opsec.AuditLevel for tenant use
type AuditLevel = opsec.AuditLevel

// SimpleRateLimiter is a simple in-memory rate limiter for tenants
type SimpleRateLimiter struct {
	mu          sync.Mutex
	tokens      int
	maxTokens   int
	refillRate  time.Duration
	lastRefill  time.Time
	requests    []time.Time
	maxRequests int
}

// NewSimpleRateLimiter creates a new simple rate limiter
func NewSimpleRateLimiter(requestsPerMinute int) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		maxTokens:   requestsPerMinute,
		tokens:      requestsPerMinute,
		refillRate:  time.Minute,
		lastRefill:  time.Now(),
		maxRequests: requestsPerMinute,
		requests:    make([]time.Time, 0),
	}
}

// Allow checks if a request is allowed under rate limit
func (rl *SimpleRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Remove old requests
	validRequests := rl.requests[:0]
	for _, t := range rl.requests {
		if now.Sub(t) < time.Minute {
			validRequests = append(validRequests, t)
		}
	}
	rl.requests = validRequests

	// Check if under limit
	if len(rl.requests) >= rl.maxRequests {
		return false
	}

	rl.requests = append(rl.requests, now)
	return true
}

// Tenant represents an isolated tenant in the system
type Tenant struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Domain     string            `json:"domain"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Status     TenantStatus      `json:"status"`
	Plan       TenantPlan        `json:"plan"`
	Settings   *TenantSettings   `json:"settings"`
	Quota      *TenantQuota      `json:"quota"`
	Compliance *TenantCompliance `json:"compliance"`

	// Tenant-specific resources (isolated)
	auditLog       *opsec.ComplianceAuditLog
	rateLimiter    *SimpleRateLimiter
	circuitBreaker *resilience.CircuitBreaker

	mu sync.RWMutex
}

// TenantStatus represents the current status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusPending   TenantStatus = "pending"
	TenantStatusInactive  TenantStatus = "inactive"
)

// TenantPlan represents the subscription plan
type TenantPlan string

const (
	TenantPlanFree       TenantPlan = "free"
	TenantPlanStarter    TenantPlan = "starter"
	TenantPlanPro        TenantPlan = "pro"
	TenantPlanEnterprise TenantPlan = "enterprise"
)

// TenantSettings contains tenant-specific configuration
type TenantSettings struct {
	AllowCustomCerts bool     `json:"allow_custom_certs"`
	AllowMTLS        bool     `json:"allow_mtls"`
	AllowWebhook     bool     `json:"allow_webhook"`
	MaxRequestSize   int64    `json:"max_request_size"`
	SessionTimeout   int      `json:"session_timeout"`
	RequireMFA       bool     `json:"require_mfa"`
	IPWhitelist      []string `json:"ip_whitelist"`
	AllowedOrigins   []string `json:"allowed_origins"`
	DefaultLanguage  string   `json:"default_language"`
	Timezone         string   `json:"timezone"`
}

// TenantQuota contains resource limits for the tenant
type TenantQuota struct {
	APIRequestsPerMinute     int   `json:"api_requests_per_minute"`
	MaxConcurrentConnections int   `json:"max_concurrent_connections"`
	MaxStorageMB             int64 `json:"max_storage_mb"`
	MaxUsers                 int   `json:"max_users"`
	MaxWebhooks              int   `json:"max_webhooks"`
	BandwidthGBPerMonth      int64 `json:"bandwidth_gb_per_month"`
}

// TenantCompliance contains compliance configuration
type TenantCompliance struct {
	EnabledFrameworks []string              `json:"enabled_frameworks"`
	DataResidency     string                `json:"data_residency"`
	RetentionPeriod   opsec.RetentionPeriod `json:"retention_period"`
	AuditLevel        opsec.AuditLevel      `json:"audit_level"`
	RequireEncryption bool                  `json:"require_encryption"`
}

// NewTenant creates a new tenant with default settings
func NewTenant(id, name, domain string) *Tenant {
	now := time.Now()
	return &Tenant{
		ID:         id,
		Name:       name,
		Domain:     domain,
		CreatedAt:  now,
		UpdatedAt:  now,
		Status:     TenantStatusActive,
		Plan:       TenantPlanFree,
		Settings:   DefaultTenantSettings(),
		Quota:      DefaultTenantQuota(),
		Compliance: DefaultTenantCompliance(),
	}
}

// DefaultTenantSettings returns default settings for a new tenant
func DefaultTenantSettings() *TenantSettings {
	return &TenantSettings{
		AllowCustomCerts: true,
		AllowMTLS:        false,
		AllowWebhook:     true,
		MaxRequestSize:   10 * 1024 * 1024, // 10MB
		SessionTimeout:   3600,
		RequireMFA:       false,
		IPWhitelist:      []string{},
		AllowedOrigins:   []string{},
		DefaultLanguage:  "en",
		Timezone:         "UTC",
	}
}

// DefaultTenantQuota returns default quota for a new tenant
func DefaultTenantQuota() *TenantQuota {
	return &TenantQuota{
		APIRequestsPerMinute:     100,
		MaxConcurrentConnections: 10,
		MaxStorageMB:             1024, // 1GB
		MaxUsers:                 5,
		MaxWebhooks:              5,
		BandwidthGBPerMonth:      10,
	}
}

// DefaultTenantCompliance returns default compliance settings
func DefaultTenantCompliance() *TenantCompliance {
	return &TenantCompliance{
		EnabledFrameworks: []string{"SOC2"},
		DataResidency:     "US",
		RetentionPeriod:   opsec.Retention1Year,
		AuditLevel:        opsec.AuditLevelInfo,
		RequireEncryption: true,
	}
}

// GetAuditLog returns the tenant's isolated audit log
func (t *Tenant) GetAuditLog() *opsec.ComplianceAuditLog {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.auditLog
}

// GetRateLimiter returns the tenant's isolated rate limiter
func (t *Tenant) GetRateLimiter() *SimpleRateLimiter {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.rateLimiter
}

// GetCircuitBreaker returns the tenant's isolated circuit breaker
func (t *Tenant) GetCircuitBreaker() *resilience.CircuitBreaker {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.circuitBreaker
}

// InitializeTenantResources initializes tenant-specific resources
func (t *Tenant) InitializeTenantResources(storagePath string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Initialize audit log with tenant-specific settings
	var storage opsec.StorageBackend
	var err error

	if storagePath != "" {
		storage, err = opsec.NewFileStorageBackend(
			fmt.Sprintf("%s/tenants/%s/audit", storagePath, t.ID),
			100*1024*1024, // 100MB max
		)
		if err != nil {
			return fmt.Errorf("failed to create tenant audit storage: %w", err)
		}
	}

	t.auditLog = opsec.NewComplianceAuditLog(
		t.Compliance.RetentionPeriod,
		storage,
		t.ID,
	)

	// Initialize rate limiter with tenant quota
	t.rateLimiter = NewSimpleRateLimiter(t.Quota.APIRequestsPerMinute)

	// Initialize circuit breaker
	t.circuitBreaker = resilience.NewCircuitBreaker(
		resilience.CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 1,
			Timeout:          30 * time.Second,
		},
	)

	return nil
}

// Update updates tenant information
func (t *Tenant) Update(name, domain string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if name != "" {
		t.Name = name
	}
	if domain != "" {
		t.Domain = domain
	}
	t.UpdatedAt = time.Now()

	return nil
}

// Suspend suspends the tenant
func (t *Tenant) Suspend() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Status == TenantStatusSuspended {
		return fmt.Errorf("tenant already suspended")
	}

	t.Status = TenantStatusSuspended
	t.UpdatedAt = time.Now()
	return nil
}

// Activate activates the tenant
func (t *Tenant) Activate() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Status == TenantStatusActive {
		return fmt.Errorf("tenant already active")
	}

	t.Status = TenantStatusActive
	t.UpdatedAt = time.Now()
	return nil
}

// CanUse checks if the tenant can use a specific feature
func (t *Tenant) CanUse(feature string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	switch feature {
	case "custom_certs":
		return t.Settings.AllowCustomCerts || t.Plan == TenantPlanEnterprise
	case "mtls":
		return t.Settings.AllowMTLS || t.Plan == TenantPlanEnterprise
	case "webhook":
		return t.Settings.AllowWebhook || t.Plan == TenantPlanEnterprise
	default:
		return false
	}
}

// CanExceed checks if the tenant can exceed a specific quota
func (t *Tenant) CanExceed(quota string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	switch quota {
	case "concurrent_connections":
		return t.Plan == TenantPlanEnterprise
	case "api_requests":
		return t.Plan == TenantPlanEnterprise
	case "storage":
		return t.Plan == TenantPlanEnterprise
	default:
		return false
	}
}

// Manager manages multiple tenants
type Manager struct {
	tenants map[string]*Tenant
	mu      sync.RWMutex
}

// NewManager creates a new tenant manager
func NewManager() *Manager {
	return &Manager{
		tenants: make(map[string]*Tenant),
	}
}

// CreateTenant creates a new tenant
func (m *Manager) CreateTenant(id, name, domain string, storagePath string) (*Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if tenant already exists
	if _, exists := m.tenants[id]; exists {
		return nil, fmt.Errorf("tenant %s already exists", id)
	}

	// Create new tenant
	tenant := NewTenant(id, name, domain)

	// Initialize tenant resources
	if err := tenant.InitializeTenantResources(storagePath); err != nil {
		return nil, fmt.Errorf("failed to initialize tenant resources: %w", err)
	}

	m.tenants[id] = tenant
	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (m *Manager) GetTenant(id string) (*Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenant, exists := m.tenants[id]
	if !exists {
		return nil, fmt.Errorf("tenant %s not found", id)
	}

	return tenant, nil
}

// ListTenants returns all tenants
func (m *Manager) ListTenants() []*Tenant {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tenants := make([]*Tenant, 0, len(m.tenants))
	for _, tenant := range m.tenants {
		tenants = append(tenants, tenant)
	}

	return tenants
}

// DeleteTenant removes a tenant
func (m *Manager) DeleteTenant(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[id]; !exists {
		return fmt.Errorf("tenant %s not found", id)
	}

	delete(m.tenants, id)
	return nil
}

// UpdateTenant updates tenant information
func (m *Manager) UpdateTenant(id, name, domain string) (*Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tenant, exists := m.tenants[id]
	if !exists {
		return nil, fmt.Errorf("tenant %s not found", id)
	}

	if err := tenant.Update(name, domain); err != nil {
		return nil, err
	}

	return tenant, nil
}

// TenantContextKey is the key for tenant context
type TenantContextKey string

const (
	TenantContextKeyID TenantContextKey = "tenant_id"
)

// WithTenant creates a context with tenant information
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantContextKeyID, tenantID)
}

// FromContext retrieves tenant ID from context
func FromContext(ctx context.Context) (string, bool) {
	tenantID, ok := ctx.Value(TenantContextKeyID).(string)
	return tenantID, ok
}
