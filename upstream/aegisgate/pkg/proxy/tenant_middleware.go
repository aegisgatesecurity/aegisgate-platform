package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/aegisgatesecurity/aegisgate/pkg/opsec"
	"github.com/aegisgatesecurity/aegisgate/pkg/tenant"
)

// TenantMiddleware provides tenant-aware proxy functionality
type TenantMiddleware struct {
	tenantManager *tenant.Manager
	logger        *slog.Logger
	headerName    string
	domainMapping map[string]string // domain -> tenantID
	mu            sync.RWMutex
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware(manager *tenant.Manager, logger *slog.Logger) *TenantMiddleware {
	return &TenantMiddleware{
		tenantManager: manager,
		logger:        logger,
		headerName:    "X-Tenant-ID",
		domainMapping: make(map[string]string),
	}
}

// Middleware returns an HTTP middleware that handles tenant isolation
func (tm *TenantMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := tm.enrichContext(r.Context(), r)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}

		// Apply tenant-specific rate limiting
		if !tm.checkRateLimit(ctx, w, r) {
			return
		}

		// Apply tenant-specific circuit breaker
		if !tm.checkCircuitBreaker(ctx, w, r) {
			return
		}

		// Log tenant-specific audit event
		tm.logAccess(ctx, r)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// enrichContext adds tenant information to the context
func (tm *TenantMiddleware) enrichContext(ctx context.Context, r *http.Request) (context.Context, error) {
	tenantID := tm.extractTenantID(r)
	if tenantID == "" {
		// Try to extract from domain
		tenantID = tm.extractTenantFromDomain(r.Host)
	}

	if tenantID == "" {
		// Try header
		tenantID = r.Header.Get(tm.headerName)
	}

	if tenantID == "" {
		return nil, fmt.Errorf("no tenant identified")
	}

	// Verify tenant exists
	t, err := tm.tenantManager.GetTenant(tenantID)
	if err != nil {
		tm.logger.Error("tenant not found", "tenant_id", tenantID)
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}

	// Check tenant status
	if t.Status != tenant.TenantStatusActive {
		return nil, fmt.Errorf("tenant not active: %s", t.Status)
	}

	// Add to context
	return tenant.WithTenant(ctx, tenantID), nil
}

// extractTenantID extracts tenant ID from request
func (tm *TenantMiddleware) extractTenantID(r *http.Request) string {
	// Check path parameter first: /tenant/{tenant_id}/...
	path := r.URL.Path
	if strings.HasPrefix(path, "/tenant/") {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return ""
}

// extractTenantFromDomain extracts tenant from domain
func (tm *TenantMiddleware) extractTenantFromDomain(host string) string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Check exact match
	if tenantID, ok := tm.domainMapping[host]; ok {
		return tenantID
	}

	// Check wildcard: *.tenant.example.com -> tenant
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		wildcard := "*." + strings.Join(parts[1:], ".")
		if tenantID, ok := tm.domainMapping[wildcard]; ok {
			return tenantID
		}
	}

	return ""
}

// RegisterDomainMapping registers a domain to tenant mapping
func (tm *TenantMiddleware) RegisterDomainMapping(domain, tenantID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.domainMapping[domain] = tenantID
}

// checkRateLimit applies tenant-specific rate limiting
func (tm *TenantMiddleware) checkRateLimit(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	tenantID, ok := tenant.FromContext(ctx)
	if !ok {
		return true // No rate limiting if no tenant
	}

	t, err := tm.tenantManager.GetTenant(tenantID)
	if err != nil {
		return true
	}

	rl := t.GetRateLimiter()
	if rl == nil {
		return true
	}

	if !rl.Allow() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		tm.logger.Warn("rate limit exceeded", "tenant_id", tenantID)
		return false
	}

	return true
}

// checkCircuitBreaker applies tenant-specific circuit breaking
func (tm *TenantMiddleware) checkCircuitBreaker(ctx context.Context, w http.ResponseWriter, r *http.Request) bool {
	tenantID, ok := tenant.FromContext(ctx)
	if !ok {
		return true
	}

	t, err := tm.tenantManager.GetTenant(tenantID)
	if err != nil {
		return true
	}

	cb := t.GetCircuitBreaker()
	if cb == nil {
		return true
	}

	// Execute with circuit breaker
	err = cb.Execute(ctx, func(ctx context.Context) error {
		return nil // Request proceeds
	})

	if err != nil {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		tm.logger.Warn("circuit breaker open", "tenant_id", tenantID)
		return false
	}

	return true
}

// logAccess logs tenant-specific access
func (tm *TenantMiddleware) logAccess(ctx context.Context, r *http.Request) {
	tenantID, ok := tenant.FromContext(ctx)
	if !ok {
		return
	}

	t, err := tm.tenantManager.GetTenant(tenantID)
	if err != nil || t.GetAuditLog() == nil {
		return
	}

	auditLog := t.GetAuditLog()
	_ = auditLog.LogComplianceEvent(ctx,
		opsec.AuditLevelInfo,
		"proxy.request",
		fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		nil,
		map[string]interface{}{
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
			"user_agent": r.UserAgent(),
		},
	)
}

// GetTenantFromRequest extracts tenant from HTTP request
func GetTenantFromRequest(mgr *tenant.Manager, r *http.Request) (*tenant.Tenant, error) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		path := r.URL.Path
		if strings.HasPrefix(path, "/tenant/") {
			parts := strings.SplitN(path, "/", 3)
			if len(parts) >= 2 {
				tenantID = parts[1]
			}
		}
	}

	if tenantID == "" {
		return nil, fmt.Errorf("no tenant identified")
	}

	return mgr.GetTenant(tenantID)
}

// TenantAwareProxy wraps a proxy with tenant awareness
type TenantAwareProxy struct {
	*Proxy
	tenantMiddleware *TenantMiddleware
}

// NewTenantAwareProxy creates a new tenant-aware proxy
func NewTenantAwareProxy(proxy *Proxy, manager *tenant.Manager, logger *slog.Logger) *TenantAwareProxy {
	return &TenantAwareProxy{
		Proxy:            proxy,
		tenantMiddleware: NewTenantMiddleware(manager, logger),
	}
}

// ServeHTTP handles HTTP requests with tenant awareness
func (tap *TenantAwareProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply tenant middleware first
	tap.tenantMiddleware.Middleware(tap.Proxy).ServeHTTP(w, r)
}

// WithTenantMiddleware wraps a handler with tenant middleware
func (tap *TenantAwareProxy) WithTenantMiddleware(handler http.Handler) http.Handler {
	return tap.tenantMiddleware.Middleware(handler)
}

// GetTenantMiddleware returns the tenant middleware
func (tap *TenantAwareProxy) GetTenantMiddleware() *TenantMiddleware {
	return tap.tenantMiddleware
}
