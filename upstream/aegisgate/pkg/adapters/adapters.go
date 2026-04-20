// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package adapters provides module wrappers for existing AegisGate packages.
// These adapters allow gradual migration to the modular plugin architecture.
package adapters

import (
	"context"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	"github.com/aegisgatesecurity/aegisgate/pkg/dashboard"
	"github.com/aegisgatesecurity/aegisgate/pkg/i18n"
	"github.com/aegisgatesecurity/aegisgate/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
	tlspkg "github.com/aegisgatesecurity/aegisgate/pkg/tls"
)

// AuthModuleAdapter wraps the auth package as a module.
type AuthModuleAdapter struct {
	*core.BaseModule
	manager *auth.Manager
	config  *auth.Config
}

// NewAuthModule creates a new auth module adapter.
func NewAuthModule() *AuthModuleAdapter {
	return &AuthModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "auth",
			Name:        "Authentication Module",
			Version:     "1.0.0",
			Description: "Multi-provider authentication with OAuth, SAML, and local auth support",
			Category:    core.CategoryAuth,
			Tier:        core.TierProfessional,
			Tags:        []string{"authentication", "oauth", "saml", "security"},
		}),
	}
}

// Initialize prepares the auth module.
func (m *AuthModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Extract auth config from module config
	if authCfg, ok := config.Settings["auth_config"].(*auth.Config); ok {
		m.config = authCfg
	} else {
		m.config = auth.DefaultConfig()
	}

	return nil
}

// Start begins the auth module operation.
func (m *AuthModuleAdapter) Start(ctx context.Context) error {
	if m.config == nil || m.config.Provider == "" {
		m.SetStatus(core.StatusActive)
		return nil // Auth disabled
	}

	manager, err := auth.NewManager(m.config)
	if err != nil {
		return err
	}

	m.manager = manager
	m.SetStatus(core.StatusActive)
	return nil
}

// Stop gracefully shuts down the auth module.
func (m *AuthModuleAdapter) Stop(ctx context.Context) error {
	if m.manager != nil {
		m.manager.Close()
	}
	return m.BaseModule.Stop(ctx)
}

// GetManager returns the underlying auth manager.
func (m *AuthModuleAdapter) GetManager() *auth.Manager {
	return m.manager
}

// Provides returns the capabilities this module provides.
func (m *AuthModuleAdapter) Provides() []string {
	return []string{"authentication", "authorization", "session_management"}
}

// DashboardModuleAdapter wraps the dashboard package as a module.
type DashboardModuleAdapter struct {
	*core.BaseModule
	dash    *dashboard.Dashboard
	config  dashboard.Config
	i18nMgr *i18n.Manager
}

// NewDashboardModule creates a new dashboard module adapter.
func NewDashboardModule() *DashboardModuleAdapter {
	return &DashboardModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "dashboard",
			Name:        "Dashboard Module",
			Version:     "1.0.0",
			Description: "Web-based administration dashboard with i18n support",
			Category:    core.CategoryUI,
			Tier:        core.TierCommunity,
			Tags:        []string{"dashboard", "ui", "admin", "monitoring"},
		}),
	}
}

// SetI18nManager sets the i18n manager for the dashboard.
func (m *DashboardModuleAdapter) SetI18nManager(i18nMgr *i18n.Manager) {
	m.i18nMgr = i18nMgr
}

// Initialize prepares the dashboard module.
func (m *DashboardModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Extract dashboard config
	if dashCfg, ok := config.Settings["dashboard_config"].(dashboard.Config); ok {
		m.config = dashCfg
	} else {
		m.config = dashboard.Config{
			Port:        8080,
			StaticDir:   "./static",
			CORSEnabled: true,
		}
	}

	return nil
}

// Start begins the dashboard module operation.
func (m *DashboardModuleAdapter) Start(ctx context.Context) error {
	if m.i18nMgr != nil {
		m.dash = dashboard.NewWithI18n(m.config, m.i18nMgr)
	} else {
		m.dash = dashboard.New(m.config)
	}

	go func() {
		if err := m.dash.Start(); err != nil {
			m.SetStatus(core.StatusError)
		}
	}()

	m.SetStatus(core.StatusActive)
	return nil
}

// Stop gracefully shuts down the dashboard module.
func (m *DashboardModuleAdapter) Stop(ctx context.Context) error {
	if m.dash != nil {
		return m.dash.Stop(ctx)
	}
	return m.BaseModule.Stop(ctx)
}

// GetDashboard returns the underlying dashboard instance.
func (m *DashboardModuleAdapter) GetDashboard() *dashboard.Dashboard {
	return m.dash
}

// Provides returns the capabilities this module provides.
func (m *DashboardModuleAdapter) Provides() []string {
	return []string{"dashboard", "web_ui", "monitoring"}
}

// Dependencies returns required modules.
func (m *DashboardModuleAdapter) Dependencies() []string {
	return []string{}
}

// OptionalDependencies returns optional modules.
func (m *DashboardModuleAdapter) OptionalDependencies() []string {
	return []string{"i18n", "auth", "metrics"}
}

// I18nModuleAdapter wraps the i18n package as a module.
type I18nModuleAdapter struct {
	*core.BaseModule
	manager *i18n.Manager
	locale  i18n.Locale
}

// NewI18nModule creates a new i18n module adapter.
func NewI18nModule() *I18nModuleAdapter {
	return &I18nModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "i18n",
			Name:        "Internationalization Module",
			Version:     "1.0.0",
			Description: "Multi-language support with 6 built-in locales",
			Category:    core.CategoryCore,
			Tier:        core.TierCommunity,
			Tags:        []string{"i18n", "localization", "internationalization"},
		}),
	}
}

// Initialize prepares the i18n module.
func (m *I18nModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	manager, err := i18n.GetEmbeddedManager()
	if err != nil {
		return err
	}

	m.manager = manager

	// Set locale from config
	if localeStr, ok := config.Settings["locale"].(string); ok {
		m.locale = i18n.ParseLocale(localeStr)
		if err := m.manager.SetCurrent(m.locale); err != nil {
			// Log warning but don't fail
		}
	}

	return nil
}

// Start begins the i18n module operation.
func (m *I18nModuleAdapter) Start(ctx context.Context) error {
	m.SetStatus(core.StatusActive)
	return nil
}

// GetManager returns the underlying i18n manager.
func (m *I18nModuleAdapter) GetManager() *i18n.Manager {
	return m.manager
}

// Provides returns the capabilities this module provides.
func (m *I18nModuleAdapter) Provides() []string {
	return []string{"i18n", "localization", "translation"}
}

// MetricsModuleAdapter wraps the metrics package as a module.
type MetricsModuleAdapter struct {
	*core.BaseModule
	collector *metrics.MetricsCollector
}

// NewMetricsModule creates a new metrics module adapter.
func NewMetricsModule() *MetricsModuleAdapter {
	return &MetricsModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "metrics",
			Name:        "Metrics Module",
			Version:     "1.0.0",
			Description: "Prometheus-compatible metrics collection and reporting",
			Category:    core.CategoryAnalytics,
			Tier:        core.TierCommunity,
			Tags:        []string{"metrics", "monitoring", "prometheus", "observability"},
		}),
	}
}

// Initialize prepares the metrics module.
func (m *MetricsModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	m.collector = metrics.GlobalCollector()
	return nil
}

// Start begins the metrics module operation.
func (m *MetricsModuleAdapter) Start(ctx context.Context) error {
	m.SetStatus(core.StatusActive)
	return nil
}

// GetCollector returns the underlying metrics collector.
func (m *MetricsModuleAdapter) GetCollector() *metrics.MetricsCollector {
	return m.collector
}

// Provides returns the capabilities this module provides.
func (m *MetricsModuleAdapter) Provides() []string {
	return []string{"metrics", "monitoring", "prometheus"}
}

// ScannerModuleAdapter wraps the scanner package as a module.
type ScannerModuleAdapter struct {
	*core.BaseModule
	scanner *scanner.Scanner
}

// NewScannerModule creates a new scanner module adapter.
func NewScannerModule() *ScannerModuleAdapter {
	return &ScannerModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "scanner",
			Name:        "Security Scanner Module",
			Version:     "1.0.0",
			Description: "AI-specific security vulnerability and pattern scanner",
			Category:    core.CategorySecurity,
			Tier:        core.TierProfessional,
			Tags:        []string{"scanner", "security", "vulnerability", "ai-security"},
		}),
	}
}

// Initialize prepares the scanner module.
func (m *ScannerModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	m.scanner = scanner.New(scanner.DefaultConfig())
	return nil
}

// Start begins the scanner module operation.
func (m *ScannerModuleAdapter) Start(ctx context.Context) error {
	m.SetStatus(core.StatusActive)
	return nil
}

// GetScanner returns the underlying scanner.
func (m *ScannerModuleAdapter) GetScanner() *scanner.Scanner {
	return m.scanner
}

// Provides returns the capabilities this module provides.
func (m *ScannerModuleAdapter) Provides() []string {
	return []string{"scanner", "security_scan", "vulnerability_detection"}
}

// TLSModuleAdapter wraps the TLS package as a module.
type TLSModuleAdapter struct {
	*core.BaseModule
	manager *tlspkg.Manager
	config  *tlspkg.Config
}

// NewTLSModule creates a new TLS module adapter.
func NewTLSModule() *TLSModuleAdapter {
	return &TLSModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "tls",
			Name:        "TLS Module",
			Version:     "1.0.0",
			Description: "TLS 1.3 certificate management with auto-generation",
			Category:    core.CategorySecurity,
			Tier:        core.TierCommunity,
			Tags:        []string{"tls", "ssl", "certificates", "security"},
		}),
	}
}

// Initialize prepares the TLS module.
func (m *TLSModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Extract TLS config
	if tlsCfg, ok := config.Settings["tls_config"].(*tlspkg.Config); ok {
		m.config = tlsCfg
	} else {
		certDir := "./certs"
		if dir, ok := config.Settings["cert_dir"].(string); ok {
			certDir = dir
		}
		m.config = &tlspkg.Config{
			CertDir:      certDir,
			AutoGenerate: true,
		}
	}

	manager, err := tlspkg.NewManager(m.config)
	if err != nil {
		return err
	}

	m.manager = manager
	return nil
}

// Start begins the TLS module operation.
func (m *TLSModuleAdapter) Start(ctx context.Context) error {
	m.SetStatus(core.StatusActive)
	return nil
}

// GetManager returns the underlying TLS manager.
func (m *TLSModuleAdapter) GetManager() *tlspkg.Manager {
	return m.manager
}

// Provides returns the capabilities this module provides.
func (m *TLSModuleAdapter) Provides() []string {
	return []string{"tls", "ssl", "certificates", "encryption"}
}

// ProxyModuleAdapter wraps the proxy package as a module.
type ProxyModuleAdapter struct {
	*core.BaseModule
	proxy  *proxy.Proxy
	config *proxy.Options
}

// NewProxyModule creates a new proxy module adapter.
func NewProxyModule() *ProxyModuleAdapter {
	return &ProxyModuleAdapter{
		BaseModule: core.NewBaseModule(core.ModuleMetadata{
			ID:          "proxy",
			Name:        "Security Proxy Module",
			Version:     "1.0.0",
			Description: "Reverse proxy with AI-specific security controls",
			Category:    core.CategoryProxy,
			Tier:        core.TierCommunity,
			Tags:        []string{"proxy", "reverse-proxy", "security"},
		}),
	}
}

// Initialize prepares the proxy module.
func (m *ProxyModuleAdapter) Initialize(ctx context.Context, config core.ModuleConfig) error {
	if err := m.BaseModule.Initialize(ctx, config); err != nil {
		return err
	}

	// Extract proxy config
	opts := &proxy.Options{}
	if proxyOpts, ok := config.Settings["proxy_options"].(*proxy.Options); ok {
		opts = proxyOpts
	}

	m.config = opts
	m.proxy = proxy.New(opts)

	return nil
}

// Start begins the proxy module operation.
func (m *ProxyModuleAdapter) Start(ctx context.Context) error {
	m.SetStatus(core.StatusActive)
	return nil
}

// GetHandler returns the underlying proxy handler.
func (m *ProxyModuleAdapter) GetHandler() *proxy.Proxy {
	return m.proxy
}

// Provides returns the capabilities this module provides.
func (m *ProxyModuleAdapter) Provides() []string {
	return []string{"proxy", "reverse_proxy", "request_filtering"}
}

// Dependencies returns required modules.
func (m *ProxyModuleAdapter) Dependencies() []string {
	return []string{"tls"}
}

// OptionalDependencies returns optional modules.
func (m *ProxyModuleAdapter) OptionalDependencies() []string {
	return []string{"scanner", "auth", "metrics"}
}

// Now is a variable for testing purposes.
var Now = func() time.Time {
	return time.Now()
}
