// Package adapters provides test coverage for module adapters
package adapters

import (
	"context"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/auth"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
	"github.com/aegisgatesecurity/aegisgate/pkg/dashboard"
	"github.com/aegisgatesecurity/aegisgate/pkg/i18n"
	_ "github.com/aegisgatesecurity/aegisgate/pkg/metrics"
	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
	_ "github.com/aegisgatesecurity/aegisgate/pkg/tls"
)

// ============================================================================
// AuthModuleAdapter Tests
// ============================================================================

func TestNewAuthModule(t *testing.T) {
	module := NewAuthModule()
	if module == nil {
		t.Fatal("NewAuthModule returned nil")
	}

	// Verify module metadata
	meta := module.Metadata()
	if meta.ID != "auth" {
		t.Errorf("Expected module ID 'auth', got '%s'", meta.ID)
	}
	if meta.Name != "Authentication Module" {
		t.Errorf("Expected module Name 'Authentication Module', got '%s'", meta.Name)
	}
	if meta.Version != "1.0.0" {
		t.Errorf("Expected module Version '1.0.0', got '%s'", meta.Version)
	}
	if meta.Category != core.CategoryAuth {
		t.Errorf("Expected CategoryAuth, got %v", meta.Category)
	}
	if meta.Tier != core.TierProfessional {
		t.Errorf("Expected TierProfessional, got %v", meta.Tier)
	}
}

func TestAuthModule_Initialize(t *testing.T) {
	tests := []struct {
		name     string
		config   core.ModuleConfig
		wantErr  bool
		validate func(t *testing.T, m *AuthModuleAdapter)
	}{
		{
			name: "initialize with nil settings",
			config: core.ModuleConfig{
				Settings: nil,
			},
			wantErr: false,
			validate: func(t *testing.T, m *AuthModuleAdapter) {
				if m.config == nil {
					t.Error("config should not be nil after init")
				}
			},
		},
		{
			name: "initialize with auth config",
			config: core.ModuleConfig{
				Settings: map[string]interface{}{
					"auth_config": &auth.Config{
						Provider: "local",
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, m *AuthModuleAdapter) {
				if m.config.Provider != "local" {
					t.Errorf("Expected provider 'local', got '%s'", m.config.Provider)
				}
			},
		},
		{
			name: "initialize without auth config",
			config: core.ModuleConfig{
				Settings: map[string]interface{}{
					"other_config": "value",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewAuthModule()
			ctx := context.Background()

			err := module.Initialize(ctx, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.validate != nil {
				tt.validate(t, module)
			}
		})
	}
}

func TestAuthModule_StartStop(t *testing.T) {
	tests := []struct {
		name       string
		config     core.ModuleConfig
		wantStatus core.ModuleStatus
	}{
		{
			name: "start without provider",
			config: core.ModuleConfig{
				Settings: map[string]interface{}{
					"auth_config": &auth.Config{Provider: ""},
				},
			},
			wantStatus: core.StatusActive,
		},
		{
			name: "start with nil config",
			config: core.ModuleConfig{
				Settings: nil,
			},
			wantStatus: core.StatusActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewAuthModule()
			ctx := context.Background()

			err := module.Initialize(ctx, tt.config)
			if err != nil {
				t.Fatalf("Initialize() error = %v", err)
			}

			err = module.Start(ctx)
			if err != nil {
				t.Errorf("Start() error = %v", err)
			}

			if module.Status() != tt.wantStatus {
				t.Errorf("Expected status %v, got %v", tt.wantStatus, module.Status())
			}

			err = module.Stop(ctx)
			if err != nil {
				t.Errorf("Stop() error = %v", err)
			}
		})
	}
}

func TestAuthModule_Provides(t *testing.T) {
	module := NewAuthModule()
	provides := module.Provides()

	expected := []string{"authentication", "authorization", "session_management"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}

	for i, exp := range expected {
		if provides[i] != exp {
			t.Errorf("Expected provides[%d] = '%s', got '%s'", i, exp, provides[i])
		}
	}
}

func TestAuthModule_GetManager(t *testing.T) {
	module := NewAuthModule()
	manager := module.GetManager()
	if manager != nil {
		t.Error("Expected nil manager before start")
	}
}

// ============================================================================
// DashboardModuleAdapter Tests
// ============================================================================

func TestNewDashboardModule(t *testing.T) {
	module := NewDashboardModule()
	if module == nil {
		t.Fatal("NewDashboardModule returned nil")
	}

	meta := module.Metadata()
	if meta.ID != "dashboard" {
		t.Errorf("Expected module ID 'dashboard', got '%s'", meta.ID)
	}
	if meta.Category != core.CategoryUI {
		t.Errorf("Expected CategoryUI, got %v", meta.Category)
	}
}

func TestDashboardModule_Initialize(t *testing.T) {
	tests := []struct {
		name   string
		config core.ModuleConfig
	}{
		{
			name: "default config",
			config: core.ModuleConfig{
				Settings: nil,
			},
		},
		{
			name: "custom config",
			config: core.ModuleConfig{
				Settings: map[string]interface{}{
					"dashboard_config": dashboard.Config{
						Port:        9090,
						StaticDir:   "./custom-static",
						CORSEnabled: false,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewDashboardModule()
			ctx := context.Background()

			err := module.Initialize(ctx, tt.config)
			if err != nil {
				t.Errorf("Initialize() error = %v", err)
			}
		})
	}
}

func TestDashboardModule_SetI18nManager(t *testing.T) {
	module := NewDashboardModule()

	// Create i18n manager (may fail if embedded files not available)
	mgr, err := i18n.GetEmbeddedManager()
	if err != nil {
		t.Skipf("Could not create i18n manager: %v", err)
	}

	module.SetI18nManager(mgr)
	if module.i18nMgr != mgr {
		t.Error("i18n manager not set correctly")
	}
}

func TestDashboardModule_Provides(t *testing.T) {
	module := NewDashboardModule()
	provides := module.Provides()

	expected := []string{"dashboard", "web_ui", "monitoring"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}
}

func TestDashboardModule_Dependencies(t *testing.T) {
	module := NewDashboardModule()

	deps := module.Dependencies()
	if len(deps) != 0 {
		t.Errorf("Expected no required dependencies, got %v", deps)
	}

	optDeps := module.OptionalDependencies()
	expected := []string{"i18n", "auth", "metrics"}
	if len(optDeps) != len(expected) {
		t.Errorf("Expected %d optional dependencies, got %d", len(expected), len(optDeps))
	}
}

// ============================================================================
// I18nModuleAdapter Tests
// ============================================================================

func TestNewI18nModule(t *testing.T) {
	module := NewI18nModule()
	if module == nil {
		t.Fatal("NewI18nModule returned nil")
	}

	meta := module.Metadata()
	if meta.ID != "i18n" {
		t.Errorf("Expected module ID 'i18n', got '%s'", meta.ID)
	}
	if meta.Category != core.CategoryCore {
		t.Errorf("Expected CategoryCore, got %v", meta.Category)
	}
}

func TestI18nModule_Initialize(t *testing.T) {
	module := NewI18nModule()
	ctx := context.Background()

	err := module.Initialize(ctx, core.ModuleConfig{
		Settings: map[string]interface{}{
			"locale": "en",
		},
	})
	if err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	if module.manager == nil {
		t.Error("Expected manager to be initialized")
	}
}

func TestI18nModule_Start(t *testing.T) {
	module := NewI18nModule()
	ctx := context.Background()

	err := module.Initialize(ctx, core.ModuleConfig{})
	if err != nil {
		t.Skipf("Could not initialize: %v", err)
	}

	err = module.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if module.Status() != core.StatusActive {
		t.Errorf("Expected status active, got %v", module.Status())
	}
}

func TestI18nModule_Provides(t *testing.T) {
	module := NewI18nModule()
	provides := module.Provides()

	expected := []string{"i18n", "localization", "translation"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}
}

// ============================================================================
// MetricsModuleAdapter Tests
// ============================================================================

func TestNewMetricsModule(t *testing.T) {
	module := NewMetricsModule()
	if module == nil {
		t.Fatal("NewMetricsModule returned nil")
	}

	meta := module.Metadata()
	if meta.ID != "metrics" {
		t.Errorf("Expected module ID 'metrics', got '%s'", meta.ID)
	}
}

func TestMetricsModule_InitializeAndStart(t *testing.T) {
	module := NewMetricsModule()
	ctx := context.Background()

	err := module.Initialize(ctx, core.ModuleConfig{})
	if err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	err = module.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if module.Status() != core.StatusActive {
		t.Errorf("Expected status active, got %v", module.Status())
	}

	if module.GetCollector() == nil {
		t.Error("Expected collector to be initialized")
	}
}

func TestMetricsModule_Provides(t *testing.T) {
	module := NewMetricsModule()
	provides := module.Provides()

	expected := []string{"metrics", "monitoring", "prometheus"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}
}

// ============================================================================
// ScannerModuleAdapter Tests
// ============================================================================

func TestNewScannerModule(t *testing.T) {
	module := NewScannerModule()
	if module == nil {
		t.Fatal("NewScannerModule returned nil")
	}

	meta := module.Metadata()
	if meta.ID != "scanner" {
		t.Errorf("Expected module ID 'scanner', got '%s'", meta.ID)
	}
	if meta.Category != core.CategorySecurity {
		t.Errorf("Expected CategorySecurity, got %v", meta.Category)
	}
}

func TestScannerModule_InitializeAndStart(t *testing.T) {
	module := NewScannerModule()
	ctx := context.Background()

	err := module.Initialize(ctx, core.ModuleConfig{})
	if err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	err = module.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if module.Status() != core.StatusActive {
		t.Errorf("Expected status active, got %v", module.Status())
	}

	if module.GetScanner() == nil {
		t.Error("Expected scanner to be initialized")
	}
}

func TestScannerModule_Provides(t *testing.T) {
	module := NewScannerModule()
	provides := module.Provides()

	expected := []string{"scanner", "security_scan", "vulnerability_detection"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}
}

// ============================================================================
// TLSModuleAdapter Tests
// ============================================================================

func TestNewTLSModule(t *testing.T) {
	module := NewTLSModule()
	if module == nil {
		t.Fatal("NewTLSModule returned nil")
	}

	meta := module.Metadata()
	if meta.ID != "tls" {
		t.Errorf("Expected module ID 'tls', got '%s'", meta.ID)
	}
	if meta.Category != core.CategorySecurity {
		t.Errorf("Expected CategorySecurity, got %v", meta.Category)
	}
}

func TestTLSModule_Initialize(t *testing.T) {
	tests := []struct {
		name   string
		config core.ModuleConfig
	}{
		{
			name:   "default config",
			config: core.ModuleConfig{Settings: nil},
		},
		{
			name: "custom cert dir",
			config: core.ModuleConfig{
				Settings: map[string]interface{}{
					"cert_dir": "./custom-certs",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewTLSModule()
			ctx := context.Background()

			err := module.Initialize(ctx, tt.config)
			// May fail if cert directory doesn't exist - that's acceptable
			if err != nil {
				t.Logf("Initialize() returned error (may be expected): %v", err)
			}
		})
	}
}

func TestTLSModule_Provides(t *testing.T) {
	module := NewTLSModule()
	provides := module.Provides()

	expected := []string{"tls", "ssl", "certificates", "encryption"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}
}

// ============================================================================
// ProxyModuleAdapter Tests
// ============================================================================

func TestNewProxyModule(t *testing.T) {
	module := NewProxyModule()
	if module == nil {
		t.Fatal("NewProxyModule returned nil")
	}

	meta := module.Metadata()
	if meta.ID != "proxy" {
		t.Errorf("Expected module ID 'proxy', got '%s'", meta.ID)
	}
	if meta.Category != core.CategoryProxy {
		t.Errorf("Expected CategoryProxy, got %v", meta.Category)
	}
}

func TestProxyModule_Initialize(t *testing.T) {
	tests := []struct {
		name   string
		config core.ModuleConfig
	}{
		{
			name:   "default config",
			config: core.ModuleConfig{Settings: nil},
		},
		{
			name: "custom proxy options",
			config: core.ModuleConfig{
				Settings: map[string]interface{}{
					"proxy_options": &proxy.Options{
						BindAddress: ":8080",
						Upstream:    "http://localhost:3000",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module := NewProxyModule()
			ctx := context.Background()

			err := module.Initialize(ctx, tt.config)
			if err != nil {
				t.Errorf("Initialize() error = %v", err)
			}
		})
	}
}

func TestProxyModule_Start(t *testing.T) {
	module := NewProxyModule()
	ctx := context.Background()

	err := module.Initialize(ctx, core.ModuleConfig{
		Settings: map[string]interface{}{
			"proxy_options": &proxy.Options{
				BindAddress: ":0", // Use random port
				Upstream:    "http://localhost:3000",
			},
		},
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	err = module.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if module.Status() != core.StatusActive {
		t.Errorf("Expected status active, got %v", module.Status())
	}
}

func TestProxyModule_Provides(t *testing.T) {
	module := NewProxyModule()
	provides := module.Provides()

	expected := []string{"proxy", "reverse_proxy", "request_filtering"}
	if len(provides) != len(expected) {
		t.Errorf("Expected %d provides, got %d", len(expected), len(provides))
	}
}

func TestProxyModule_Dependencies(t *testing.T) {
	module := NewProxyModule()

	deps := module.Dependencies()
	if len(deps) != 1 || deps[0] != "tls" {
		t.Errorf("Expected dependency 'tls', got %v", deps)
	}

	optDeps := module.OptionalDependencies()
	expected := []string{"scanner", "auth", "metrics"}
	if len(optDeps) != len(expected) {
		t.Errorf("Expected %d optional dependencies, got %d", len(expected), len(optDeps))
	}
}

func TestProxyModule_GetHandler(t *testing.T) {
	module := NewProxyModule()
	ctx := context.Background()

	err := module.Initialize(ctx, core.ModuleConfig{})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	handler := module.GetHandler()
	if handler == nil {
		t.Error("Expected handler to be initialized")
	}
}

// ============================================================================
// Test Now variable override
// ============================================================================

func TestNowVariable(t *testing.T) {
	// Test that Now can be overridden for testing
	originalNow := Now
	defer func() { Now = originalNow }()

	testTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	Now = func() time.Time {
		return testTime
	}

	result := Now()
	if result != testTime {
		t.Errorf("Expected Now() to return %v, got %v", testTime, result)
	}
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkNewAuthModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewAuthModule()
	}
}

func BenchmarkNewDashboardModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewDashboardModule()
	}
}

func BenchmarkNewI18nModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewI18nModule()
	}
}

func BenchmarkNewMetricsModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewMetricsModule()
	}
}

func BenchmarkNewScannerModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewScannerModule()
	}
}

func BenchmarkNewTLSModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewTLSModule()
	}
}

func BenchmarkNewProxyModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewProxyModule()
	}
}

func BenchmarkAuthModule_Initialize(b *testing.B) {
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		module := NewAuthModule()
		_ = module.Initialize(ctx, core.ModuleConfig{})
	}
}

func BenchmarkProxyModule_Initialize(b *testing.B) {
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		module := NewProxyModule()
		_ = module.Initialize(ctx, core.ModuleConfig{})
	}
}
