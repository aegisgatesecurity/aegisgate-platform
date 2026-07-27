// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard License Management
//
// =========================================================================
//
// This package provides license validation for AegisGuard.
// Licenses are validated centrally against the AegisGate Admin Panel.
//
// Tier Levels:
// - Community (0): Free tier with basic features
// - Developer (1): Enhanced features for small teams
// - Professional (2): Advanced features for organizations
// - Enterprise (3): Full feature set with dedicated support
//
// Architecture:
// AegisGuard validates licenses by calling the Admin Panel API.
// No local license database is needed - validation is centralized.

package license

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Tier represents license tier levels
type Tier int

const (
	TierCommunity Tier = iota
	TierDeveloper
	TierProfessional
	TierEnterprise
)

func (t Tier) String() string {
	switch t {
	case TierCommunity:
		return "community"
	case TierDeveloper:
		return "developer"
	case TierProfessional:
		return "professional"
	case TierEnterprise:
		return "enterprise"
	default:
		return "unknown"
	}
}

func GetTierByName(name string) Tier {
	switch name {
	case "community", "Community", "COMMUNITY":
		return TierCommunity
	case "developer", "Developer", "DEVELOPER":
		return TierDeveloper
	case "professional", "Professional", "PROFESSIONAL":
		return TierProfessional
	case "enterprise", "Enterprise", "ENTERPRISE":
		return TierEnterprise
	default:
		return TierCommunity
	}
}

// License represents a validated license
type License struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Email        string    `json:"email"`
	Organization string    `json:"organization,omitempty"`
	Tiers        []Tier    `json:"tiers,omitempty"`
	MaxServers   int       `json:"max_servers"`
	MaxUsers     int       `json:"max_users"`
	Features     []string  `json:"features,omitempty"`
	Modules      []string  `json:"modules,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Valid        bool      `json:"valid"`
}

// Status represents license validation status
type Status int

const (
	StatusValid Status = iota
	StatusExpired
	StatusRevoked
	StatusNotFound
	StatusInvalid
	StatusServiceUnavailable
)

func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusExpired:
		return "expired"
	case StatusRevoked:
		return "revoked"
	case StatusNotFound:
		return "not_found"
	case StatusInvalid:
		return "invalid"
	case StatusServiceUnavailable:
		return "service_unavailable"
	default:
		return "unknown"
	}
}

// ValidationResult from the admin panel
type ValidationResult struct {
	Valid       bool      `json:"valid"`
	Status      string    `json:"status"`
	Message     string    `json:"message"`
	License     *License  `json:"license,omitempty"`
	ValidatedAt time.Time `json:"validated_at"`
}

// Config holds license configuration
type Config struct {
	// LicenseKey is the license key from the admin panel
	LicenseKey string `yaml:"license_key" json:"license_key"`

	// AdminPanelURL is the URL of the AegisGate Admin Panel
	AdminPanelURL string `yaml:"admin_panel_url" json:"admin_panel_url"`

	// PublicKeyPEM for offline signature verification (optional)
	PublicKeyPEM string `yaml:"public_key_pem" json:"public_key_pem"`

	// CacheDuration is how long to cache validation results
	CacheDuration time.Duration `yaml:"cache_duration" json:"cache_duration"`

	// RetryInterval is time between retries on failure
	RetryInterval time.Duration `yaml:"retry_interval" json:"retry_interval"`

	// FailOpen allows operation if license service is unavailable
	FailOpen bool `yaml:"fail_open" json:"fail_open"`

	// GracePeriod allows operation after license expires
	GracePeriod time.Duration `yaml:"grace_period" json:"grace_period"`
}

// DefaultConfig returns default license configuration
func DefaultConfig() *Config {
	return &Config{
		LicenseKey:    getEnv("LICENSE_KEY", ""),
		AdminPanelURL: getEnv("ADMIN_PANEL_URL", "https://license.aegisgatesecurity.io"),
		CacheDuration: 5 * time.Minute,
		RetryInterval: 30 * time.Second,
		FailOpen:      false,
		GracePeriod:   7 * 24 * time.Hour,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Manager handles license validation
type Manager struct {
	config     *Config
	httpClient *http.Client
	publicKey  *rsa.PublicKey

	mu          sync.RWMutex
	license     *License
	status      Status
	validatedAt time.Time
	cachedUntil time.Time
}

// NewManager creates a new license manager
func NewManager(config *Config) *Manager {
	if config == nil {
		config = DefaultConfig()
	}

	m := &Manager{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		status: StatusNotFound,
	}

	// Load public key if provided
	if config.PublicKeyPEM != "" {
		_ = m.setPublicKey([]byte(config.PublicKeyPEM))
	}

	// Validate license on startup
	if config.LicenseKey != "" {
		_, _ = m.Validate(context.Background())
	} else {
		log.Println("[LICENSE] No license key configured, using Community tier")
	}

	return m
}

// Validate validates the license against the admin panel
func (m *Manager) Validate(ctx context.Context) (*License, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check cache
	if m.cachedUntil.After(time.Now()) && m.license != nil {
		return m.license, nil
	}

	// No license key = Community tier
	if m.config.LicenseKey == "" {
		m.status = StatusValid
		m.license = &License{
			Type:       "community",
			Tiers:      []Tier{TierCommunity},
			MaxUsers:   3,
			MaxServers: 1,
			Valid:      true,
			IssuedAt:   time.Now(),
			ExpiresAt:  time.Now().Add(365 * 24 * time.Hour),
		}
		m.cachedUntil = time.Now().Add(m.config.CacheDuration)
		return m.license, nil
	}

	// Validate remotely
	result, err := m.validateRemote(ctx)
	if err != nil {
		if m.config.FailOpen {
			log.Printf("[LICENSE] Service unavailable, fail-open mode: %v", err)
			m.status = StatusServiceUnavailable
			m.license = m.getGraceLicense()
			m.cachedUntil = time.Now().Add(m.config.CacheDuration)
			return m.license, nil
		}
		m.status = StatusServiceUnavailable
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	if !result.Valid {
		m.status = StatusInvalid
		return nil, fmt.Errorf("invalid license: %s", result.Message)
	}

	m.license = result.License
	m.status = StatusValid
	m.validatedAt = time.Now()
	m.cachedUntil = time.Now().Add(m.config.CacheDuration)

	log.Printf("[LICENSE] License validated: %s tier, expires %s",
		m.license.Type, m.license.ExpiresAt.Format("2006-01-02"))

	return m.license, nil
}

// validateRemote calls the admin panel API
func (m *Manager) validateRemote(ctx context.Context) (*ValidationResult, error) {
	validateURL := fmt.Sprintf("%s/api/licenses/validate", m.config.AdminPanelURL)

	payload := map[string]string{"license_key": m.config.LicenseKey}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", validateURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var apiResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	valid, _ := apiResp["valid"].(bool)
	status, _ := apiResp["status"].(string)
	message, _ := apiResp["message"].(string)

	if !valid {
		return &ValidationResult{
			Valid:   false,
			Status:  status,
			Message: message,
		}, fmt.Errorf("invalid license: %s", message)
	}

	licenseData, ok := apiResp["license"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid license data in response")
	}

	license := parseLicenseResponse(licenseData)
	return &ValidationResult{
		Valid:       true,
		Status:      status,
		Message:     message,
		License:     license,
		ValidatedAt: time.Now(),
	}, nil
}

// parseLicenseResponse converts API response to License struct
func parseLicenseResponse(data map[string]interface{}) *License {
	license := &License{
		Valid: true,
	}

	if id, ok := data["id"].(string); ok {
		license.ID = id
	}
	if typ, ok := data["type"].(string); ok {
		license.Type = typ
	}
	if email, ok := data["email"].(string); ok {
		license.Email = email
	}
	if org, ok := data["organization"].(string); ok {
		license.Organization = org
	}
	if ms, ok := data["max_servers"].(float64); ok {
		license.MaxServers = int(ms)
	}
	if mu, ok := data["max_users"].(float64); ok {
		license.MaxUsers = int(mu)
	}
	if tiers, ok := data["tiers"].([]interface{}); ok {
		for _, t := range tiers {
			if tierName, ok := t.(string); ok {
				license.Tiers = append(license.Tiers, GetTierByName(tierName))
			}
		}
	}
	if features, ok := data["features"].([]interface{}); ok {
		for _, f := range features {
			if feat, ok := f.(string); ok {
				license.Features = append(license.Features, feat)
			}
		}
	}
	if modules, ok := data["modules"].([]interface{}); ok {
		for _, m := range modules {
			if mod, ok := m.(string); ok {
				license.Modules = append(license.Modules, mod)
			}
		}
	}
	if issued, ok := data["issued_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, issued); err == nil {
			license.IssuedAt = t
		}
	}
	if expires, ok := data["expires_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, expires); err == nil {
			license.ExpiresAt = t
		}
	}

	return license
}

// getGraceLicense returns a grace period license for fail-open mode
func (m *Manager) getGraceLicense() *License {
	return &License{
		Type:       "grace",
		Tiers:      []Tier{TierCommunity},
		MaxUsers:   3,
		MaxServers: 1,
		Valid:      true,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(m.config.GracePeriod),
	}
}

// setPublicKey loads the RSA public key for offline verification
func (m *Manager) setPublicKey(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	m.publicKey = rsaPub
	return nil
}

// GetLicense returns the current license
func (m *Manager) GetLicense() *License {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.license
}

// GetStatus returns the current license status
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// GetTier returns the maximum tier available
func (m *Manager) GetTier() Tier {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.license == nil {
		return TierCommunity
	}

	maxTier := TierCommunity
	for _, t := range m.license.Tiers {
		if t > maxTier {
			maxTier = t
		}
	}
	return maxTier
}

// IsFeatureEnabled checks if a feature is available
func (m *Manager) IsFeatureEnabled(feature string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.license == nil {
		return false
	}

	for _, f := range m.license.Features {
		if f == feature || f == "*" {
			return true
		}
	}
	return false
}

// IsModuleEnabled checks if a module is available
func (m *Manager) IsModuleEnabled(module string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.license == nil {
		return false
	}

	for _, m := range m.license.Modules {
		if m == module || m == "*" {
			return true
		}
	}
	return false
}

// CanAccessTier checks if license includes a tier level
func (m *Manager) CanAccessTier(requiredTier Tier) bool {
	currentTier := m.GetTier()
	return currentTier >= requiredTier
}

// IsExpiringSoon checks if license expires within duration
func (m *Manager) IsExpiringSoon(within time.Duration) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.license == nil {
		return false
	}

	return time.Until(m.license.ExpiresAt) < within
}

// ClearCache clears the validation cache
func (m *Manager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cachedUntil = time.Time{}
}

// Summary returns a human-readable license summary
type Summary struct {
	Type          string    `json:"type"`
	Tier          string    `json:"tier"`
	Email         string    `json:"email,omitempty"`
	Organization  string    `json:"organization,omitempty"`
	MaxUsers      int       `json:"max_users"`
	MaxServers    int       `json:"max_servers"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
	Status        string    `json:"status"`
}

func (m *Manager) Summary() *Summary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.license == nil {
		return &Summary{
			Type:       "community",
			Tier:       TierCommunity.String(),
			MaxUsers:   3,
			MaxServers: 1,
			Status:     "community",
		}
	}

	daysRemaining := int(time.Until(m.license.ExpiresAt).Hours() / 24)
	if daysRemaining < 0 {
		daysRemaining = 0
	}

	return &Summary{
		Type:          m.license.Type,
		Tier:          m.GetTier().String(),
		Email:         m.license.Email,
		Organization:  m.license.Organization,
		MaxUsers:      m.license.MaxUsers,
		MaxServers:    m.license.MaxServers,
		IssuedAt:      m.license.IssuedAt,
		ExpiresAt:     m.license.ExpiresAt,
		DaysRemaining: daysRemaining,
		Status:        m.status.String(),
	}
}

// Global license manager instance
var (
	globalManager *Manager
	managerOnce   sync.Once
)

// GetManager returns the global license manager
func GetManager() *Manager {
	managerOnce.Do(func() {
		globalManager = NewManager(nil)
	})
	return globalManager
}

// Initialize sets up the global license manager with custom config
func Initialize(config *Config) {
	managerOnce.Do(func() {
		globalManager = NewManager(config)
	})
}
