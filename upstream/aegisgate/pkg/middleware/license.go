// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// License Validation Middleware - Integrates with AegisGate Admin Panel
// =========================================================================

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

// LicenseConfig holds configuration for license validation
type LicenseConfig struct {
	AdminPanelURL string        // URL of the admin panel API
	LicenseKey    string        // License key to validate
	PublicKeyPEM  string        // Public key for license verification
	CacheDuration time.Duration // How long to cache validation results
	RetryInterval time.Duration // Time between retries on failure
	FailOpen      bool          // Allow requests if license service is unavailable
}

// DefaultLicenseConfig returns sensible defaults
func DefaultLicenseConfig() *LicenseConfig {
	return &LicenseConfig{
		AdminPanelURL: getEnv("ADMIN_PANEL_URL", "http://localhost:8443"),
		LicenseKey:    getEnv("LICENSE_KEY", ""),
		PublicKeyPEM:  getEnv("LICENSE_PUBLIC_KEY", ""),
		CacheDuration: 5 * time.Minute,
		RetryInterval: 30 * time.Second,
		FailOpen:      false, // Security: Do not allow requests if license service is unavailable
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ValidationResult represents the result of license validation
type ValidationResult struct {
	Valid       bool      `json:"valid"`
	Status      string    `json:"status"`
	Message     string    `json:"message"`
	Tier        core.Tier `json:"tier"`
	ValidatedAt time.Time `json:"validated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	MaxServers  int       `json:"max_servers"`
	MaxUsers    int       `json:"max_users"`
	RateLimit   int       `json:"rate_limit_per_minute"`
}

type cachedValidation struct {
	result    ValidationResult
	expiresAt time.Time
}

// LicenseValidator handles license validation via the admin panel API
type LicenseValidator struct {
	config     *LicenseConfig
	httpClient *http.Client
	cache      map[string]cachedValidation
	cacheMu    sync.RWMutex
}

func NewLicenseValidator(config *LicenseConfig) *LicenseValidator {
	if config == nil {
		config = DefaultLicenseConfig()
	}
	return &LicenseValidator{
		config:     config,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      make(map[string]cachedValidation),
	}
}

func (v *LicenseValidator) Validate(ctx context.Context) (*ValidationResult, error) {
	v.cacheMu.RLock()
	if cached, ok := v.cache["current"]; ok && time.Now().Before(cached.expiresAt) {
		v.cacheMu.RUnlock()
		return &cached.result, nil
	}
	v.cacheMu.RUnlock()

	if v.config.LicenseKey == "" {
		return &ValidationResult{
			Valid:       true,
			Status:      "community",
			Message:     "No license key - using Community tier",
			Tier:        core.TierCommunity,
			ValidatedAt: time.Now(),
			RateLimit:   60,
			MaxServers:  1,
			MaxUsers:    3,
		}, nil
	}

	result, err := v.validateRemote(ctx)
	if err != nil {
		if v.config.FailOpen {
			log.Printf("[LICENSE] Service unavailable, fail-open: %v", err)
			return &ValidationResult{
				Valid:       true,
				Status:      "fail_open",
				Message:     "License service unavailable",
				Tier:        core.TierCommunity,
				ValidatedAt: time.Now(),
				RateLimit:   60,
			}, nil
		}
		return nil, fmt.Errorf("license validation failed: %w", err)
	}

	v.cacheMu.Lock()
	v.cache["current"] = cachedValidation{result: *result, expiresAt: time.Now().Add(v.config.CacheDuration)}
	v.cacheMu.Unlock()
	return result, nil
}

func (v *LicenseValidator) validateRemote(ctx context.Context) (*ValidationResult, error) {
	validateURL := fmt.Sprintf("%s/api/licenses/validate", v.config.AdminPanelURL)
	payload := map[string]string{"license_key": v.config.LicenseKey}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", validateURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var apiResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	valid, ok := apiResp["valid"].(bool)
	if !ok || !valid {
		status, _ := apiResp["status"].(string)
		message, _ := apiResp["message"].(string)
		return &ValidationResult{Valid: false, Status: status, Message: message}, fmt.Errorf("invalid: %s", message)
	}

	licenseData, ok := apiResp["license"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid license data")
	}

	tierName, _ := licenseData["tier_name"].(string)
	tier := core.GetTierByName(tierName)

	maxServers, maxUsers, rateLimit := 1, 3, 60
	if ms, ok := licenseData["max_servers"].(float64); ok {
		maxServers = int(ms)
	}
	if mu, ok := licenseData["max_users"].(float64); ok {
		maxUsers = int(mu)
	}
	if rl, ok := licenseData["rate_limit_per_minute"].(float64); ok {
		rateLimit = int(rl)
	}

	var expiresAt time.Time
	if exp, ok := licenseData["expires_at"].(string); ok {
		expiresAt, _ = time.Parse(time.RFC3339, exp)
	}

	return &ValidationResult{
		Valid:       true,
		Status:      "valid",
		Message:     "License is valid",
		Tier:        tier,
		ValidatedAt: time.Now(),
		ExpiresAt:   expiresAt,
		MaxServers:  maxServers,
		MaxUsers:    maxUsers,
		RateLimit:   rateLimit,
	}, nil
}

func (v *LicenseValidator) ClearCache() {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	v.cache = make(map[string]cachedValidation)
}

func (v *LicenseValidator) GetTier(ctx context.Context) core.Tier {
	result, err := v.Validate(ctx)
	if err != nil || !result.Valid {
		return core.TierCommunity
	}
	return result.Tier
}

var globalValidator *LicenseValidator
var validatorOnce sync.Once

func GetGlobalValidator() *LicenseValidator {
	validatorOnce.Do(func() { globalValidator = NewLicenseValidator(nil) })
	return globalValidator
}

func LicenseMiddleware() func(http.Handler) http.Handler {
	validator := GetGlobalValidator()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/health") ||
				strings.HasPrefix(r.URL.Path, "/version") ||
				strings.HasPrefix(r.URL.Path, "/stats") {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			result, err := validator.Validate(ctx)
			if err != nil || !result.Valid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": "license_invalid", "message": result.Message})
				return
			}
			ctx = context.WithValue(ctx, "license_tier", result.Tier)
			ctx = context.WithValue(ctx, "license_rate_limit", result.RateLimit)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func GetLicenseTierFromContext(ctx context.Context) core.Tier {
	if tier, ok := ctx.Value("license_tier").(core.Tier); ok {
		return tier
	}
	return core.TierCommunity
}

func GetLicenseRateLimitFromContext(ctx context.Context) int {
	if rl, ok := ctx.Value("license_rate_limit").(int); ok {
		return rl
	}
	return 60
}
