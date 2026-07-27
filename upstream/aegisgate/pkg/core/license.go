// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package core provides license management for module activation.
package core

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"
)

// LicenseStatus represents the validity of a license.
type LicenseStatus int

const (
	LicenseStatusValid LicenseStatus = iota
	LicenseStatusExpired
	LicenseStatusInvalid
	LicenseStatusNotFound
	LicenseStatusTierMismatch
	LicenseStatusSignatureInvalid
)

func (s LicenseStatus) String() string {
	switch s {
	case LicenseStatusValid:
		return "valid"
	case LicenseStatusExpired:
		return "expired"
	case LicenseStatusInvalid:
		return "invalid"
	case LicenseStatusNotFound:
		return "not_found"
	case LicenseStatusTierMismatch:
		return "tier_mismatch"
	case LicenseStatusSignatureInvalid:
		return "signature_invalid"
	default:
		return "unknown"
	}
}

// LicenseType represents the type of license.
type LicenseType string

const (
	LicenseTypeCommunity    LicenseType = "community"
	LicenseTypeDeveloper    LicenseType = "developer"
	LicenseTypeProfessional LicenseType = "professional"
	LicenseTypeEnterprise   LicenseType = "enterprise"
	LicenseTypeCustom       LicenseType = "custom"
)

// License represents a parsed license.
type License struct {
	ID           string      `json:"id"`
	Type         LicenseType `json:"type"`
	Email        string      `json:"email"`
	Organization string      `json:"organization,omitempty"`
	Modules      []string    `json:"modules,omitempty"`
	Tiers        []Tier      `json:"tiers,omitempty"`
	IssuedAt     time.Time   `json:"issued_at"`
	ExpiresAt    time.Time   `json:"expires_at"`
	MaxServers   int         `json:"max_servers,omitempty"`
	Features     []string    `json:"features,omitempty"`
	Signature    string      `json:"signature,omitempty"`
}

// LicenseConfig contains configuration for the license manager.
type LicenseConfig struct {
	LicenseKey   string
	PublicKeyPEM string // For production: embedded public key
	GracePeriod  time.Duration
}

// LicenseManager handles license validation and module activation.
type LicenseManager struct {
	mu          sync.RWMutex
	config      LicenseConfig
	license     *License
	status      LicenseStatus
	validatedAt time.Time
	publicKey   *rsa.PublicKey
}

// NewLicenseManager creates a new license manager.
func NewLicenseManager(licenseKey string) *LicenseManager {
	lm := &LicenseManager{
		config: LicenseConfig{
			LicenseKey:  licenseKey,
			GracePeriod: 7 * 24 * time.Hour, // 7 days grace period
		},
		status: LicenseStatusNotFound,
	}

	// Validate license on creation
	if licenseKey != "" {
		_ = lm.validateLicense()
	}

	return lm
}

// NewLicenseManagerWithKey creates a license manager with a public key for signature verification
func NewLicenseManagerWithKey(licenseKey string, publicKeyPEM string) *LicenseManager {
	lm := NewLicenseManager(licenseKey)
	if publicKeyPEM != "" {
		_ = lm.SetPublicKey([]byte(publicKeyPEM))
	}
	return lm
}

// SetLicenseKey sets or updates the license key.
func (lm *LicenseManager) SetLicenseKey(key string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	lm.config.LicenseKey = key
	lm.license = nil
	lm.status = LicenseStatusNotFound

	return lm.validateLicense()
}

// GetLicense returns the current license.
func (lm *LicenseManager) GetLicense() *License {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.license
}

// GetStatus returns the current license status.
func (lm *LicenseManager) GetStatus() LicenseStatus {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.status
}

// IsModuleLicensed checks if a specific module is licensed.
func (lm *LicenseManager) IsModuleLicensed(moduleID string, tier Tier) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	// CRITICAL SECURITY: No license means only free tiers
	if lm.license == nil || lm.status != LicenseStatusValid {
		return tier <= TierCommunity
	}

	// Community is always free
	if tier <= TierCommunity {
		return true
	}

	// Check if license has explicit module permission
	for _, mod := range lm.license.Modules {
		if mod == moduleID || mod == "*" {
			return true
		}
	}

	// Check if license covers this tier
	for _, licensedTier := range lm.license.Tiers {
		if licensedTier >= tier {
			return true
		}
	}

	// Check license type tier permissions
	return lm.tierAllowedByLicenseType(tier)
}

// tierAllowedByLicenseType checks if the license type permits the tier.
func (lm *LicenseManager) tierAllowedByLicenseType(tier Tier) bool {
	if lm.license == nil {
		return false
	}

	switch lm.license.Type {
	case LicenseTypeCommunity:
		return tier <= TierCommunity

	case LicenseTypeDeveloper:
		return tier <= TierDeveloper

	case LicenseTypeProfessional:
		return tier <= TierProfessional

	case LicenseTypeEnterprise:
		return tier <= TierEnterprise

	case LicenseTypeCustom:
		// Custom licenses must explicitly grant tiers
		return false

	default:
		return false
	}
}

// IsFeatureLicensed checks if a specific feature is licensed.
func (lm *LicenseManager) IsFeatureLicensed(feature string) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if lm.license == nil {
		return false
	}

	for _, f := range lm.license.Features {
		if f == feature || f == "*" {
			return true
		}
	}

	return false
}

// LicenseExpiringSoon checks if license expires within the given duration.
func (lm *LicenseManager) LicenseExpiringSoon(within time.Duration) bool {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if lm.license == nil {
		return false
	}

	return time.Until(lm.license.ExpiresAt) < within
}

// validateLicense parses and validates the license key.
func (lm *LicenseManager) validateLicense() error {
	if lm.config.LicenseKey == "" {
		lm.status = LicenseStatusNotFound
		return fmt.Errorf("no license key configured")
	}

	// Decode license
	license, err := lm.parseLicense(lm.config.LicenseKey)
	if err != nil {
		lm.status = LicenseStatusInvalid
		return err
	}

	// Check expiration
	if time.Now().After(license.ExpiresAt) {
		lm.status = LicenseStatusExpired
		return fmt.Errorf("license expired at %s", license.ExpiresAt)
	}

	lm.license = license
	lm.status = LicenseStatusValid
	lm.validatedAt = time.Now()

	return nil
}

// parseLicense parses a license key into a License struct.
func (lm *LicenseManager) parseLicense(key string) (*License, error) {

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		// Try raw URL encoding
		decoded, err = base64.RawURLEncoding.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("invalid license encoding: %w", err)
		}
	}

	decodedStr := string(decoded)

	// Check for signed license format: payload.signature
	// Locate payload boundary
	lastBrace := strings.LastIndex(decodedStr, "}")
	if lastBrace == -1 {
		return nil, fmt.Errorf("invalid license format: no JSON object found")
	}

	jsonPayload := []byte(decodedStr[:lastBrace+1])
	signature := decodedStr[lastBrace+1:]

	// Remove leading period from signature if present
	signature = strings.TrimPrefix(signature, ".")

	// Parse the license JSON
	var license License
	if err := json.Unmarshal(jsonPayload, &license); err != nil {
		return nil, fmt.Errorf("invalid license format: %w", err)
	}

	// Verify RSA signature if present and we have a public key
	if signature != "" && lm.publicKey != nil {
		if err := lm.verifySignature(jsonPayload, signature); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	} else if signature != "" && lm.publicKey == nil {
		// No public key configured for verification
		_ = lm
	}

	return &license, nil
}

// verifySignature verifies an RSA-SHA256 signature against the license payload
func (lm *LicenseManager) verifySignature(payload []byte, signatureB64 string) error {
	if lm.publicKey == nil {
		return fmt.Errorf("no public key configured for signature verification")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	hash := sha256.Sum256(payload)

	// Verify signature
	err = rsa.VerifyPKCS1v15(lm.publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		lm.status = LicenseStatusSignatureInvalid
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// generateLicenseID creates a unique license ID.
func generateLicenseID() string {
	// Simple ID generation - use proper UUID in production
	return fmt.Sprintf("PAD-%d", time.Now().UnixNano())
}

// LicenseSummary provides a human-readable license summary.
type LicenseSummary struct {
	Type          string    `json:"type"`
	Email         string    `json:"email"`
	Organization  string    `json:"organization,omitempty"`
	Modules       []string  `json:"modules"`
	MaxTier       string    `json:"max_tier"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
	Status        string    `json:"status"`
}

// Summary returns a human-readable license summary.
func (lm *LicenseManager) Summary() *LicenseSummary {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	if lm.license == nil {
		return &LicenseSummary{
			Type:    string(LicenseTypeCommunity),
			MaxTier: TierCommunity.String(),
			Status:  LicenseStatusNotFound.String(),
		}
	}

	maxTier := TierCommunity
	for _, t := range lm.license.Tiers {
		if t > maxTier {
			maxTier = t
		}
	}

	return &LicenseSummary{
		Type:          string(lm.license.Type),
		Email:         lm.license.Email,
		Organization:  lm.license.Organization,
		Modules:       lm.license.Modules,
		MaxTier:       maxTier.String(),
		IssuedAt:      lm.license.IssuedAt,
		ExpiresAt:     lm.license.ExpiresAt,
		DaysRemaining: int(time.Until(lm.license.ExpiresAt).Hours() / 24),
		Status:        lm.status.String(),
	}
}

// SetPublicKey sets the public key for license signature verification.
func (lm *LicenseManager) SetPublicKey(pemData []byte) error {
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

	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.publicKey = rsaPub
	return nil
}

// GetPublicKey returns the current public key
func (lm *LicenseManager) GetPublicKey() *rsa.PublicKey {
	lm.mu.RLock()
	defer lm.mu.RUnlock()
	return lm.publicKey
}
