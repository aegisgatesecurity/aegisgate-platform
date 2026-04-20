// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package opsec

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// SecretRotationConfig configures secret rotation behavior
type SecretRotationConfig struct {
	Enabled        bool
	RotationPeriod time.Duration
	SecretLength   int
}

// DefaultSecretRotationConfig returns default configuration
func DefaultSecretRotationConfig() SecretRotationConfig {
	return SecretRotationConfig{
		Enabled:        true,
		RotationPeriod: 24 * time.Hour,
		SecretLength:   32,
	}
}

// SecretManager handles secure secret generation, storage, and rotation
type SecretManager struct {
	mu             sync.RWMutex
	config         SecretRotationConfig
	currentSecret  []byte // Store as []byte for memory scrubbing
	lastRotation   time.Time
	rotationCount  int
	scrubber       *MemoryScrubber
	licenseManager *core.LicenseManager // For Professional tier validation
}

// NewSecretManager creates a new secret manager with the given configuration
func NewSecretManager(config SecretRotationConfig) *SecretManager {
	secret := make([]byte, config.SecretLength)
	rand.Read(secret)

	return &SecretManager{
		config:        config,
		currentSecret: secret,
		lastRotation:  time.Now(),
		scrubber:      NewMemoryScrubber(),
	}
}

// NewSecretManagerWithLicense creates a new secret manager with license tier validation
// This should be used in production to enforce Professional tier requirements
func NewSecretManagerWithLicense(config SecretRotationConfig, lm *core.LicenseManager) *SecretManager {
	sm := NewSecretManager(config)
	sm.licenseManager = lm
	return sm
}

// checkProfessionalTier verifies the license tier for secret rotation operations
// Returns error if license manager is set but tier is not Professional or higher
func (s *SecretManager) checkProfessionalTier() error {
	if s.licenseManager != nil {
		if !s.licenseManager.IsModuleLicensed("secret_rotation", core.TierProfessional) {
			return fmt.Errorf("secret rotation requires Professional tier or higher")
		}
	}
	return nil
}

// EnableSecretRotation enables automatic secret rotation
// Validates that the Professional tier license is active (if license manager configured)
func (s *SecretManager) EnableSecretRotation() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check license tier if license manager is set
	if err := s.checkProfessionalTier(); err != nil {
		return err
	}

	s.config.Enabled = true
	return nil
}

// DisableSecretRotation disables automatic secret rotation
func (s *SecretManager) DisableSecretRotation() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.Enabled = false
}

// IsSecretRotationEnabled returns whether rotation is enabled
func (s *SecretManager) IsSecretRotationEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Enabled
}

// SetRotationPeriod sets the rotation period
func (s *SecretManager) SetRotationPeriod(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.RotationPeriod = d
}

// GetRotationPeriod returns the rotation period
func (s *SecretManager) GetRotationPeriod() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.RotationPeriod
}

// GetSecretRotationStatus returns current status
func (s *SecretManager) GetSecretRotationStatus() (bool, time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Enabled, s.config.RotationPeriod
}

// GetLastRotation returns the time of last rotation
func (s *SecretManager) GetLastRotation() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRotation
}

// IsTimeForRotation checks if rotation is due
func (s *SecretManager) IsTimeForRotation() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.Enabled && time.Since(s.lastRotation) > s.config.RotationPeriod
}

// GetRotationTimeRemaining returns time until next rotation
// Returns 0 if rotation is disabled or overdue
func (s *SecretManager) GetRotationTimeRemaining() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.config.Enabled {
		return 0
	}

	nextRotation := s.lastRotation.Add(s.config.RotationPeriod)
	if time.Now().After(nextRotation) {
		return 0
	}
	return time.Until(nextRotation)
}

// RotateSecret manually rotates the secret
// Returns the new secret (base64 encoded) or error
// Requires Professional tier or higher if license manager is configured
func (s *SecretManager) RotateSecret() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check license tier for manual rotation
	if err := s.checkProfessionalTier(); err != nil {
		return "", err
	}

	// Securely wipe the old secret
	if len(s.currentSecret) > 0 {
		_ = s.scrubber.ScrubBytes(s.currentSecret)
	}

	// Generate new secret
	newSecret := make([]byte, s.config.SecretLength)
	if _, err := rand.Read(newSecret); err != nil {
		return "", err
	}

	s.currentSecret = newSecret
	s.lastRotation = time.Now()
	s.rotationCount++

	return base64.URLEncoding.EncodeToString(newSecret), nil
}

// RotateIfNecessary rotates the secret if it's time
// Returns (rotated bool, newSecret string, error)
// Checks Professional tier before any rotation
func (s *SecretManager) RotateIfNecessary() (bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.config.Enabled || time.Since(s.lastRotation) <= s.config.RotationPeriod {
		return false, "", nil
	}

	// Check license tier
	if err := s.checkProfessionalTier(); err != nil {
		return false, "", err
	}

	// Securely wipe old secret
	if len(s.currentSecret) > 0 {
		_ = s.scrubber.ScrubBytes(s.currentSecret)
	}

	// Generate new secret
	newSecret := make([]byte, s.config.SecretLength)
	if _, err := rand.Read(newSecret); err != nil {
		return false, "", err
	}

	s.currentSecret = newSecret
	s.lastRotation = time.Now()
	s.rotationCount++

	return true, base64.URLEncoding.EncodeToString(newSecret), nil
}

// GetSecret returns the current secret (base64 encoded)
// Automatically rotates if enabled and rotation period has passed
// Checks Professional tier before any auto-rotation
func (s *SecretManager) GetSecret() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.config.Enabled && time.Since(s.lastRotation) > s.config.RotationPeriod {
		// Check license tier before auto-rotation
		if err := s.checkProfessionalTier(); err != nil {
			return "", err
		}

		// Securely wipe old secret
		if len(s.currentSecret) > 0 {
			_ = s.scrubber.ScrubBytes(s.currentSecret)
		}

		// Generate new secret
		newSecret := make([]byte, s.config.SecretLength)
		if _, err := rand.Read(newSecret); err != nil {
			return "", err
		}
		s.currentSecret = newSecret
		s.lastRotation = time.Now()
		s.rotationCount++
	}

	return base64.URLEncoding.EncodeToString(s.currentSecret), nil
}

// GetSecretBytes returns the raw secret bytes (careful with this!)
// Caller is responsible for wiping the returned slice
func (s *SecretManager) GetSecretBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy
	copy := make([]byte, len(s.currentSecret))
	copyBytes(copy, s.currentSecret)
	return copy
}

func copyBytes(dst, src []byte) {
	for i := range dst {
		if i < len(src) {
			dst[i] = src[i]
		}
	}
}

// GetSecretLength returns the configured secret length
func (s *SecretManager) GetSecretLength() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config.SecretLength
}

// GetRotationCount returns the number of rotations performed
func (s *SecretManager) GetRotationCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rotationCount
}

// Destroy securely wipes all secrets and resets state
// This should be called on shutdown or when secrets are no longer needed
func (s *SecretManager) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Securely clear the secret from memory
	if len(s.currentSecret) > 0 {
		_ = s.scrubber.SecureDelete(s.currentSecret)
	}
	s.currentSecret = nil
	s.rotationCount = 0
}

// ValidateSecret checks if a provided secret matches the current secret
// This is used for authentication/verification purposes
func (s *SecretManager) ValidateSecret(provided string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	currentB64 := base64.URLEncoding.EncodeToString(s.currentSecret)

	// Constant-time comparison to prevent timing attacks
	if len(provided) != len(currentB64) {
		return false
	}

	result := 0
	for i := 0; i < len(provided); i++ {
		result |= int(provided[i]) ^ int(currentB64[i])
	}
	return result == 0
}
