// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package opsec

import (
	"fmt"
	"time"
)

// OPSECManager is the operational security manager
type OPSECManager struct {
	config         *OPSECConfig
	auditLog       *SecureAuditLog
	secretMgr      *SecretManager
	memoryScrubber *MemoryScrubber
	initialized    bool
	running        bool
}

// New creates a new OPSEC manager with default configuration
func New() *OPSECManager {
	cfg := DefaultOPSECConfig()
	return NewWithConfig(&cfg)
}

// NewWithConfig creates a new OPSEC manager with the specified configuration
func NewWithConfig(config *OPSECConfig) *OPSECManager {
	return &OPSECManager{
		config:         config,
		auditLog:       NewSecureAuditLog(),
		secretMgr:      NewSecretManager(DefaultSecretRotationConfig()),
		memoryScrubber: NewMemoryScrubber(),
	}
}

// Initialize prepares the OPSEC manager for use
func (m *OPSECManager) Initialize() error {
	if m.initialized {
		return nil
	}

	// Initialize audit logging if enabled
	if m.config.AuditEnabled {
		m.auditLog.EnableAudit()
	}

	m.initialized = true
	return nil
}

// IsInitialized returns whether the manager has been initialized
func (m *OPSECManager) IsInitialized() bool {
	return m.initialized
}

// Start begins OPSEC operations
func (m *OPSECManager) Start() error {
	if !m.initialized {
		return fmt.Errorf("OPSEC manager not initialized")
	}
	m.running = true
	return nil
}

// Stop ends OPSEC operations
func (m *OPSECManager) Stop() error {
	m.running = false
	return nil
}

// GetAuditLog returns the secure audit log
func (m *OPSECManager) GetAuditLog() *SecureAuditLog {
	return m.auditLog
}

// GetSecretManager returns the secret manager
func (m *OPSECManager) GetSecretManager() *SecretManager {
	return m.secretMgr
}

// LogAudit logs an audit event
func (m *OPSECManager) LogAudit(event string, details map[string]string) error {
	if m.auditLog == nil {
		return nil
	}

	// Convert to AuditEntry and log
	entry := &AuditEntry{
		EventType: event,
		Message:   event,
		Data:      convertMap(details),
		Timestamp: time.Now(),
		Source:    "aegisgate",
		ID:        generateEntryID(),
	}
	m.auditLog.LogAudit(entry)
	return nil
}

// convertMap converts a string map to interface map
func convertMap(m map[string]string) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}

// GetSecret retrieves the current secret
func (m *OPSECManager) GetSecret() (string, error) {
	if m.secretMgr == nil {
		return "", fmt.Errorf("secret manager not initialized")
	}
	return m.secretMgr.GetSecret()
}

// RotateSecret rotates to a new secret
func (m *OPSECManager) RotateSecret() (string, error) {
	if m.secretMgr == nil {
		return "", fmt.Errorf("secret manager not initialized")
	}
	return m.secretMgr.RotateSecret()
}

// ScrubBytes securely clears memory
func (m *OPSECManager) ScrubBytes(data []byte) {
	if m.memoryScrubber != nil {
		_ = m.memoryScrubber.ScrubBytes(data)
	}
}

// ScrubString securely clears a string from memory
func (m *OPSECManager) ScrubString(s *string) {
	if m.memoryScrubber != nil {
		_ = m.memoryScrubber.ScrubString(s)
	}
}
