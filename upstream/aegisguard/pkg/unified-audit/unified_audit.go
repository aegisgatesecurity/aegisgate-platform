package unifiedaudit

import (
	"context"
	"github.com/aegisguardsecurity/aegisguard/shared/unified-audit"
)

// AuditLog wraps the shared AuditLog type for local use.
type AuditLog = unifiedaudit.AuditLog

// ComplianceViolation wraps the shared ComplianceViolation type for local use.
type ComplianceViolation = unifiedaudit.ComplianceViolation

// AuditLogger wraps the shared AuditLogger interface for local use.
type AuditLogger = unifiedaudit.AuditLogger

// FileAuditLogger wraps the shared FileAuditLogger for local use.
type FileAuditLogger = unifiedaudit.FileAuditLogger

// NewFileAuditLogger creates a new FileAuditLogger.
func NewFileAuditLogger(filePath string) (*FileAuditLogger, error) {
	return unifiedaudit.NewFileAuditLogger(filePath)
}

// MemoryAuditLogger wraps the shared MemoryAuditLogger for local use.
type MemoryAuditLogger = unifiedaudit.MemoryAuditLogger

// NewMemoryAuditLogger creates a new MemoryAuditLogger.
func NewMemoryAuditLogger() *MemoryAuditLogger {
	return unifiedaudit.NewMemoryAuditLogger()
}

// ComplianceFramework wraps the shared ComplianceFramework interface for local use.
type ComplianceFramework = unifiedaudit.ComplianceFramework

// CheckInput wraps the shared CheckInput type for local use.
type CheckInput = unifiedaudit.CheckInput

// CheckResult wraps the shared CheckResult type for local use.
type CheckResult = unifiedaudit.CheckResult

// ComplianceRegistry wraps the shared ComplianceRegistry for local use.
type ComplianceRegistry = unifiedaudit.ComplianceRegistry

// NewComplianceRegistry creates a new ComplianceRegistry.
func NewComplianceRegistry() *ComplianceRegistry {
	return unifiedaudit.NewComplianceRegistry()
}
