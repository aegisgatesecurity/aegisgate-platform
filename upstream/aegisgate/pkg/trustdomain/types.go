// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package trustdomain

import (
	"time"
)

// TrustDomainID is a unique identifier for a trust domain
type TrustDomainID string

// TrustDomainConfig holds configuration for a trust domain
type TrustDomainConfig struct {
	ID                TrustDomainID
	Name              string
	Description       string
	Enabled           bool
	ValidationTimeout time.Duration
	MaxTrustAnchors   int
	EnableAuditLog    bool
	IsolationLevel    IsolationLevel
	HashChainEnabled  bool
	SignatureVerified bool
}

// IsolationLevel defines the degree of isolation for a trust domain
type IsolationLevel int

const (
	// IsolationNone - No isolation, shared with other domains
	IsolationNone IsolationLevel = iota
	// IsolationPartial - Partial isolation, some shared resources
	IsolationPartial
	// IsolationFull - Complete isolation, dedicated resources
	IsolationFull
)

// TrustAnchor represents a trusted certificate authority within a domain
type TrustAnchor struct {
	CertificateID string
	DomainID      TrustDomainID
	FeedID        string
	AddedAt       time.Time
	AddedBy       string
	Data          []byte
}

// ValidationStatus represents the current validation state
type ValidationStatus struct {
	LastValidation time.Time
	SuccessCount   int64
	FailureCount   int64
	TotalCount     int64
	LastError      string
}

// ValidationError represents a validation error with context
type ValidationError struct {
	Code      string
	Message   string
	Field     string
	Details   map[string]interface{}
	Timestamp time.Time
	FeedID    string
	DomainID  string
}

func (e *ValidationError) Error() string {
	if e.Message == "" {
		return "validation error: " + e.Code
	}
	return e.Message
}

// FeedTrustPolicy defines trust policies for a specific feed
type FeedTrustPolicy struct {
	FeedID         string
	TrustDomainID  TrustDomainID
	Policies       []Policy
	ValidationMode ValidationMode
	Parameters     map[string]interface{}
	CreatedAt      time.Time
	CreatedBy      string
	UpdatedAt      time.Time
	UpdatedBy      string
}

// Policy represents a specific trust policy
type Policy struct {
	ID            string
	Name          string
	Description   string
	Type          PolicyType
	Enabled       bool
	Configuration map[string]interface{}
	CreatedAt     time.Time
	ModifiedAt    time.Time
}

// PolicyType defines the type of policy
type PolicyType string

const (
	PolicyTypeCertificate PolicyType = "certificate"
	PolicyTypeSignature   PolicyType = "signature"
)

// ValidationMode defines how validation is performed
type ValidationMode int

const (
	// ValidationStrict - All validations must pass
	ValidationStrict ValidationMode = iota
	// ValidationPermissive - Some validations can fail with warnings
	ValidationPermissive
	// ValidationDisabled - Validation is disabled (dangerous)
	ValidationDisabled
)

// ValidationStats holds validation statistics
type ValidationStats struct {
	TotalValidations   int64
	Successful         int64
	Failed             int64
	FailedPercentage   float64
	LastValidationTime time.Time
	AverageDuration    time.Duration
	LastError          string
}

// AuditLogEntry represents a log entry for trust domain operations
type AuditLogEntry struct {
	Timestamp time.Time
	Operation string
	DomainID  TrustDomainID
	FeedID    string
	User      string
	Success   bool
	Message   string
	Details   map[string]interface{}
}

// TrustDomainManagerConfig holds configuration for the trust domain manager
type TrustDomainManagerConfig struct {
	DefaultIsolationLevel IsolationLevel
	MaxTrustDomains       int
	EnableAuditLog        bool
	AuditLogBufferSize    int
	DefaultValidationMode ValidationMode
}

// ValidationResult represents the result of trust domain validation
type ValidationResult struct {
	Success   bool
	Status    ValidationStatus
	Message   string
	Timestamp time.Time
}
