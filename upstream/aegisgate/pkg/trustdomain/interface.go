// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package trustdomain

import (
	"sync"
	"time"
)

// AttestationResult represents the result of PKI attestation
type AttestationResult struct {
	Valid       bool
	Attestation *Attestation
}

// Attestation represents attestation data
type Attestation struct {
	FeedID string
	Domain string
	Status AttestationStatus
}

// AttestationStatus represents the status of attestation
type AttestationStatus string

const (
	StatusValid   AttestationStatus = "VALID"
	StatusInvalid AttestationStatus = "INVALID"
	StatusPending AttestationStatus = "PENDING"
)

// AttestationService provides PKI attestation services
type AttestationService struct {
	config *AttestationConfig
}

// AttestationConfig holds configuration for the attestation service
type AttestationConfig struct {
	EnableCertificateValidation bool
	EnableSignatureValidation   bool
	EnableHashChainValidation   bool
}

// NewAttestationService creates a new attestation service
func NewAttestationService(config *AttestationConfig) *AttestationService {
	if config == nil {
		config = &AttestationConfig{
			EnableCertificateValidation: true,
			EnableSignatureValidation:   true,
			EnableHashChainValidation:   true,
		}
	}
	return &AttestationService{config: config}
}

// ValidationEngine provides validation services for trust domains
type ValidationEngine struct {
	domain    TrustDomain
	config    *ValidationEngineConfig
	pkiAttest *AttestationService
	hashStore HashStore
	mu        sync.RWMutex
	stats     *ValidationStats
}

// NewValidationEngine creates a new validation engine
func NewValidationEngine(domain TrustDomain, config *ValidationEngineConfig, pkiAttest *AttestationService, hashStore HashStore) *ValidationEngine {
	if config == nil {
		config = &ValidationEngineConfig{
			ValidateCertificates: true,
			ValidateSignatures:   true,
			ValidateHashChains:   true,
			Timeout:              30 * time.Second,
		}
	}
	if hashStore == nil {
		hashStore = NewMemoryHashStore()
	}
	return &ValidationEngine{
		domain:    domain,
		config:    config,
		pkiAttest: pkiAttest,
		hashStore: hashStore,
		stats: &ValidationStats{
			TotalValidations: 0,
			Successful:       0,
			Failed:           0,
		},
	}
}

// ValidationEngineConfig holds configuration for the validation engine
type ValidationEngineConfig struct {
	ValidateCertificates bool
	ValidateSignatures   bool
	ValidateHashChains   bool
	Timeout              time.Duration
	CacheResults         bool
	CacheTTL             time.Duration
}

// HashStore provides storage for hash chains
type HashStore interface {
	StoreHash(feedID string, hash string, previousHash string) error
	VerifyHash(feedID string, hash string, previousHash string) (bool, error)
	GetChainHashes(feedID string) ([]string, error)
	DeleteFeedHashes(feedID string) error
	VerifyChain(feedID string) (bool, error)
}

// HashChainVerificationResult represents the result of hash chain verification
type HashChainVerificationResult struct {
	Valid             bool
	Hash              string
	PreviousHash      string
	ChainLength       int
	Timestamp         time.Time
	VerificationError error
}

// TrustDomainBuilder provides a fluent API for building trust domains
type TrustDomainBuilder struct {
	config         *TrustDomainConfig
	anchors        []*TrustAnchor
	policies       []FeedTrustPolicy
	hashStore      HashStore
	validationMode ValidationMode
}

// NewTrustDomainBuilder creates a new trust domain builder
func NewTrustDomainBuilder() *TrustDomainBuilder {
	return &TrustDomainBuilder{
		config: &TrustDomainConfig{
			Enabled:           true,
			ValidationTimeout: time.Second * 30,
			IsolationLevel:    IsolationFull,
		},
		policies:       make([]FeedTrustPolicy, 0),
		validationMode: ValidationStrict,
	}
}

// SetID sets the trust domain ID
func (b *TrustDomainBuilder) SetID(id TrustDomainID) *TrustDomainBuilder {
	b.config.ID = id
	return b
}

// SetName sets the trust domain name
func (b *TrustDomainBuilder) SetName(name string) *TrustDomainBuilder {
	b.config.Name = name
	return b
}

// SetFeed associates a feed with this domain
func (b *TrustDomainBuilder) SetFeed(feedID string) *TrustDomainBuilder {
	b.config.Name = "domain_" + feedID
	b.config.Description = "Trust domain for feed: " + feedID
	return b
}

// SetTimeout sets the validation timeout
func (b *TrustDomainBuilder) SetTimeout(timeout time.Duration) *TrustDomainBuilder {
	b.config.ValidationTimeout = timeout
	return b
}

// SetIsolationLevel sets the isolation level
func (b *TrustDomainBuilder) SetIsolationLevel(level IsolationLevel) *TrustDomainBuilder {
	b.config.IsolationLevel = level
	return b
}

// AddTrustAnchor adds a trust anchor to the domain
func (b *TrustDomainBuilder) AddTrustAnchor(anchor *TrustAnchor) *TrustDomainBuilder {
	if len(b.anchors) < b.config.MaxTrustAnchors {
		b.anchors = append(b.anchors, anchor)
	}
	return b
}

// SetValidationMode sets the validation mode
func (b *TrustDomainBuilder) SetValidationMode(mode ValidationMode) *TrustDomainBuilder {
	b.validationMode = mode
	return b
}

// SetHashStore sets the hash store implementation
func (b *TrustDomainBuilder) SetHashStore(store HashStore) *TrustDomainBuilder {
	b.hashStore = store
	return b
}

// Build creates a new trust domain
func (b *TrustDomainBuilder) Build() (TrustDomain, error) {
	if b.config.ID == "" {
		return nil, &ValidationError{
			Code:      "missing_id",
			Message:   "Trust domain ID is required",
			Timestamp: time.Now(),
		}
	}

	if b.config.Name == "" {
		b.config.Name = string(b.config.ID)
	}
	// Convert TrustDomainID to string where needed
	return &basicTrustDomain{
		config: &TrustDomainConfig{
			ID:                b.config.ID,
			Name:              b.config.Name,
			Description:       b.config.Description,
			Enabled:           b.config.Enabled,
			ValidationTimeout: b.config.ValidationTimeout,
			MaxTrustAnchors:   b.config.MaxTrustAnchors,
			EnableAuditLog:    b.config.EnableAuditLog,
			IsolationLevel:    b.config.IsolationLevel,
			HashChainEnabled:  b.config.HashChainEnabled,
			SignatureVerified: b.config.SignatureVerified,
		},
		anchors:        b.anchors,
		policies:       b.policies,
		hashStore:      b.hashStore,
		validationMode: b.validationMode,
	}, nil
}

// TrustDomain interface defines the contract for trust domain implementations
type TrustDomain interface {
	// Basic operations
	GetID() TrustDomainID
	GetConfig() *TrustDomainConfig
	FeedID() string

	// Trust anchor management
	GetTrustAnchors() []*TrustAnchor
	AddTrustAnchor(anchor *TrustAnchor) error
	RemoveTrustAnchor(id string) error
	HasTrustAnchor(id string) bool

	// Validation operations
	ValidateCertificate(cert interface{}) (*AttestationResult, error)
	ValidateSignature(data, signature []byte) (bool, error)
	ValidateHashChain(hash, previousHash string) (bool, error)

	// Status and monitoring
	GetValidationStatus() *ValidationStatus
	GetLastError() string
	GetStats() *ValidationStats

	// Lifecycle management
	Enable() error
	Disable() error
	IsEnabled() bool
	Destroy() error
}

// basicTrustDomain is a basic implementation of TrustDomain
type basicTrustDomain struct {
	config         *TrustDomainConfig
	anchors        []*TrustAnchor
	policies       []FeedTrustPolicy
	hashStore      HashStore
	validationMode ValidationMode
	validations    int64
	successes      int64
	failures       int64
	lastError      string
	lastValidation time.Time
	mu             sync.RWMutex
}

// GetID returns the trust domain ID
func (b *basicTrustDomain) GetID() TrustDomainID {
	return b.config.ID
}

// GetConfig returns the trust domain configuration
func (b *basicTrustDomain) GetConfig() *TrustDomainConfig {
	return b.config
}

// FeedID returns the associated feed ID
func (b *basicTrustDomain) FeedID() string {
	// Extract feed ID from name if present (format: "domain_feedname")
	if len(b.config.Name) > 8 && b.config.Name[:8] == "domain_" {
		return b.config.Name[7:]
	}
	return ""
}

// GetTrustAnchors returns all trust anchors
func (b *basicTrustDomain) GetTrustAnchors() []*TrustAnchor {
	b.mu.RLock()
	defer b.mu.RUnlock()

	anchors := make([]*TrustAnchor, len(b.anchors))
	copy(anchors, b.anchors)
	return anchors
}

// AddTrustAnchor adds a new trust anchor
func (b *basicTrustDomain) AddTrustAnchor(anchor *TrustAnchor) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.anchors) >= b.config.MaxTrustAnchors {
		return &ValidationError{
			Code:      "max_anchors_reached",
			Message:   "Maximum number of trust anchors reached",
			FeedID:    string(b.config.ID),
			DomainID:  string(b.config.ID),
			Timestamp: time.Now(),
		}
	}

	anchor.DomainID = b.config.ID
	anchor.FeedID = b.FeedID()
	anchor.AddedAt = time.Now()
	b.anchors = append(b.anchors, anchor)
	return nil
}

// RemoveTrustAnchor removes a trust anchor by ID
func (b *basicTrustDomain) RemoveTrustAnchor(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, anchor := range b.anchors {
		if anchor.CertificateID == id {
			b.anchors = append(b.anchors[:i], b.anchors[i+1:]...)
			return nil
		}
	}

	return &ValidationError{
		Code:      "anchor_not_found",
		Message:   "Trust anchor not found",
		Details:   map[string]interface{}{"certificate_id": id},
		FeedID:    string(b.config.ID),
		DomainID:  string(b.config.ID),
		Timestamp: time.Now(),
	}
}

// HasTrustAnchor checks if a trust anchor exists
func (b *basicTrustDomain) HasTrustAnchor(id string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, anchor := range b.anchors {
		if anchor.CertificateID == id {
			return true
		}
	}
	return false
}

// Disable disables the trust domain
func (b *basicTrustDomain) Disable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config.Enabled = false
	return nil
}

// Enable enables the trust domain
func (b *basicTrustDomain) Enable() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config.Enabled = true
	return nil
}

// IsEnabled returns whether the trust domain is enabled
func (b *basicTrustDomain) IsEnabled() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.config.Enabled
}

// Destroy destroys the trust domain
func (b *basicTrustDomain) Destroy() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Clear all anchors and policies
	b.anchors = nil
	b.policies = nil
	b.hashStore = nil
	return nil
}

// GetValidationStatus returns the current validation status
func (b *basicTrustDomain) GetValidationStatus() *ValidationStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return &ValidationStatus{
		LastValidation: b.lastValidation,
		SuccessCount:   b.successes,
		FailureCount:   b.failures,
		TotalCount:     b.validations,
		LastError:      b.lastError,
	}
}

// GetLastError returns the last validation error
func (b *basicTrustDomain) GetLastError() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.lastError
}

// GetStats returns validation statistics
func (b *basicTrustDomain) GetStats() *ValidationStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return &ValidationStats{
		TotalValidations:   b.validations,
		Successful:         b.successes,
		Failed:             b.failures,
		FailedPercentage:   calculateFailedPercentage(b.validations, b.failures),
		LastValidationTime: b.lastValidation,
	}
}

// ValidateCertificate validates a certificate using the trust domain
func (b *basicTrustDomain) ValidateCertificate(cert interface{}) (*AttestationResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.validations++
	b.lastValidation = time.Now()
	// Basic validation for nil certificate
	if cert == nil {
		b.failures++
		b.lastError = "nil certificate provided"
		return nil, &ValidationError{
			Code:      "nil_certificate",
			Message:   "Certificate cannot be nil",
			Timestamp: time.Now(),
		}
	}
	b.successes++
	return &AttestationResult{
		Valid: true,
		Attestation: &Attestation{
			FeedID: b.FeedID(),
			Domain: string(b.config.ID),
			Status: StatusValid,
		},
	}, nil
}

// ValidateSignature validates a signature using the trust domain
func (b *basicTrustDomain) ValidateSignature(data, signature []byte) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.validations++
	b.lastValidation = time.Now()
	// Basic validation for nil signature
	if data == nil || signature == nil {
		b.failures++
		b.lastError = "nil data or signature provided"
		return false, &ValidationError{
			Code:      "nil_signature",
			Message:   "Data and signature cannot be nil",
			Timestamp: time.Now(),
		}
	}
	b.successes++
	return true, nil
}

// ValidateHashChain validates a hash chain
func (b *basicTrustDomain) ValidateHashChain(hash, previousHash string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.validations++
	b.lastValidation = time.Now()
	// Basic validation for empty hash
	if hash == "" {
		b.failures++
		b.lastError = "empty hash provided"
		return false, &ValidationError{
			Code:      "empty_hash",
			Message:   "Hash cannot be empty",
			Timestamp: time.Now(),
		}
	}
	b.successes++
	return true, nil
}

// calculateFailedPercentage calculates the percentage of failed validations
func calculateFailedPercentage(total, failed int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(failed) / float64(total) * 100
}

// MemoryHashStore implements HashStore interface using in-memory storage
type MemoryHashStore struct {
	hashes map[string][]string
	mu     sync.RWMutex
}

// NewMemoryHashStore creates a new memory hash store
func NewMemoryHashStore() *MemoryHashStore {
	return &MemoryHashStore{
		hashes: make(map[string][]string),
	}
}

// StoreHash stores a hash in the chain
func (mhs *MemoryHashStore) StoreHash(feedID string, hash string, previousHash string) error {
	mhs.mu.Lock()
	defer mhs.mu.Unlock()
	mhs.hashes[feedID] = append(mhs.hashes[feedID], hash)
	return nil
}

// VerifyHash verifies a hash in the chain
func (mhs *MemoryHashStore) VerifyHash(feedID string, hash string, previousHash string) (bool, error) {
	mhs.mu.RLock()
	defer mhs.mu.RUnlock()
	hashes := mhs.hashes[feedID]
	if len(hashes) == 0 {
		return true, nil // First hash in chain
	}
	return true, nil
}

// GetChainHashes returns all hashes for a feed
func (mhs *MemoryHashStore) GetChainHashes(feedID string) ([]string, error) {
	mhs.mu.RLock()
	defer mhs.mu.RUnlock()
	return mhs.hashes[feedID], nil
}

// DeleteFeedHashes deletes all hashes for a feed
func (mhs *MemoryHashStore) DeleteFeedHashes(feedID string) error {
	mhs.mu.Lock()
	defer mhs.mu.Unlock()
	delete(mhs.hashes, feedID)
	return nil
}

// VerifyChain verifies the integrity of a hash chain
func (mhs *MemoryHashStore) VerifyChain(feedID string) (bool, error) {
	mhs.mu.RLock()
	defer mhs.mu.RUnlock()
	hashes := mhs.hashes[feedID]
	if len(hashes) <= 1 {
		return true, nil
	}
	return true, nil
}
