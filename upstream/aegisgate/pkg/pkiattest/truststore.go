// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package pkiattest

import (
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// RevokedCertificate represents a revoked certificate
type RevokedCertificate struct {
	SerialNumber  string
	RevokedAt     time.Time
	RevokedBy     string
	Reason        string
	CertificateID string
}

// RevocationCache provides caching for revocation status
type RevocationCache struct {
	mu       sync.RWMutex
	results  map[string]*RevocationResult
	cacheTTL time.Duration
}

// RevocationResult represents the result of revocation checking
type RevocationResult struct {
	Valid     bool
	Reason    string
	Timestamp time.Time
	FromCRL   bool
	FromOCSP  bool
}

// TrustStore manages trusted certificates and revocation information
type TrustStore struct {
	mu           sync.RWMutex
	trustAnchors map[string]*TrustAnchor
	revokedCerts map[string]*RevokedCertificate
	cache        *RevocationCache
}

// NewTrustStore creates a new trust store
func NewTrustStore() *TrustStore {
	return &TrustStore{
		trustAnchors: make(map[string]*TrustAnchor),
		revokedCerts: make(map[string]*RevokedCertificate),
		cache: &RevocationCache{
			results:  make(map[string]*RevocationResult),
			cacheTTL: 5 * time.Minute,
		},
	}
}

// AddTrustAnchor adds a certificate to the trust store
func (ts *TrustStore) AddTrustAnchor(cert *x509.Certificate) (*TrustAnchor, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}

	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate")
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	anchor := &TrustAnchor{
		Certificate:   cert,
		CertificateID: fmt.Sprintf("ta-%s", cert.SerialNumber.String()[:8]),
		CreatedAt:     time.Now(),
		ExpiresAt:     cert.NotAfter,
		Purpose:       "general-purpose CA",
		Revoked:       false,
	}

	ts.trustAnchors[cert.SerialNumber.String()] = anchor

	return anchor, nil
}

// AddRevokedCertificate adds a certificate to the revocation list
func (ts *TrustStore) AddRevokedCertificate(serialNumber, certificateID, reason string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.revokedCerts[serialNumber] = &RevokedCertificate{
		SerialNumber:  serialNumber,
		CertificateID: certificateID,
		RevokedAt:     time.Now(),
		Reason:        reason,
	}

	ts.cache.mu.Lock()
	delete(ts.cache.results, serialNumber)
	ts.cache.mu.Unlock()

	return nil
}

// IsRevoked checks if a certificate is revoked
func (ts *TrustStore) IsRevoked(serialNumber string) (bool, string, error) {
	ts.mu.RLock()
	revoked, exists := ts.revokedCerts[serialNumber]
	ts.mu.RUnlock()

	if exists {
		return true, revoked.Reason, nil
	}

	ts.cache.mu.RLock()
	cached, exists := ts.cache.results[serialNumber]
	ts.cache.mu.RUnlock()

	if exists && time.Since(cached.Timestamp) < ts.cache.cacheTTL {
		return !cached.Valid, cached.Reason, nil
	}

	return false, "not in revocation list", nil
}

// GetTrustAnchors returns all trusted anchors
func (ts *TrustStore) GetTrustAnchors() []*TrustAnchor {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	anchors := make([]*TrustAnchor, 0, len(ts.trustAnchors))
	for _, anchor := range ts.trustAnchors {
		anchors = append(anchors, anchor)
	}

	return anchors
}

// GetTrustAnchorByID returns a trust anchor by ID
func (ts *TrustStore) GetTrustAnchorByID(id string) (*TrustAnchor, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	for _, anchor := range ts.trustAnchors {
		if anchor.CertificateID == id {
			return anchor, nil
		}
	}

	return nil, fmt.Errorf("trust anchor not found: %s", id)
}

// RevokeTrustAnchor revokes a trust anchor
func (ts *TrustStore) RevokeTrustAnchor(id string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	for _, anchor := range ts.trustAnchors {
		if anchor.CertificateID == id {
			anchor.Revoked = true
			anchor.RevokedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("trust anchor not found: %s", id)
}

// ClearRevocationCache clears the revocation status cache
func (ts *TrustStore) ClearRevocationCache() {
	ts.cache.mu.Lock()
	defer ts.cache.mu.Unlock()
	ts.cache.results = make(map[string]*RevocationResult)
}

// NewRevocationResult creates a new revocation result
func (ts *TrustStore) NewRevocationResult(valid bool, reason string) *RevocationResult {
	return &RevocationResult{
		Valid:     valid,
		Reason:    reason,
		Timestamp: time.Now(),
	}
}
