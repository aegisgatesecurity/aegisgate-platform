// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package pkiattest

import (
	"crypto/x509"
	"fmt"
	"time"
)

// CRLManager manages Certificate Revocation Lists
type CRLManager struct {
	crls         map[string]*CRL
	maxAge       time.Duration
	refreshDelay time.Duration
}

// CRL represents a Certificate Revocation List
type CRL struct {
	Issuer             string
	LastUpdate         time.Time
	NextUpdate         time.Time
	RevokedCerts       []*CRLEntry
	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm
}

// CRLEntry represents an entry in the CRL
type CRLEntry struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
}

// NewCRLManager creates a new CRL manager
func NewCRLManager(maxAge, refreshDelay time.Duration) *CRLManager {
	if maxAge == 0 {
		maxAge = 7 * 24 * time.Hour
	}
	if refreshDelay == 0 {
		refreshDelay = 1 * time.Hour
	}

	return &CRLManager{
		crls:         make(map[string]*CRL),
		maxAge:       maxAge,
		refreshDelay: refreshDelay,
	}
}

// AddCRL adds a CRL to the manager
func (cm *CRLManager) AddCRL(crl *CRL) error {
	if crl == nil {
		return fmt.Errorf("CRL cannot be nil")
	}
	cm.crls[crl.Issuer] = crl
	return nil
}

// GetCRL retrieves a CRL by issuer
func (cm *CRLManager) GetCRL(issuer string) (*CRL, error) {
	crl, exists := cm.crls[issuer]
	if !exists {
		return nil, fmt.Errorf("CRL not found for issuer: %s", issuer)
	}

	if time.Now().After(crl.NextUpdate) {
		return nil, fmt.Errorf("CRL has expired, needs refresh")
	}

	if time.Now().After(crl.NextUpdate.Add(-cm.refreshDelay)) {
		return nil, fmt.Errorf("CRL needs refresh, near expiration")
	}

	return crl, nil
}

// IsRevokedInCRL checks if a certificate is revoked in a specific CRL
func (cm *CRLManager) IsRevokedInCRL(issuer, serialNumber string) (bool, error) {
	crl, err := cm.GetCRL(issuer)
	if err != nil {
		return false, err
	}

	for _, entry := range crl.RevokedCerts {
		if entry.SerialNumber == serialNumber {
			return true, nil
		}
	}

	return false, nil
}

// HasExpiredCRL checks if any CRLs have expired
func (cm *CRLManager) HasExpiredCRL() (bool, []string) {
	expiredCRLs := []string{}
	now := time.Now()

	for issuer, crl := range cm.crls {
		if now.After(crl.NextUpdate) {
			expiredCRLs = append(expiredCRLs, issuer)
		}
	}

	return len(expiredCRLs) > 0, expiredCRLs
}

// CRLForCA creates a new CRL for a CA certificate
func (cm *CRLManager) CRLForCA(caCert *x509.Certificate) *CRL {
	now := time.Now()
	return &CRL{
		Issuer:             caCert.Subject.CommonName,
		LastUpdate:         now,
		NextUpdate:         now.Add(cm.maxAge),
		RevokedCerts:       []*CRLEntry{},
		Signature:          nil,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}
