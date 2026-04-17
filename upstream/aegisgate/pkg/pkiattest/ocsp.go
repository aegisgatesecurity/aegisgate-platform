// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package pkiattest

import (
	"crypto/x509"
	"fmt"
	"time"
)

// OCSPManager manages Online Certificate Status Protocol requests
type OCSPManager struct {
	responses map[string]*OCSPResponse
	cacheTTL  time.Duration
	timeout   time.Duration
}

// OCSPResponse represents an OCSP response
type OCSPResponse struct {
	CertificateID      string
	Status             OCSPStatus
	ProducedAt         time.Time
	ThisUpdate         time.Time
	NextUpdate         time.Time
	ProducingCertChain []*x509.Certificate
	Signature          []byte
	SignatureAlgorithm x509.SignatureAlgorithm
}

// OCSPStatus represents the status of a certificate in OCSP
type OCSPStatus int

const (
	OCSPStatusGood    OCSPStatus = 0
	OCSPStatusRevoked OCSPStatus = 1
	OCSPStatusUnknown OCSPStatus = 2
)

func (s OCSPStatus) String() string {
	switch s {
	case OCSPStatusGood:
		return "good"
	case OCSPStatusRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// NewOCSPManager creates a new OCSP manager
func NewOCSPManager(cacheTTL, timeout time.Duration) *OCSPManager {
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &OCSPManager{
		responses: make(map[string]*OCSPResponse),
		cacheTTL:  cacheTTL,
		timeout:   timeout,
	}
}

// AddOCSPResponse adds an OCSP response to the manager
func (om *OCSPManager) AddOCSPResponse(certID string, resp *OCSPResponse) error {
	if resp == nil {
		return fmt.Errorf("OCSP response cannot be nil")
	}
	om.responses[certID] = resp
	return nil
}

// GetOCSPResponse retrieves an OCSP response for a certificate
func (om *OCSPManager) GetOCSPResponse(certID string) (*OCSPResponse, error) {
	resp, exists := om.responses[certID]
	if !exists {
		return nil, fmt.Errorf("OCSP response not found for certificate: %s", certID)
	}

	if time.Now().After(resp.NextUpdate) {
		return nil, fmt.Errorf("OCSP response has expired")
	}

	if time.Now().After(resp.NextUpdate.Add(-om.cacheTTL)) {
		return nil, fmt.Errorf("OCSP response is stale, needs refresh")
	}

	return resp, nil
}

// CheckCertificateStatus checks the status of a certificate via OCSP
func (om *OCSPManager) CheckCertificateStatus(cert *x509.Certificate, issuerCert *x509.Certificate) (OCSPStatus, error) {
	certID := fmt.Sprintf("%s-%s", issuerCert.Subject.CommonName, cert.SerialNumber.String())
	resp, err := om.GetOCSPResponse(certID)
	if err != nil {
		return OCSPStatusUnknown, err
	}
	return resp.Status, nil
}

// IsRevokedViaOCSP checks if a certificate is revoked via OCSP
func (om *OCSPManager) IsRevokedViaOCSP(cert *x509.Certificate, issuerCert *x509.Certificate) (bool, error) {
	status, err := om.CheckCertificateStatus(cert, issuerCert)
	if err != nil {
		return false, err
	}
	return status == OCSPStatusRevoked, nil
}

// CreateOCSPResponse creates a new OCSP response for a certificate
func (om *OCSPManager) CreateOCSPResponse(cert *x509.Certificate, issuerCert *x509.Certificate, status OCSPStatus) *OCSPResponse {
	now := time.Now()
	certID := fmt.Sprintf("%s-%s", issuerCert.Subject.CommonName, cert.SerialNumber.String())

	return &OCSPResponse{
		CertificateID:      certID,
		Status:             status,
		ProducedAt:         now,
		ThisUpdate:         now,
		NextUpdate:         now.Add(om.cacheTTL),
		ProducingCertChain: []*x509.Certificate{issuerCert},
		Signature:          nil,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
}
