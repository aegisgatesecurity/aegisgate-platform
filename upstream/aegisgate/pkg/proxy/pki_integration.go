// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package proxy

import (
	"crypto/x509"
	"fmt"
	"log/slog"

	"github.com/aegisgatesecurity/aegisgate/pkg/pkiattest"
)

// PKIAttestationIntegrator integrates PKI attestation with MITM proxy
type PKIAttestationIntegrator struct {
	attestation        *pkiattest.Attestation
	backdoorPrevention *pkiattest.BackdoorPrevention
	trustStore         *pkiattest.TrustStore
	enabled            bool
}

// PKIConfig holds configuration for PKI attestation integration
type PKIConfig struct {
	Enabled      bool
	RequireCRL   bool
	RequireOCSP  bool
	VerifyChain  bool
	TrustAnchors []*pkiattest.TrustAnchor
}

// NewPKIAttestationIntegrator creates a new PKI attestation integrator
func NewPKIAttestationIntegrator(config *PKIConfig) (*PKIAttestationIntegrator, error) {
	if config == nil {
		config = &PKIConfig{
			Enabled:     true,
			RequireCRL:  true,
			RequireOCSP: true,
			VerifyChain: true,
		}
	}

	// Initialize trust store
	trustStore := pkiattest.NewTrustStore()

	// Add trust anchors if provided
	if config.TrustAnchors != nil {
		for _, anchor := range config.TrustAnchors {
			_, err := trustStore.AddTrustAnchor(anchor.Certificate)
			if err != nil {
				slog.Warn("Failed to add trust anchor", "error", err)
			}
		}
	}

	// Initialize attestation
	attestationConfig := &pkiattest.AttestationConfig{
		TrustAnchors: config.TrustAnchors,
		RequireCRL:   config.RequireCRL,
		RequireOCSP:  config.RequireOCSP,
		VerifyChain:  config.VerifyChain,
	}

	attestation, err := pkiattest.NewAttestation(attestationConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation: %w", err)
	}

	// Initialize backdoor prevention
	backdoorPrevention := pkiattest.NewBackdoorPrevention()
	backdoorPrevention.SetAttestation(attestation)

	return &PKIAttestationIntegrator{
		attestation:        attestation,
		backdoorPrevention: backdoorPrevention,
		trustStore:         trustStore,
		enabled:            config.Enabled,
	}, nil
}

// VerifyClientCertificate verifies a client certificate using PKI attestation
func (p *PKIAttestationIntegrator) VerifyClientCertificate(cert *x509.Certificate) (bool, string, error) {
	if !p.enabled {
		return true, "PKI attestation disabled", nil
	}

	// Check for backdoors first
	isBackdoor, reason, err := p.backdoorPrevention.DetectBackdoor(cert)
	if err != nil {
		return false, fmt.Sprintf("backdoor check error: %v", err), err
	}
	if isBackdoor {
		slog.Warn("Backdoor detected in certificate", "reason", reason)
		return false, reason, nil
	}

	// Attest the certificate
	result, err := p.attestation.AttestCertificate(cert)
	if err != nil {
		return false, fmt.Sprintf("attestation error: %v", err), err
	}
	if !result.Valid {
		slog.Warn("Certificate attestation failed", "reason", result.Reason)
		return false, result.Reason, nil
	}

	// Check revocation
	isRevoked, revocationReason, err := p.trustStore.IsRevoked(cert.SerialNumber.String())
	if err != nil {
		return false, fmt.Sprintf("revocation check error: %v", err), err
	}
	if isRevoked {
		slog.Warn("Certificate is revoked", "reason", revocationReason)
		return false, revocationReason, nil
	}

	slog.Info("Certificate verified successfully",
		"serial", cert.SerialNumber.String(),
		"subject", cert.Subject.CommonName)

	return true, "certificate verified successfully", nil
}

// AddTrustAnchor adds a new trust anchor to the integrator
func (p *PKIAttestationIntegrator) AddTrustAnchor(cert *x509.Certificate) (*pkiattest.TrustAnchor, error) {
	anchor, err := p.attestation.AddTrustAnchor(cert)
	if err != nil {
		return nil, err
	}

	_, err = p.trustStore.AddTrustAnchor(cert)
	if err != nil {
		return nil, err
	}

	return anchor, nil
}

// RevokeCertificate revokes a certificate by serial number
func (p *PKIAttestationIntegrator) RevokeCertificate(serialNumber, reason string) error {
	err := p.trustStore.AddRevokedCertificate(serialNumber, "", reason)
	if err != nil {
		return err
	}

	slog.Warn("Certificate revoked", "serial", serialNumber, "reason", reason)
	return nil
}

// VerifyCertificateChain verifies a complete certificate chain
func (p *PKIAttestationIntegrator) VerifyCertificateChain(cert *x509.Certificate) ([]x509.Certificate, error) {
	return pkiattest.VerifyCertificateChain(cert, p.attestation.GetTrustAnchors())
}

// GetAttestationStatus returns the current attestation status
func (p *PKIAttestationIntegrator) GetAttestationStatus() map[string]interface{} {
	return map[string]interface{}{
		"enabled":            p.enabled,
		"trust_anchor_count": len(p.attestation.GetTrustAnchors()),
	}
}

// GetTrustStoreStats returns trust store statistics
func (p *PKIAttestationIntegrator) GetTrustStoreStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":            p.enabled,
		"trust_anchor_count": len(p.attestation.GetTrustAnchors()),
	}
}
