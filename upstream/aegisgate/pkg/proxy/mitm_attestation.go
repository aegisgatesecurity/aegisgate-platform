package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/pkiattest"
)

// MITMAttestationConfig holds configuration for MITM attestation
type MITMAttestationConfig struct {
	// Enable attestation checks
	Enabled bool

	// Require chain verification before interception
	RequireChainVerification bool

	// Enable CRL checking
	RequireCRL bool

	// Enable OCSP checking
	RequireOCSP bool

	// CRL check timeout
	CRLTimeout time.Duration

	// OCSP check timeout
	OCSPTimeout time.Duration

	// Trust anchors for certificate validation
	TrustAnchors []*pkiattest.TrustAnchor

	// Enable backdoor detection
	BackdoorPrevention bool

	// Fail closed (block on attestation failure)
	FailClosed bool

	// Log attestation results
	LogResults bool

	// Cache attestation results
	CacheResults bool

	// Cache TTL
	CacheTTL time.Duration
}

// DefaultMITMAttestationConfig returns default configuration
func DefaultMITMAttestationConfig() *MITMAttestationConfig {
	return &MITMAttestationConfig{
		Enabled:                  true,
		RequireChainVerification: true,
		RequireCRL:               true,
		RequireOCSP:              false, // OCSP can be slow
		CRLTimeout:               5 * time.Second,
		OCSPTimeout:              5 * time.Second,
		TrustAnchors:             []*pkiattest.TrustAnchor{},
		BackdoorPrevention:       true,
		FailClosed:               true,
		LogResults:               true,
		CacheResults:             true,
		CacheTTL:                 5 * time.Minute,
	}
}

// MITMAttestationResult represents the result of an attestation check
type MITMAttestationResult struct {
	Valid               bool
	Reason              string
	Certificate         *x509.Certificate
	ChainVerified       bool
	RevocationChecked   bool
	BackdoorChecked     bool
	BackdoorDetected    bool
	AttestationDuration time.Duration
	Timestamp           time.Time
}

// MITMAttestation integrates PKI attestation into the MITM proxy
type MITMAttestation struct {
	config             *MITMAttestationConfig
	attestation        *pkiattest.Attestation
	backdoorPrevention *pkiattest.BackdoorPrevention
	trustStore         *pkiattest.TrustStore
	crlManager         *pkiattest.CRLManager
	ocspManager        *pkiattest.OCSPManager
	resultCache        map[string]*MITMAttestationResult
	cacheTTL           time.Duration
}

// NewMITMAttestation creates a new MITM attestation service
func NewMITMAttestation(config *MITMAttestationConfig) (*MITMAttestation, error) {
	if config == nil {
		config = DefaultMITMAttestationConfig()
	}

	// Create attestation config
	attestationConfig := &pkiattest.AttestationConfig{
		TrustAnchors:     config.TrustAnchors,
		RequireCRL:       config.RequireCRL,
		RequireOCSP:      config.RequireOCSP,
		CRLCheckTimeout:  config.CRLTimeout,
		OCSPCheckTimeout: config.OCSPTimeout,
		VerifyChain:      config.RequireChainVerification,
	}

	// Initialize attestation service
	attestation, err := pkiattest.NewAttestation(attestationConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation service: %w", err)
	}

	// Initialize backdoor prevention
	backdoorPrevention := pkiattest.NewBackdoorPrevention()
	if config.BackdoorPrevention {
		backdoorPrevention.SetAttestation(attestation)
	}

	// Initialize trust store
	trustStore := pkiattest.NewTrustStore()

	// Add trust anchors to trust store
	for _, anchor := range config.TrustAnchors {
		if _, err := trustStore.AddTrustAnchor(anchor.Certificate); err != nil {
			slog.Warn("Failed to add trust anchor to trust store", "error", err)
		}
	}

	// Initialize CRL manager
	crlManager := pkiattest.NewCRLManager(7*24*time.Hour, 1*time.Hour)

	// Initialize OCSP manager
	ocspManager := pkiattest.NewOCSPManager(config.CacheTTL, config.OCSPTimeout)

	return &MITMAttestation{
		config:             config,
		attestation:        attestation,
		backdoorPrevention: backdoorPrevention,
		trustStore:         trustStore,
		crlManager:         crlManager,
		ocspManager:        ocspManager,
		resultCache:        make(map[string]*MITMAttestationResult),
		cacheTTL:           config.CacheTTL,
	}, nil
}

// AttestUpstreamCertificate validates an upstream server certificate
func (m *MITMAttestation) AttestUpstreamCertificate(cert *x509.Certificate) *MITMAttestationResult {
	startTime := time.Now()

	result := &MITMAttestationResult{
		Certificate: cert,
		Timestamp:   startTime,
	}

	// Check cache first
	if m.config.CacheResults {
		cacheKey := cert.SerialNumber.String()
		if cached, ok := m.resultCache[cacheKey]; ok {
			if time.Since(cached.Timestamp) < m.cacheTTL {
				slog.Debug("Using cached attestation result",
					"serial", cacheKey,
					"valid", cached.Valid)
				return cached
			}
		}
	}

	if !m.config.Enabled {
		result.Valid = true
		result.Reason = "attestation disabled"
		result.AttestationDuration = time.Since(startTime)
		return result
	}

	// Step 1: Backdoor detection
	if m.config.BackdoorPrevention {
		isBackdoor, reason, err := m.backdoorPrevention.DetectBackdoor(cert)
		result.BackdoorChecked = true
		if err != nil {
			result.Valid = !m.config.FailClosed
			result.Reason = fmt.Sprintf("backdoor check error: %v", err)
			result.AttestationDuration = time.Since(startTime)
			slog.Warn("Backdoor check error",
				"serial", cert.SerialNumber.String(),
				"error", err)
			return m.cacheResult(result)
		}
		if isBackdoor {
			result.BackdoorDetected = true
			result.Valid = false
			result.Reason = reason
			result.AttestationDuration = time.Since(startTime)
			slog.Warn("Backdoor detected in certificate",
				"serial", cert.SerialNumber.String(),
				"subject", cert.Subject.CommonName,
				"reason", reason)
			return m.cacheResult(result)
		}
	}

	// Step 2: Certificate attestation
	attestationResult, err := m.attestation.AttestCertificate(cert)
	if err != nil {
		result.Valid = !m.config.FailClosed
		result.Reason = fmt.Sprintf("attestation error: %v", err)
		result.AttestationDuration = time.Since(startTime)
		slog.Warn("Certificate attestation failed",
			"serial", cert.SerialNumber.String(),
			"error", err)
		return m.cacheResult(result)
	}

	if !attestationResult.Valid {
		result.Valid = false
		result.Reason = attestationResult.Reason
		result.ChainVerified = m.config.RequireChainVerification
		result.AttestationDuration = time.Since(startTime)
		slog.Warn("Certificate validation failed",
			"serial", cert.SerialNumber.String(),
			"reason", attestationResult.Reason)
		return m.cacheResult(result)
	}

	result.ChainVerified = true

	// Step 3: CRL check
	if m.config.RequireCRL {
		revoked, reason, err := m.trustStore.IsRevoked(cert.SerialNumber.String())
		result.RevocationChecked = true
		if err != nil {
			slog.Debug("CRL check error", "serial", cert.SerialNumber.String(), "error", err)
		}
		if revoked {
			result.Valid = false
			result.Reason = fmt.Sprintf("certificate revoked: %s", reason)
			result.AttestationDuration = time.Since(startTime)
			slog.Warn("Certificate is revoked",
				"serial", cert.SerialNumber.String(),
				"reason", reason)
			return m.cacheResult(result)
		}
	}

	// Step 4: OCSP check (optional)
	if m.config.RequireOCSP && len(cert.OCSPServer) > 0 {
		// Try OCSP validation
		for _, issuer := range m.config.TrustAnchors {
			status, err := m.ocspManager.CheckCertificateStatus(cert, issuer.Certificate)
			result.RevocationChecked = true
			if err != nil {
				slog.Debug("OCSP check error", "error", err)
				continue
			}
			if status == pkiattest.OCSPStatusRevoked {
				result.Valid = false
				result.Reason = "certificate revoked via OCSP"
				result.AttestationDuration = time.Since(startTime)
				return m.cacheResult(result)
			}
			break
		}
	}

	// All checks passed
	result.Valid = true
	result.Reason = "certificate validated successfully"
	result.AttestationDuration = time.Since(startTime)

	if m.config.LogResults {
		slog.Info("Upstream certificate attested successfully",
			"serial", cert.SerialNumber.String(),
			"subject", cert.Subject.CommonName,
			"issuer", cert.Issuer.CommonName,
			"duration", result.AttestationDuration,
			"chain_verified", result.ChainVerified,
			"revocation_checked", result.RevocationChecked,
			"backdoor_checked", result.BackdoorChecked)
	}

	return m.cacheResult(result)
}

// AttestConnection validates a TLS connection's peer certificates
func (m *MITMAttestation) AttestConnection(connState *tls.ConnectionState) (*MITMAttestationResult, error) {
	if connState == nil || len(connState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates available")
	}

	// Validate the leaf certificate (first in chain)
	leafCert := connState.PeerCertificates[0]
	result := m.AttestUpstreamCertificate(leafCert)

	// Also check intermediate certificates if present
	if result.Valid && len(connState.PeerCertificates) > 1 {
		for i, cert := range connState.PeerCertificates[1:] {
			intermediateResult := m.AttestUpstreamCertificate(cert)
			if !intermediateResult.Valid {
				slog.Warn("Intermediate certificate validation failed",
					"index", i,
					"serial", cert.SerialNumber.String(),
					"reason", intermediateResult.Reason)
				// Don't fail on intermediate issues unless FailClosed is set
				if m.config.FailClosed {
					return intermediateResult, nil
				}
			}
		}
	}

	return result, nil
}

// AddTrustAnchor adds a new trust anchor to the attestation service
func (m *MITMAttestation) AddTrustAnchor(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate cannot be nil")
	}

	// Add to attestation
	_, err := m.attestation.AddTrustAnchor(cert)
	if err != nil {
		return fmt.Errorf("failed to add to attestation: %w", err)
	}

	// Add to trust store
	_, err = m.trustStore.AddTrustAnchor(cert)
	if err != nil {
		return fmt.Errorf("failed to add to trust store: %w", err)
	}

	slog.Info("Trust anchor added to MITM attestation",
		"subject", cert.Subject.CommonName,
		"serial", cert.SerialNumber.String())

	return nil
}

// RevokeCertificate marks a certificate as revoked
func (m *MITMAttestation) RevokeCertificate(serialNumber, reason string) error {
	err := m.trustStore.AddRevokedCertificate(serialNumber, "", reason)
	if err != nil {
		return err
	}

	// Invalidate cache for this certificate
	delete(m.resultCache, serialNumber)

	slog.Warn("Certificate revoked in MITM attestation",
		"serial", serialNumber,
		"reason", reason)

	return nil
}

// fetchUpstreamCertificate connects to the upstream server and retrieves its certificate
func (m *MITMAttestation) fetchUpstreamCertificate(host string, timeout time.Duration) (*x509.Certificate, error) {
	// Ensure port is included
	_, _, err := net.SplitHostPort(host)
	if err != nil {
		host = host + ":443"
	}

	// Create TLS connection config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // lgtm[go/disabled-certificate-check] — MITM attestation proxy validates cert manually after connecting
		MinVersion:         tls.VersionTLS12,
	}

	// Connect with timeout
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	// Get peer certificates
	connState := conn.ConnectionState()
	if len(connState.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates received from upstream")
	}

	return connState.PeerCertificates[0], nil
}

// FetchAndAttestCertificate fetches and attests an upstream certificate
func (m *MITMAttestation) FetchAndAttestCertificate(host string, timeout time.Duration) (*MITMAttestationResult, error) {
	cert, err := m.fetchUpstreamCertificate(host, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch upstream certificate: %w", err)
	}

	result := m.AttestUpstreamCertificate(cert)
	return result, nil
}

// GetStats returns attestation statistics
func (m *MITMAttestation) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":             m.config.Enabled,
		"chain_verification":  m.config.RequireChainVerification,
		"crl_checking":        m.config.RequireCRL,
		"ocsp_checking":       m.config.RequireOCSP,
		"backdoor_prevention": m.config.BackdoorPrevention,
		"fail_closed":         m.config.FailClosed,
		"trust_anchor_count":  len(m.attestation.GetTrustAnchors()),
		"cached_result_count": len(m.resultCache),
	}
}

// GetTrustAnchors returns configured trust anchors
func (m *MITMAttestation) GetTrustAnchors() []*pkiattest.TrustAnchor {
	return m.attestation.GetTrustAnchors()
}

// cacheResult caches an attestation result if caching is enabled
func (m *MITMAttestation) cacheResult(result *MITMAttestationResult) *MITMAttestationResult {
	if m.config.CacheResults && result.Certificate != nil {
		cacheKey := result.Certificate.SerialNumber.String()
		m.resultCache[cacheKey] = result
	}
	return result
}

// ClearCache clears the attestation result cache
func (m *MITMAttestation) ClearCache() {
	m.resultCache = make(map[string]*MITMAttestationResult)
	m.trustStore.ClearRevocationCache()
}

// PreInterceptCheck performs attestation before TLS interception
// Returns true if the connection should be allowed, false if it should be blocked
func (m *MITMAttestation) PreInterceptCheck(host string, timeout time.Duration) (bool, *MITMAttestationResult, error) {
	if !m.config.Enabled {
		return true, nil, nil
	}

	result, err := m.FetchAndAttestCertificate(host, timeout)
	if err != nil {
		slog.Warn("Failed to fetch upstream certificate for attestation",
			"host", host,
			"error", err)

		// If FailClosed is set, block on error
		if m.config.FailClosed {
			return false, nil, err
		}

		// Otherwise, allow the connection
		return true, nil, err
	}

	if !result.Valid {
		slog.Warn("Upstream certificate attestation failed",
			"host", host,
			"reason", result.Reason,
			"backdoor_detected", result.BackdoorDetected)

		// Block if FailClosed is set or if backdoor was detected
		if m.config.FailClosed || result.BackdoorDetected {
			return false, result, nil
		}
	}

	return true, result, nil
}

// ValidateExistingConnection validates certificates from an existing TLS connection
func (m *MITMAttestation) ValidateExistingConnection(conn *tls.Conn) (*MITMAttestationResult, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection is nil")
	}
	connState := conn.ConnectionState()
	return m.AttestConnection(&connState)
}

// IsEnabled returns whether attestation is enabled
func (m *MITMAttestation) IsEnabled() bool {
	return m.config.Enabled
}

// SetEnabled enables or disables attestation
func (m *MITMAttestation) SetEnabled(enabled bool) {
	m.config.Enabled = enabled
}

// ShouldFailClosed returns whether the attestation should fail closed
func (m *MITMAttestation) ShouldFailClosed() bool {
	return m.config.FailClosed
}
