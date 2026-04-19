// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Manager handles TLS certificates and configuration
type Manager struct {
	certDir      string
	certFile     string
	keyFile      string
	autoGenerate bool
	tlsConfig    *tls.Config
}

// Config contains TLS manager configuration
type Config struct {
	CertDir      string
	CertFile     string
	KeyFile      string
	AutoGenerate bool
	MinVersion   uint16
}

// NewManager creates a new TLS certificate manager
func NewManager(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = &Config{
			CertDir:      "./certs",
			AutoGenerate: true,
			MinVersion:   tls.VersionTLS12,
		}
	}

	m := &Manager{
		certDir:      cfg.CertDir,
		certFile:     cfg.CertFile,
		keyFile:      cfg.KeyFile,
		autoGenerate: cfg.AutoGenerate,
	}

	// Ensure certificate directory exists
	if err := os.MkdirAll(m.certDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Generate or load certificates
	if err := m.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize certificates: %w", err)
	}

	return m, nil
}

// Initialize ensures certificates are available
func (m *Manager) Initialize() error {
	// If specific cert files provided, use them
	if m.certFile != "" && m.keyFile != "" {
		slog.Info("Using provided TLS certificates", "cert", m.certFile, "key", m.keyFile)
		if err := m.loadExternalCertificates(); err != nil {
			return err
		}
		// Only proceed if load succeeded
		return nil
	}

	// If auto-generate enabled, check for or create self-signed certs
	if m.autoGenerate {
		certPath := filepath.Join(m.certDir, "server.crt")
		keyPath := filepath.Join(m.certDir, "server.key")

		// Check if certificates already exist
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				slog.Info("Loading existing TLS certificates", "cert", certPath, "key", keyPath)
				m.certFile = certPath
				m.keyFile = keyPath
				// Try to load; if invalid, fall back to regeneration
				if err := m.loadExternalCertificates(); err == nil {
					return nil
				}
				slog.Warn("Existing certificates invalid, regenerating", "error", err)
			}
		}

		// Generate new self-signed certificate
		slog.Info("Generating self-signed TLS certificates")
		if err := m.generateSelfSigned(certPath, keyPath); err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}

		m.certFile = certPath
		m.keyFile = keyPath
		return m.loadExternalCertificates()
	}

	return fmt.Errorf("no certificates provided and auto-generate disabled")
}

// loadExternalCertificates loads certificates from file paths
func (m *Manager) loadExternalCertificates() error {
	cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	// Validate certificate
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("no certificates found in file")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check expiration
	if time.Now().After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired on %v", x509Cert.NotAfter)
	}

	if time.Now().Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate not valid until %v", x509Cert.NotBefore)
	}

	daysUntilExpiry := time.Until(x509Cert.NotAfter) / (24 * time.Hour)
	slog.Info("TLS certificate loaded",
		"subject", x509Cert.Subject.CommonName,
		"issuer", x509Cert.Issuer.CommonName,
		"expiry", x509Cert.NotAfter.Format("2006-01-02"),
		"days_until_expiry", daysUntilExpiry,
	)

	if daysUntilExpiry < 30 {
		slog.Warn("TLS certificate expires soon", "days_remaining", daysUntilExpiry)
	}

	// Create TLS config
	m.tlsConfig = &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	return nil
}

// generateSelfSigned creates a self-signed certificate
func (m *Manager) generateSelfSigned(certPath, keyPath string) error {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"AegisGate Self-Signed"},
			CommonName:   "aegisgate.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost", "aegisgate.local", "*.aegisgate.local"},
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer func() {
		if err := certOut.Close(); err != nil {
			slog.Error("failed to close cert file", "error", err)
		}
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key to file
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer func() {
		if err := keyOut.Close(); err != nil {
			slog.Error("failed to close key file", "error", err)
		}
	}()

	privKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	if err := pem.Encode(keyOut, privKeyPEM); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	slog.Info("Self-signed TLS certificates generated",
		"cert_path", certPath,
		"key_path", keyPath,
		"validity", "1 year",
	)

	return nil
}

// GetCertificatePaths returns the paths to certificate files
func (m *Manager) GetCertificatePaths() (certFile, keyFile string) {
	return m.certFile, m.keyFile
}

// GetTLSConfig returns the TLS configuration
func (m *Manager) GetTLSConfig() *tls.Config {
	return m.tlsConfig
}

// IsAutoGenerated returns true if using auto-generated certificates
func (m *Manager) IsAutoGenerated() bool {
	return m.autoGenerate
}

// GetCertificateInfo returns information about the loaded certificate
func (m *Manager) GetCertificateInfo() (map[string]interface{}, error) {
	if m.tlsConfig == nil || len(m.tlsConfig.Certificates) == 0 {
		return nil, fmt.Errorf("no certificate loaded")
	}

	cert := m.tlsConfig.Certificates[0]
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return map[string]interface{}{
		"subject":        x509Cert.Subject.CommonName,
		"issuer":         x509Cert.Issuer.CommonName,
		"not_before":     x509Cert.NotBefore.Format("2006-01-02 15:04:05"),
		"not_after":      x509Cert.NotAfter.Format("2006-01-02 15:04:05"),
		"serial_number":  x509Cert.SerialNumber.String(),
		"dns_names":      x509Cert.DNSNames,
		"ip_addresses":   x509Cert.IPAddresses,
		"auto_generated": m.autoGenerate,
	}, nil
}
