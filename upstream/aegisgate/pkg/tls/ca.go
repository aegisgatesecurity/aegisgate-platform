// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
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
	"sync"
	"time"
)

// CertificateAuthority manages CA certificate for MITM intercept
type CertificateAuthority struct {
	mu sync.RWMutex

	// CA certificate and key
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	caCertPEM []byte
	caKeyPEM  []byte

	// Certificate cache for generated domain certificates
	certCache map[string]*tls.Certificate
	cacheTTL  time.Duration

	// Configuration
	certDir string
	orgName string
}

// CAConfig holds Certificate Authority configuration
type CAConfig struct {
	CertDir      string
	OrgName      string
	CacheTTL     time.Duration
	AutoGenerate bool
}

// NewCertificateAuthority creates a new CA for MITM certificate generation
func NewCertificateAuthority(cfg *CAConfig) (*CertificateAuthority, error) {
	if cfg == nil {
		cfg = &CAConfig{
			CertDir:      "./certs/ca",
			OrgName:      "AegisGate MITM CA",
			CacheTTL:     time.Hour,
			AutoGenerate: true,
		}
	}

	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Hour
	}

	ca := &CertificateAuthority{
		certCache: make(map[string]*tls.Certificate),
		cacheTTL:  cfg.CacheTTL,
		certDir:   cfg.CertDir,
		orgName:   cfg.OrgName,
	}

	// Ensure CA directory exists
	if err := os.MkdirAll(ca.certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Load or generate CA certificate
	certPath := filepath.Join(ca.certDir, "ca.crt")
	keyPath := filepath.Join(ca.certDir, "ca.key")

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if certExists && keyExists {
		if err := ca.loadCA(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		slog.Info("Loaded existing CA certificate", "path", certPath)
	} else if cfg.AutoGenerate {
		if err := ca.generateCA(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("failed to generate CA certificate: %w", err)
		}
		slog.Info("Generated new CA certificate", "path", certPath)
	} else {
		return nil, fmt.Errorf("CA certificate not found and auto-generation disabled")
	}

	return ca, nil
}

// loadCA loads an existing CA certificate and key
func (ca *CertificateAuthority) loadCA(certPath, keyPath string) error {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Load key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA key: %w", err)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA key is not an RSA private key")
		}
	}

	ca.mu.Lock()
	ca.caCert = caCert
	ca.caKey = caKey
	ca.caCertPEM = certPEM
	ca.caKeyPEM = keyPEM
	ca.mu.Unlock()

	return nil
}

// generateCA generates a new CA certificate and key
func (ca *CertificateAuthority) generateCA(certPath, keyPath string) error {
	// Generate CA private key (4096 bits for CA)
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Create CA certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{ca.orgName},
			CommonName:         ca.orgName,
			OrganizationalUnit: []string{"MITM Proxy CA"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost", "aegisgate.local", "*.aegisgate.local"},
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})

	// Write certificate
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Write key (more restrictive permissions)
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// Parse the certificate for in-memory use
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	ca.mu.Lock()
	ca.caCert = caCert
	ca.caKey = caKey
	ca.caCertPEM = certPEM
	ca.caKeyPEM = keyPEM
	ca.mu.Unlock()

	slog.Info("Generated CA certificate",
		"subject", caCert.Subject.CommonName,
		"serial", caCert.SerialNumber.String(),
		"valid_until", caCert.NotAfter.Format("2006-01-02"),
	)

	return nil
}

// GetCertificate generates or retrieves a certificate for a domain
func (ca *CertificateAuthority) GetCertificate(domain string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if cert, ok := ca.certCache[domain]; ok {
		ca.mu.RUnlock()
		return cert, nil
	}
	ca.mu.RUnlock()

	// Generate new certificate
	cert, err := ca.generateCertificate(domain)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	ca.mu.Lock()
	ca.certCache[domain] = cert
	ca.mu.Unlock()

	return cert, nil
}

// generateCertificate generates a certificate for a domain signed by the CA
func (ca *CertificateAuthority) generateCertificate(domain string) (*tls.Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if ca.caCert == nil || ca.caKey == nil {
		return nil, fmt.Errorf("CA certificate not initialized")
	}

	// Generate server key (2048 bits for leaf certificates)
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{ca.orgName},
			CommonName:         domain,
			OrganizationalUnit: []string{"MITM Generated"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(ca.cacheTTL * 24), // Use cache TTL as days
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{domain, "*." + domain},
		IPAddresses: parseIPAddresses(domain),
	}

	// Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &serverKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Create tls.Certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, ca.caCert.Raw},
		PrivateKey:  serverKey,
		Leaf:        template,
	}

	slog.Debug("Generated certificate for domain", "domain", domain, "serial", serialNumber.String())

	return cert, nil
}

// GetConfigForClient returns a TLS config that generates certificates on-the-fly
func (ca *CertificateAuthority) GetConfigForClient() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			domain := hello.ServerName
			if domain == "" {
				domain = "unknown.local"
			}
			return ca.GetCertificate(domain)
		},
		MinVersion: tls.VersionTLS13,
	}
}

// GetCACertificate returns the CA certificate in DER format
func (ca *CertificateAuthority) GetCACertificate() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.caCert == nil {
		return nil
	}
	return ca.caCert.Raw
}

// GetCACertificatePEM returns the CA certificate in PEM format
func (ca *CertificateAuthority) GetCACertificatePEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.caCertPEM
}

// GetCAKeyPEM returns the CA key in PEM format (for export)
func (ca *CertificateAuthority) GetCAKeyPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.caKeyPEM
}

// GetCACertInfo returns information about the CA certificate
func (ca *CertificateAuthority) GetCACertInfo() (map[string]interface{}, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if ca.caCert == nil {
		return nil, fmt.Errorf("CA certificate not loaded")
	}

	return map[string]interface{}{
		"subject":      ca.caCert.Subject.CommonName,
		"issuer":       ca.caCert.Issuer.CommonName,
		"not_before":   ca.caCert.NotBefore.Format("2006-01-02 15:04:05"),
		"not_after":    ca.caCert.NotAfter.Format("2006-01-02 15:04:05"),
		"serial":       ca.caCert.SerialNumber.String(),
		"dns_names":    ca.caCert.DNSNames,
		"ip_addresses": ca.caCert.IPAddresses,
		"is_ca":        ca.caCert.IsCA,
	}, nil
}

// ClearCache clears the certificate cache
func (ca *CertificateAuthority) ClearCache() {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.certCache = make(map[string]*tls.Certificate)
	slog.Info("Cleared certificate cache")
}

// CacheSize returns the number of cached certificates
func (ca *CertificateAuthority) CacheSize() int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.certCache)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// parseIPAddresses attempts to parse domain as IP if applicable
func parseIPAddresses(domain string) []net.IP {
	ip := net.ParseIP(domain)
	if ip != nil {
		return []net.IP{ip}
	}
	return []net.IP{net.IPv4(127, 0, 0, 1)}
}
