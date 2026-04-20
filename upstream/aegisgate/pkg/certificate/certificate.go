// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// Certificate represents a certificate with its key
type Certificate struct {
	Certificate *x509.Certificate
	PrivateKey  interface{}
	CertBytes   []byte
	KeyBytes    []byte
}

// Manager handles certificate generation and management
type Manager struct {
	mu            sync.RWMutex
	certCache     map[string]*Certificate
	autoGenerate  bool
	caCertificate *Certificate
	caPrivateKey  interface{}
}

// NewManager creates a new certificate manager
func NewManager() *Manager {
	return &Manager{
		certCache:    make(map[string]*Certificate),
		autoGenerate: true,
	}
}

// GenerateSelfSigned generates a self-signed CA certificate
func (m *Manager) GenerateSelfSigned() (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "AegisGate CA",
			Organization: []string{"AegisGate"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certObj := &Certificate{
		Certificate: cert,
		PrivateKey:  key,
		CertBytes:   certPEM,
		KeyBytes:    keyPEM,
	}
	m.certCache["self-signed-ca"] = certObj
	m.caCertificate = certObj
	m.caPrivateKey = key

	return certObj, nil
}

// GenerateProxyCertificate generates a proxy certificate for MITM
func (m *Manager) GenerateProxyCertificate(hostname string) (*Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.caCertificate == nil {
		ca, err := m.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		m.caCertificate = ca
	}

	if cached, exists := m.certCache[hostname]; exists {
		return cached, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"AegisGate"},
			Country:      []string{"US"},
		},
		DNSNames:              []string{hostname},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, m.caCertificate.Certificate, &key.PublicKey, m.caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certObj := &Certificate{
		Certificate: cert,
		PrivateKey:  key,
		CertBytes:   certPEM,
		KeyBytes:    keyPEM,
	}
	m.certCache[hostname] = certObj

	return certObj, nil
}

// Save saves a certificate to file
func (m *Manager) Save(cert *Certificate, certPath, keyPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.WriteFile(certPath, cert.CertBytes, 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, cert.KeyBytes, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// GetCACertificate returns the CA certificate
func (m *Manager) GetCACertificate() (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.caCertificate == nil {
		return nil, fmt.Errorf("CA certificate not generated yet")
	}
	return m.caCertificate, nil
}

// CacheCertificate caches a certificate
func (m *Manager) CacheCertificate(hostname string, cert *Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache[hostname] = cert
	return nil
}

// GetCertificate retrieves a cached certificate
func (m *Manager) GetCertificate(hostname string) (*Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, exists := m.certCache[hostname]
	if !exists {
		return nil, fmt.Errorf("certificate not found for %s", hostname)
	}
	return cert, nil
}

// EnableAutoGenerate enables automatic certificate generation
func (m *Manager) EnableAutoGenerate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoGenerate = true
}

// DisableAutoGenerate disables automatic certificate generation
func (m *Manager) DisableAutoGenerate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.autoGenerate = false
}

// IsAutoGenerateEnabled checks if auto-generation is enabled
func (m *Manager) IsAutoGenerateEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.autoGenerate
}

// GetCertificateCount returns the number of cached certificates
func (m *Manager) GetCertificateCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.certCache)
}

// ClearCache clears all cached certificates
func (m *Manager) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certCache = make(map[string]*Certificate)
}
