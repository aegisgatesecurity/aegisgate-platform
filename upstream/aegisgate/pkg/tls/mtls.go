// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// mTLSMode represents the mode of mTLS operation
type mTLSMode int

const (
	// mTLSModeDisabled means mTLS is disabled
	mTLSModeDisabled mTLSMode = iota
	// mTLSModeOptional means client certificates are requested but not required
	mTLSModeOptional
	// mTLSModeRequired means client certificates are required
	mTLSModeRequired
)

// mTLSConfig contains configuration for mTLS
type mTLSConfig struct {
	Mode                 mTLSMode
	ClientCAFile         string
	ClientCAPath         string
	CertFile             string
	KeyFile              string
	VerifyClientCert     bool
	SkipClientCertVerify bool   // Only for development/testing
	ClientCertSubjectCN  string // Expected CN for client certs (optional validation)
}

// mTLSContext holds mTLS state and configuration
type mTLSContext struct {
	config        *mTLSConfig
	clientCAs     *x509.CertPool
	certPair      tls.Certificate
	mu            sync.RWMutex
	isInitialized bool
}

// mTLSClientConfig for client-side mTLS (connecting to services)
type mTLSClientConfig struct {
	CertFile           string
	KeyFile            string
	CAFile             string
	InsecureSkipVerify bool // Only for testing/development
	ServerName         string
	RenewalInterval    time.Duration
}

// mTLSClient holds client-side mTLS configuration
type mTLSClient struct {
	config    *mTLSClientConfig
	tlsConfig *tls.Config
	mu        sync.RWMutex
	lastLoad  time.Time
}

// NewmTLSContext creates a new mTLS server context for validating client certificates
func NewmTLSContext(cfg *mTLSConfig) (*mTLSContext, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mTLS config is nil")
	}

	ctx := &mTLSContext{
		config: cfg,
	}

	if cfg.Mode == mTLSModeDisabled {
		slog.Info("mTLS is disabled")
		ctx.isInitialized = true
		return ctx, nil
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize mTLS: %w", err)
	}

	return ctx, nil
}

// Initialize sets up the mTLS context
func (m *mTLSContext) Initialize() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.initializeLocked()
}

// initializeLocked is the internal initialization that assumes lock is held
func (m *mTLSContext) initializeLocked() error {
	if m.isInitialized {
		return nil
	}

	// Load client CA certificates
	if err := m.loadClientCAs(); err != nil {
		return fmt.Errorf("failed to load client CAs: %w", err)
	}

	// Load server certificate for mutual TLS
	if m.config.CertFile != "" && m.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(m.config.CertFile, m.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load server certificate: %w", err)
		}
		m.certPair = cert
		slog.Info("Loaded server certificate for mTLS",
			"cert_file", m.config.CertFile,
		)
	}

	m.isInitialized = true
	slog.Info("mTLS context initialized", "mode", m.config.Mode)

	return nil
}

// loadClientCAs loads the CA certificates for client validation
func (m *mTLSContext) loadClientCAs() error {
	m.clientCAs = x509.NewCertPool()

	// Load from single file
	if m.config.ClientCAFile != "" {
		caData, err := os.ReadFile(m.config.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to read client CA file: %w", err)
		}

		if ok := m.clientCAs.AppendCertsFromPEM(caData); !ok {
			return fmt.Errorf("failed to parse client CA certificate")
		}

		slog.Info("Loaded client CA certificate from file", "file", m.config.ClientCAFile)
	}

	// Load from directory
	if m.config.ClientCAPath != "" {
		entries, err := os.ReadDir(m.config.ClientCAPath)
		if err != nil {
			return fmt.Errorf("failed to read CA directory: %w", err)
		}

		for _, entry := range entries {
			if entry.IsDir() || !isCertFile(entry.Name()) {
				continue
			}

			path := m.config.ClientCAPath + "/" + entry.Name()
			caData, err := os.ReadFile(path)
			if err != nil {
				slog.Warn("Failed to read CA file", "file", path, "error", err)
				continue
			}

			if ok := m.clientCAs.AppendCertsFromPEM(caData); !ok {
				slog.Warn("Failed to parse CA file", "file", path)
				continue
			}

			slog.Debug("Loaded CA certificate", "file", entry.Name())
		}
	}

	return nil
}

// isCertFile checks if a filename looks like a certificate file
func isCertFile(name string) bool {
	return len(name) > 4 && (name[len(name)-4:] == ".crt" || name[len(name)-4:] == ".pem")
}

// GetTLSConfig returns a TLS configuration with mTLS settings
func (m *mTLSContext) GetTLSConfig() *tls.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config.Mode == mTLSModeDisabled {
		return &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    m.clientCAs,
		RootCAs:      m.clientCAs,
		Certificates: []tls.Certificate{m.certPair},
	}

	// Configure client certificate verification
	switch m.config.Mode {
	case mTLSModeOptional:
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	case mTLSModeRequired:
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		tlsConfig.ClientAuth = tls.NoClientCert
	}

	// Add custom verification if needed
	if m.config.VerifyClientCert && !m.config.SkipClientCertVerify {
		tlsConfig.VerifyPeerCertificate = m.verifyPeerCertificate
	}

	return tlsConfig
}

// verifyPeerCertificate performs additional certificate verification
func (m *mTLSContext) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}

	cert := verifiedChains[0][0]

	// Validate CN if specified
	if m.config.ClientCertSubjectCN != "" {
		if cert.Subject.CommonName != m.config.ClientCertSubjectCN {
			return fmt.Errorf("certificate CN mismatch: expected %s, got %s",
				m.config.ClientCertSubjectCN, cert.Subject.CommonName)
		}
	}

	// Log successful verification
	slog.Info("Client certificate verified",
		"subject", cert.Subject.String(),
		"issuer", cert.Issuer.String(),
		"cn", cert.Subject.CommonName,
	)

	return nil
}

// IsInitialized returns true if mTLS is initialized
func (m *mTLSContext) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isInitialized
}

// GetMode returns the current mTLS mode
func (m *mTLSContext) GetMode() mTLSMode {
	if m.config == nil {
		return mTLSModeDisabled
	}
	return m.config.Mode
}

// Reload reloads certificates from disk
func (m *mTLSContext) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isInitialized = false
	return m.initializeLocked()
}

// ==================== Client-Side mTLS ====================

// NewmTLSClient creates a new mTLS client for connecting to services
func NewmTLSClient(cfg *mTLSClientConfig) (*mTLSClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mTLS client config is nil")
	}

	// Set default renewal interval
	if cfg.RenewalInterval == 0 {
		cfg.RenewalInterval = 24 * time.Hour
	}

	client := &mTLSClient{
		config: cfg,
	}

	if err := client.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize mTLS client: %w", err)
	}

	return client, nil
}

// Initialize sets up the mTLS client
func (c *mTLSClient) Initialize() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         c.config.ServerName,
		InsecureSkipVerify: c.config.InsecureSkipVerify,
	}

	// Load client certificate
	if c.config.CertFile != "" && c.config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.config.CertFile, c.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		slog.Info("Loaded client certificate for mTLS",
			"cert_file", c.config.CertFile,
		)
	}

	// Load CA certificate for server verification
	if c.config.CAFile != "" {
		caData, err := os.ReadFile(c.config.CAFile)
		if err != nil {
			return fmt.Errorf("failed to read CA file: %w", err)
		}

		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caData); !ok {
			return fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = pool
		slog.Info("Loaded CA certificate for server verification",
			"ca_file", c.config.CAFile,
		)
	} else if !c.config.InsecureSkipVerify {
		// Use system roots if not using insecure mode
		pool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("failed to load system cert pool: %w", err)
		}
		tlsConfig.RootCAs = pool
	}

	c.tlsConfig = tlsConfig
	c.lastLoad = time.Now()

	return nil
}

// GetTLSConfig returns the client TLS configuration
func (c *mTLSClient) GetTLSConfig() *tls.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tlsConfig
}

// ShouldRenew returns true if certificates should be reloaded
func (c *mTLSClient) ShouldRenew() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.lastLoad) > c.config.RenewalInterval
}

// Renew reloads certificates if needed
func (c *mTLSClient) Renew() error {
	if !c.ShouldRenew() {
		return nil
	}

	slog.Info("Renewing mTLS client certificates")
	return c.Initialize()
}

// ==================== Utility Functions ====================

// VerifyCertificate verifies a raw certificate against a CA pool
func VerifyCertificate(certPEM []byte, caPool *x509.CertPool) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:       caPool,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// ExtractCertificateInfo extracts information from a certificate
func ExtractCertificateInfo(certPEM []byte) (map[string]interface{}, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return map[string]interface{}{
		"subject_cn":    cert.Subject.CommonName,
		"issuer_cn":     cert.Issuer.CommonName,
		"serial_number": cert.SerialNumber.String(),
		"not_before":    cert.NotBefore.Format(time.RFC3339),
		"not_after":     cert.NotAfter.Format(time.RFC3339),
		"dns_names":     cert.DNSNames,
		"email":         cert.EmailAddresses,
		"is_ca":         cert.IsCA,
		"key_usage":     cert.KeyUsage,
	}, nil
}

// CreateCertPool creates a certificate pool from PEM files
func CreateCertPool(certFiles ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for _, file := range certFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %w", file, err)
		}

		if ok := pool.AppendCertsFromPEM(data); !ok {
			return nil, fmt.Errorf("failed to parse certificates from %s", file)
		}
	}

	return pool, nil
}

// DefaultmTLSConfig returns a default mTLS configuration
func DefaultmTLSConfig() *mTLSConfig {
	return &mTLSConfig{
		Mode:             mTLSModeDisabled,
		VerifyClientCert: true,
	}
}

// DefaultmTLSClientConfig returns a default client configuration
func DefaultmTLSClientConfig() *mTLSClientConfig {
	return &mTLSClientConfig{
		RenewalInterval: 24 * time.Hour,
	}
}
