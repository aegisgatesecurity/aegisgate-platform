// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/x509"
	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
	tlspkg "github.com/aegisgatesecurity/aegisgate/pkg/tls"
)

// MITMConfig holds configuration for MITM proxy
type MITMConfig struct {
	// Enable MITM mode
	Enabled bool

	// Certificate Authority for generating certificates
	CA *tlspkg.CertificateAuthority

	// Listen address for MITM proxy
	BindAddress string

	// Upstream proxy (optional, for chaining)
	UpstreamProxy string

	// Maximum concurrent connections
	MaxConnections int

	// Connection timeout
	Timeout time.Duration

	// Enable TLS 1.3
	EnableTLS13 bool

	// Skip TLS verification for upstream connections
	InsecureSkipVerify bool

	// Enable content scanning
	EnableScanning bool

	// Scanner for content inspection
	Scanner *scanner.Scanner

	// Compliance manager for ATLAS/NIST checks
	ComplianceManager *compliance.ComplianceManager

	// Attestation configuration for PKI certificate validation
	AttestationConfig *MITMAttestationConfig
}

// MITMProxy implements HTTPS Man-in-the-Middle interception
type MITMProxy struct {
	config      *MITMConfig
	ca          *tlspkg.CertificateAuthority
	server      *http.Server
	serverMutex sync.RWMutex

	// Content scanner
	scanner *scanner.Scanner

	// Compliance manager
	complianceManager *compliance.ComplianceManager

	// PKI attestation for upstream certificate validation
	attestation *MITMAttestation

	// Statistics
	connectionCount atomic.Int64
	requestCount    atomic.Int64
	blockedCount    atomic.Int64
	bytesUploaded   atomic.Int64
	bytesDownloaded atomic.Int64

	// Connection tracking
	connections map[string]net.Conn
	connMutex   sync.RWMutex

	// Shutdown
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc

	// Ready signal - closed when server is ready to accept connections
	ready chan struct{}
}

// NewMITMProxy creates a new MITM proxy
func NewMITMProxy(config *MITMConfig) (*MITMProxy, error) {
	if config == nil {
		config = &MITMConfig{
			Enabled:            true,
			BindAddress:        ":3128",
			MaxConnections:     10000,
			Timeout:            30 * time.Second,
			EnableTLS13:        true,
			InsecureSkipVerify: false,
			EnableScanning:     true,
		}
	}

	// Apply defaults
	if config.BindAddress == "" {
		config.BindAddress = ":3128"
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 10000
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	// Initialize CA if not provided
	if config.CA == nil && config.Enabled {
		ca, err := tlspkg.NewCertificateAuthority(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize CA: %w", err)
		}
		config.CA = ca
	}

	// Initialize scanner if not provided
	if config.Scanner == nil && config.EnableScanning {
		config.Scanner = scanner.New(nil)
	}

	ctx, cancel := context.WithCancel(context.Background())

	proxy := &MITMProxy{
		config:            config,
		ca:                config.CA,
		scanner:           config.Scanner,
		complianceManager: config.ComplianceManager,
		connections:       make(map[string]net.Conn),
		shutdownCtx:       ctx,
		shutdownCancel:    cancel,
		ready:             make(chan struct{}),
	}

	// Initialize attestation if configured
	if config.AttestationConfig != nil && config.AttestationConfig.Enabled {
		att, err := NewMITMAttestation(config.AttestationConfig)
		if err != nil {
			slog.Warn("Failed to initialize attestation", "error", err)
		} else {
			proxy.attestation = att
			slog.Info("PKI attestation initialized successfully")
		}
	}

	return proxy, nil
}

// SetScanner sets the content scanner
func (m *MITMProxy) SetScanner(s *scanner.Scanner) {
	m.scanner = s
}

// SetComplianceManager sets the compliance manager
func (m *MITMProxy) SetComplianceManager(cm *compliance.ComplianceManager) {
	m.complianceManager = cm
}

// SetAttestation sets the PKI attestation
func (m *MITMProxy) SetAttestation(a *MITMAttestation) {
	m.attestation = a
}

// GetAttestation returns the PKI attestation
func (m *MITMProxy) GetAttestation() *MITMAttestation {
	return m.attestation
}

// AddTrustAnchor adds a trust anchor for attestation
func (m *MITMProxy) AddTrustAnchor(cert *x509.Certificate) error {
	if m.attestation == nil {
		return fmt.Errorf("attestation not initialized")
	}
	_, err := m.attestation.attestation.AddTrustAnchor(cert)
	return err
}

// Start starts the MITM proxy server
func (m *MITMProxy) Start() error {
	m.serverMutex.Lock()
	m.server = &http.Server{
		Addr:         m.config.BindAddress,
		Handler:      m,
		ReadTimeout:  m.config.Timeout,
		WriteTimeout: m.config.Timeout,
		IdleTimeout:  120 * time.Second,
	}
	m.serverMutex.Unlock()

	slog.Info("Starting MITM proxy server",
		"address", m.config.BindAddress,
		"mitm_enabled", m.config.Enabled,
		"max_connections", m.config.MaxConnections,
	)

	// Signal that server is ready
	close(m.ready)

	return m.server.ListenAndServe()
}

// Stop gracefully stops the MITM proxy
func (m *MITMProxy) Stop(ctx context.Context) error {
	m.shutdownCancel()

	// Close all active connections
	m.connMutex.Lock()
	for id, conn := range m.connections {
		if err := conn.Close(); err != nil {
			slog.Debug("Error closing connection", "id", id, "error", err)
		}
	}
	m.connections = make(map[string]net.Conn)
	m.connMutex.Unlock()

	m.serverMutex.RLock()
	server := m.server
	m.serverMutex.RUnlock()

	if server != nil {
		slog.Info("Shutting down MITM proxy server...")
		return server.Shutdown(ctx)
	}
	return nil
}

// Ready returns a channel that is closed when the server is ready to accept connections
func (m *MITMProxy) Ready() <-chan struct{} {
	return m.ready
}

// ServeHTTP handles HTTP requests
func (m *MITMProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.requestCount.Add(1)

	// Log request
	slog.Debug("MITM proxy request",
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
	)

	// Handle CONNECT method for HTTPS
	if r.Method == http.MethodConnect {
		m.handleCONNECT(w, r)
		return
	}

	// Handle regular HTTP requests
	m.handleHTTP(w, r)
}

// handleCONNECT handles HTTPS tunneling with MITM interception
func (m *MITMProxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	m.connectionCount.Add(1)

	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	slog.Info("CONNECT request received", "host", host, "remote", r.RemoteAddr)

	// Check if MITM is enabled
	if !m.config.Enabled {
		// Simple tunnel without interception
		m.tunnel(w, r, host)
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		slog.Error("Response writer does not support hijacking", "host", host)
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		slog.Error("Failed to hijack connection", "host", host, "error", err)
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	_ = clientConn.Close()

	// Track connection
	connID := r.RemoteAddr + "->" + host
	m.trackConnection(connID, clientConn)
	defer m.untrackConnection(connID)

	// Send 200 Connection Established
	_, err = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		slog.Error("Failed to send connection established", "host", host, "error", err)
		return
	}
	_ = clientBuf.Flush()

	// Get target host (without port) for certificate generation
	targetHost := strings.Split(host, ":")[0]

	// PKI Attestation: Validate upstream certificate before interception
	if m.attestation != nil && m.config.AttestationConfig != nil && m.config.AttestationConfig.Enabled {
		allowed, result, err := m.attestation.PreInterceptCheck(targetHost, m.config.Timeout)
		if err != nil {
			slog.Error("Attestation check failed", "host", targetHost, "error", err)
			if m.config.AttestationConfig.FailClosed {
				// Block connection on attestation error
				_, _ = clientBuf.WriteString("HTTP/1.1 403 Forbidden\r\nConnection blocked: certificate validation error\r\n\r\n")
				_ = clientBuf.Flush()
				m.blockedCount.Add(1)
				return
			}
			// Allow on error if FailClosed is false
		} else if !allowed {
			slog.Warn("Connection blocked by attestation",
				"host", targetHost,
				"reason", result.Reason,
				"chain_verified", result.ChainVerified,
				"backdoor_detected", result.BackdoorDetected)
			_, _ = clientBuf.WriteString("HTTP/1.1 403 Forbidden\r\nConnection blocked: certificate validation failed\r\n\r\n")
			_ = clientBuf.Flush()
			m.blockedCount.Add(1)
			return
		}
		slog.Debug("Attestation check passed", "host", targetHost, "duration", result.AttestationDuration)
	}

	// Wrap client connection with TLS using our CA certificate
	tlsConfig := m.ca.GetConfigForClient()
	if m.config.EnableTLS13 {
		tlsConfig.MaxVersion = tls.VersionTLS13
	}
	tlsConfig.MinVersion = tls.VersionTLS12

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		slog.Error("TLS handshake failed", "host", targetHost, "error", err)
		return
	}
	_ = tlsConn.Close()

	slog.Debug("TLS handshake completed", "host", targetHost, "version", tlsConn.ConnectionState().Version)

	// Create an HTTP client connection over TLS
	connReader := bufio.NewReader(tlsConn)
	connWriter := bufio.NewWriter(tlsConn)

	// Handle HTTPS requests
	for {
		// Set read deadline
		if err := tlsConn.SetReadDeadline(time.Now().Add(m.config.Timeout)); err != nil {
			slog.Debug("Failed to set read deadline", "error", err)
		}

		// Read the HTTPS request
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if err != io.EOF {
				slog.Debug("Error reading request from client", "host", targetHost, "error", err)
			}
			break
		}

		m.requestCount.Add(1)

		// Set the host and scheme
		req.URL.Host = host
		req.URL.Scheme = "https"
		req.RequestURI = ""

		// Process the request through MITM
		resp, err := m.processHTTPSRequest(req, targetHost)
		if err != nil {
			slog.Error("Error processing HTTPS request", "host", targetHost, "path", req.URL.Path, "error", err)
			resp = m.createErrorResponse(err)
		}

		// Write response back to client
		if err := resp.Write(connWriter); err != nil {
			slog.Error("Error writing response to client", "host", targetHost, "error", err)
			break
		}
		connWriter.Flush()

		// Close response body if it's not a persistent connection
		if resp.Close {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}
}

// handleHTTP handles regular HTTP requests
func (m *MITMProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Create target URL
	targetURL := r.URL
	if !targetURL.IsAbs() {
		targetURL = &url.URL{
			Scheme: "http",
			Host:   r.Host,
			Path:   r.URL.Path,
		}
	}

	// Process request through scanner if enabled
	if m.scanner != nil && m.config.EnableScanning && r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			slog.Error("Failed to read request body", "error", err)
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Scan request body
		findings := m.scanner.ScanBytes(bodyBytes)
		if len(findings) > 0 {
			slog.Info("Request content scan findings",
				"url", targetURL.String(),
				"findings", len(findings),
			)

			if m.scanner.ShouldBlock(findings) {
				m.blockedCount.Add(1)
				patterns := getViolationNames(findings)
				slog.Warn("Request blocked by content scanner",
					"url", targetURL.String(),
					"patterns", strings.Join(patterns, ", "),
				)
				http.Error(w, "Request blocked: prohibited content detected", http.StatusForbidden)
				return
			}
		}

		// Check compliance
		if m.complianceManager != nil {
			atlas := compliance.NewAtlas()
			complianceFindings, _ := atlas.Check(string(bodyBytes))
			if len(complianceFindings) > 0 {
				m.logComplianceFindings("request", targetURL.String(), complianceFindings)
			}
		}
	}

	// Create HTTP client for upstream connection
	client := &http.Client{
		Timeout: m.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Forward the request
	resp, err := client.Do(r)
	if err != nil {
		slog.Error("Failed to forward request", "url", targetURL.String(), "error", err)
		http.Error(w, "Failed to reach upstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// Read and scan response body if enabled
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read response body", "error", err)
		http.Error(w, "Failed to read response", http.StatusInternalServerError)
		return
	}

	if m.scanner != nil && m.config.EnableScanning {
		findings := m.scanner.ScanBytes(bodyBytes)
		if len(findings) > 0 {
			slog.Info("Response content scan findings",
				"url", targetURL.String(),
				"findings", len(findings),
			)
		}

		// Check compliance
		if m.complianceManager != nil {
			atlas := compliance.NewAtlas()
			complianceFindings, _ := atlas.Check(string(bodyBytes))
			if len(complianceFindings) > 0 {
				m.logComplianceFindings("response", targetURL.String(), complianceFindings)
			}
		}
	}

	// Write response
	w.WriteHeader(resp.StatusCode)
	w.Write(bodyBytes)

	m.bytesDownloaded.Add(int64(len(bodyBytes)))
}

// tunnel creates a simple TCP tunnel without MITM
func (m *MITMProxy) tunnel(w http.ResponseWriter, r *http.Request, host string) {
	// Connect to target
	targetConn, err := net.DialTimeout("tcp", host, m.config.Timeout)
	if err != nil {
		slog.Error("Failed to connect to target", "host", host, "error", err)
		http.Error(w, "Failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Hijack client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	_ = clientConn.Close()

	// Send 200 Connection Established
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Track connection
	connID := r.RemoteAddr + "->" + host
	m.trackConnection(connID, clientConn)
	defer m.untrackConnection(connID)

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()

	// Wait for both directions to complete
	<-done
	<-done
}

// processHTTPSRequest processes an HTTPS request through the MITM proxy
func (m *MITMProxy) processHTTPSRequest(req *http.Request, targetHost string) (*http.Response, error) {
	// Read request body for scanning
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		m.bytesUploaded.Add(int64(len(bodyBytes)))
	}

	// Scan request content if enabled
	if m.scanner != nil && m.config.EnableScanning && len(bodyBytes) > 0 {
		findings := m.scanner.ScanBytes(bodyBytes)
		if len(findings) > 0 {
			slog.Info("HTTPS request scan findings",
				"host", targetHost,
				"path", req.URL.Path,
				"findings", len(findings),
			)

			if m.scanner.ShouldBlock(findings) {
				m.blockedCount.Add(1)
				patterns := getViolationNames(findings)
				slog.Warn("HTTPS request blocked",
					"host", targetHost,
					"path", req.URL.Path,
					"patterns", strings.Join(patterns, ", "),
				)
				return m.createBlockedResponse(patterns), nil
			}
		}

		// Check compliance
		if m.complianceManager != nil {
			atlas := compliance.NewAtlas()
			complianceFindings, _ := atlas.Check(string(bodyBytes))
			if len(complianceFindings) > 0 {
				m.logComplianceFindings("request", targetHost+req.URL.Path, complianceFindings)
			}
		}
	}

	// Create TLS config for upstream connection
	tlsConfig := &tls.Config{
		InsecureSkipVerify: m.config.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if m.config.EnableTLS13 {
		tlsConfig.MaxVersion = tls.VersionTLS13
	}

	// Create HTTP transport
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   m.config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: m.config.Timeout,
		IdleConnTimeout:     90 * time.Second,
	}

	// Use upstream proxy if configured
	if m.config.UpstreamProxy != "" {
		proxyURL, err := url.Parse(m.config.UpstreamProxy)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   m.config.Timeout,
	}

	// Forward request to target
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for scanning
	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	m.bytesDownloaded.Add(int64(len(respBodyBytes)))

	// Scan response content if enabled
	if m.scanner != nil && m.config.EnableScanning {
		findings := m.scanner.ScanBytes(respBodyBytes)
		if len(findings) > 0 {
			slog.Info("HTTPS response scan findings",
				"host", targetHost,
				"path", req.URL.Path,
				"findings", len(findings),
			)
		}

		// Check response compliance
		if m.complianceManager != nil {
			atlas := compliance.NewAtlas()
			complianceFindings, _ := atlas.Check(string(respBodyBytes))
			if len(complianceFindings) > 0 {
				m.logComplianceFindings("response", targetHost+req.URL.Path, complianceFindings)
			}
		}
	}

	// Create new response with the body
	return &http.Response{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Proto:      resp.Proto,
		ProtoMajor: resp.ProtoMajor,
		ProtoMinor: resp.ProtoMinor,
		Header:     resp.Header,
		Body:       io.NopCloser(bytes.NewReader(respBodyBytes)),
	}, nil
}

// createErrorResponse creates an HTTP error response
func (m *MITMProxy) createErrorResponse(err error) *http.Response {
	body := fmt.Sprintf("Proxy Error: %s", err.Error())
	return &http.Response{
		StatusCode:    http.StatusBadGateway,
		Status:        http.StatusText(http.StatusBadGateway),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

// createBlockedResponse creates a response for blocked requests
func (m *MITMProxy) createBlockedResponse(patterns []string) *http.Response {
	body := fmt.Sprintf("Request blocked: prohibited content detected (%s)", strings.Join(patterns, ", "))
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        http.StatusText(http.StatusForbidden),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

// logComplianceFindings logs compliance findings from ATLAS/NIST checks
func (m *MITMProxy) logComplianceFindings(direction, path string, findings []compliance.Finding) {
	if len(findings) == 0 {
		return
	}

	critical, high, medium, low := 0, 0, 0, 0
	var techniqueIDs []string
	seen := make(map[string]bool)

	for _, finding := range findings {
		switch finding.Severity {
		case compliance.SeverityCritical:
			critical++
		case compliance.SeverityHigh:
			high++
		case compliance.SeverityMedium:
			medium++
		case compliance.SeverityLow:
			low++
		}

		// Extract technique ID
		desc := finding.Description
		if idx := strings.Index(desc, " - "); idx > 0 {
			techID := desc[:idx]
			if !seen[techID] {
				seen[techID] = true
				techniqueIDs = append(techniqueIDs, techID)
			}
		}
	}

	slog.Info("MITM compliance scan results",
		"direction", direction,
		"path", path,
		"total_findings", len(findings),
		"critical", critical,
		"high", high,
		"medium", medium,
		"low", low,
		"techniques", strings.Join(techniqueIDs, ", "),
	)
}

// trackConnection tracks an active connection
func (m *MITMProxy) trackConnection(id string, conn net.Conn) {
	m.connMutex.Lock()
	m.connections[id] = conn
	m.connMutex.Unlock()
}

// untrackConnection removes a connection from tracking
func (m *MITMProxy) untrackConnection(id string) {
	m.connMutex.Lock()
	delete(m.connections, id)
	m.connMutex.Unlock()
}

// getViolationNames extracts pattern names from findings
func getViolationNames(findings []scanner.Finding) []string {
	names := make(map[string]bool)
	for _, finding := range findings {
		if finding.Pattern != nil {
			names[finding.Pattern.Name] = true
		}
	}

	var result []string
	for name := range names {
		result = append(result, name)
	}
	return result
}

// GetStats returns statistics about the MITM proxy
func (m *MITMProxy) GetStats() map[string]interface{} {
	m.connMutex.RLock()
	connCount := len(m.connections)
	m.connMutex.RUnlock()

	return map[string]interface{}{
		"enabled":             m.config.Enabled,
		"bind_address":        m.config.BindAddress,
		"connection_count":    m.connectionCount.Load(),
		"request_count":       m.requestCount.Load(),
		"blocked_count":       m.blockedCount.Load(),
		"bytes_uploaded":      m.bytesUploaded.Load(),
		"bytes_downloaded":    m.bytesDownloaded.Load(),
		"active_connections":  connCount,
		"max_connections":     m.config.MaxConnections,
		"timeout":             m.config.Timeout.String(),
		"tls_13_enabled":      m.config.EnableTLS13,
		"scanning_enabled":    m.config.EnableScanning,
		"attestation_enabled": m.attestation != nil && m.config.AttestationConfig != nil && m.config.AttestationConfig.Enabled,
	}
}

// GetCA returns the Certificate Authority
func (m *MITMProxy) GetCA() *tlspkg.CertificateAuthority {
	return m.ca
}

// GetHealth returns health status
func (m *MITMProxy) GetHealth() map[string]interface{} {
	return map[string]interface{}{
		"status":             "healthy",
		"enabled":            m.config.Enabled,
		"active_connections": m.connectionCount.Load(),
	}
}
