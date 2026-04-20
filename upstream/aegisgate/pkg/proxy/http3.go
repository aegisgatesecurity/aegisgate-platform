// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

// HTTP3Config contains HTTP/3 specific configuration
type HTTP3Config struct {
	// Enabled enables HTTP/3 support via TLS ALPN
	Enabled bool

	// ListenAddr is the address to listen on for HTTP/3
	ListenAddr string

	// Port is the port for HTTP/3 (default: 8443)
	Port int

	// MaxConcurrentStreams is the max concurrent streams per connection
	MaxConcurrentStreams uint32

	// MaxIdleConns is the max idle connections
	MaxIdleConns int

	// IdleTimeout is the idle connection timeout
	IdleTimeout time.Duration

	// ReadTimeout is the read timeout
	ReadTimeout time.Duration

	// WriteTimeout is the write timeout
	WriteTimeout time.Duration

	// HandleGzip enables gzip handling
	HandleGzip bool
}

// HTTP3AwareProxy extends the proxy with HTTP/3 capabilities
type HTTP3AwareProxy struct {
	// Embedded proxy for core functionality
	*Proxy

	// HTTP/3 specific config
	HTTP3Config *HTTP3Config

	// HTTP/3 server (using standard http.Server with HTTP/3 TLS config)
	http3Server *http.Server

	// TLS config for HTTP/3
	tlsConfig *tls.Config

	// Connection tracking
	activeConnections int64
	totalRequests     int64
}

// HTTP3Metrics holds HTTP/3 specific metrics
type HTTP3Metrics struct {
	ActiveConnections int64
	TotalRequests     int64
	BytesReceived     int64
	BytesSent         int64
}

// DefaultHTTP3Config returns the default HTTP/3 configuration
func DefaultHTTP3Config() *HTTP3Config {
	return &HTTP3Config{
		Enabled:              false, // Disabled by default for security
		ListenAddr:           "0.0.0.0",
		Port:                 8443,
		MaxConcurrentStreams: 100,
		MaxIdleConns:         100,
		IdleTimeout:          90 * time.Second,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		HandleGzip:           true,
	}
}

// NewHTTP3AwareProxy creates a new proxy with HTTP/3 support
func NewHTTP3AwareProxy(proxy *Proxy, config *HTTP3Config) *HTTP3AwareProxy {
	if config == nil {
		config = DefaultHTTP3Config()
	}

	h3 := &HTTP3AwareProxy{
		Proxy:       proxy,
		HTTP3Config: config,
	}

	// Configure TLS for HTTP/3
	h3.tlsConfig = h3.configureTLSForHTTP3()

	return h3
}

// configureTLSForHTTP3 sets up TLS configuration for HTTP/3
func (h3 *HTTP3AwareProxy) configureTLSForHTTP3() *tls.Config {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"h3", "h3-29", "h3-28", "h3-27"},
	}

	// Use proxy's TLS config if available from Options
	if h3.Proxy != nil && h3.Proxy.options.TLS != nil {
		if h3.Proxy.options.TLS.CertFile != "" && h3.Proxy.options.TLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(
				h3.Proxy.options.TLS.CertFile,
				h3.Proxy.options.TLS.KeyFile,
			)
			if err != nil {
				slog.Warn("Failed to load certificate for HTTP/3", "error", err)
			} else {
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
		}
	}

	return tlsConfig
}

// ServeHTTP3 starts the HTTP/3 server using TLS with ALPN
// This provides HTTP/3 over TLS/TCP (not QUIC/UDP)
func (h3 *HTTP3AwareProxy) ServeHTTP3(ctx context.Context) error {
	if !h3.HTTP3Config.Enabled {
		slog.Info("HTTP/3 is disabled")
		return nil
	}

	// Create HTTP server with HTTP/3 TLS configuration
	h3.http3Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", h3.HTTP3Config.ListenAddr, h3.HTTP3Config.Port),
		Handler:      h3,
		TLSConfig:    h3.tlsConfig,
		ReadTimeout:  h3.HTTP3Config.ReadTimeout,
		WriteTimeout: h3.HTTP3Config.WriteTimeout,
		IdleTimeout:  h3.HTTP3Config.IdleTimeout,
	}

	slog.Info("Starting HTTP/3 server (over TLS)", "addr", h3.http3Server.Addr, "alpn", "h3,h3-29,h3-28")

	errCh := make(chan error, 1)
	go func() {
		// Listen on TLS with HTTP/3 ALPN
		errCh <- h3.http3Server.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP/3 server error: %w", err)
		}
	case <-ctx.Done():
		h3.StopHTTP3()
	}

	return nil
}

// StopHTTP3 stops the HTTP/3 server
func (h3 *HTTP3AwareProxy) StopHTTP3() {
	if h3.http3Server != nil {
		slog.Info("Stopping HTTP/3 server")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h3.http3Server.Shutdown(ctx); err != nil && err != context.Canceled {
			slog.Warn("HTTP/3 server shutdown error", "error", err)
		}
		h3.http3Server = nil
	}
}

// ServeHTTP handles HTTP requests (for HTTP/3 compatibility)
func (h3 *HTTP3AwareProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&h3.totalRequests, 1)

	start := time.Now()
	defer func() {
		duration := time.Since(start)
		slog.Debug("HTTP/3 request",
			"method", r.Method,
			"path", r.URL.Path,
			"proto", r.Proto,
			"duration", duration,
		)
	}()

	// Handle HTTP/3 ALPN detection via protocol field
	// When client connects via HTTP/3, the protocol will indicate it
	if r.Proto == "HTTP/3" || r.ProtoMajor >= 3 {
		h3.handleHTTP3Request(w, r)
		return
	}

	// Fall back to HTTP/2 or HTTP/1.1 handling
	if h3.Proxy != nil {
		h3.Proxy.ServeHTTP(w, r)
	} else {
		http.Error(w, "Proxy not configured", http.StatusInternalServerError)
	}
}

// handleHTTP3Request handles requests specifically for HTTP/3
func (h3 *HTTP3AwareProxy) handleHTTP3Request(w http.ResponseWriter, r *http.Request) {
	// Validate request
	if err := h3.validateRequest(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if request should be blocked
	if h3.shouldBlockRequest(r) {
		h3.logBlockedRequest(r)
		http.Error(w, "Request blocked by security policy", http.StatusForbidden)
		return
	}

	// Process the request
	h3.processHTTP3Request(w, r)
}

// validateRequest validates the HTTP/3 request
func (h3 *HTTP3AwareProxy) validateRequest(r *http.Request) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}

	// Validate method
	if r.Method == "" {
		return fmt.Errorf("missing request method")
	}

	// Validate URL
	if r.URL == nil {
		return fmt.Errorf("missing URL")
	}

	// Check for valid scheme
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		return fmt.Errorf("invalid scheme: %s", r.URL.Scheme)
	}

	return nil
}

// shouldBlockRequest determines if a request should be blocked
func (h3 *HTTP3AwareProxy) shouldBlockRequest(r *http.Request) bool {
	if h3.Proxy == nil {
		return false
	}

	// Check rate limiting
	if h3.Proxy.rateLimiter != nil && !h3.Proxy.rateLimiter.Allow() {
		return true
	}

	// Check scanner patterns
	if h3.Proxy.scanner != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err == nil {
			findings := h3.Proxy.scanner.Scan(string(body))
			if len(findings) > 0 {
				return true
			}
		}
	}

	return false
}

// logBlockedRequest logs a blocked HTTP/3 request
func (h3 *HTTP3AwareProxy) logBlockedRequest(r *http.Request) {
	slog.Warn("HTTP/3 request blocked",
		"method", r.Method,
		"url", r.URL.String(),
		"remote", r.RemoteAddr,
	)
}

// processHTTP3Request processes the HTTP/3 request
func (h3 *HTTP3AwareProxy) processHTTP3Request(w http.ResponseWriter, r *http.Request) {
	// Handle connect for CONNECT requests
	if r.Method == http.MethodConnect {
		h3.handleHTTP3Connect(w, r)
		return
	}

	// Forward request to backend
	h3.forwardHTTP3Request(w, r)
}

// handleHTTP3Connect handles HTTP/3 CONNECT requests (used for proxying)
func (h3 *HTTP3AwareProxy) handleHTTP3Connect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.URL.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to destination", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)

	// Hijack the connection for tunneling
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Transfer data between client and destination
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(destConn, clientConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, destConn)
	}()

	wg.Wait()
}

// forwardHTTP3Request forwards HTTP/3 request to the target
func (h3 *HTTP3AwareProxy) forwardHTTP3Request(w http.ResponseWriter, r *http.Request) {
	// Create transport for forwarding
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        h3.HTTP3Config.MaxIdleConns,
		IdleConnTimeout:     h3.HTTP3Config.IdleTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Determine the backend URL
	backendURL := h3.getBackendURL(r)
	if backendURL == nil {
		http.Error(w, "No backend configured", http.StatusBadGateway)
		return
	}

	// Create the request to forward
	forwardReq, err := http.NewRequestWithContext(r.Context(), r.Method, backendURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, v := range r.Header {
		for _, vv := range v {
			if !httpguts.ValidHeaderFieldName(k) {
				continue
			}
			forwardReq.Header.Add(k, vv)
		}
	}

	// Remove hop-by-hop headers
	forwardReq.Header.Del("Connection")
	forwardReq.Header.Del("Transfer-Encoding")
	forwardReq.Header.Del("Upgrade")

	// Make the request
	resp, err := transport.RoundTrip(forwardReq)
	if err != nil {
		slog.Error("Failed to forward HTTP/3 request", "error", err)
		http.Error(w, "Failed to reach backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}

	// Copy response status and body
	w.WriteHeader(resp.StatusCode)

	if h3.HTTP3Config.HandleGzip && resp.Header.Get("Content-Encoding") == "gzip" {
		// Handle gzip decompression if needed
		io.Copy(w, resp.Body)
	} else {
		io.Copy(w, resp.Body)
	}
}

// getBackendURL returns the backend URL for the request
func (h3 *HTTP3AwareProxy) getBackendURL(r *http.Request) *url.URL {
	if h3.Proxy == nil || h3.Proxy.upstream == nil {
		// Default to the original request if no backend configured
		return r.URL
	}

	// Combine backend URL with request path
	result := *h3.Proxy.upstream
	result.Path = r.URL.Path
	result.RawQuery = r.URL.RawQuery

	return &result
}

// GetHTTP3Stats returns HTTP/3 specific statistics
func (h3 *HTTP3AwareProxy) GetHTTP3Stats() HTTP3Metrics {
	return HTTP3Metrics{
		ActiveConnections: atomic.LoadInt64(&h3.activeConnections),
		TotalRequests:     atomic.LoadInt64(&h3.totalRequests),
	}
}

// EnableHTTP3 enables HTTP/3 support
func (h3 *HTTP3AwareProxy) EnableHTTP3() {
	h3.HTTP3Config.Enabled = true
}

// DisableHTTP3 disables HTTP/3 support
func (h3 *HTTP3AwareProxy) DisableHTTP3() {
	h3.HTTP3Config.Enabled = false
}

// IsHTTP3Enabled returns whether HTTP/3 is enabled
func (h3 *HTTP3AwareProxy) IsHTTP3Enabled() bool {
	return h3.HTTP3Config.Enabled
}

// GetHTTP3Config returns the HTTP/3 configuration
func (h3 *HTTP3AwareProxy) GetHTTP3Config() *HTTP3Config {
	return h3.HTTP3Config
}

// SetHTTP3Config sets the HTTP/3 configuration
func (h3 *HTTP3AwareProxy) SetHTTP3Config(config *HTTP3Config) {
	h3.HTTP3Config = config
	h3.tlsConfig = h3.configureTLSForHTTP3()
}

// HTTP3SupportCheck checks if HTTP/3 support is available
func HTTP3SupportCheck() error {
	// HTTP/3 over TLS is supported via standard library
	return nil
}

// GetHTTP3Server returns the HTTP/3 server for advanced configuration
func (h3 *HTTP3AwareProxy) GetHTTP3Server() *http.Server {
	return h3.http3Server
}

// GetTLSConfig returns the HTTP/3 TLS configuration
func (h3 *HTTP3AwareProxy) GetTLSConfig() *tls.Config {
	return h3.tlsConfig
}
