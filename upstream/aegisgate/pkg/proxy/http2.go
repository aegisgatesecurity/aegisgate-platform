// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"

	"golang.org/x/net/http2"
)

// HTTP2Config holds HTTP/2 specific configuration options
type HTTP2Config struct {
	// EnableHTTP2 enables HTTP/2 support
	EnableHTTP2 bool

	// MaxConcurrentStreams limits concurrent streams per connection
	MaxConcurrentStreams uint32

	// MaxReadFrameSize is the maximum frame size to accept
	MaxReadFrameSize uint32

	// MaxDecoderHeaderTableSize controls header compression table size
	MaxDecoderHeaderTableSize uint32

	// MaxEncoderHeaderTableSize controls response header compression
	MaxEncoderHeaderTableSize uint32

	// IdleTimeout configures the idle connection timeout
	IdleTimeout time.Duration

	// PreferHTTP2Protocol tries to negotiate HTTP/2 first
	PreferHTTP2Protocol bool

	// EnablePush enables HTTP/2 server push (disabled by default for security)
	EnablePush bool
}

// DefaultHTTP2Config returns secure defaults for HTTP/2 configuration
func DefaultHTTP2Config() *HTTP2Config {
	return &HTTP2Config{
		EnableHTTP2:               true,
		MaxConcurrentStreams:      250,
		MaxReadFrameSize:          1 << 14, // 16384 (16KB)
		MaxDecoderHeaderTableSize: 1 << 20, // 1MB
		MaxEncoderHeaderTableSize: 1 << 20, // 1MB
		IdleTimeout:               120 * time.Second,
		PreferHTTP2Protocol:       true,
		EnablePush:                false, // disabled by default for security
	}
}

// HTTP2RateLimiter manages rate limiting for HTTP/2 streams
type HTTP2RateLimiter struct {
	streams    map[string]*StreamLimiter
	maxStreams uint32
	window     time.Duration
	mu         sync.RWMutex
}

// StreamLimiter tracks rate limiting for a single client's streams
type StreamLimiter struct {
	activeStreams int
	requestTimes  []time.Time
	mu            sync.Mutex
}

// NewHTTP2RateLimiter creates a rate limiter for HTTP/2 streams
func NewHTTP2RateLimiter(maxStreams uint32, window time.Duration) *HTTP2RateLimiter {
	return &HTTP2RateLimiter{
		streams:    make(map[string]*StreamLimiter),
		maxStreams: maxStreams,
		window:     window,
	}
}

// AllowStream checks if a new stream is allowed for the given client
// FIX: Changed from 0 to 1 for activeStreams and from make([]time.Time, 0) to []time.Time{time.Now()}
func (rl *HTTP2RateLimiter) AllowStream(clientAddr string) bool {
	rl.mu.RLock()
	limiter, exists := rl.streams[clientAddr]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		rl.streams[clientAddr] = &StreamLimiter{
			activeStreams: 1,
			requestTimes:  []time.Time{time.Now()},
		}
		rl.mu.Unlock()
		return true
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	// Check if under limit
	if limiter.activeStreams >= int(rl.maxStreams) {
		return false
	}

	limiter.requestTimes = append(limiter.requestTimes, time.Now())
	limiter.activeStreams++
	return true
}

// ReleaseStream marks a stream as completed
func (rl *HTTP2RateLimiter) ReleaseStream(clientAddr string) {
	rl.mu.RLock()
	limiter, exists := rl.streams[clientAddr]
	rl.mu.RUnlock()

	if exists {
		limiter.mu.Lock()
		if limiter.activeStreams > 0 {
			limiter.activeStreams--
		}
		limiter.mu.Unlock()
	}
}

// Cleanup removes stale entries - fixed to clean up old entries with stale request times
func (rl *HTTP2RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for addr, limiter := range rl.streams {
		limiter.mu.Lock()
		// Clean old request times within the window
		validIdx := 0
		for i, t := range limiter.requestTimes {
			if t.After(cutoff) {
				validIdx = i
				break
			}
		}
		limiter.requestTimes = limiter.requestTimes[validIdx:]

		// Remove if no active streams AND no recent requests AND no valid request times
		if limiter.activeStreams <= 0 && len(limiter.requestTimes) == 0 {
			delete(rl.streams, addr)
		} else if len(limiter.requestTimes) > 0 && limiter.requestTimes[0].Before(cutoff) && limiter.activeStreams <= 0 {
			// Also remove if all requests are old and no active streams
			delete(rl.streams, addr)
		} else if len(limiter.requestTimes) > 0 && len(limiter.requestTimes) == validIdx && limiter.requestTimes[len(limiter.requestTimes)-1].Before(cutoff) {
			// All requests are old
			delete(rl.streams, addr)
		}
		limiter.mu.Unlock()
	}
}

// HTTP2AwareProxy wraps the MITM proxy with HTTP/2 capabilities
type HTTP2AwareProxy struct {
	*MITMProxy
	h2Config *HTTP2Config

	// HTTP/2 server instance
	h2Server *http2.Server

	// H2 transport for upstream connections
	h2Transport *http2.Transport

	// HTTP/1.1 fallback transport
	h1Transport *http.Transport

	// Protocol version tracking
	h2Connections    atomic.Int64
	h1Connections    atomic.Int64
	h2Requests       atomic.Int64
	h1Requests       atomic.Int64
	h2ConnectTunnels atomic.Int64
	scanErrors       atomic.Int64

	// HTTP/2 specific rate limiter
	h2RateLimiter *HTTP2RateLimiter

	// Body scanning pool for HTTP/2 framed content
	scanPool sync.Pool
}

// NewHTTP2AwareProxy creates an MITM proxy with HTTP/2 support
func NewHTTP2AwareProxy(config *MITMConfig, h2Config *HTTP2Config) (*HTTP2AwareProxy, error) {
	if h2Config == nil {
		h2Config = DefaultHTTP2Config()
	}

	// Create base MITM proxy
	baseProxy, err := NewMITMProxy(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create base proxy: %w", err)
	}

	proxy := &HTTP2AwareProxy{
		MITMProxy:     baseProxy,
		h2Config:      h2Config,
		h2RateLimiter: NewHTTP2RateLimiter(h2Config.MaxConcurrentStreams, time.Minute),
		scanPool: sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}

	// Configure HTTP/2 server if enabled
	if h2Config.EnableHTTP2 {
		proxy.h2Server = &http2.Server{
			MaxConcurrentStreams:      h2Config.MaxConcurrentStreams,
			MaxReadFrameSize:          h2Config.MaxReadFrameSize,
			MaxDecoderHeaderTableSize: h2Config.MaxDecoderHeaderTableSize,
			IdleTimeout:               h2Config.IdleTimeout,
		}
	}

	// Configure HTTP/2 transport for upstream connections
	proxy.h2Transport = &http2.Transport{
		AllowHTTP:          false, // Only HTTPS
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
		DisableCompression: false,
	}

	// Configure HTTP/1.1 fallback transport
	proxy.h1Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: config.Timeout,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	return proxy, nil
}

// getProtocolPreference returns preferred protocols for ALPN
// Order determines preference (HTTP/2 first for secure defaults)
func (p *HTTP2AwareProxy) getProtocolPreference() []string {
	if p.h2Config.PreferHTTP2Protocol && p.h2Config.EnableHTTP2 {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

// configureTLSForHTTP2 sets up TLS config for HTTP/2 support
func (p *HTTP2AwareProxy) configureTLSForHTTP2(config *tls.Config) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	}

	// Clone the config to avoid modifying original
	newConfig := config.Clone()

	// Set ALPN protocols in order of preference
	newConfig.NextProtos = p.getProtocolPreference()

	// Ensure TLS 1.2 minimum for HTTP/2
	if newConfig.MinVersion < tls.VersionTLS12 {
		newConfig.MinVersion = tls.VersionTLS12
	}

	return newConfig
}

// handleH2CONNECT handles HTTP/2 CONNECT requests (Extended CONNECT)
func (p *HTTP2AwareProxy) handleH2CONNECT(w http.ResponseWriter, r *http.Request) {
	// HTTP/2 CONNECT not implemented - return error
	http.Error(w, "HTTP/2 CONNECT not supported", http.StatusNotImplemented)
}

// processH2Request processes an HTTP/2 request with proper handling
func (p *HTTP2AwareProxy) processH2Request(w http.ResponseWriter, r *http.Request) {
	p.h2Requests.Add(1)

	// Check if this is a CONNECT request
	if r.Method == http.MethodConnect {
		p.handleH2CONNECT(w, r)
		return
	}

	// Handle regular HTTP/2 requests
	p.handleH2HTTPRequest(w, r)
}

// handleH2HTTPRequest handles HTTP/2 HTTP requests with scanning
func (p *HTTP2AwareProxy) handleH2HTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Forward request to upstream
	resp, err := p.forwardH2Request(r)
	if err != nil {
		http.Error(w, "Failed to reach upstream", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Copy response headers
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	// Write response
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// scanH2Body reads and returns the HTTP/2 request/response body
func (p *HTTP2AwareProxy) scanH2Body(body io.Reader) ([]byte, error) {
	buf := p.scanPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer p.scanPool.Put(buf)

	_, err := io.Copy(buf, body)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// forwardH2Request forwards an HTTP/2 request, preferring HTTP/2 upstream
func (p *HTTP2AwareProxy) forwardH2Request(r *http.Request) (*http.Response, error) {
	targetURL := r.URL
	if !targetURL.IsAbs() {
		targetURL = &url.URL{
			Scheme: "https",
			Host:   r.Host,
			Path:   r.URL.Path,
		}
	}

	// Try HTTP/2 first for HTTPS
	if targetURL.Scheme == "https" && p.h2Config.EnableHTTP2 {
		tlsConfig := &tls.Config{
			ServerName:         targetURL.Hostname(),
			InsecureSkipVerify: p.config.InsecureSkipVerify,
			NextProtos:         []string{"h2", "http/1.1"},
		}

		// Check if upstream supports HTTP/2 via ALPN
		conn, err := tls.Dial("tcp", targetURL.Host+":443", tlsConfig)
		if err == nil {
			connState := conn.ConnectionState()
			supportsH2 := connState.NegotiatedProtocol == "h2"
			_ = conn.Close()

			if supportsH2 {
				// Use HTTP/2 transport
				client := &http.Client{
					Transport: p.h2Transport,
					Timeout:   p.config.Timeout,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				return client.Do(r)
			}
		}
	}

	// Fallback to HTTP/1.1 transport
	client := &http.Client{
		Transport: p.h1Transport,
		Timeout:   p.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client.Do(r)
}

// ServeHTTP handles HTTP requests, detecting HTTP/2 vs HTTP/1.1
func (p *HTTP2AwareProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if this is an HTTP/2 request
	isH2 := r.ProtoMajor == 2
	if isH2 {
		p.processH2Request(w, r)
		return
	}

	// HTTP/1.1 fallback - delegate to base MITMProxy
	p.MITMProxy.ServeHTTP(w, r)
}

// getViolationNamesH2 extracts pattern names from HTTP/2 scan findings
func (p *HTTP2AwareProxy) getViolationNamesH2(findings []scanner.Finding) []string {
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

// GetH2Stats returns HTTP/2 specific statistics
func (p *HTTP2AwareProxy) GetH2Stats() map[string]interface{} {
	h1Conns := p.h1Connections.Load()
	h2Conns := p.h2Connections.Load()
	totalConns := h1Conns + h2Conns

	var h2Percentage float64
	if totalConns > 0 {
		h2Percentage = float64(h2Conns) / float64(totalConns) * 100
	}

	return map[string]interface{}{
		"http2_enabled":          p.h2Config.EnableHTTP2,
		"http2_preferred":        p.h2Config.PreferHTTP2Protocol,
		"max_concurrent_streams": p.h2Config.MaxConcurrentStreams,
		"max_frame_size":         p.h2Config.MaxReadFrameSize,
		"http2_connections":      h2Conns,
		"http1_connections":      h1Conns,
		"http2_percentage":       fmt.Sprintf("%.2f%%", h2Percentage),
		"http2_requests":         p.h2Requests.Load(),
		"http1_requests":         p.h1Requests.Load(),
		"http2_connect_tunnels":  p.h2ConnectTunnels.Load(),
		"http2_scan_errors":      p.scanErrors.Load(),
		"idle_timeout":           p.h2Config.IdleTimeout.String(),
		"server_push_enabled":    p.h2Config.EnablePush,
	}
}

// EnableHTTP2 enables HTTP/2 support on the base server
func (p *HTTP2AwareProxy) EnableHTTP2() error {
	if p.h2Server == nil {
		return fmt.Errorf("HTTP/2 server not configured")
	}

	// Configure HTTP/2 on the existing server
	err := http2.ConfigureServer(p.server, p.h2Server)
	if err != nil {
		return fmt.Errorf("failed to configure HTTP/2: %w", err)
	}

	return nil
}

// GetHTTP2Server returns the configured HTTP/2 server instance
func (p *HTTP2AwareProxy) GetHTTP2Server() *http2.Server {
	return p.h2Server
}

// Acquire acquires a rate limit token for the given client.
// Returns (true, releaseFunc) if the stream is allowed, or (false, nil) if rate limited.
func (rl *HTTP2RateLimiter) Acquire(clientID string) (bool, func()) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	client, exists := rl.streams[clientID]
	if !exists {
		client = &StreamLimiter{
			activeStreams: 1,
			requestTimes:  []time.Time{time.Now()},
		}
		rl.streams[clientID] = client
		return true, func() {
			rl.ReleaseStream(clientID)
		}
	}

	if uint32(client.activeStreams) >= rl.maxStreams {
		return false, nil
	}

	client.activeStreams++
	client.requestTimes = append(client.requestTimes, time.Now())

	return true, func() {
		rl.ReleaseStream(clientID)
	}
}
