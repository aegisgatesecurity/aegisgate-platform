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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"

	"github.com/aegisgatesecurity/aegisgate/pkg/resilience"
	"github.com/aegisgatesecurity/aegisgate/pkg/scanner"
)

// Options contains proxy configuration
type Options struct {
	BindAddress    string
	Upstream       string
	TLS            *TLSConfig
	MaxBodySize    int64         // Default: 10MB
	Timeout        time.Duration // Default: 30s
	RateLimit      int           // Requests per minute, default: 100
	HTTP2          *HTTP2Config  // HTTP/2 configuration
	HTTP3          *HTTP3Config  // HTTP/3 configuration
	CircuitBreaker *resilience.CircuitBreakerConfig

	// ML Configuration - Integrated in v0.41.0
	EnableMLDetection              bool
	MLSensitivity                  string
	MLBlockOnCriticalSeverity      bool
	MLBlockOnHighSeverity          bool
	MLMinScoreToBlock              float64
	MLSampleRate                   int
	MLExcludedPaths                []string
	MLExcludedMethods              []string
	EnablePromptInjectionDetection bool
	PromptInjectionSensitivity     int
	EnableContentAnalysis          bool
	EnableBehavioralAnalysis       bool

	// OnRateLimited is called when a request is rejected by rate limiting.
	// The callback receives the client remote address for metrics/accounting.
	// If nil, no callback is invoked (backward compatible).
	OnRateLimited func(client string)
}

// TLSConfig holds TLS settings
type TLSConfig struct {
	CertFile string
	KeyFile  string
	Config   *tls.Config
}

// Proxy represents the reverse proxy
type Proxy struct {
	options  Options
	server   *http.Server
	upstream *url.URL
	reverse  *httputil.ReverseProxy
	mu       sync.RWMutex

	// Security features
	rateLimiter  *RateLimiter
	requestCount atomic.Int64

	// Content scanner
	scanner *scanner.Scanner

	// Compliance manager
	complianceManager *compliance.ComplianceManager

	// Circuit breaker
	circuitBreaker *resilience.CircuitBreaker

	// ML Anomaly Detection - v0.41.0
	mlMiddleware *MLMiddleware
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	tokens   chan struct{}
	interval time.Duration
	stopChan chan struct{}
}

// New creates a new hardened proxy
func New(opts *Options) *Proxy {
	if opts == nil {
		opts = &Options{}
	}

	// Apply secure defaults
	if opts.MaxBodySize <= 0 {
		opts.MaxBodySize = 10 * 1024 * 1024
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.RateLimit <= 0 {
		opts.RateLimit = 100
	}

	// Parse upstream URL
	upstream, err := url.Parse(opts.Upstream)
	if err != nil {
		slog.Error("Invalid upstream URL", "error", err)
		upstream, _ = url.Parse("http://127.0.0.1:3000")
	}

	// Initialize compliance manager
	cfg := compliance.DefaultConfig()
	cfg.EnableAtlas = true
	cfg.ContextLines = 2
	compManager, _ := compliance.NewManager(cfg)

	p := &Proxy{
		options:           *opts,
		upstream:          upstream,
		scanner:           scanner.New(nil),
		complianceManager: compManager,
	}

	// Initialize ML Middleware if enabled
	if opts.EnableMLDetection {
		mlConfig := &MLMiddlewareConfig{
			Enabled:                 opts.EnableMLDetection,
			Sensitivity:             opts.MLSensitivity,
			BlockOnCriticalSeverity: opts.MLBlockOnCriticalSeverity,
			BlockOnHighSeverity:     opts.MLBlockOnHighSeverity,
			MinScoreToBlock:         opts.MLMinScoreToBlock,
			SampleRate:              opts.MLSampleRate,
			ExcludedPaths:           opts.MLExcludedPaths,
			ExcludedMethods:         opts.MLExcludedMethods,
			LogAllAnomalies:         true,
		}

		mlMiddleware, err := NewMLMiddleware(mlConfig)
		if err != nil {
			slog.Error("Failed to create ML middleware", "error", err)
		} else {
			p.mlMiddleware = mlMiddleware
			slog.Info("ML anomaly detection enabled",
				"sensitivity", opts.MLSensitivity,
				"sample_rate", opts.MLSampleRate,
			)
		}
	}

	// Initialize circuit breaker if configured
	if opts.CircuitBreaker != nil {
		p.circuitBreaker = resilience.NewCircuitBreaker(*opts.CircuitBreaker)
		slog.Info("Circuit breaker enabled",
			"failure_threshold", opts.CircuitBreaker.FailureThreshold,
			"timeout", opts.CircuitBreaker.Timeout)
	}

	// Initialize rate limiter
	p.rateLimiter = NewRateLimiter(opts.RateLimit)

	// Create reverse proxy
	p.reverse = httputil.NewSingleHostReverseProxy(upstream)

	// Customize the reverse proxy director for security
	originalDirector := p.reverse.Director
	p.reverse.Director = func(req *http.Request) {
		originalDirector(req)

		// Add security headers to outbound request
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Frame-Options", "DENY")
		req.Header.Set("X-Content-Type-Options", "nosniff")
		req.Header.Set("X-XSS-Protection", "1; mode=block")
		req.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		req.Header.Set("Content-Security-Policy", "default-src 'self'")
	}

	// Add error handler
	p.reverse.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
		slog.Error("Proxy error", "error", err, "path", req.URL.Path)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Proxy Error: Unable to reach upstream server"))
	}

	// Wrap the response writer for response body scanning
	p.reverse.ModifyResponse = p.modifyResponse

	return p
}

// NewRateLimiter creates a token bucket rate limiter
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	interval := time.Minute / time.Duration(ratePerMinute)
	rl := &RateLimiter{
		tokens:   make(chan struct{}, ratePerMinute),
		interval: interval,
		stopChan: make(chan struct{}),
	}

	// Fill bucket initially
	for i := 0; i < ratePerMinute; i++ {
		rl.tokens <- struct{}{}
	}

	// Refill tokens at interval
	go rl.refill()

	return rl
}

func (rl *RateLimiter) refill() {
	ticker := time.NewTicker(rl.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		case <-rl.stopChan:
			return
		}
	}
}

// Allow checks if request is allowed under rate limit
func (rl *RateLimiter) Allow() bool {
	select {
	case <-rl.tokens:
		return true
	default:
		return false
	}
}

// Stop stops the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
}

// ServeHTTP handles incoming requests with security features and content inspection
func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Increment request counter
	p.requestCount.Add(1)

	// Check rate limit
	if !p.rateLimiter.Allow() {
		slog.Warn("Rate limit exceeded", "client", req.RemoteAddr, "path", req.URL.Path)
		if p.options.OnRateLimited != nil {
			p.options.OnRateLimited(req.RemoteAddr)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte("Rate limit exceeded. Please try again later."))
		return
	}

	// ML Anomaly Detection - v0.41.0
	if p.mlMiddleware != nil {
		result := p.mlMiddleware.analyzeRequest(req)

		if result.ShouldBlock {
			slog.Warn("ML blocked request",
				"client", req.RemoteAddr,
				"path", req.URL.Path,
				"reason", result.BlockingReason,
				"anomalies", len(result.Anomalies),
			)
			p.mlMiddleware.blockRequest(w, req, result)
			return
		}
	}

	// Scan request body if present
	var requestFindings []scanner.Finding
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			slog.Error("Failed to read request body", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Failed to process request"))
			return
		}

		// Restore the body
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Scan the request body
		requestFindings = p.scanner.ScanBytes(bodyBytes)

		// Log all findings
		p.logFindings("request", req.URL.Path, requestFindings)

		// Check for MITRE ATLAS threats
		if p.complianceManager != nil {
			atlasFindings := p.checkAtlasCompliance(string(bodyBytes))
			if len(atlasFindings) > 0 {
				p.logAtlasFindings("request", req.URL.Path, atlasFindings)
				if p.shouldBlockAtlas(atlasFindings) {
					techniqueIDs := p.getAtlasTechniqueIDs(atlasFindings)
					slog.Error("Request blocked: MITRE ATLAS threat detected",
						"client", req.RemoteAddr,
						"path", req.URL.Path,
						"techniques", strings.Join(techniqueIDs, ", "),
					)
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte(fmt.Sprintf("Request blocked: MITRE ATLAS violation detected (%s)", strings.Join(techniqueIDs, ", "))))
					return
				}
			}
		}

		// Check if request should be blocked
		if p.scanner.ShouldBlock(requestFindings) {
			violationNames := p.scanner.GetViolationNames(requestFindings)
			slog.Error("Request blocked: Critical data found in request body",
				"client", req.RemoteAddr,
				"path", req.URL.Path,
				"patterns", strings.Join(violationNames, ", "),
			)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(fmt.Sprintf("Content blocked: %s", strings.Join(violationNames, ", "))))
			return
		}

		// ML Pattern Analysis - Prompt Injection Detection
		if p.mlMiddleware != nil && p.options.EnablePromptInjectionDetection {
			content := string(bodyBytes)
			anomalies := p.mlMiddleware.config.Detector.AnalyzePatterns(content)
			for _, anomaly := range anomalies {
				slog.Warn("ML Pattern anomaly detected",
					"client", req.RemoteAddr,
					"path", req.URL.Path,
					"type", anomaly.Type,
					"score", anomaly.Score,
				)
			}
		}
	}

	// Check body size limit
	if req.ContentLength > p.options.MaxBodySize {
		slog.Warn("Request body too large", "size", req.ContentLength, "max", p.options.MaxBodySize)
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		w.Write([]byte(fmt.Sprintf("Request body exceeds maximum size of %d bytes", p.options.MaxBodySize)))
		return
	}

	// Limit request body reading
	if req.Body != nil {
		req.Body = http.MaxBytesReader(w, req.Body, p.options.MaxBodySize)
	}

	// Add security response headers
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Log request
	slog.Info("Proxy request",
		"method", req.Method,
		"path", req.URL.Path,
		"client", req.RemoteAddr,
	)

	// Forward to upstream with circuit breaker protection
	if p.circuitBreaker != nil {
		err := p.circuitBreaker.Execute(req.Context(), func(ctx context.Context) error {
			p.reverse.ServeHTTP(w, req)
			return nil
		})
		if err != nil {
			slog.Warn("Circuit breaker rejected request", "error", err)
			return
		}
	} else {
		p.reverse.ServeHTTP(w, req)
	}
}

// checkAtlasCompliance runs MITRE ATLAS compliance checks on content
func (p *Proxy) checkAtlasCompliance(content string) []compliance.Finding {
	if p.complianceManager == nil {
		return nil
	}

	atlas := compliance.NewAtlas()
	findings, _ := atlas.Check(content)
	return findings
}

// shouldBlockAtlas returns true if ATLAS findings should block the request
func (p *Proxy) shouldBlockAtlas(findings []compliance.Finding) bool {
	for _, finding := range findings {
		if finding.Severity == compliance.SeverityCritical || finding.Severity == compliance.SeverityHigh {
			return true
		}
	}
	return false
}

// getAtlasTechniqueIDs extracts technique IDs from ATLAS findings
func (p *Proxy) getAtlasTechniqueIDs(findings []compliance.Finding) []string {
	seen := make(map[string]bool)
	var techniques []string

	for _, finding := range findings {
		desc := finding.Description
		if idx := strings.Index(desc, " - "); idx > 0 {
			techID := desc[:idx]
			if !seen[techID] {
				seen[techID] = true
				techniques = append(techniques, techID)
			}
		}
	}

	return techniques
}

// modifyResponse scans response body for sensitive data
func (p *Proxy) modifyResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read response body", "error", err)
		return err
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	// Scan the response body
	findings := p.scanner.ScanBytes(bodyBytes)
	p.logFindings("response", resp.Request.URL.Path, findings)

	// Check for MITRE ATLAS threats
	if p.complianceManager != nil {
		atlas := compliance.NewAtlas()
		atlasFindings, _ := atlas.Check(string(bodyBytes))
		if len(atlasFindings) > 0 {
			p.logAtlasFindings("response", resp.Request.URL.Path, atlasFindings)
		}
	}

	// ML Content Analysis for LLM Responses
	if p.mlMiddleware != nil && p.options.EnableContentAnalysis {
		content := string(bodyBytes)
		entropy, anomaly := p.mlMiddleware.config.Detector.AnalyzeContent([]byte(content))
		if anomaly != nil {
			slog.Warn("ML Content anomaly in response",
				"path", resp.Request.URL.Path,
				"entropy", entropy,
				"type", anomaly.Type,
				"score", anomaly.Score,
			)
		}
	}

	// Log critical findings
	if p.scanner.ShouldBlock(findings) {
		violationNames := p.scanner.GetViolationNames(findings)
		slog.Error("Critical data found in response",
			"path", resp.Request.URL.Path,
			"status", resp.StatusCode,
			"patterns", strings.Join(violationNames, ", "),
		)
	}

	return nil
}

// logFindings logs all findings from a scan
func (p *Proxy) logFindings(direction, path string, findings []scanner.Finding) {
	if len(findings) == 0 {
		return
	}

	summary := p.scanner.GetViolationSummary(findings)

	slog.Info("Content scan results",
		"direction", direction,
		"path", path,
		"total_findings", len(findings),
		"critical", summary[scanner.Critical],
		"high", summary[scanner.High],
		"medium", summary[scanner.Medium],
		"low", summary[scanner.Low],
		"info", summary[scanner.Info],
	)
}

// logAtlasFindings logs MITRE ATLAS findings
func (p *Proxy) logAtlasFindings(direction, path string, findings []compliance.Finding) {
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

		desc := finding.Description
		if idx := strings.Index(desc, " - "); idx > 0 {
			techID := desc[:idx]
			if !seen[techID] {
				seen[techID] = true
				techniqueIDs = append(techniqueIDs, techID)
			}
		}
	}

	slog.Info("MITRE ATLAS scan results",
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

// GetScanner returns the scanner instance
func (p *Proxy) GetScanner() *scanner.Scanner {
	return p.scanner
}

// SetScanner sets the scanner instance
func (p *Proxy) SetScanner(s *scanner.Scanner) {
	if s != nil {
		p.scanner = s
	}
}

// GetComplianceManager returns the compliance manager
func (p *Proxy) GetComplianceManager() *compliance.ComplianceManager {
	return p.complianceManager
}

// GetCircuitBreaker returns the circuit breaker
func (p *Proxy) GetCircuitBreaker() *resilience.CircuitBreaker {
	return p.circuitBreaker
}

// GetMLMiddleware returns the ML middleware
func (p *Proxy) GetMLMiddleware() *MLMiddleware {
	return p.mlMiddleware
}

// Start starts the hardened proxy server
func (p *Proxy) Start() error {
	p.server = &http.Server{
		Addr:           p.options.BindAddress,
		Handler:        p,
		ReadTimeout:    p.options.Timeout,
		WriteTimeout:   p.options.Timeout,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if p.options.TLS != nil && p.options.TLS.Config != nil {
		p.server.TLSConfig = p.options.TLS.Config
	}

	slog.Info("Starting hardened proxy server",
		"address", p.options.BindAddress,
		"upstream", p.options.Upstream,
		"max_body_size", p.options.MaxBodySize,
		"timeout", p.options.Timeout,
		"rate_limit", p.options.RateLimit,
		"ml_enabled", p.mlMiddleware != nil,
	)

	if p.options.TLS != nil && p.options.TLS.CertFile != "" && p.options.TLS.KeyFile != "" {
		return p.server.ListenAndServeTLS(p.options.TLS.CertFile, p.options.TLS.KeyFile)
	}
	return p.server.ListenAndServe()
}

// Stop gracefully stops the proxy server
func (p *Proxy) Stop(ctx context.Context) error {
	if p.rateLimiter != nil {
		p.rateLimiter.Stop()
	}

	if p.server != nil {
		slog.Info("Shutting down proxy server...")
		return p.server.Shutdown(ctx)
	}
	return nil
}

// GetHealth returns health status
func (p *Proxy) GetHealth() map[string]interface{} {
	health := map[string]interface{}{
		"status":        "healthy",
		"enabled":       p.IsEnabled(),
		"bind_address":  p.options.BindAddress,
		"upstream":      p.options.Upstream,
		"request_count": p.requestCount.Load(),
		"max_body_size": p.options.MaxBodySize,
		"timeout":       p.options.Timeout.String(),
		"rate_limit":    p.options.RateLimit,
		"ml_enabled":    p.mlMiddleware != nil,
	}

	if p.circuitBreaker != nil {
		health["circuit_breaker"] = map[string]interface{}{
			"enabled":           true,
			"state":             p.circuitBreaker.GetState(),
			"total_requests":    p.circuitBreaker.TotalRequests(),
			"failed_requests":   p.circuitBreaker.FailedRequests(),
			"rejected_requests": p.circuitBreaker.RejectedRequests(),
		}
	}

	// Add ML stats if enabled
	if p.mlMiddleware != nil {
		mlStats := p.mlMiddleware.GetStats()
		health["ml_stats"] = map[string]interface{}{
			"total_requests":    mlStats.TotalRequests,
			"analyzed_requests": mlStats.AnalyzedRequests,
			"blocked_requests":  mlStats.BlockedRequests,
		}
	}

	return health
}

// IsEnabled returns whether proxy is enabled
func (p *Proxy) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.server != nil
}

// GetStats returns proxy statistics
func (p *Proxy) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":       p.IsEnabled(),
		"bind":          p.options.BindAddress,
		"upstream":      p.options.Upstream,
		"request_count": p.requestCount.Load(),
		"options": map[string]interface{}{
			"max_body_size": p.options.MaxBodySize,
			"timeout":       p.options.Timeout.String(),
			"rate_limit":    p.options.RateLimit,
			"ml_enabled":    p.mlMiddleware != nil,
		},
	}

	if p.mlMiddleware != nil {
		mlStats := p.mlMiddleware.GetStats()
		stats["ml"] = map[string]interface{}{
			"total_requests":    mlStats.TotalRequests,
			"analyzed_requests": mlStats.AnalyzedRequests,
			"blocked_requests":  mlStats.BlockedRequests,
			"anomaly_counts":    mlStats.AnomalyCounts,
		}
	}

	return stats
}

// StatsStruct represents proxy statistics in a structured format
type StatsStruct struct {
	RequestsTotal     int64
	RequestsBlocked   int64
	RequestsAllowed   int64
	BytesIn           int64
	BytesOut          int64
	ActiveConnections int64
	AvgLatencyMs      float64
	P99LatencyMs      float64
	Errors            int64
}

// GetStatsStruct returns proxy statistics as a struct
func (p *Proxy) GetStatsStruct() *StatsStruct {
	stats := &StatsStruct{
		RequestsTotal:     p.requestCount.Load(),
		RequestsBlocked:   0,
		RequestsAllowed:   0,
		BytesIn:           0,
		BytesOut:          0,
		ActiveConnections: 0,
		AvgLatencyMs:      0,
		P99LatencyMs:      0,
		Errors:            0,
	}

	if p.mlMiddleware != nil {
		mlStats := p.mlMiddleware.GetStats()
		stats.RequestsBlocked = mlStats.BlockedRequests
	}

	return stats
}

// Request represents an incoming request
type Request struct {
	Method    string
	URL       string
	Headers   http.Header
	Body      []byte
	SourceIP  string
	Timestamp time.Time
}

// Response represents an outgoing response
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Timestamp  time.Time
	Duration   time.Duration
}

// Violation represents a security violation
type Violation struct {
	Type     string
	Message  string
	Severity string
}

// Inspector interface for request/response inspection
type Inspector interface {
	InspectRequest(req *Request) ([]Violation, error)
	InspectResponse(resp *Response) ([]Violation, error)
}

// Metrics interface for metrics collection
type Metrics interface {
	RecordRequest(duration time.Duration, statusCode int)
	RecordViolation(violation Violation)
}
