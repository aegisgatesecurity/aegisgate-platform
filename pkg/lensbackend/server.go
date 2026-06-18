// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - HTTP Server
// =========================================================================
//
// server.go is the top-level orchestrator. It owns:
//
//   - the HTTP server (net/http)
//   - the IOC store (*ioc.Store)
//   - the in-memory IOC writer/aggregator (iocWriter)
//   - the audit logger (auditLogger)
//   - the rate limiter (LensRateLimiter)
//   - the retention state (retentionState)
//
// and wires them together with the HTTP handlers. The server
// is created by NewServer(cfg) and started by ListenAndServe.
// Shutdown is graceful (context cancellation propagates through
// the listener and all in-flight requests).
//
// The server is intentionally a small struct: no router library,
// no middleware library, no config library. The stdlib net/http
// and the Platform's existing pkg/resilience/ratelimit are
// the only "framework" we use.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package lensbackend

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// Server is the Lens backend's HTTP server.
type Server struct {
	cfg     *Config
	logger  *slog.Logger
	version string

	// Dependencies, populated by NewServer.
	store  *ioc.Store
	ioc    *iocWriter
	audit  *auditLogger
	rate   *LensRateLimiter
	retent *retentionState
	ring   *logging.RingBuffer
	hmgr   *httpAuthMiddleware

	// httpServer is the net/http.Server. It is constructed
	// in NewServer and started in ListenAndServe.
	httpServer *http.Server

	// rawEventMu guards the raw-event append file. Each
	// successful /telemetry call appends one line to
	// <storePath>/events.jsonl; the retention jobs purge
	// from that file.
	rawEventMu sync.Mutex
}

// NewServer creates a Server with the given config and version
// string. The version is reported by /healthz and is the Lens
// backend's semantic version (e.g., "0.1.0").
func NewServer(cfg *Config, version string) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must be non-nil")
	}
	if version == "" {
		version = "dev"
	}

	logger := slog.New(slog.NewTextHandler(slogOutput(cfg.LogPath), &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Ensure the IOC store directory exists.
	if err := os.MkdirAll(cfg.IOCStorePath, 0o755); err != nil { // #nosec G301 -- IOC store directory is a service data dir, world-readable is correct for the Lens backend
		return nil, fmt.Errorf("create ioc store dir: %w", err)
	}

	// Open the IOC store.
	store, err := ioc.NewStore(ioc.StoreConfig{
		Capacity:      100_000,
		FlushInterval: 5 * time.Minute,
		DiskPath:      filepath.Join(cfg.IOCStorePath, "ioc.json"),
	})
	if err != nil {
		return nil, fmt.Errorf("open ioc store: %w", err)
	}

	// Open the in-memory ring buffer for the audit log.
	ring := logging.NewRingBuffer(10_000)

	audit := newAuditLogger(ring, logger)

	// Load the HMAC key for rate limiting, if configured.
	var hmacKey []byte
	if cfg.HMACKeyPath != "" {
		hk, err := os.ReadFile(cfg.HMACKeyPath) // #nosec G304 G703 -- HMAC key path is from the LENS_HMAC_KEY env var, which the operator configures; not user-reachable
		if err != nil {
			return nil, fmt.Errorf("read hmac key: %w", err)
		}
		if len(hk) < 32 {
			return nil, fmt.Errorf("hmac key must be at least 32 bytes, got %d", len(hk))
		}
		hmacKey = hk
	}

	rate := NewLensRateLimiter(hmacKey, cfg.RateLimitPerMin)
	iocW := newIOCWriter(store, 100)
	retent := newRetentionState(cfg.IOCStorePath, cfg.EventRetention, DefaultSendAnywayRetention, audit, logger)

	s := &Server{
		cfg:     cfg,
		logger:  logger,
		version: version,
		store:   store,
		ioc:     iocW,
		audit:   audit,
		rate:    rate,
		retent:  retent,
		ring:    ring,
		hmgr:    newHTTPAuthMiddleware(cfg.BearerToken),
	}

	// Wire the HTTP server.
	mux := s.Mux()
	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// TLS config is set in ListenAndServe if both
		// TLSCert and TLSKey are configured.
	}

	return s, nil
}

// Mux returns the *http.ServeMux with the 4 endpoints registered.
// Extracted for testing; tests can call Mux() and pass the result
// to httptest.NewServer.
func (s *Server) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h := NewHandlers(s)

	// /healthz is the only unauthenticated endpoint. It's
	// used by load balancers and the testlab's docker-compose
	// healthcheck.
	mux.HandleFunc("/api/v1/lens/healthz", h.HandleHealthz)

	// The other three endpoints are auth + rate-limit gated.
	// We chain: rate limit -> auth -> handler. The order
	// matters: rate limit first to shed load cheaply, then
	// auth, then the handler.
	auth := s.hmgr.Middleware
	gated := func(path string, handler http.HandlerFunc) {
		mux.Handle(path, s.rate.Middleware(auth(handler)))
	}
	gated("/api/v1/lens/telemetry", h.HandleTelemetry)
	gated("/api/v1/lens/check", h.HandleCheck)
	gated("/api/v1/lens/stats", h.HandleStats)

	return mux
}

// ListenAndServe starts the HTTP server. If TLSCert and TLSKey
// are configured, listens with TLS. Otherwise listens in plaintext
// (for the testlab, which terminates TLS at the edge proxy).
func (s *Server) ListenAndServe() error {
	s.logger.Info("lens_server_starting",
		slog.Int("port", s.cfg.Port),
		slog.Bool("tls", s.cfg.TLSCert != ""),
		slog.String("version", s.version),
	)
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return s.httpServer.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server. It is safe to call from
// any goroutine.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("lens_server_shutting_down")
	return s.httpServer.Shutdown(ctx)
}

// appendRawEvent appends a single event to the on-disk events.jsonl
// file. Called by the /telemetry handler on success. The file is
// the source of truth for raw events; the IOC store is the source
// of truth for IOCs.
func (s *Server) appendRawEvent(ctx context.Context, e Event) error {
	s.rawEventMu.Lock()
	defer s.rawEventMu.Unlock()
	path := filepath.Join(s.cfg.IOCStorePath, "events.jsonl")               // #nosec G304 -- events.jsonl is the service's own data file, path is hardcoded
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G302 G304 G703 -- service data file, owner-writable; hardcoded path
	if err != nil {
		return fmt.Errorf("open events file: %w", err)
	}
	defer f.Close()
	// Persist a strict subset: timestamp, domain_hash, category,
	// user_action, severity. NEVER the user_action's specific
	// value if it would leak intent (e.g., we persist the enum
	// but not the surrounding context).
	rec := map[string]any{
		"timestamp":   e.Timestamp,
		"domain_hash": e.DomainHash,
		"category":    e.Category,
		"user_action": e.UserAction,
		"severity":    e.Severity,
	}
	enc := json.NewEncoder(f)
	return enc.Encode(rec)
}

// RunRetention starts the retention loop. Blocks until ctx is
// cancelled. Call from a goroutine in main().
func (s *Server) RunRetention(ctx context.Context) {
	s.retent.RunRetention(ctx, DefaultRetentionInterval)
}

// httpAuthMiddleware is the bearer-token auth middleware.
// We use crypto/subtle.ConstantTimeCompare to avoid timing
// attacks on the token comparison.
type httpAuthMiddleware struct {
	token string
}

func newHTTPAuthMiddleware(token string) *httpAuthMiddleware {
	return &httpAuthMiddleware{token: token}
}

func (m *httpAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.token == "" {
			// No token configured -- the backend is in
			// "configuration required" mode. Reject all
			// non-healthz requests with 503.
			writeError(w, http.StatusServiceUnavailable, "bearer_token_required",
				"the LENS_BEARER_TOKEN environment variable must be set")
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			writeError(w, http.StatusUnauthorized, "missing_bearer", "Authorization: Bearer <token> required")
			return
		}
		provided := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(provided), []byte(m.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid_bearer", "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// slogOutput returns an io.Writer for the slog handler, based on
// the configured log path. If the path is empty, returns os.Stdout.
func slogOutput(path string) *os.File {
	if path == "" {
		return os.Stdout
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) // #nosec G302 G304 -- service log file, owner-writable; path is from LENS_LOG_PATH config
	if err != nil {
		// Fall back to stdout if we can't open the log file.
		return os.Stdout
	}
	return f
}

// LocalAddr returns the address the server is listening on.
// Used by tests to discover the dynamically-allocated port.
func (s *Server) LocalAddr() net.Addr {
	if s.httpServer == nil || s.httpServer.Addr == "" {
		return nil
	}
	// Parse the address; for ":9090" this returns ":9090".
	return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: s.cfg.Port}
}
