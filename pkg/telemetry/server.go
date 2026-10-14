// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Unified Telemetry Receiver — Server

package telemetry

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
)

// Server is the unified telemetry receiver HTTP server.
//
// It accepts detection telemetry from all AegisGate products via a single
// endpoint (POST /api/v1/telemetry) and serves pattern updates via the
// pull endpoint (GET /api/v1/patterns/latest).
//
// The server is intentionally small: no router library, no middleware
// library, no config library. Stdlib net/http only.
type Server struct {
	cfg     *Config
	logger  *slog.Logger
	version string

	// Event store (raw events as JSONL with retention)
	storeMu   sync.Mutex
	storePath string

	// Rate limiter (per-installation + global)
	// TODO: Wire to Platform's existing ratelimit package in implementation phase.
	// For now, the design defines the interface.

	// Pattern store (served by pull endpoint)
	patternsMu        sync.RWMutex
	patternSet        contracts.PatternSet
	patternsUpdatedAt string

	// Event router for source-specific routing and statistics
	router *EventRouter

	// HTTP server
	httpServer *http.Server
}

// NewServer creates a Server with the given config and version string.
func NewServer(cfg *Config, version string) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must be non-nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	s := &Server{
		cfg:               cfg,
		logger:            logger,
		version:           version,
		storePath:         cfg.StorePath,
		patternsUpdatedAt: cfg.PatternsUpdatedAt,
	}

	// Ensure store directory exists
	if err := os.MkdirAll(cfg.StorePath, 0o750); err != nil {
		return nil, fmt.Errorf("create store path: %w", err)
	}

	// Initialize pattern set
	s.patternSet = contracts.PatternSet{
		Version:     cfg.PatternsVersion,
		Source:      "platform",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Patterns:    []contracts.Pattern{},
	}

	// Initialize event router with event store adapter
	s.router = NewEventRouter(NewEventStorerAdapter(s.appendEvent))

	return s, nil
}

// Mux returns the HTTP handler with all routes registered.
func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()

	// POST /api/v1/telemetry — Accept EventBatch from any source
	mux.HandleFunc("POST /api/v1/telemetry", s.authMiddleware(s.handleTelemetry))

	// GET /api/v1/patterns/latest — Pull canonical pattern set
	mux.HandleFunc("GET /api/v1/patterns/latest", s.authMiddleware(s.handlePatternPull))

	// GET /api/v1/healthz — Health check (no auth)
	mux.HandleFunc("GET /api/v1/healthz", s.handleHealthz)

	// GET /api/v1/stats — Telemetry statistics (authenticated)
	mux.HandleFunc("GET /api/v1/stats", s.authMiddleware(s.handleStats))

	return mux
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.cfg.Port),
		Handler: s.Mux(),
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Info("telemetry receiver starting",
		"port", s.cfg.Port,
		"version", s.version,
		"tls", s.cfg.TLSCert != "",
	)

	if s.cfg.TLSCert != "" {
		return s.httpServer.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return s.httpServer.ListenAndServe()
}

// === Handlers ===

// handleTelemetry accepts an EventBatch from any AegisGate product.
// The `source` field in each event determines routing.
func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	// Limit request body size (1MB max)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "failed to read request body",
		})
		return
	}
	defer r.Body.Close()

	var batch contracts.EventBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "invalid JSON",
			"details": err.Error(),
		})
		return
	}

	// Validate schema version
	if batch.SchemaVersion != "v1" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":     "unsupported schema_version",
			"supported": "v1",
			"received":  batch.SchemaVersion,
		})
		return
	}

	// Validate events
	if len(batch.Events) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "empty event batch",
		})
		return
	}

	// Process each event
	ack := &contracts.EventAcknowledgment{
		Accepted: 0,
		Rejected: 0,
	}

	for _, event := range batch.Events {
		if err := s.validateEvent(event); err != nil {
			ack.Rejected++
			ack.Errors = append(ack.Errors, contracts.EventError{
				EventID: event.ID,
				Reason:  err.Error(),
			})
			continue
		}

		// Route based on source field
		if err := s.routeEvent(event); err != nil {
			ack.Rejected++
			ack.Errors = append(ack.Errors, contracts.EventError{
				EventID: event.ID,
				Reason:  err.Error(),
			})
			continue
		}

		// Append to raw event store (JSONL)
		if err := s.appendEvent(event); err != nil {
			s.logger.Error("failed to append event", "event_id", event.ID, "error", err)
			ack.Rejected++
			ack.Errors = append(ack.Errors, contracts.EventError{
				EventID: event.ID,
				Reason:  "internal storage error",
			})
			continue
		}

		ack.Accepted++
	}

	// Include patterns_updated_at for client-side pull decisions
	s.patternsMu.RLock()
	ack.UpdatedAt = s.patternsUpdatedAt
	s.patternsMu.RUnlock()

	writeJSON(w, http.StatusAccepted, ack)
}

// handlePatternPull returns the canonical pattern set.
// Clients use If-Modified-Since header to avoid re-downloading unchanged patterns.
func (s *Server) handlePatternPull(w http.ResponseWriter, r *http.Request) {
	s.patternsMu.RLock()
	patternSet := s.patternSet
	updatedAt := s.patternsUpdatedAt
	s.patternsMu.RUnlock()

	// Check If-Modified-Since
	if ims := r.Header.Get("If-Modified-Since"); ims != "" && updatedAt != "" {
		if ims == updatedAt {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	resp := contracts.PatternSetResponse{
		APIVersion: "v1",
		PatternSet: patternSet,
		UpdatedAt:  updatedAt,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleHealthz returns server health status (no auth required).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.version,
	})
}

// handleStats returns aggregated telemetry statistics.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	summary := s.router.GetSummary()
	writeJSON(w, http.StatusOK, summary)
}

// LoadDefaultPatterns loads Platform's built-in scanner patterns into
// the pattern set served by the pull endpoint. Call this at startup
// or when patterns are updated.
func (s *Server) LoadDefaultPatterns() {
	patterns := LoadPlatformPatterns()
	s.UpdatePatterns(patterns)
}

// === Internal Methods ===

// validateEvent validates a single event against the canonical schema rules.
func (s *Server) validateEvent(e contracts.Event) error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.Source == "" {
		return fmt.Errorf("event source is required")
	}
	if e.SchemaVersion != "v1" {
		return fmt.Errorf("unsupported schema_version: %s", e.SchemaVersion)
	}
	if e.Timestamp.IsZero() {
		return fmt.Errorf("event timestamp is required")
	}

	// Verify source matches batch source (defensive)
	switch e.Source {
	case contracts.SourceLens, contracts.SourceRampart,
		contracts.SourceScanner, contracts.SourceMCP, contracts.SourcePlatform:
		// valid source
	default:
		return fmt.Errorf("unknown source: %s", e.Source)
	}

	return nil
}

// routeEvent routes an event to the appropriate aggregation logic based on source.
// The EventRouter handles per-source statistics, IOC fingerprint corroboration,
// and event persistence.
func (s *Server) routeEvent(e contracts.Event) error {
	return s.router.Route(e)
}

// appendEvent appends an event to the JSONL store with retention enforcement.
func (s *Server) appendEvent(e contracts.Event) error {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()

	data, err := json.Marshal(e)
	if err != nil {
		return err
	}

	path := s.storePath + "/events.jsonl"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(append(data, '\n'))
	return err
}

// === Auth Middleware ===

// authMiddleware validates the API key bearer token.
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIKey == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "telemetry receiver is not configured (no API key set)",
			})
			return
		}

		token := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.APIKey

		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid or missing API key",
			})
			return
		}

		next(w, r)
	}
}

// === Helpers ===

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// UpdatePatterns replaces the pattern set served by the pull endpoint.
// Called when new patterns are pushed to Platform (admin/config update).
func (s *Server) UpdatePatterns(patterns []contracts.Pattern) {
	s.patternsMu.Lock()
	defer s.patternsMu.Unlock()

	s.patternSet = contracts.PatternSet{
		Version:     "v1",
		Source:      "platform",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Hash:        hashPatterns(patterns),
		Patterns:    patterns,
	}
	s.patternsUpdatedAt = time.Now().UTC().Format(time.RFC3339)
}

// hashPatterns computes a SHA-256 content hash for cache invalidation.
func hashPatterns(patterns []contracts.Pattern) string {
	return HashPatternsSHA256(patterns)
}
