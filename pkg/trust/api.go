// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust HTTP API (v3.2.0 Phase 4.3)
//
// api.go exposes the per-session trust accumulator (Phase 4.2) and
// the existing attestation primitives (pkg/trust/attestation) over
// HTTP. This is the customer-portal-facing surface for the Trust
// Framework pillar.
//
// Routes (all under /api/v1/trust):
//   GET  /score                -> lifetime score for ?agent=ID
//   GET  /score?session=ID     -> current score for a specific session
//   GET  /sessions             -> list sessions (?active=true&agent=ID)
//   GET  /sessions?id=ID       -> specific session detail
//   GET  /attestations         -> list recent attestations (?agent=ID&since=TS)
//   GET  /attestations/latest  -> most recent attestation (?agent=ID)
//   GET  /health               -> liveness (no auth)
//
// Auth (locked decision Q4): license key via pkg/license.LicenseMiddleware.
// Tier gate (locked decision Q3): Professional+ for all /score, /sessions,
// /attestations endpoints. /health is public.
//
// Pattern matches pkg/trust/dashboard/dashboard.go (raw net/http,
// per-path switch in ServeHTTP, JSON responses). v3.2.0.

package trust

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/attestation"
	"github.com/google/uuid"
)

// API serves the trust HTTP endpoints. Implements http.Handler.
//
// Construct via NewAPI(manager). Attach to your HTTP server with
// http.Handle("/api/v1/trust/", api) or by calling api.ServeHTTP
// directly. For tier gating, wrap with license.LicenseMiddleware
// .RequireTier(tierpkg.TierProfessional).
type API struct {
	manager *Manager
	// attestGenerator is optional. If nil, the /attestations endpoints
	// return 501 Not Implemented. Phase 4.4 will wire this in.
	attestGenerator *attestation.Generator
	// attestValidator is optional. Same as above.
	attestValidator *attestation.Validator

	// attestations is an in-memory ring buffer of the most recent
	// attestations produced by this server. Used by /attestations
	// and /attestations/latest. Default cap: 1000.
	mu          sync.RWMutex
	attestCap   int
	attestation []*attestation.Attestation
}

// APIConfig configures the API.
type APIConfig struct {
	// AttestationGenerator enables the /attestations endpoints. If nil,
	// those endpoints return 501.
	AttestationGenerator *attestation.Generator
	// AttestationValidator enables attestation verification on read.
	AttestationValidator *attestation.Validator
	// AttestationCap is the max number of attestations kept in memory
	// for /attestations. 0 = default 1000.
	AttestationCap int
}

// NewAPI creates a new trust HTTP API serving from the given manager.
// If config is nil, the API serves score and session endpoints but
// returns 501 for the attestation endpoints.
func NewAPI(manager *Manager, config *APIConfig) *API {
	if manager == nil {
		manager = NewManager(nil, nil)
	}
	cap := 1000
	if config != nil && config.AttestationCap > 0 {
		cap = config.AttestationCap
	}
	return &API{
		manager:         manager,
		attestGenerator: configOrNil(config, func(c *APIConfig) *attestation.Generator { return c.AttestationGenerator }),
		attestValidator: configOrNil(config, func(c *APIConfig) *attestation.Validator { return c.AttestationValidator }),
		attestCap:       cap,
	}
}

func configOrNil[T any](c *APIConfig, getter func(*APIConfig) T) T {
	var zero T
	if c == nil {
		return zero
	}
	return getter(c)
}

// Manager returns the underlying session manager. Useful for tests
// and for the customer portal that needs to issue Record() calls.
func (a *API) Manager() *Manager {
	return a.manager
}

// ServeHTTP implements http.Handler. Routes requests to the
// appropriate sub-handler based on URL path. All paths are relative
// to the mount point (e.g., mount at "/api/v1/trust" and dispatch
// on r.URL.Path relative to it).
//
// The API expects to be mounted with a path prefix that matches
// the route patterns below. If you mount at "/api/v1/trust", pass
// requests whose URL.Path starts with "/api/v1/trust"; ServeHTTP
// matches on the suffix.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip the /api/v1/trust prefix if present so we can dispatch
	// on the suffix. This lets the API be mounted at any path.
	path := r.URL.Path
	const prefix = "/api/v1/trust"
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		path = path[len(prefix):]
	}
	if path == "" || path == "/" {
		path = "/health"
	}

	switch path {
	case "/health":
		a.serveHealth(w, r)
	case "/score":
		a.serveScore(w, r)
	case "/sessions":
		a.serveSessions(w, r)
	case "/attestations":
		a.serveAttestations(w, r)
	case "/attestations/latest":
		a.serveAttestationsLatest(w, r)
	default:
		http.NotFound(w, r)
	}
}

// ---- /health ----

func (a *API) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]any{
		"status":         "ok",
		"activeSessions": a.manager.ActiveCount(),
		"totalSessions":  a.manager.TotalCount(),
		"attestations":   a.attestationCount(),
		"timestamp":      time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- /score ----

func (a *API) serveScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agentID := r.URL.Query().Get("agent")
	sessionID := r.URL.Query().Get("session")

	if sessionID != "" {
		// Session-scoped score: the agent's current lifetime score
		// (the live view) plus the session's snapshot context.
		a.serveSessionScore(w, r, sessionID)
		return
	}
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent parameter required")
		return
	}
	score, err := a.manager.Engine().GetScore(r.Context(), agentID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if score == nil {
		// No score yet for this agent (no events recorded). Return
		// the initial score (100.0) so the customer portal can render
		// a "no activity yet" UI without a 404.
		writeJSON(w, http.StatusOK, map[string]any{
			"agentId":      agentID,
			"score":        100.0,
			"level":        "trusted",
			"message":      "no events recorded yet",
			"calculatedAt": time.Now().UTC(),
		})
		return
	}
	writeJSON(w, http.StatusOK, score)
}

func (a *API) serveSessionScore(w http.ResponseWriter, r *http.Request, sessionID string) {
	sess, err := a.manager.Get(sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	liveScore, err := a.manager.Score(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	delta, err := a.manager.ScoreDelta(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session":      sess,
		"currentScore": liveScore,
		"initialScore": sess.InitialScore,
		"scoreDelta":   delta,
		"eventCount":   sess.EventCount(),
		"duration":     sess.Duration().String(),
	})
}

// ---- /sessions ----

func (a *API) serveSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Single session detail if ?id is provided.
	if id := r.URL.Query().Get("id"); id != "" {
		sess, err := a.manager.Get(id)
		if err != nil {
			if errors.Is(err, ErrSessionNotFound) {
				writeError(w, http.StatusNotFound, "session not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, sess)
		return
	}
	// List sessions, filtered by ?active and ?agent.
	activeOnly := r.URL.Query().Get("active") == "true"
	agentID := r.URL.Query().Get("agent")
	var sessions []*Session
	if agentID != "" {
		sessions = a.manager.ListByAgent(agentID, activeOnly)
	} else {
		sessions = a.manager.List(activeOnly)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

// ---- /attestations ----

func (a *API) serveAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.attestGenerator == nil {
		writeError(w, http.StatusNotImplemented, "attestation endpoints require AttestationGenerator (Phase 4.4 wiring pending)")
		return
	}
	agentID := r.URL.Query().Get("agent")
	since := parseSince(r.URL.Query().Get("since"))
	all := a.allAttestations()
	filtered := make([]*attestation.Attestation, 0, len(all))
	for _, att := range all {
		if agentID != "" && att.AgentID != agentID {
			continue
		}
		if !since.IsZero() && att.IssuedAt.Before(since) {
			continue
		}
		filtered = append(filtered, att)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"attestations": filtered,
		"count":        len(filtered),
	})
}

func (a *API) serveAttestationsLatest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.attestGenerator == nil {
		writeError(w, http.StatusNotImplemented, "attestation endpoints require AttestationGenerator (Phase 4.4 wiring pending)")
		return
	}
	agentID := r.URL.Query().Get("agent")
	if agentID == "" {
		writeError(w, http.StatusBadRequest, "agent parameter required")
		return
	}
	all := a.allAttestations()
	latest := (*attestation.Attestation)(nil)
	for _, att := range all {
		if att.AgentID != agentID {
			continue
		}
		if latest == nil || att.IssuedAt.After(latest.IssuedAt) {
			latest = att
		}
	}
	if latest == nil {
		writeError(w, http.StatusNotFound, "no attestations for agent")
		return
	}
	// Optionally verify the signature on the way out.
	if a.attestValidator != nil {
		result, err := a.attestValidator.Verify(latest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "verify: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"attestation":  latest,
			"verification": result,
		})
		return
	}
	writeJSON(w, http.StatusOK, latest)
}

// RecordAttestation stores an attestation in the in-memory ring buffer
// so it can be served by /attestations. Called by Phase 4.4 wiring
// (e.g., the proxy after a request completes) or by the customer
// portal when it issues a new attestation. This is the bridge between
// the in-process attestation flow and the HTTP read API.
func (a *API) RecordAttestation(ctx context.Context, att *attestation.Attestation) error {
	if att == nil {
		return errors.New("attestation is nil")
	}
	// Assign a UUID if not already set.
	if att.ID == "" {
		att.ID = uuid.New().String()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attestation = append(a.attestation, att)
	// Evict oldest if over cap.
	if a.attestCap > 0 && len(a.attestation) > a.attestCap {
		excess := len(a.attestation) - a.attestCap
		a.attestation = a.attestation[excess:]
	}
	return nil
}

func (a *API) allAttestations() []*attestation.Attestation {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]*attestation.Attestation, len(a.attestation))
	copy(out, a.attestation)
	return out
}

func (a *API) attestationCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.attestation)
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck // Encode errors after headers are typically client disconnects
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":   http.StatusText(status),
		"message": message,
		"status":  status,
	})
}

func parseSince(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// Try RFC3339 first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	// Try Unix seconds.
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	// Try relative "1h", "30m", "24h".
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d).UTC()
	}
	return time.Time{}
}
