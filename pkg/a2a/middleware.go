// SPDX-License-Identifier: Apache-2.0
package a2a

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
)

// A2A error codes — structured, actionable error identifiers for developers.
// These provide machine-readable error codes alongside human-readable messages,
// enabling automated incident response, programmatic retry logic, and
// cross-platform error classification.
const (
	// A2A_ERR_AUTH indicates authentication failure (mTLS client certificate).
	A2A_ERR_AUTH = "A2A_AUTH_FAILED"

	// A2A_ERR_AUTH_NO_CERT indicates no client certificate was presented.
	A2A_ERR_AUTH_NO_CERT = "A2A_AUTH_NO_CERT"

	// A2A_ERR_AUTH_MISSING_CN indicates the client certificate has no common name.
	A2A_ERR_AUTH_MISSING_CN = "A2A_AUTH_MISSING_CN"

	// A2A_ERR_LICENSE_MISSING indicates no license header was provided.
	A2A_ERR_LICENSE_MISSING = "A2A_LICENSE_MISSING"

	// A2A_ERR_LICENSE_INVALID indicates the provided license key is invalid or expired.
	A2A_ERR_LICENSE_INVALID = "A2A_LICENSE_INVALID"

	// A2A_ERR_RATE_LIMITED indicates the agent has exceeded its request rate.
	A2A_ERR_RATE_LIMITED = "A2A_RATE_LIMITED"

	// A2A_ERR_INTEGRITY_MISSING indicates no HMAC signature was provided.
	A2A_ERR_INTEGRITY_MISSING = "A2A_INTEGRITY_MISSING"

	// A2A_ERR_INTEGRITY_INVALID indicates the HMAC signature does not match the body.
	A2A_ERR_INTEGRITY_INVALID = "A2A_INTEGRITY_INVALID"

	// A2A_ERR_INTEGRITY_MALFORMED indicates the signature header could not be decoded.
	A2A_ERR_INTEGRITY_MALFORMED = "A2A_INTEGRITY_MALFORMED"

	// A2A_ERR_CAP_MISSING indicates the A2A-Capability header was not provided.
	A2A_ERR_CAP_MISSING = "A2A_CAP_MISSING"

	// A2A_ERR_CAP_DENIED indicates the agent does not have the requested capability.
	A2A_ERR_CAP_DENIED = "A2A_CAP_DENIED"

	// A2A_ERR_CAP_UNKNOWN_AGENT indicates the agent ID is not registered in the capability map.
	A2A_ERR_CAP_UNKNOWN_AGENT = "A2A_CAP_UNKNOWN_AGENT"

	// A2A_ERR_CAP_CHECK_FAILED indicates an internal error during capability lookup.
	A2A_ERR_CAP_CHECK_FAILED = "A2A_CAP_CHECK_FAILED"

	// A2A_ERR_INTERNAL indicates an unexpected internal error (panic recovery).
	A2A_ERR_INTERNAL = "A2A_INTERNAL_ERROR"
)

// a2aErrorResponse writes a structured JSON error response with an A2A error code.
func a2aErrorResponse(w http.ResponseWriter, code, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"code":    code,
		"message": message,
	}); err != nil {
		// Response headers already sent; log the encoding error for observability.
		slog.Default().Error("a2aErrorResponse: failed to encode JSON", "error", err, "code", code)
	}
}

// NewA2AMiddleware creates an HTTP middleware that wraps the provided handler with A2A guard‑rails.
// It wires mTLS authentication, integrity verification, rate‑limiting, capability enforcement,
// and optional license validation.  The token‑bucket parameters are currently hard‑coded
// (capacity 100, refill 10 per minute) but can be made configurable later.
func NewA2AMiddleware(next http.Handler, secret []byte, lm *license.Manager, caps CapabilityEnforcer) http.Handler {
	// Use sensible defaults for rate limiting – these match the defaults used in the demo config.
	limiter := NewTokenBucket(100, 10, time.Minute)
	return &Middleware{
		auth:       &MTLSAuth{},
		integrity:  NewIntegrityVerifier(secret),
		caps:       caps,
		limiter:    limiter,
		next:       next,
		licenseMgr: lm,
		logger:     slog.Default().With("component", "a2a-middleware"),
	}
}

// ----- AuthProvider -----
// Simple mTLS auth that extracts the common name from the client cert.
// In production this would verify against a certificate store.

type AuthProvider interface {
	Authenticate(r *http.Request) (string, error) // returns AgentID
}

type MTLSAuth struct{}

func (a *MTLSAuth) Authenticate(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate provided")
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	if cn == "" {
		return "", errors.New("client certificate missing common name")
	}
	return cn, nil
}

// ----- Message Integrity -----
// HMAC‑SHA256 signature verification for request bodies.
// The shared secret would be derived per‑agent in a real system.

type IntegrityVerifier struct {
	secret []byte
}

func NewIntegrityVerifier(secret []byte) *IntegrityVerifier {
	return &IntegrityVerifier{secret: secret}
}

func (v *IntegrityVerifier) Verify(r *http.Request) error {
	sigHeader := r.Header.Get("A2A-Signature")
	if sigHeader == "" {
		return errors.New("missing A2A-Signature header")
	}
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return fmt.Errorf("malformed A2A-Signature header: %w", err)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	mac := hmac.New(sha256.New, v.secret)
	mac.Write(body)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return errors.New("invalid message signature")
	}
	return nil
}

// ----- Capability Enforcement -----
// Simple in‑memory capability registry for demo purposes.

type CapabilityEnforcer interface {
	IsAllowed(agentID, capability string) (bool, error)
}

type InMemoryCapEnforcer struct {
	mu        sync.RWMutex
	agentCaps map[string]map[string]struct{}
}

func NewInMemoryCapEnforcer() *InMemoryCapEnforcer {
	return &InMemoryCapEnforcer{agentCaps: make(map[string]map[string]struct{})}
}

func (e *InMemoryCapEnforcer) SetCapabilities(agentID string, caps []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	set := make(map[string]struct{})
	for _, c := range caps {
		set[c] = struct{}{}
	}
	e.agentCaps[agentID] = set
}

func (e *InMemoryCapEnforcer) IsAllowed(agentID, capability string) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	caps, ok := e.agentCaps[agentID]
	if !ok {
		return false, nil
	}
	_, ok = caps[capability]
	return ok, nil
}

// Agents returns a list of all registered agent IDs.
func (e *InMemoryCapEnforcer) Agents() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	agents := make([]string, 0, len(e.agentCaps))
	for id := range e.agentCaps {
		agents = append(agents, id)
	}
	return agents
}

// GetCapabilities returns the capability list for a given agent.
// Returns nil if the agent is not found.
func (e *InMemoryCapEnforcer) GetCapabilities(agentID string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	caps, ok := e.agentCaps[agentID]
	if !ok {
		return nil
	}
	result := make([]string, 0, len(caps))
	for cap := range caps {
		result = append(result, cap)
	}
	return result
}

// ----- Rate Limiter -----
// Token bucket per agent ID.

type RateLimiter interface {
	Allow(agentID string) bool
}

type TokenBucket struct {
	mu       sync.Mutex
	capacity int64
	refill   int64
	interval time.Duration
	buckets  map[string]*bucketState
}

type bucketState struct {
	tokens         int64
	lastRefillTime time.Time
}

func NewTokenBucket(capacity, refill int64, interval time.Duration) *TokenBucket {
	return &TokenBucket{capacity: capacity, refill: refill, interval: interval, buckets: make(map[string]*bucketState)}
}

func (tb *TokenBucket) getState(agentID string) *bucketState {
	if st, ok := tb.buckets[agentID]; ok {
		return st
	}
	st := &bucketState{tokens: tb.capacity, lastRefillTime: time.Now()}
	tb.buckets[agentID] = st
	return st
}

func (tb *TokenBucket) Allow(agentID string) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	st := tb.getState(agentID)
	now := time.Now()
	elapsed := now.Sub(st.lastRefillTime)
	if elapsed >= tb.interval {
		periods := int64(elapsed / tb.interval)
		added := periods * tb.refill
		if added > 0 {
			st.tokens += added
			if st.tokens > tb.capacity {
				st.tokens = tb.capacity
			}
			st.lastRefillTime = now
		}
	}
	if st.tokens > 0 {
		st.tokens--
		return true
	}
	return false
}

// ----- Middleware Chain -----

type Middleware struct {
	auth       AuthProvider
	integrity  *IntegrityVerifier
	caps       CapabilityEnforcer
	limiter    RateLimiter
	next       http.Handler
	licenseMgr *license.Manager
	logger     *slog.Logger
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// FAIL-CLOSED: Panic recovery denies request on internal error.
	defer func() {
		if rec := recover(); rec != nil {
			m.logger.Error("A2A middleware panic — denying request by default",
				"panic", rec, "path", r.URL.Path, "method", r.Method)
			metrics.RecordA2AAuthFailure("panic")
			a2aErrorResponse(w, A2A_ERR_INTERNAL,
				fmt.Sprintf("internal security error — request denied: %v", rec),
				http.StatusForbidden)
		}
	}()

	// --- Guard 1: License validation (if configured) ---
	if m.licenseMgr != nil {
		licHeader := r.Header.Get("A2A-License")
		if licHeader == "" {
			metrics.RecordA2ALicenseFailure("")
			a2aErrorResponse(w, A2A_ERR_LICENSE_MISSING,
				"A2A license header is required", http.StatusForbidden)
			return
		}
		result := m.licenseMgr.Validate(licHeader)
		if !result.Valid {
			metrics.RecordA2ALicenseFailure("")
			a2aErrorResponse(w, A2A_ERR_LICENSE_INVALID,
				"invalid license: "+result.Message, http.StatusForbidden)
			return
		}
	}

	// --- Guard 2: mTLS Authentication (FAIL-CLOSED: no cert = deny) ---
	agentID, err := m.auth.Authenticate(r)
	if err != nil {
		// Determine specific error code for better developer experience
		code := A2A_ERR_AUTH
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			code = A2A_ERR_AUTH_NO_CERT
		} else {
			code = A2A_ERR_AUTH_MISSING_CN
		}
		metrics.RecordA2AAuthFailure(agentID)
		a2aErrorResponse(w, code, "unauthenticated: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// --- Guard 3: Rate limiting (FAIL-CLOSED: deny on rate limit exceeded) ---
	if !m.limiter.Allow(agentID) {
		a2aErrorResponse(w, A2A_ERR_RATE_LIMITED,
			"rate limit exceeded for agent: "+agentID, http.StatusTooManyRequests)
		return
	}

	// --- Guard 4: HMAC Integrity verification (FAIL-CLOSED: missing/invalid = deny) ---
	if err = m.integrity.Verify(r); err != nil {
		// Determine specific error code
		code := A2A_ERR_INTEGRITY_INVALID
		if r.Header.Get("A2A-Signature") == "" {
			code = A2A_ERR_INTEGRITY_MISSING
		} else if _, decodeErr := base64.StdEncoding.DecodeString(r.Header.Get("A2A-Signature")); decodeErr != nil {
			code = A2A_ERR_INTEGRITY_MALFORMED
		}
		metrics.RecordA2AIntegrityFailure(agentID)
		a2aErrorResponse(w, code, "signature verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// --- Guard 5: Capability enforcement (FAIL-CLOSED: no capability header = deny) ---
	// SECURITY: A2A-Capability header is REQUIRED. Requests without a declared
	// capability are denied by default. An agent must explicitly declare what it
	// intends to do — this is the zero-trust principle for A2A communication.
	capName := r.Header.Get("A2A-Capability")
	if capName == "" {
		// FAIL-CLOSED: No capability declared = deny by default
		metrics.RecordA2ACapabilityDenial(agentID, "")
		a2aErrorResponse(w, A2A_ERR_CAP_MISSING,
			"A2A-Capability header is required — capability declaration is mandatory",
			http.StatusForbidden)
		return
	}

	allowed, err := m.caps.IsAllowed(agentID, capName)
	if err != nil {
		// FAIL-CLOSED: Internal error during capability check = deny
		metrics.RecordA2ACapabilityDenial(agentID, capName)
		m.logger.Error("capability check internal error",
			"agent_id", agentID, "capability", capName, "error", err)
		a2aErrorResponse(w, A2A_ERR_CAP_CHECK_FAILED,
			"capability check error", http.StatusInternalServerError)
		return
	}
	if !allowed {
		metrics.RecordA2ACapabilityDenial(agentID, capName)
		// Determine if agent is unknown or capability is denied
		a2aErrorResponse(w, A2A_ERR_CAP_DENIED,
			"capability '"+capName+"' denied for agent: "+agentID,
			http.StatusForbidden)
		return
	}

	// --- All guards passed — delegate to next handler ---
	m.next.ServeHTTP(w, r)
}

func EchoHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		a2aErrorResponse(w, "A2A_BAD_REQUEST", "invalid json", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		a2aErrorResponse(w, A2A_ERR_INTERNAL, "failed to write response", http.StatusInternalServerError)
		return
	}
}

func RegisterA2AServer(mux *http.ServeMux, secret []byte, lm *license.Manager, caps CapabilityEnforcer) {
	mux.Handle("/a2a/echo", NewA2AMiddleware(http.HandlerFunc(EchoHandler), secret, lm, caps))
}

// Note: In a real deployment the server would be started elsewhere; this file
// provides only the middleware implementation needed for Sprint 7 Phase 2.
