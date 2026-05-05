package a2a

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/metrics"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

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
		return err
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
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.licenseMgr != nil {
		licHeader := r.Header.Get("A2A-License")
		if licHeader == "" {
			metrics.RecordA2ALicenseFailure("")
			http.Error(w, "missing license header", http.StatusForbidden)
			return
		}
		result := m.licenseMgr.Validate(licHeader)
		if !result.Valid {
			metrics.RecordA2ALicenseFailure("")
			http.Error(w, "invalid license: "+result.Message, http.StatusForbidden)
			return
		}
	}
	agentID, err := m.auth.Authenticate(r)
	if err != nil {
		metrics.RecordA2AAuthFailure(agentID)
		http.Error(w, "unauthenticated: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if !m.limiter.Allow(agentID) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if err = m.integrity.Verify(r); err != nil {
		metrics.RecordA2AIntegrityFailure(agentID)
		http.Error(w, "invalid signature: "+err.Error(), http.StatusBadRequest)
		return
	}
	capName := r.Header.Get("A2A-Capability")
	if capName != "" {
		allowed, _ := m.caps.IsAllowed(agentID, capName)
		if !allowed {
			metrics.RecordA2ACapabilityDenial(agentID, capName)
			http.Error(w, "capability denied", http.StatusForbidden)
			return
		}
	}
	m.next.ServeHTTP(w, r)
}

func EchoHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func RegisterA2AServer(mux *http.ServeMux, secret []byte, lm *license.Manager, caps CapabilityEnforcer) {
	mux.Handle("/a2a/echo", NewA2AMiddleware(http.HandlerFunc(EchoHandler), secret, lm, caps))
}

// Note: In a real deployment the server would be started elsewhere; this file
// provides only the middleware implementation needed for Sprint 7 Phase 2.
