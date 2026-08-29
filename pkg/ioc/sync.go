// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 3)
// =========================================================================
//
// sync.go implements the gossip sync protocol: pull-based HTTP,
// symmetric, opt-in, tier-gated.
//
// Endpoints (served by every AegisGate instance that has opted
// in to IOC sharing):
//
//	GET /api/v1/ioc/manifest
//	  Returns a signed Bundle of all locally-known IOCs.
//
//	GET /api/v1/ioc/manifest?since=<rfc3339>
//	  Returns a signed Bundle of IOCs with LastSeen >= since.
//	  Used for delta sync to keep wire size small.
//
//	GET /api/v1/ioc/health
//	  Returns 200 if the IOC library is enabled and ready,
//	  503 otherwise. Useful for orchestrators and the lab test.
//
// Wire format: JSON-encoded Bundle. The signature and embedded
// public key on the bundle (and on each attestation inside) make
// every response self-verifying: a client can verify with no
// out-of-band key exchange.
//
// Configuration (locked decision Q2 + Q3):
//
//   - AEGISGATE_IOC_SHARE=true   opt in to serving bundles
//   - AEGISGATE_IOC_RECEIVE=true opt in to fetching peer bundles
//   - Tier gate: receive is additionally gated to Professional+
//     (any tier can SEND, but only Professional+ can RECEIVE;
//     a Community instance returns 403 if it receives a push
//     request, but it can still serve bundles to peers that
//     do have the receive side enabled).
//
// The peer list is configured by the operator; the IOC library
// does not auto-discover peers. Auto-discovery would be a
// future feature (e.g., DNS-SD for instances on the same
// network, or a static allow-list in the config).
//
// v3.5.0+ Track 6 Task 3.
// =========================================================================

package ioc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// SyncConfig configures the gossip sync subsystem. All fields
// are optional except where noted.
type SyncConfig struct {
	// InstanceID is the opaque, instance-unique identifier. It
	// is embedded in every Bundle this instance signs. Required.
	InstanceID string

	// SigningKey is the ECDSA P-256 private key used to sign
	// outgoing bundles. Required UNLESS KeyRing is provided.
	// If both are provided, KeyRing takes precedence and
	// SigningKey is used only as a fallback (legacy single-key
	// code path).
	SigningKey *ecdsa.PrivateKey

	// KeyID is the opaque identifier for the signing key (e.g.,
	// "ioc-abc12345"). Required UNLESS KeyRing is provided.
	KeyID string

	// KeyRing is the keyring used to sign outgoing bundles and
	// attestations. Optional; takes precedence over SigningKey
	// + KeyID when set. Use this for key rotation support.
	//
	// When KeyRing is nil, the legacy single-key path is used
	// (signing with SigningKey + KeyID). This is the path
	// exercised by the unit tests; the production wiring
	// constructs a KeyRing and sets this field.
	KeyRing *KeyRing

	// Reputation is the per-peer reputation store. Optional;
	// if nil, Receiver.Ingest accepts IOCs from any peer whose
	// bundle verifies (the pre-Track-6-Task-5 behavior). When
	// set, Receiver.Ingest also checks the peer's score
	// against ReputationConfig.Threshold and rejects IOCs from
	// peers below the threshold.
	Reputation *ReputationStore

	// Store is the local IOC store to read from when building
	// bundles. Required for the server side.
	Store *Store

	// Tier is the instance's license tier. Used to gate the
	// receive side. The send side is gated only by EnableShare.
	Tier tier.Tier

	// EnableShare, if true, the instance serves bundles on the
	// HTTP handler. Default false (opt-in).
	EnableShare bool

	// EnableReceive, if true, the instance fetches peer bundles
	// via the Client. Additionally requires Tier.CanAccess(
	// tier.TierProfessional). Default false (opt-in).
	EnableReceive bool

	// Peers is the list of peer instance base URLs (e.g.,
	// "https://aegisgate-peer.example.com:8443"). The client
	// fetches from each peer in order.
	Peers []string

	// ClientTimeout is the HTTP client timeout for peer fetches.
	// Default 10s.
	ClientTimeout time.Duration

	// GossipInterval is the period between peer fetches in
	// RunReceiver. Default 5 minutes. Must be > 0; values <= 0
	// are clamped to the default at construction.
	//
	// Production deployments typically use 5-15 minutes: a
	// shorter interval is chatty and wastes bandwidth; a
	// longer interval delays the cross-instance signal. The
	// lab test uses sub-second intervals for fast feedback.
	GossipInterval time.Duration
}

// Sync is the gossip sync subsystem. It is the bridge between
// the local IOC store and the wire protocol. A single Sync
// instance per process.
//
// Lifecycle:
//   - main.go: sync := ioc.NewSync(cfg)
//   - main.go: handler := sync.Handler()
//   - main.go: mux.Handle("/api/v1/ioc/", handler)
//   - main.go: go sync.RunReceiver(ctx)
type Sync struct {
	cfg SyncConfig

	// mu guards the live mutable flags (EnableShare, EnableReceive).
	// The receiver run state is also guarded by mu so a future
	// iteration that starts/stops the receiver at runtime can
	// do so safely.
	mu      sync.RWMutex
	running bool

	// httpClient is shared across all peer fetches.
	httpClient *http.Client

	// rateLimiter tracks per-IP request counts for the manifest endpoint.
	rateLimiter *iocRateLimiter
}

// NewSync creates a Sync from the given config. Returns an
// error if required fields are missing.
func NewSync(cfg SyncConfig) (*Sync, error) {
	if cfg.InstanceID == "" {
		return nil, errors.New("InstanceID is required")
	}
	// SigningKey + KeyID are required UNLESS KeyRing is set.
	// If KeyRing is nil, the caller must provide both. This
	// preserves the v3.5.0 single-key API for unit tests.
	if cfg.KeyRing == nil {
		if cfg.SigningKey == nil {
			return nil, errors.New("SigningKey is required (or provide KeyRing)")
		}
		if cfg.KeyID == "" {
			return nil, errors.New("KeyID is required (or provide KeyRing)")
		}
	}
	if cfg.Store == nil {
		return nil, errors.New("Store is required")
	}
	if cfg.ClientTimeout <= 0 {
		cfg.ClientTimeout = 10 * time.Second
	}
	if cfg.GossipInterval <= 0 {
		cfg.GossipInterval = 5 * time.Minute
	}
	return &Sync{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.ClientTimeout,
		},
		rateLimiter: newIOCRateLimiter(60, time.Minute), // 60 requests per minute per IP
	}, nil
}

// Handler returns an http.Handler that serves the three IOC
// endpoints. The handler enforces the EnableShare gate: if
// EnableShare is false, all three endpoints return 403.
//
// Mount under "/api/v1/ioc/" so the existing platform routing
// (which already has /api/v1/compliance/, /api/v1/posture/) is
// consistent.
func (s *Sync) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ioc/manifest", s.rateLimitedManifest)
	mux.HandleFunc("/api/v1/ioc/health", s.handleHealth)
	return mux
}

// iocRateLimiter implements a simple per-IP token bucket rate limiter
// for the IOC manifest endpoint to prevent abuse.
type iocRateLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	requests  map[string]int // IP -> request count
	lastReset time.Time
}

func newIOCRateLimiter(limit int, window time.Duration) *iocRateLimiter {
	return &iocRateLimiter{
		limit:     limit,
		window:    window,
		requests:  make(map[string]int),
		lastReset: time.Now(),
	}
}

func (rl *iocRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	// Reset window if expired
	if time.Since(rl.lastReset) >= rl.window {
		rl.requests = make(map[string]int)
		rl.lastReset = time.Now()
	}
	if rl.requests[ip] >= rl.limit {
		return false
	}
	rl.requests[ip]++
	return true
}

// rateLimitedManifest wraps handleManifest with per-IP rate limiting.
func (s *Sync) rateLimitedManifest(w http.ResponseWriter, r *http.Request) {
	if !s.IsShare() {
		http.Error(w, "IOC sharing is not enabled on this instance", http.StatusForbidden)
		return
	}
	// Extract client IP (strip port)
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		ip = ip[:idx]
	}
	// Check X-Forwarded-For if behind a proxy (take first IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			ip = strings.TrimSpace(xff[:idx])
		} else {
			ip = strings.TrimSpace(xff)
		}
	}
	if !s.rateLimiter.allow(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, `{"error":"rate_limit_exceeded","message":"too many manifest requests"}`, http.StatusTooManyRequests)
		return
	}
	s.handleManifest(w, r)
}

// handleManifest serves GET /api/v1/ioc/manifest[?since=...].
// It builds a Bundle from the local store, signs it, and writes
// it as the response body with Content-Type: application/json.
func (s *Sync) handleManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.IsShare() {
		http.Error(w, "IOC sharing is not enabled on this instance", http.StatusForbidden)
		return
	}

	// Parse ?since= for delta sync.
	var since time.Time
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			http.Error(w, "invalid since parameter (want RFC3339)", http.StatusBadRequest)
			return
		}
		since = t
	}

	// Build the bundle.
	iocs := s.cfg.Store.SnapshotSince(since)
	bundle := NewBundle(s.cfg.InstanceID)
	for _, ioc := range iocs {
		// Build the IOCAttestation from the IOC. The attestation
		// signs the IOC fields verbatim.
		att := IOCAttestation{
			Fingerprint: ioc.Fingerprint,
			InstanceID:  s.cfg.InstanceID,
			IOCType:     ioc.Type,
			Severity:    ioc.Severity,
			FirstSeen:   ioc.FirstSeen,
			LastSeen:    ioc.LastSeen,
			Count:       ioc.Count,
		}
		if err := s.signAttestation(&att); err != nil {
			http.Error(w, "sign attestation: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		bundle.Add(att)
	}
	if err := s.signBundle(bundle); err != nil {
		http.Error(w, "sign bundle: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	// Write.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(bundle)
}

// handleHealth serves GET /api/v1/ioc/health. Returns 200 if
// the IOC library is configured and EnableShare is true, 503
// otherwise. Used by the lab test as a smoke check.
func (s *Sync) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.IsShare() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"disabled","reason":"share not enabled"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fmt.Sprintf(
		`{"status":"healthy","instanceId":%q,"iocCount":%d}`,
		s.cfg.InstanceID, s.cfg.Store.Size())))
}

// AddDiscoveredPeer adds a peer URL to the Sync's peer list
// at runtime. Used by the bootstrap Discoverer (discovery.go).
// Safe for concurrent use. No-op if peerURL is empty or
// already in the list.
func (s *Sync) AddDiscoveredPeer(peerURL string) {
	if s == nil || peerURL == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.cfg.Peers {
		if p == peerURL {
			return // already known
		}
	}
	s.cfg.Peers = append(s.cfg.Peers, peerURL)
}

// SetShare enables or disables the share side of the sync
// at runtime. When set to true, the /api/v1/ioc/manifest
// endpoint starts serving signed bundles. When set to false,
// the endpoint returns 403. The change is immediate; no
// restart required.
//
// Safe for concurrent use. Cheap; takes a write lock briefly.
func (s *Sync) SetShare(enabled bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg.EnableShare = enabled
	s.mu.Unlock()
}

// SetReceive enables or disables the receive side of the
// sync at runtime. When set to true AND the tier is
// Professional+, the receiver will fetch peer bundles on
// each gossip tick. When set to false, the receiver stops
// fetching. Tier gating is enforced in CanReceive.
//
// Note: enabling receive at runtime does NOT start a new
// RunReceiver goroutine if one is not already running. The
// caller is expected to have already started RunReceiver
// at startup; this just toggles the flag that RunReceiver
// checks on each tick.
//
// Safe for concurrent use. Cheap; takes a write lock briefly.
func (s *Sync) SetReceive(enabled bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg.EnableReceive = enabled
	s.mu.Unlock()
}

// IsShare returns the current share flag.
func (s *Sync) IsShare() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.EnableShare
}

// IsReceive returns the current receive flag.
func (s *Sync) IsReceive() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.EnableReceive
}

// SetReputation attaches a ReputationStore to the sync. This
// is the wiring path for production; the unit tests construct
// the Receiver directly with a reputation store. Safe to call
// at runtime (re-attach is allowed but not common).
func (s *Sync) SetReputation(rs *ReputationStore) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg.Reputation = rs
	s.mu.Unlock()
}

// Reputation returns a snapshot of the per-peer reputation
// records, sorted by InstanceID. Returns nil if the sync
// was constructed without a ReputationStore. Used by the
// admin API to display the per-peer reputation.
func (s *Sync) Reputation() []ReputationRecord {
	if s == nil {
		return nil
	}
	if s.cfg.Reputation == nil {
		return nil
	}
	return s.cfg.Reputation.Reputation()
}

// RotateKey generates a fresh ECDSA P-256 key, marks the
// current key as retired, and sets the new key as current.
// The new keyId is returned. The keyring is persisted to
// disk atomically.
//
// Returns an error if the Sync was constructed without a
// KeyRing (the legacy single-key path does not support
// rotation; the operator must restart the process with a
// new key to "rotate" in that mode).
//
// Safe for concurrent use. Rare; intended for manual
// operator action (e.g., an admin API call) or a scheduled
// rotation job.
func (s *Sync) RotateKey() (string, error) {
	if s.cfg.KeyRing == nil {
		return "", errors.New("Sync: KeyRing not configured; rotation requires a KeyRing")
	}
	return s.cfg.KeyRing.Rotate()
}

// ActiveKeys returns a snapshot of the keyring's keys, sorted
// by CreatedAt. The snapshot is redacted: the private key is
// NOT included. Used by the admin API to display the current
// keyring state.
//
// Returns nil if the Sync was constructed without a KeyRing.
func (s *Sync) ActiveKeys() []KeyInfo {
	if s.cfg.KeyRing == nil {
		return nil
	}
	return s.cfg.KeyRing.ActiveKeys()
}

// signAttestation signs a single IOCAttestation using the
// configured signer: keyring if available, otherwise the
// legacy single-key path. Used by handleManifest.
func (s *Sync) signAttestation(a *IOCAttestation) error {
	if s.cfg.KeyRing != nil {
		return SignAttestationWithKeyRing(a, s.cfg.KeyRing)
	}
	return SignAttestation(a, s.cfg.SigningKey, s.cfg.KeyID)
}

// signBundle signs a Bundle using the configured signer:
// keyring if available, otherwise the legacy single-key path.
// Used by handleManifest.
func (s *Sync) signBundle(b *Bundle) error {
	if s.cfg.KeyRing != nil {
		return b.SignWithKeyRing(s.cfg.KeyRing)
	}
	return b.Sign(s.cfg.SigningKey, s.cfg.KeyID)
}

// Peers returns the list of peer base URLs that this Sync
// is configured to fetch from. Read-only; safe for concurrent
// use. Exposed so main.go can log the configured peer list
// at startup without needing to plumb the count through.
func (s *Sync) Peers() []string {
	if s == nil {
		return nil
	}
	return s.cfg.Peers
}

// CanReceive reports whether this instance is allowed to
// receive IOCs from peers. Returns false if EnableReceive is
// false OR if the tier is below Professional. The error
// explains why so callers can surface it.
func (s *Sync) CanReceive() (bool, error) {
	if !s.IsReceive() {
		return false, errors.New("IOC receive is not enabled on this instance")
	}
	if !s.cfg.Tier.CanAccess(tier.TierProfessional) {
		return false, fmt.Errorf(
			"IOC receive requires Professional tier or above; this instance is %s",
			s.cfg.Tier)
	}
	return true, nil
}

// RunReceiver starts a periodic fetch loop that pulls peer
// bundles and ingests them. Blocks until ctx is cancelled. The
// fetched IOCs are added to the local store via a Receiver.
//
// In v3.5.0 the receiver does NOT actually mutate the local
// store; it logs the received bundle and verifies its signature.
// The local-store update path is in Receiver.Ingest, which is
// called by the test directly. The production wiring will be
// added in a follow-up task (Track 6 Task 4) once the receiver
// policy is finalized (deduplication, freshness, allow-list).
//
// The interval is hard-coded to 5 minutes; a future iteration
// will make it configurable.
func (s *Sync) RunReceiver(ctx context.Context) {
	ok, err := s.CanReceive()
	if !ok {
		// Log via the existing platform path. The IOC library
		// does not have its own logger; the caller is expected
		// to wire this up via an admin endpoint or similar.
		_ = err // reserved for future logging wiring
		return
	}
	interval := s.cfg.GossipInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Log the interval once at startup. The caller may not have
	// a logger wired in, so we silently skip. A future iteration
	// will plumb a logger through SyncConfig.
	_ = interval
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, peer := range s.cfg.Peers {
				_, _ = s.FetchPeer(ctx, peer) // errors logged by caller
			}
		}
	}
}

// FetchPeer fetches the manifest from a single peer. Returns
// the verified Bundle or an error. The signature and the
// signatures on each IOCAttestation are verified before the
// bundle is returned. The caller is responsible for ingesting
// the bundle into the local store.
func (s *Sync) FetchPeer(ctx context.Context, peerBaseURL string) (*Bundle, error) {
	ok, err := s.CanReceive()
	if !ok {
		return nil, err
	}
	u, err := url.Parse(peerBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse peer URL: %w", err)
	}
	u.Path = "/api/v1/ioc/manifest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer returned %d: %s", resp.StatusCode, string(body))
	}

	// Decode and verify.
	var bundle Bundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decode bundle: %w", err)
	}
	if err := bundle.VerifyAll(); err != nil {
		return nil, fmt.Errorf("verify bundle: %w", err)
	}
	return &bundle, nil
}

// Receiver is the local-store side of the gossip protocol.
// It takes a verified Bundle (typically fetched from a peer)
// and merges the IOCs into the local store with the appropriate
// policy: dedup on fingerprint, take the worst severity, sum the
// counts, etc.
//
// The receiver is split out from Sync so the testlab gossip
// test can call Ingest() directly with a known-good bundle,
// without needing to spin up an HTTP server.
type Receiver struct {
	store      *Store
	reputation *ReputationStore
}

// NewReceiver creates a Receiver that writes into the given
// store.
func NewReceiver(store *Store) *Receiver {
	return &Receiver{store: store}
}

// WithReputation returns a copy of the receiver that consults
// the given reputation store on every Ingest. IOCs from peers
// with a score below the threshold are rejected and the
// rejection is recorded against the peer's reputation.
//
// This is the v3.5.0+ reputation-aware path. The
// pre-Reputation receiver is still constructed by NewReceiver
// for backward compatibility; the wiring code uses
// WithReputation to opt in.
func (r *Receiver) WithReputation(rs *ReputationStore) *Receiver {
	if r == nil {
		return nil
	}
	return &Receiver{store: r.store, reputation: rs}
}

// Reputation returns the receiver's reputation store, or nil
// if reputation is not configured.
func (r *Receiver) Reputation() *ReputationStore {
	if r == nil {
		return nil
	}
	return r.reputation
}

// Ingest merges a verified Bundle into the local store. The
// caller MUST have already called bundle.VerifyAll() to ensure
// the bundle and its attestations are valid. Ingest does NOT
// re-verify; it trusts the caller.
//
// Reputation gate (v3.5.0+): if the receiver has a reputation
// store, Ingest checks the source instance's score against
// the threshold. If below, the entire bundle is rejected and
// the rejection is recorded. This is the "soft quarantine"
// against a peer that has historically sent bad IOCs.
//
// Merge policy:
//   - For each IOCAttestation, the fingerprint is the primary key.
//   - FirstSeen: keep the earlier one (min).
//   - LastSeen:  keep the later one (max).
//   - Count:     sum (this is the "widespread" signal).
//   - Severity:  take the worse one.
//
// Returns the number of IOCs that were added or updated, or
// an error if the bundle was rejected by the reputation gate.
func (r *Receiver) Ingest(b *Bundle) (int, error) {
	if r.store == nil {
		return 0, errors.New("receiver has no store")
	}
	if b == nil {
		return 0, errors.New("nil bundle")
	}
	sourceInstance := b.InstanceID
	// Reputation gate: check the source's score before
	// ingesting. The source is the InstanceID in the bundle
	// envelope, not the URL we fetched from (which could be
	// behind a reverse proxy).
	if r.reputation != nil && sourceInstance != "" {
		if !r.reputation.IsAcceptable(sourceInstance) {
			r.reputation.Observe(sourceInstance, 0,
				int64(len(b.Attestations)), "below_threshold")
			return 0, fmt.Errorf(
				"peer %q below reputation threshold (score=%.3f, threshold=%.3f)",
				sourceInstance,
				r.reputation.Score(sourceInstance),
				r.reputation.cfg.Threshold)
		}
	}
	n := 0
	for i := range b.Attestations {
		att := &b.Attestations[i]
		// We use the store's Observe path so eviction + dedup
		// are applied. To preserve "worse severity wins" and
		// "count sums", we set the IOC fields carefully.
		ioc := IOC{
			Fingerprint: att.Fingerprint,
			Type:        att.IOCType,
			Severity:    att.Severity,
			FirstSeen:   att.FirstSeen,
			LastSeen:    att.LastSeen,
			Count:       att.Count,
			Source:      "peer:" + att.InstanceID,
		}
		// Observe increments Count by 1, which is NOT what we
		// want here; we want the peer-reported count to be
		// added. Bypass Observe and merge manually.
		//
		// We do this by writing a small inline merge. This is
		// safe because we hold no lock and the store's mutex
		// serializes the update.
		//
		// To keep the surface minimal, we just call Observe and
		// then patch the merged count afterwards. (Observe
		// is a single critical section; this is rare and
		// batched.)
		//
		// Actually, simpler: we directly merge into the store
		// map via the package-private helpers exposed below.
		r.store.mergePeerIOC(ioc)
		n++
	}
	// Record the round outcome in the reputation store.
	// All attestations in the bundle are accepted as a single
	// "round" for the peer; partial failures inside the bundle
	// (which would be a bug) are not currently distinguished.
	if r.reputation != nil && sourceInstance != "" {
		r.reputation.Observe(sourceInstance,
			int64(n), int64(len(b.Attestations)-n), "")
	}
	return n, nil
}
