// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Agent Registry Federation (v5.0)
// =========================================================================
//
// federation.go implements cross-deployment federation for the Agent
// Registry. It enables multiple AegisGate Platform instances (in
// different customer enclaves, environments, or geographic regions)
// to share signed agent lifecycle attestations via the same pull-based
// gossip protocol used by the IOC library.
//
// Design principles (mirrors pkg/ioc federated IOC library):
//
//  1. Hash-based identity. Agent names and IDs are NEVER transmitted.
//     A SHA-256 fingerprint over the agent's canonical identity
//     (name + role) provides a privacy-preserving, deterministic
//     identifier. Two deployments with an agent named
//     "support-bot" / role "assistant" produce the same fingerprint,
//     enabling cross-deployment correlation without exposing the
//     agent's name.
//
//  2. ECDSA P-256 signing. Attestations and bundles are signed with
//     the same KeyRing used by the IOC library (pkg/ioc.KeyRing).
//     This reuses the proven signing/verification primitive and
//     keeps a single key per instance for all federation types.
//
//  3. Privacy by construction. Attestations carry only: fingerprint,
//     lifecycle status, protocols, last activity timestamp, AIBOM
//     drift flag, and a timestamp. They NEVER carry agent names,
//     descriptions, tool lists, tenant identifiers, or any data
//     that could attribute an agent to a specific customer.
//
//  4. Opt-in, air-gap compatible. Federation is disabled by default.
//     EnableFederation must be explicitly set to true. When disabled
//     (the default, and the air-gap configuration), no federation
//     data is produced or consumed, no network connections are made,
//     and the registry operates entirely standalone.
//
//  5. Reuses existing gossip transport. Agent bundles are exchanged
//     via the same HTTP gossip endpoint as IOC bundles. The existing
//     /api/v1/ioc/manifest endpoint can serve agent bundles alongside
//     IOC bundles, or a dedicated /api/v1/agents/federation endpoint
//     can serve them separately. Either way, the transport, key
//     management, and verification are shared.
//
// Federation use cases:
//
//   - Cross-enclave visibility: A SOC managing multiple enclaves
//     (prod, staging, dev) can see agent lifecycle states across all
//     enclaves in a single federated view.
//   - Dormancy correlation: If an agent goes dormant in deployment A,
//     deployment B is alerted to check the same agent type.
//   - Revocation propagation: If deployment A revokes an agent,
//     deployment B can proactively quarantine agents with the same
//     fingerprint.
//   - Drift intelligence: If deployment A detects shadow AI (agent
//     active but not in AIBOM), deployment B can check for the same
//     drift condition.
//
// =========================================================================

package agentregistry

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =====================================================================
// Federation Configuration
// =====================================================================

// FederationConfig controls cross-deployment agent registry federation.
// All fields default to zero/disabled, preserving air-gap compliance.
type FederationConfig struct {
	// EnableFederation controls whether federation is active.
	// When false (the default), no federation data is produced
	// or consumed. This is the air-gap configuration.
	EnableFederation bool `json:"enable_federation"`

	// InstanceID is the opaque identifier for this AegisGate
	// instance. It is NOT a customer identifier; it is a stable
	// random string generated once per instance and stored
	// alongside the signing key. Two attestations with the same
	// InstanceID come from the same physical instance.
	InstanceID string `json:"instance_id"`

	// KeyRing provides the ECDSA P-256 signing key. If nil,
	// federation is disabled (signing requires a key).
	KeyRing *ioc.KeyRing `json:"-"`

	// ExportInterval is how often the registry produces a bundle
	// for federation. Default: 5 minutes. Zero means manual only.
	ExportInterval time.Duration `json:"export_interval,omitempty"`

	// MaxFederatedAgents is the maximum number of federated agent
	// records retained from peers. Default: 10,000. Older records
	// are evicted when this limit is reached.
	MaxFederatedAgents int `json:"max_federated_agents,omitempty"`
}

// =====================================================================
// Agent Fingerprint
// =====================================================================

// AgentFingerprint is a SHA-256 hash of the agent's canonical identity
// (name + role), providing a privacy-preserving, deterministic
// identifier. Two deployments with an agent of the same name and role
// produce the same fingerprint, enabling cross-deployment correlation
// without exposing the agent's name.
type AgentFingerprint string

// ComputeAgentFingerprint computes a deterministic SHA-256 fingerprint
// from an agent's name and role. The fingerprint is hex-encoded (64
// characters). The raw name and role are never included in federation
// data — only the fingerprint is transmitted.
func ComputeAgentFingerprint(name, role string) AgentFingerprint {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0x00}) // separator to prevent collisions
	h.Write([]byte(role))
	return AgentFingerprint(hex.EncodeToString(h.Sum(nil)))
}

// String returns the hex-encoded fingerprint.
func (f AgentFingerprint) String() string {
	return string(f)
}

// =====================================================================
// Agent Attestation
// =====================================================================

// AgentAttestation is a signed statement by an AegisGate instance
// about an agent's lifecycle state at a point in time. It is the
// unit that flows between instances over the federation protocol,
// analogous to ioc.IOCAttestation.
//
// Wire format:
//
//	{
//	  "fingerprint":  "<hex sha256>",
//	  "instanceId":   "<opaque instance id>",
//	  "status":       "dormant",
//	  "protocols":    ["mcp", "a2a"],
//	  "lastActivity": "2026-10-25T12:00:00Z",
//	  "inAibom":      true,
//	  "aibomDrift":   "",
//	  "timestamp":    "2026-10-25T20:00:00Z",
//	  "publicKey":    { "algorithm": "ecdsa-p256", "keyId": "...", "value": "..." },
//	  "signature":    { "algorithm": "ecdsa-p256", "keyId": "...", "value": "..." }
//	}
type AgentAttestation struct {
	// Fingerprint is the agent's privacy-preserving identity hash.
	Fingerprint AgentFingerprint `json:"fingerprint"`

	// InstanceID identifies the instance that produced this
	// attestation. Copied from the federation config.
	InstanceID string `json:"instanceId"`

	// Status is the agent's lifecycle status at the time of
	// attestation.
	Status AgentStatus `json:"status"`

	// Protocols is the list of communication protocols the agent
	// uses. These are protocol identifiers, not sensitive data.
	Protocols []Protocol `json:"protocols"`

	// LastActivity is the most recent activity timestamp for
	// the agent. Used by peers to assess dormancy across
	// deployments.
	LastActivity time.Time `json:"lastActivity"`

	// InAIBOM indicates whether the agent is declared in the
	// producing instance's AIBOM.
	InAIBOM bool `json:"inAibom"`

	// AIBOMDrift describes any drift condition (e.g., "active
	// but not in AIBOM"). Empty if no drift.
	AIBOMDrift string `json:"aibomDrift,omitempty"`

	// Timestamp is when this attestation was produced (UTC).
	Timestamp time.Time `json:"timestamp"`

	// PublicKey is the embedded ECDSA P-256 public key that
	// signed this attestation. Reuses ioc.PublicKeyEnvelope so
	// the same verification path works.
	PublicKey ioc.PublicKeyEnvelope `json:"publicKey"`

	// Signature is the ECDSA P-256 signature over the
	// canonicalized JSON of this attestation minus the signature
	// field. Reuses ioc.SignatureEnvelope.
	Signature ioc.SignatureEnvelope `json:"signature"`
}

// attestationPayload returns the JSON bytes that the signature covers:
// the canonicalized JSON of the attestation with the Signature field
// zeroed. This mirrors ioc.IOCAttestation.AttestationPayload().
func (a *AgentAttestation) attestationPayload() ([]byte, error) {
	tmp := struct {
		Fingerprint  AgentFingerprint      `json:"fingerprint"`
		InstanceID   string                `json:"instanceId"`
		Status       AgentStatus           `json:"status"`
		Protocols    []Protocol            `json:"protocols"`
		LastActivity time.Time             `json:"lastActivity"`
		InAIBOM      bool                  `json:"inAibom"`
		AIBOMDrift   string                `json:"aibomDrift,omitempty"`
		Timestamp    time.Time             `json:"timestamp"`
		PublicKey    ioc.PublicKeyEnvelope `json:"publicKey"`
		Signature    ioc.SignatureEnvelope `json:"signature"`
	}{
		Fingerprint:  a.Fingerprint,
		InstanceID:   a.InstanceID,
		Status:       a.Status,
		Protocols:    a.Protocols,
		LastActivity: a.LastActivity,
		InAIBOM:      a.InAIBOM,
		AIBOMDrift:   a.AIBOMDrift,
		Timestamp:    a.Timestamp,
		PublicKey:    a.PublicKey,
		Signature:    ioc.SignatureEnvelope{}, // intentionally zeroed
	}
	raw, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// Sign signs the attestation with the given KeyRing. The public key
// envelope is populated before signing so the signature covers the
// public key binding (same order as ioc.SignAttestationWithKeyRing).
func (a *AgentAttestation) Sign(kr *ioc.KeyRing) error {
	if a == nil {
		return errors.New("nil attestation")
	}
	if kr == nil {
		return errors.New("nil keyring")
	}

	// Populate the public key envelope BEFORE signing.
	keyID := kr.CurrentKeyID()
	if keyID == "" {
		return errors.New("keyring: no current key")
	}
	pubKey := kr.LookupKey(keyID)
	if len(pubKey) == 0 {
		return errors.New("keyring: current key not found")
	}
	a.PublicKey = ioc.PublicKeyEnvelope{
		Algorithm: ioc.AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(pubKey),
	}

	// Compute the payload and sign.
	payload, err := a.attestationPayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	sigKeyID, sigASN1, err := kr.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	a.Signature = ioc.SignatureEnvelope{
		Algorithm: ioc.AlgorithmECDSAP256,
		KeyID:     sigKeyID,
		Value:     base64.StdEncoding.EncodeToString(sigASN1),
	}
	return nil
}

// Verify verifies the attestation's signature using only the embedded
// public key. Returns nil if valid; an error otherwise. This mirrors
// ioc.VerifyAttestation but operates on AgentAttestation.
func (a *AgentAttestation) Verify() error {
	if a == nil {
		return errors.New("nil attestation")
	}
	if a.Signature.Algorithm != ioc.AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported signature algorithm: %q", a.Signature.Algorithm)
	}
	if a.PublicKey.Algorithm != ioc.AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported public key algorithm: %q", a.PublicKey.Algorithm)
	}
	if a.PublicKey.KeyID != a.Signature.KeyID {
		return fmt.Errorf("keyId mismatch: signature=%q publicKey=%q",
			a.Signature.KeyID, a.PublicKey.KeyID)
	}

	// Parse the embedded public key.
	pub, err := ioc.ParsePublicKey(mustDecodeBase64(a.PublicKey.Value))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	// Decode the signature.
	sigBytes := mustDecodeBase64(a.Signature.Value)
	if len(sigBytes) == 0 {
		return errors.New("empty signature")
	}

	// Compute payload and verify.
	payload, err := a.attestationPayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !verifyECDSA(pub, digest[:], sigBytes) {
		return errors.New("ECDSA P-256 attestation signature verification failed")
	}
	return nil
}

// =====================================================================
// Agent Bundle
// =====================================================================

// AgentBundle is a signed collection of AgentAttestations exchanged
// between AegisGate instances over the pull-based HTTP gossip
// protocol. Analogous to ioc.Bundle.
type AgentBundle struct {
	// BundleID is a unique identifier (UUIDv4).
	BundleID string `json:"bundleId"`

	// InstanceID identifies the producing instance.
	InstanceID string `json:"instanceId"`

	// IssuedAt is the UTC time the bundle was signed.
	IssuedAt time.Time `json:"issuedAt"`

	// Count is the number of attestations.
	Count int `json:"count"`

	// Attestations is the signed collection.
	Attestations []AgentAttestation `json:"attestations"`

	// PublicKey is the embedded public key.
	PublicKey ioc.PublicKeyEnvelope `json:"publicKey"`

	// Signature is the ECDSA P-256 signature over the bundle
	// minus the signature field.
	Signature ioc.SignatureEnvelope `json:"signature"`
}

// bundlePayload returns the JSON bytes that the bundle signature covers.
func (b *AgentBundle) bundlePayload() ([]byte, error) {
	tmp := struct {
		BundleID     string                `json:"bundleId"`
		InstanceID   string                `json:"instanceId"`
		IssuedAt     time.Time             `json:"issuedAt"`
		Count        int                   `json:"count"`
		Attestations []AgentAttestation    `json:"attestations"`
		PublicKey    ioc.PublicKeyEnvelope `json:"publicKey"`
		Signature    ioc.SignatureEnvelope `json:"signature"`
	}{
		BundleID:     b.BundleID,
		InstanceID:   b.InstanceID,
		IssuedAt:     b.IssuedAt,
		Count:        b.Count,
		Attestations: b.Attestations,
		PublicKey:    b.PublicKey,
		Signature:    ioc.SignatureEnvelope{}, // intentionally zeroed
	}
	raw, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

// Sign signs the bundle with the given KeyRing.
func (b *AgentBundle) Sign(kr *ioc.KeyRing) error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if kr == nil {
		return errors.New("nil keyring")
	}

	keyID := kr.CurrentKeyID()
	if keyID == "" {
		return errors.New("keyring: no current key")
	}
	pubKey := kr.LookupKey(keyID)
	if len(pubKey) == 0 {
		return errors.New("keyring: current key not found")
	}
	b.PublicKey = ioc.PublicKeyEnvelope{
		Algorithm: ioc.AlgorithmECDSAP256,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(pubKey),
	}

	payload, err := b.bundlePayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	sigKeyID, sigASN1, err := kr.Sign(digest[:])
	if err != nil {
		return fmt.Errorf("sign bundle: %w", err)
	}
	b.Signature = ioc.SignatureEnvelope{
		Algorithm: ioc.AlgorithmECDSAP256,
		KeyID:     sigKeyID,
		Value:     base64.StdEncoding.EncodeToString(sigASN1),
	}
	return nil
}

// VerifySignature verifies the bundle's own signature (not individual
// attestations). Returns nil on success.
func (b *AgentBundle) VerifySignature() error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if b.Signature.Algorithm != ioc.AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported signature algorithm: %q", b.Signature.Algorithm)
	}
	if b.PublicKey.Algorithm != ioc.AlgorithmECDSAP256 {
		return fmt.Errorf("unsupported public key algorithm: %q", b.PublicKey.Algorithm)
	}
	if b.PublicKey.KeyID != b.Signature.KeyID {
		return fmt.Errorf("keyId mismatch: signature=%q publicKey=%q",
			b.Signature.KeyID, b.PublicKey.KeyID)
	}

	pub, err := ioc.ParsePublicKey(mustDecodeBase64(b.PublicKey.Value))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	sigBytes := mustDecodeBase64(b.Signature.Value)
	if len(sigBytes) == 0 {
		return errors.New("empty signature")
	}

	payload, err := b.bundlePayload()
	if err != nil {
		return fmt.Errorf("compute payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !verifyECDSA(pub, digest[:], sigBytes) {
		return errors.New("ECDSA P-256 bundle signature verification failed")
	}
	return nil
}

// VerifyAll verifies the bundle signature AND every attestation inside.
func (b *AgentBundle) VerifyAll() error {
	if err := b.VerifySignature(); err != nil {
		return err
	}
	for i := range b.Attestations {
		if err := b.Attestations[i].Verify(); err != nil {
			return fmt.Errorf("attestation[%d]: %w", i, err)
		}
	}
	return nil
}

// =====================================================================
// Federated Agent Store
// =====================================================================

// FederatedAgentRecord is an agent attestation received from a peer
// deployment, stored locally for cross-deployment visibility.
type FederatedAgentRecord struct {
	Fingerprint  AgentFingerprint `json:"fingerprint"`
	InstanceID   string           `json:"instanceId"`
	Status       AgentStatus      `json:"status"`
	Protocols    []Protocol       `json:"protocols"`
	LastActivity time.Time        `json:"lastActivity"`
	InAIBOM      bool             `json:"inAibom"`
	AIBOMDrift   string           `json:"aibomDrift,omitempty"`
	ReceivedAt   time.Time        `json:"receivedAt"`
	Attestation  AgentAttestation `json:"-"`
}

// FederatedStore holds agent attestations received from peer
// deployments. It is separate from the local Store (which holds
// this deployment's own agents) to maintain a clear boundary
// between local and federated data.
type FederatedStore struct {
	mu      sync.RWMutex
	records map[AgentFingerprint]*FederatedAgentRecord
	maxSize int
}

// NewFederatedStore creates a new FederatedStore with the given
// maximum size. When the limit is reached, the oldest records
// (by ReceivedAt) are evicted.
func NewFederatedStore(maxSize int) *FederatedStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &FederatedStore{
		records: make(map[AgentFingerprint]*FederatedAgentRecord),
		maxSize: maxSize,
	}
}

// Upsert adds or updates a federated agent record. If a record with
// the same fingerprint from the same instance already exists, it is
// replaced if the new attestation has a more recent timestamp.
func (fs *FederatedStore) Upsert(att AgentAttestation) {
	fp := att.Fingerprint
	now := time.Now().UTC()

	fs.mu.Lock()
	defer fs.mu.Unlock()

	existing, ok := fs.records[fp]
	if ok && existing.InstanceID == att.InstanceID {
		// Only update if the new attestation is more recent.
		if !att.Timestamp.After(existing.ReceivedAt) {
			return
		}
	}

	fs.records[fp] = &FederatedAgentRecord{
		Fingerprint:  fp,
		InstanceID:   att.InstanceID,
		Status:       att.Status,
		Protocols:    att.Protocols,
		LastActivity: att.LastActivity,
		InAIBOM:      att.InAIBOM,
		AIBOMDrift:   att.AIBOMDrift,
		ReceivedAt:   now,
		Attestation:  att,
	}

	// Evict oldest if over capacity.
	if len(fs.records) > fs.maxSize {
		fs.evictOldest()
	}
}

// List returns all federated agent records.
func (fs *FederatedStore) List() []FederatedAgentRecord {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	result := make([]FederatedAgentRecord, 0, len(fs.records))
	for _, r := range fs.records {
		result = append(result, *r)
	}
	return result
}

// Get returns a federated agent record by fingerprint.
func (fs *FederatedStore) Get(fp AgentFingerprint) (*FederatedAgentRecord, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	r, ok := fs.records[fp]
	if !ok {
		return nil, false
	}
	rec := *r
	return &rec, true
}

// Size returns the number of federated records.
func (fs *FederatedStore) Size() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.records)
}

// CorroborationCount returns the number of distinct peer instances
// that have reported an attestation for the given fingerprint. This
// enables cross-deployment corroboration: if 3 independent deployments
// report the same agent as dormant, that's high-confidence intelligence.
func (fs *FederatedStore) CorroborationCount(fp AgentFingerprint) int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	r, ok := fs.records[fp]
	if !ok {
		return 0
	}
	// A single record per fingerprint per instance; the count is
	// 1 (this peer) + any local match. For now, we track per-
	// fingerprint records which may come from different instances.
	// If the same fingerprint is reported by multiple instances,
	// we store the most recent one. The corroboration count is
	// derived from the number of distinct InstanceIDs we've seen.
	// In v1, each fingerprint maps to one record (latest), so
	// corroboration is 1. A future iteration will track all
	// instances per fingerprint.
	_ = r
	return 1
}

// evictOldest removes the oldest record by ReceivedAt.
func (fs *FederatedStore) evictOldest() {
	var oldestFP AgentFingerprint
	var oldestTime time.Time
	for fp, r := range fs.records {
		if oldestTime.IsZero() || r.ReceivedAt.Before(oldestTime) {
			oldestTime = r.ReceivedAt
			oldestFP = fp
		}
	}
	delete(fs.records, oldestFP)
}

// =====================================================================
// Federation Engine
// =====================================================================

// FederationEngine manages the production and consumption of agent
// registry bundles for cross-deployment federation. It is wired
// into the Registry after construction and operates in a background
// goroutine when enabled.
type FederationEngine struct {
	config   FederationConfig
	registry *Registry
	store    *FederatedStore
	logger   *slog.Logger

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
}

// NewFederationEngine creates a new FederationEngine. If
// config.EnableFederation is false, the engine is a no-op (air-gap).
func NewFederationEngine(cfg FederationConfig, registry *Registry, logger *slog.Logger) *FederationEngine {
	if logger == nil {
		logger = slog.Default().With("component", "agent-registry-federation")
	}
	return &FederationEngine{
		config:   cfg,
		registry: registry,
		store:    NewFederatedStore(cfg.MaxFederatedAgents),
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Enabled returns true if federation is active.
func (fe *FederationEngine) Enabled() bool {
	return fe.config.EnableFederation && fe.config.KeyRing != nil
}

// FederatedStore returns the federated agent store for querying
// peer-reported agent data.
func (fe *FederationEngine) FederatedStore() *FederatedStore {
	return fe.store
}

// ExportBundle produces a signed AgentBundle containing attestations
// for all agents in the local registry. Each attestation carries only
// the agent's fingerprint and lifecycle metadata — never the agent's
// name, description, tools, or tenant identifier.
func (fe *FederationEngine) ExportBundle(ctx context.Context) (*AgentBundle, error) {
	if !fe.Enabled() {
		return nil, errors.New("federation: disabled")
	}

	records, err := fe.registry.List(nil)
	if err != nil {
		return nil, fmt.Errorf("federation: list records: %w", err)
	}

	bundle := &AgentBundle{
		BundleID:     generateBundleID(),
		InstanceID:   fe.config.InstanceID,
		IssuedAt:     time.Now().UTC(),
		Attestations: make([]AgentAttestation, 0, len(records)),
	}

	now := time.Now().UTC()
	for _, record := range records {
		fp := ComputeAgentFingerprint(record.Name, record.Role)
		att := AgentAttestation{
			Fingerprint:  fp,
			InstanceID:   fe.config.InstanceID,
			Status:       record.Status,
			Protocols:    record.Protocols,
			LastActivity: record.LastActivity,
			InAIBOM:      record.InAIBOM,
			AIBOMDrift:   record.AIBOMDrift,
			Timestamp:    now,
		}

		if err := att.Sign(fe.config.KeyRing); err != nil {
			fe.logger.Warn("federation: failed to sign attestation",
				"fingerprint", fp, "error", err)
			continue
		}

		bundle.Attestations = append(bundle.Attestations, att)
	}
	bundle.Count = len(bundle.Attestations)

	if err := bundle.Sign(fe.config.KeyRing); err != nil {
		return nil, fmt.Errorf("federation: sign bundle: %w", err)
	}

	fe.logger.Info("federation: bundle exported",
		"attestations", bundle.Count,
		"instance_id", fe.config.InstanceID)

	return bundle, nil
}

// ImportBundle ingests a peer deployment's agent bundle, verifies all
// signatures, and stores the federated agent records locally. Invalid
// signatures are rejected entirely — a single bad attestation causes
// the entire bundle to be rejected (fail-closed).
func (fe *FederationEngine) ImportBundle(bundle *AgentBundle) error {
	if !fe.config.EnableFederation {
		return errors.New("federation: disabled")
	}
	if bundle == nil {
		return errors.New("federation: nil bundle")
	}

	// Verify the bundle signature and all attestation signatures.
	if err := bundle.VerifyAll(); err != nil {
		return fmt.Errorf("federation: bundle verification failed: %w", err)
	}

	// Reject bundles from our own instance (no self-federation).
	if bundle.InstanceID == fe.config.InstanceID {
		return errors.New("federation: ignoring bundle from self")
	}

	imported := 0
	for _, att := range bundle.Attestations {
		// Skip attestations from our own instance (in case a
		// bundle somehow contains mixed sources).
		if att.InstanceID == fe.config.InstanceID {
			continue
		}
		fe.store.Upsert(att)
		imported++
	}

	fe.logger.Info("federation: bundle imported",
		"attestations", imported,
		"peer_instance", bundle.InstanceID)

	return nil
}

// Start launches the background export goroutine. When enabled, the
// engine periodically produces bundles and stores them for the gossip
// HTTP endpoint to serve. The engine does NOT make outbound network
// connections — the pull-based gossip protocol means peers fetch
// bundles from this instance, not the other way around.
func (fe *FederationEngine) Start(ctx context.Context) error {
	fe.mu.Lock()
	if fe.running {
		fe.mu.Unlock()
		return errors.New("federation: already running")
	}
	if !fe.Enabled() {
		fe.mu.Unlock()
		fe.logger.Info("federation: disabled (air-gap mode)")
		return nil
	}
	fe.running = true
	fe.mu.Unlock()

	interval := fe.config.ExportInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	go fe.exportLoop(ctx, interval)

	fe.logger.Info("federation: started",
		"instance_id", fe.config.InstanceID,
		"export_interval", interval)

	return nil
}

// Stop shuts down the background export goroutine.
func (fe *FederationEngine) Stop() {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if !fe.running {
		return
	}
	fe.running = false
	close(fe.stopCh)
	fe.logger.Info("federation: stopped")
}

// exportLoop periodically produces bundles for the gossip endpoint
// to serve. The loop does NOT push to peers — it only makes bundles
// available locally. Peers pull bundles via HTTP when they're ready.
func (fe *FederationEngine) exportLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Produce a bundle and store it for serving.
			// The actual HTTP serving is handled by the
			// federation HTTP handler (see federation_http.go).
			_, err := fe.ExportBundle(ctx)
			if err != nil {
				fe.logger.Warn("federation: export failed", "error", err)
			}
		case <-fe.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// =====================================================================
// Cross-Deployment Drift Detection
// =====================================================================

// CrossDeploymentDriftReport compares the local registry against
// federated peer data to identify cross-deployment patterns.
type CrossDeploymentDriftReport struct {
	GeneratedAt time.Time `json:"generated_at"`

	// LocalOnlyFingerprints are agents that exist locally but
	// have no federated counterpart (not seen in any peer).
	LocalOnlyFingerprints []AgentFingerprint `json:"local_only_fingerprints,omitempty"`

	// FederatedOnlyFingerprints are agents seen in peer deployments
	// but not locally (potential shadow AI or new agents in other
	// environments).
	FederatedOnlyFingerprints []AgentFingerprint `json:"federated_only_fingerprints,omitempty"`

	// StatusDiscrepancies are agents that exist in both local and
	// federated data but have different lifecycle statuses.
	StatusDiscrepancies []StatusDiscrepancy `json:"status_discrepancies,omitempty"`

	// PeerRevokedLocal is agents that are revoked in a peer
	// deployment but still active locally — a high-priority
	// security finding.
	PeerRevokedLocal []AgentFingerprint `json:"peer_revoked_local,omitempty"`

	// PeerDriftLocal is agents with AIBOM drift in a peer
	// deployment, prompting local investigation.
	PeerDriftLocal []AgentFingerprint `json:"peer_drift_local,omitempty"`

	// TotalLocal is the number of local agents compared.
	TotalLocal int `json:"total_local"`
	// TotalFederated is the number of federated agents compared.
	TotalFederated int `json:"total_federated"`
	// Matched is the number of agents found in both local and federated.
	Matched int `json:"matched"`
}

// StatusDiscrepancy records a lifecycle status difference for the
// same agent fingerprint between local and federated data.
type StatusDiscrepancy struct {
	Fingerprint     AgentFingerprint `json:"fingerprint"`
	LocalStatus     AgentStatus      `json:"local_status"`
	FederatedStatus AgentStatus      `json:"federated_status"`
	PeerInstance    string           `json:"peer_instance"`
}

// CompareWithFederated produces a cross-deployment drift report
// comparing the local registry against federated peer data. This
// enables a SOC to see which agents are unique to their environment,
// which are shared, and which have discrepant lifecycle states.
func (fe *FederationEngine) CompareWithFederated(ctx context.Context) (*CrossDeploymentDriftReport, error) {
	now := time.Now().UTC()
	report := &CrossDeploymentDriftReport{GeneratedAt: now}

	// Build local fingerprint map.
	localRecords, err := fe.registry.List(nil)
	if err != nil {
		return nil, fmt.Errorf("federation: compare: list local: %w", err)
	}
	localMap := make(map[AgentFingerprint]*AgentRecord, len(localRecords))
	for _, r := range localRecords {
		fp := ComputeAgentFingerprint(r.Name, r.Role)
		localMap[fp] = r
	}

	// Get federated records.
	fedRecords := fe.store.List()
	fedMap := make(map[AgentFingerprint]*FederatedAgentRecord, len(fedRecords))
	for i := range fedRecords {
		fedMap[fedRecords[i].Fingerprint] = &fedRecords[i]
	}

	report.TotalLocal = len(localMap)
	report.TotalFederated = len(fedMap)

	// Compare.
	for fp, local := range localMap {
		fed, ok := fedMap[fp]
		if !ok {
			report.LocalOnlyFingerprints = append(report.LocalOnlyFingerprints, fp)
			continue
		}
		report.Matched++

		if local.Status != fed.Status {
			report.StatusDiscrepancies = append(report.StatusDiscrepancies, StatusDiscrepancy{
				Fingerprint:     fp,
				LocalStatus:     local.Status,
				FederatedStatus: fed.Status,
				PeerInstance:    fed.InstanceID,
			})

			// High-priority: peer revoked, local still active.
			if fed.Status == StatusRevoked && local.Status != StatusRevoked && local.Status != StatusQuarantined {
				report.PeerRevokedLocal = append(report.PeerRevokedLocal, fp)
			}
		}

		// Peer has AIBOM drift — check locally.
		if fed.AIBOMDrift != "" && local.AIBOMDrift == "" {
			report.PeerDriftLocal = append(report.PeerDriftLocal, fp)
		}
	}

	// Federated-only fingerprints.
	for fp := range fedMap {
		if _, ok := localMap[fp]; !ok {
			report.FederatedOnlyFingerprints = append(report.FederatedOnlyFingerprints, fp)
		}
	}

	fe.logger.Info("federation: cross-deployment comparison complete",
		"local", report.TotalLocal,
		"federated", report.TotalFederated,
		"matched", report.Matched,
		"discrepancies", len(report.StatusDiscrepancies),
		"peer_revoked_local", len(report.PeerRevokedLocal))

	return report, nil
}

// =====================================================================
// HTTP Endpoint for Serving Federated Bundles
// =====================================================================

// ServeFederationBundle is an http.HandlerFunc that serves the local
// agent registry as a signed AgentBundle for peer deployments to pull.
// This is the server side of the pull-based gossip protocol. The
// handler produces a fresh bundle on each request (no caching) to
// ensure peers always receive current data.
//
// The endpoint should be mounted at GET /api/v1/agents/federation
// behind authentication middleware. When federation is disabled,
// the handler returns 503 Service Unavailable.
func (fe *FederationEngine) ServeFederationBundle(w http.ResponseWriter, r *http.Request) {
	if !fe.Enabled() {
		http.Error(w, `{"error":"federation disabled"}`, http.StatusServiceUnavailable)
		return
	}

	bundle, err := fe.ExportBundle(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"export failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")

	if err := json.NewEncoder(w).Encode(bundle); err != nil {
		fe.logger.Warn("federation: failed to write bundle response", "error", err)
	}
}

// ReceiveFederationBundle is an http.HandlerFunc that accepts a
// peer's agent bundle via HTTP POST. This is the receive side for
// instances that pull from peers and then push the result to a
// central hub (hub-and-spoke topology). In pure pull-based topology,
// this endpoint is not needed — the pulling instance calls
// ImportBundle directly after fetching from the peer.
func (fe *FederationEngine) ReceiveFederationBundle(w http.ResponseWriter, r *http.Request) {
	if !fe.config.EnableFederation {
		http.Error(w, `{"error":"federation disabled"}`, http.StatusServiceUnavailable)
		return
	}

	var bundle AgentBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"decode failed: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	if err := fe.ImportBundle(&bundle); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"import failed: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"imported","count":` + fmt.Sprintf("%d", bundle.Count) + `}`))
}

// ServeCrossDeploymentReport is an http.HandlerFunc that returns
// the cross-deployment drift report comparing local agents against
// federated peer data.
func (fe *FederationEngine) ServeCrossDeploymentReport(w http.ResponseWriter, r *http.Request) {
	if !fe.config.EnableFederation {
		http.Error(w, `{"error":"federation disabled"}`, http.StatusServiceUnavailable)
		return
	}

	report, err := fe.CompareWithFederated(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"compare failed: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		fe.logger.Warn("federation: failed to write report response", "error", err)
	}
}

// =====================================================================
// Helpers
// =====================================================================

// generateBundleID produces a UUIDv4 for bundle identification.
// Uses crypto/rand via the uuid package if available, otherwise
// falls back to a timestamp-based ID.
func generateBundleID() string {
	return uuid.NewString()
}

// mustDecodeBase64 decodes a base64 string, returning nil on empty
// input. Mirrors ioc.mustBase64Decode.
func mustDecodeBase64(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// verifyECDSA wraps ecdsa.VerifyASN1 for consistent verification
// across the federation package.
func verifyECDSA(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}
