// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library Wiring (v3.5.0+ Track 6)
// =========================================================================
//
// ioc_wiring.go is the bridge between the IOC library and the
// platform's main process. It handles:
//
//   1. Loading or generating the persistent ECDSA P-256 signing key
//      (stored in ${DataDir}/ioc/key.json). The key survives
//      process restarts so signed bundles are still verifiable
//      and IOCs can be deduplicated across restarts.
//
//   2. Loading or generating a stable, opaque InstanceID
//      (stored in ${DataDir}/ioc/instance-id). The InstanceID
//      is embedded in every Bundle and IOCAttestation this
//      instance produces. Two bundles with the same InstanceID
//      come from the same physical instance.
//
//   3. Resolving the opt-in flags: --ioc-share / --ioc-receive
//      on the command line, or AEGISGATE_IOC_SHARE /
//      AEGISGATE_IOC_RECEIVE in the environment. The flag wins
//      over the env var. Both default to false (opt-in).
//
//   4. Constructing the Store, Producer, and Sync objects and
//      wiring them into the platform. The Producer is installed
//      as the global logging.Recorder (layered on top of the
//      existing audit ring buffer, so all existing audit paths
//      keep working). The Sync handler is returned to the
//      caller for mounting on the proxy mux.
//
// The wiring is split out of main.go so the persistence and
// key-management logic is testable in isolation and so main.go
// stays focused on process composition.
//
// v3.5.0+ Track 6 Task 4.
// =========================================================================

package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"

	"github.com/aegisgatesecurity/aegisgate/pkg/proxy"
)

// iocWiring is the result of IOC wiring: the components the
// caller needs to start goroutines and mount the HTTP handler.
type iocWiring struct {
	Store       *ioc.Store
	Producer    *ioc.Producer
	Sync        *ioc.Sync
	KeyRing     *ioc.KeyRing     // TODO-301: shared with the AR-EaaS HTTP endpoint
	Checker     *ioc.IOCChecker  // v4.5.1+: IOC→Detection feedback loop checker
	FeedManager *ioc.FeedManager // v4.5.1+ Phase 2: external TAXII feed manager
	Enabled     bool             // true if either share or receive is enabled
}

// iocKeyFile is the on-disk filename for the persisted signing
// key. The file is JSON; when AEGISGATE_IOC_KEY_PASSPHRASE is
// set, it is encrypted with AES-256-GCM. Otherwise it is
// plaintext JSON (backward compatible).
// v4.5.1+ Phase 4: Hardening.
const iocKeyFile = "key.json"

// iocInstanceIDFile is the on-disk filename for the persisted
// instance ID. It is a 32-character random hex string.
const iocInstanceIDFile = "instance-id"

// iocStoreFile is the on-disk filename for the persisted IOC
// store. The store is a single JSON object: map from fingerprint
// to IOC. Atomic write (rename) on flush.
const iocStoreFile = "store.json"

// iocMinSharePeersDefault is the default peer list when
// --ioc-receive is enabled but no --ioc-peers is set. Empty by
// default: the operator must explicitly configure peers. We do
// NOT auto-discover peers (that would be a privacy and a security
// problem; a future iteration may add DNS-SD for instances on
// the same trusted network).
// wireIOC constructs the IOC subsystem. Returns:
//
//   - iocWiring with the Store, Producer, Sync, and Enabled flag
//   - The persisted instance ID (for logging)
//   - An error if the store or key could not be initialized
//
// The function is safe to call when IOC sharing is fully
// disabled: the Store, Producer, and Sync are still constructed
// (so the /api/v1/ioc/health endpoint returns the correct
// status), but the Enabled flag is false and no goroutines are
// started.
//
// The data dir layout:
//
//	${DataDir}/ioc/
//	  key.json          ECDSA P-256 private key (base64 JSON)
//	  instance-id       32-char random hex (text file)
//	  store.json        IOC store (JSON; atomic write on flush)
//
// All three files are 0600 (owner read/write only) where the
// platform supports it.
func wireIOC(dataDir string, platformTier tier.Tier) (*iocWiring, string, error) {
	// Resolve the opt-in flags. CLI wins, env var otherwise, false otherwise.
	share, receive, peers := resolveIOCFlags()

	// Ensure the data dir exists.
	iocDir := filepath.Join(dataDir, "ioc")
	if err := os.MkdirAll(iocDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create IOC data dir: %w", err)
	}

	// Load or generate the keyring. The keyring holds the
	// current key plus any retired keys (from past rotations).
	// Retired keys are kept so the instance can still verify
	// attestations it signed under an old keyId.
	//
	// v4.5.1+ Phase 4: If AEGISGATE_IOC_KEY_PASSPHRASE is set,
	// the keyring file is encrypted with AES-256-GCM at rest.
	keyPassphrase := os.Getenv("AEGISGATE_IOC_KEY_PASSPHRASE")
	var keyring *ioc.KeyRing
	var err error
	if keyPassphrase != "" {
		keyring, err = ioc.LoadKeyRingWithPassphrase(filepath.Join(iocDir, iocKeyFile), keyPassphrase)
	} else {
		keyring, err = ioc.LoadKeyRing(filepath.Join(iocDir, iocKeyFile))
	}
	if err != nil {
		return nil, "", fmt.Errorf("load IOC keyring: %w", err)
	}
	_ = keyring.CurrentKeyID() // log it later; just touch to keep a handle
	if _, _, err := keyring.CurrentKey(); err != nil {
		return nil, "", fmt.Errorf("get current key: %w", err)
	}

	// Load or generate the stable instance ID.
	instanceID, err := loadOrGenerateInstanceID(filepath.Join(iocDir, iocInstanceIDFile))
	if err != nil {
		return nil, "", fmt.Errorf("load IOC instance ID: %w", err)
	}

	// Construct the store.
	store, err := ioc.NewStore(ioc.StoreConfig{
		Capacity:      100_000,
		FlushInterval: 30 * time.Second,
		MaxAge:        0, // 0 = ioc default (30 days)
		DiskPath:      filepath.Join(iocDir, iocStoreFile),
	})
	if err != nil {
		return nil, "", fmt.Errorf("create IOC store: %w", err)
	}

	// Construct the producer. The producer is the bridge from
	// logging.Record() events to IOCs. The allow-list is
	// configured in the producer (proxy_response >= medium,
	// anomaly_score >= high, response_* >= medium — see
	// pkg/ioc/producer.go for the policy).
	producer := ioc.NewProducer(ioc.ProducerConfig{}, store)

	// Construct the sync. The Sync serves the /api/v1/ioc/manifest
	// and /api/v1/ioc/health endpoints, and the receiver fetches
	// peer bundles if receive is enabled.
	//
	// GossipInterval is the period between peer fetches. The
	// CLI flag --ioc-gossip-interval (env: AEGISGATE_IOC_GOSSIP_INTERVAL)
	// overrides the package default of 5m. A future iteration
	// will make the interval dynamically adjustable at runtime.
	gossipInterval := *iocGossipInterval
	if envRaw := os.Getenv("AEGISGATE_IOC_GOSSIP_INTERVAL"); envRaw != "" {
		if d, err := time.ParseDuration(envRaw); err == nil && d > 0 {
			gossipInterval = d
		}
		// On parse error, fall back to the CLI value (which
		// itself defaults to 5m).
	}
	// v4.5.1+ Phase 4: Rate limiting + peer allow-list for gossip endpoints.
	// AEGISGATE_IOC_RATE_LIMIT (int, default 60) controls requests/minute/IP.
	// AEGISGATE_IOC_PEER_ALLOWLIST (comma-separated IPs/CIDRs) bypasses rate limiting.
	rateLimit := 60
	if envRaw := os.Getenv("AEGISGATE_IOC_RATE_LIMIT"); envRaw != "" {
		if v, err := strconv.Atoi(envRaw); err == nil && v > 0 {
			rateLimit = v
		}
	}
	var peerAllowList []string
	if alRaw := os.Getenv("AEGISGATE_IOC_PEER_ALLOWLIST"); alRaw != "" {
		for _, entry := range strings.Split(alRaw, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				peerAllowList = append(peerAllowList, entry)
			}
		}
	}
	syncCfg := ioc.SyncConfig{
		InstanceID:         instanceID,
		SigningKey:         nil, // not used when KeyRing is set
		KeyID:              "",  // not used when KeyRing is set
		KeyRing:            keyring,
		Store:              store,
		Tier:               platformTier,
		EnableShare:        share,
		EnableReceive:      receive,
		Peers:              peers,
		ClientTimeout:      10 * time.Second,
		GossipInterval:     gossipInterval,
		RateLimitPerMinute: rateLimit,
		PeerAllowList:      peerAllowList,
	}
	syncSub, err := ioc.NewSync(syncCfg)
	if err != nil {
		return nil, "", fmt.Errorf("create IOC sync: %w", err)
	}

	// v4.5.1+ Phase 1: Construct the IOC feedback loop checker.
	// The checker is always constructed (even if sharing is disabled)
	// so the admin status endpoint can report its config. It only
	// has an effect when injected into the proxy via SetCorroborationChecker.
	checker := ioc.NewIOCChecker(store, ioc.DefaultCheckerConfig())

	// v4.5.1+ Phase 2: External TAXII feed manager.
	// Load feed configs from env var AEGISGATE_IOC_FEEDS (JSON array).
	// If no feeds are configured, FeedManager is nil (no external feeds).
	var feedManager *ioc.FeedManager
	feedConfigs := loadFeedConfigs()
	if len(feedConfigs) > 0 {
		fm, err := ioc.NewFeedManager(store, feedConfigs)
		if err != nil {
			log.Printf("IOC feed manager: failed to construct: %v", err)
		} else {
			feedManager = fm
			log.Printf("IOC feed manager: %d feeds configured", len(feedConfigs))
		}
	}

	return &iocWiring{
		Store:       store,
		Producer:    producer,
		Sync:        syncSub,
		KeyRing:     keyring, // TODO-301: shared with the AR-EaaS HTTP endpoint
		Checker:     checker,
		FeedManager: feedManager, // v4.5.1+ Phase 2
		Enabled:     share || receive,
	}, instanceID, nil
}

// bootstrapIOCs loads a signed baseline IOC bundle from disk and
// ingests it into the local store. This is called at startup when
// --ioc-bootstrap-bundle (or AEGISGATE_IOC_BOOTSTRAP_BUNDLE) is set.
//
// The bundle must be signed (ECDSA P-256). The signature is verified
// before ingestion. If verification fails, the bundle is rejected and
// a warning is logged.
//
// IOCs from the bootstrap bundle are ingested as LOCAL observations
// (Source = "bootstrap"), not peer observations. This means:
//   - They appear in the store immediately.
//   - They are NOT gated by peer reputation (they're local).
//   - They DO participate in the corroboration feedback loop: if a
//     real detection matches a bootstrap IOC's fingerprint, the
//     checker will find it and report Found=true.
//
// This is the intended behavior: the bootstrap seeds the store with
// known detection patterns so that even before any production traffic
// or peer IOCs arrive, the corroboration checker can match detections
// against the baseline.
//
// The bootstrap is idempotent: if the store already has IOCs with
// the same fingerprints (e.g., from a previous bootstrap or from real
// production observations), the merge updates the count and
// last-seen timestamp but does not create duplicates.
//
// v4.5.2: Added as part of IOC baseline seeding.
func bootstrapIOCs(store *ioc.Store, bundlePath string) error {
	data, err := os.ReadFile(filepath.Clean(bundlePath))
	if err != nil {
		return fmt.Errorf("read bootstrap bundle: %w", err)
	}

	var bundle ioc.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("unmarshal bootstrap bundle: %w", err)
	}

	// Verify the bundle signature before ingesting. This ensures
	// we don't ingest a tampered or forged baseline.
	if err := ioc.VerifyBundleSignature(&bundle); err != nil {
		return fmt.Errorf("bootstrap bundle signature verification failed: %w", err)
	}

	// Ingest each attestation as a local observation. We use
	// store.Observe() directly (not receiver.Ingest) because these
	// are local bootstrap IOCs, not peer IOCs.
	ingested := 0
	for i := range bundle.Attestations {
		att := &bundle.Attestations[i]
		newIOC := ioc.IOC{
			Fingerprint: att.Fingerprint,
			Type:        att.IOCType,
			Severity:    att.Severity,
			FirstSeen:   att.FirstSeen,
			LastSeen:    att.LastSeen,
			Count:       att.Count,
			Source:      "bootstrap",
		}
		if _, err := store.Observe(newIOC); err != nil {
			// Log and continue — one bad IOC shouldn't abort the bootstrap.
			log.Printf("IOC bootstrap: skip attestation %s: %v", att.Fingerprint[:16], err)
			continue
		}
		ingested++
	}

	log.Printf("IOC bootstrap: ingested %d/%d IOCs from %s", ingested, len(bundle.Attestations), bundlePath)
	return nil
}

// installIOCRecorder layers the IOC producer on top of the
// existing audit ring buffer. After this call:
//
//   - logging.SetDefault(producer) — every logging.Record() call
//     flows through the producer's allow-list. Events that pass
//     the allow-list are fingerprinted and written to the IOC
//     store. All events are then fanned out to the existing ring
//     buffer (inner), so the existing audit path is preserved.
//
//   - The producer's Enabled flag is set according to the
//     resolved share flag. The producer itself does not gate
//     share vs receive (the sync layer does); it only decides
//     whether to fingerprint+store the event.
//
// Returns the producer for the caller to start the receiver /
// flusher goroutines.
func installIOCRecorder(inner logging.Recorder, producer *ioc.Producer, share, receive bool) {
	if inner == nil {
		// Should not happen (caller installs the ring buffer
		// first), but be defensive.
		return
	}
	producer.Attach(inner)
	// Enable the producer. Both share and receive need the
	// producer running: we only fingerprint/store events when
	// the producer is enabled, so a Community instance with
	// only --ioc-share still needs the producer on to build up
	// a store worth sharing. (The receive tier gate is enforced
	// in pkg/ioc/sync.go, not here.)
	if share || receive {
		producer.SetEnabled(true)
	}
	logging.SetDefault(producer)
}

// resolveIOCFlags resolves the IOC opt-in flags from CLI args
// and env vars. CLI wins; env var is the fallback. Returns
// (share, receive, peers).
//
// --ioc-share      / AEGISGATE_IOC_SHARE     (bool, default false)
// --ioc-receive    / AEGISGATE_IOC_RECEIVE   (bool, default false)
// --ioc-peers      / AEGISGATE_IOC_PEERS     (comma-separated list, default empty)
func resolveIOCFlags() (share, receive bool, peers []string) {
	share = resolveBoolFlag(*iocShare, "AEGISGATE_IOC_SHARE")
	receive = resolveBoolFlag(*iocReceive, "AEGISGATE_IOC_RECEIVE")
	peersRaw := *iocPeers
	if peersRaw == "" {
		peersRaw = os.Getenv("AEGISGATE_IOC_PEERS")
	}
	if peersRaw != "" {
		for _, p := range strings.Split(peersRaw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				peers = append(peers, p)
			}
		}
	}
	return
}

// resolveBoolFlag resolves a boolean flag: CLI value if it
// differs from the default, else env var, else the env default.
// Treats "true", "1", "yes", "on" (case-insensitive) as true.
func resolveBoolFlag(cliValue bool, envName string) bool {
	// If the CLI was explicitly set, it wins. We detect "set"
	// by comparing against the default. The default for
	// flag.Bool is false; if the CLI is true, it was set.
	// This is a common Go-flag idiom; it works because the
	// default is false in our case.
	if cliValue {
		return true
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(envName)))
	switch raw {
	case "true", "1", "yes", "on":
		return true
	}
	// strconv.ParseBool handles the "true"/"false" cases for
	// completeness; falls through to false on any other value.
	b, _ := strconv.ParseBool(raw)
	return b
}

// loadOrGenerateInstanceID loads the persisted instance ID, or
// generates a fresh one and persists it. The ID is a 32-character
// random hex string (16 random bytes). It is opaque; no customer
// data is encoded in it.
func loadOrGenerateInstanceID(path string) (string, error) {
	// G304 (CodeQL): sanitize the path. The path is
	// a server-controlled config value, but CodeQL's
	// taint analysis still flags it. The safeFilePath
	// call satisfies the linter and rejects
	// path-traversal patterns defensively.
	cleanPath, err := safeFilePath(path)
	if err != nil {
		return "", err
	}
	path = cleanPath
	if data, err := os.ReadFile(filepath.Clean(path)); err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) >= 16 {
			return id, nil
		}
		// Corrupt: regenerate.
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read instance ID: %w", err)
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("generate instance ID: %w", err)
	}
	id := fmt.Sprintf("%x", idBytes)
	if err := os.WriteFile(filepath.Clean(path), []byte(id), 0o600); err != nil {
		return "", fmt.Errorf("write instance ID: %w", err)
	}
	return id, nil
}

// iocCorroborationAdapter adapts pkg/ioc.IOCChecker to the
// proxy.CorroborationChecker interface. This adapter exists because
// the upstream proxy package cannot import pkg/ioc (circular
// dependency); the adapter bridges the two packages.
//
// v4.5.1+ Phase 1: IOC→Detection Feedback Loop.
type iocCorroborationAdapter struct {
	checker *ioc.IOCChecker
}

// CheckCorroborationResult implements proxy.CorroborationChecker.
// It delegates to the IOCChecker and maps the result to the
// proxy's CorroborationResult type.
func (a *iocCorroborationAdapter) CheckCorroborationResult(fingerprint string, hasLocalDetection bool) proxy.CorroborationResult {
	if a == nil || a.checker == nil {
		return proxy.CorroborationResult{}
	}
	result := a.checker.CheckFingerprint(fingerprint, hasLocalDetection)
	return proxy.CorroborationResult{
		Found:          result.Found,
		PeerCount:      result.PeerCount,
		TotalCount:     result.TotalCount,
		RecommendBlock: result.RecommendBlock,
		Reason:         result.Reason,
	}
}

// loadFeedConfigs loads external TAXII feed configurations from
// the AEGISGATE_IOC_FEEDS environment variable. The value is a
// JSON array of ioc.FeedConfig objects. If the env var is not set
// or empty, no feeds are configured (returns nil).
//
// Example:
//
//	AEGISGATE_IOC_FEEDS='[{name:cisa-acs,server_url:https://limo.anomali.com/api/v1/taxii/taxii2/,auth_type:token,api_token:...,collection_id:...,poll_interval:1h,reputation_weight:1.0,enabled:true}]'
func loadFeedConfigs() []ioc.FeedConfig {
	raw := os.Getenv("AEGISGATE_IOC_FEEDS")
	if raw == "" {
		return nil
	}
	var configs []ioc.FeedConfig
	if err := json.Unmarshal([]byte(raw), &configs); err != nil {
		log.Printf("IOC feed manager: failed to parse AEGISGATE_IOC_FEEDS: %v", err)
		return nil
	}
	return configs
}
