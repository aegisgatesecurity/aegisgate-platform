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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// iocWiring is the result of IOC wiring: the components the
// caller needs to start goroutines and mount the HTTP handler.
type iocWiring struct {
	Store    *ioc.Store
	Producer *ioc.Producer
	Sync     *ioc.Sync
	KeyRing  *ioc.KeyRing // TODO-301: shared with the AR-EaaS HTTP endpoint
	Enabled  bool         // true if either share or receive is enabled
}

// iocKeyFile is the on-disk filename for the persisted signing
// key. The file is base64 JSON; not encrypted at rest. A future
// iteration may add KMS-backed encryption.
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
var iocMinSharePeersDefault = []string{}

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
	keyring, err := ioc.LoadKeyRing(filepath.Join(iocDir, iocKeyFile))
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
	syncCfg := ioc.SyncConfig{
		InstanceID:     instanceID,
		SigningKey:     nil, // not used when KeyRing is set
		KeyID:          "",  // not used when KeyRing is set
		KeyRing:        keyring,
		Store:          store,
		Tier:           platformTier,
		EnableShare:    share,
		EnableReceive:  receive,
		Peers:          peers,
		ClientTimeout:  10 * time.Second,
		GossipInterval: gossipInterval,
	}
	syncSub, err := ioc.NewSync(syncCfg)
	if err != nil {
		return nil, "", fmt.Errorf("create IOC sync: %w", err)
	}

	return &iocWiring{
		Store:    store,
		Producer: producer,
		Sync:     syncSub,
		KeyRing:  keyring, // TODO-301: shared with the AR-EaaS HTTP endpoint
		Enabled:  share || receive,
	}, instanceID, nil
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
