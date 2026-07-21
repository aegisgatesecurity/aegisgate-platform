// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Federated IOC Library (v3.5.0+ Track 6 Task 5)
// =========================================================================
//
// keyring.go implements key rotation for the IOC library. The
// keyring holds a set of ECDSA P-256 keys, one of which is
// "current" (used for signing new attestations and bundles) and
// the rest are "retired" (kept for verifying old attestations
// that were signed before the rotation).
//
// Rotation model
// ==============
//
// The keyring supports in-place rotation:
//
//   - Rotate() generates a fresh ECDSA P-256 key, marks the
//     current key as "retired" (with a timestamp), and sets the
//     new key as current. The retired key is kept on disk and
//     in memory so the instance can still verify attestations
//     it signed under the old keyId.
//
//   - Sign() always uses the current key. The signature
//     envelope's keyId field tells the verifier which key was
//     used.
//
//   - Verify() looks up the key by keyId. The lookup succeeds
//     for any current or retired key in the ring. An unknown
//     keyId returns an error (not a silent failure).
//
//   - A future iteration will add a TTL for retired keys (e.g.,
//     90 days), after which they are purged from the on-disk
//     file. The v3.5.0 implementation keeps retired keys
//     indefinitely; the keyring is small (a few KB per key)
//     and the operational benefit of indefinite retention is
//     that an instance that has been offline for a long time
//     can still verify old attestations when it comes back.
//
// On-disk format
// ==============
//
// The on-disk file is JSON, version 2:
//
//	{
//	  "version": 2,
//	  "current": "ioc-XXXXXXXX",
//	  "keys": [
//	    {
//	      "keyId": "ioc-XXXXXXXX",
//	      "privateKeyPem": "-----BEGIN EC PRIVATE KEY-----\n...",
//	      "publicKeySec1": "<base64 SEC 1 uncompressed>",
//	      "createdAt": "2026-06-15T08:00:00Z",
//	      "retiredAt": null
//	    },
//	    {
//	      "keyId": "ioc-YYYYYYYY",
//	      "privateKeyPem": "...",
//	      "publicKeySec1": "...",
//	      "createdAt": "2026-06-15T08:00:00Z",
//	      "retiredAt": "2026-09-15T08:00:00Z"
//	    }
//	  ]
//	}
//
// The v1 format (a single key in the file, no version field,
// written by the Track 6 Task 4 wiring) is auto-migrated on
// first read: the single key becomes a v2 ring with one
// current key, and the file is rewritten in v2 format.
//
// Concurrency
// ===========
//
// The keyring is safe for concurrent use. The hot path (Sign
// and Verify) acquires a read lock and looks up the current
// or by-id key in O(1). Rotation acquires a write lock and
// is rare (manual operator action or scheduled job).
//
// v3.5.0+ Track 6 Task 5.
// =========================================================================

package ioc

//lint:file-ignore SA1019 U1000 -- D25 cleanup: elliptic deprecations + unused, deferred to Path B (Sprint 19+). See plans/TECHNICAL-DEBT.md.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// KeyRingFileVersion is the current on-disk version of the
// keyring file. Bump this on breaking changes to the format;
// keep migration logic in loadKeyRing for older versions.
const KeyRingFileVersion = 2

// DefaultRetiredKeyTTL is how long a retired key is kept in
// the on-disk keyring before it is pruned. After this TTL,
// manifests signed by the retired key can no longer be
// verified by THIS instance (auditors can still verify them
// if they have the retired key's public key, but the
// instance no longer keeps a copy of the private key or the
// public key in the on-disk file).
//
// v3.4.0+ adds this TTL. Previously, retired keys were
// kept indefinitely. The 90-day default matches typical
// compliance retention windows (e.g., SOC 2 evidence
// retention is 12 months minimum; 90 days for the key
// itself is a reasonable compromise between letting late
// verifications succeed and not accumulating stale keys).
//
// Tunable per instance via KeyRingConfig.RetiredKeyTTL.
const DefaultRetiredKeyTTL = 90 * 24 * time.Hour

// KeyRingConfig configures a new KeyRing at construction
// time. The zero value is valid: TTL defaults to
// DefaultRetiredKeyTTL and persistence is in-memory only.
type KeyRingConfig struct {
	// RetiredKeyTTL is how long a retired key is kept in
	// the on-disk keyring. Zero means DefaultRetiredKeyTTL.
	RetiredKeyTTL time.Duration
}

// KeyRing is the IOC signing keyring. Holds the current key
// plus any retired keys. Safe for concurrent use.
type KeyRing struct {
	mu      sync.RWMutex
	keys    map[string]*ringKey // by keyId
	current string              // keyId of the current key
	persist string              // on-disk file path; "" = no persistence
	// retiredKeyTTL is how long a retired key is kept. Zero
	// = use DefaultRetiredKeyTTL. Set via SetRetiredKeyTTL.
	// v3.4.0+ primitive.
	retiredKeyTTL time.Duration
}

// ringKey is a single key in the keyring. The public and
// private halves are kept together so Sign() doesn't need a
// second lookup. The retiredAt is zero for the current key.
type ringKey struct {
	KeyID         string    `json:"keyId"`
	PrivateKeyPEM string    `json:"privateKeyPem"`
	PublicKeySEC1 string    `json:"publicKeySec1"` // base64(SEC 1 uncompressed)
	CreatedAt     time.Time `json:"createdAt"`
	RetiredAt     time.Time `json:"retiredAt,omitempty"`
	priv          *ecdsa.PrivateKey
}

// keyRingOnDisk is the on-disk format. Kept distinct from the
// in-memory KeyRing so the wire format is documented and so
// adding fields (e.g., a future key-purpose tag) doesn't
// require touching the in-memory struct.
type keyRingOnDisk struct {
	Version int       `json:"version"`
	Current string    `json:"current"`
	Keys    []ringKey `json:"keys"`
}

// loadKeyRing loads the keyring from disk, or creates a fresh
// one if the file does not exist. The persist path is the
// file the keyring will write to on every rotation.
//
// If the file exists but is in v1 format (the Task 4 format:
// a single key with no "version" field, written by
// loadOrGenerateIOCKey), it is auto-migrated to v2: the
// single key becomes the current key in a v2 ring.
func loadKeyRing(persist string) (*KeyRing, error) {
	// G304 (CodeQL): sanitize the path before
	// os.ReadFile. The persist arg is typically
	// derived from a config value or CLI flag, not
	// from an untrusted user; cleanFilePath rejects
	// path-traversal patterns defensively.
	cleanPath, err := cleanFilePath(persist)
	if err != nil {
		return nil, err
	}
	persist = cleanPath
	kr := &KeyRing{
		keys:    make(map[string]*ringKey),
		persist: persist,
	}
	if persist == "" {
		// No persistence. Generate a fresh ephemeral key.
		// (In-memory only; the key is lost on restart, which
		// is appropriate for unit tests.)
		_, err := kr.Rotate()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		return kr, nil
	}
	// G304 (CodeQL): filepath.Clean is the recognized
	// sanitizer for the Go pack. Call it explicitly
	// at the I/O site in addition to the safeFilePath
	// defense-in-depth check.
	data, err := os.ReadFile(filepath.Clean(persist))
	if err != nil {
		if os.IsNotExist(err) {
			// First run. Generate a fresh key, persist, return.
			_, rerr := kr.Rotate()
			if rerr != nil {
				return nil, fmt.Errorf("generate initial key: %w", rerr)
			}
			return kr, nil
		}
		return nil, fmt.Errorf("read keyring: %w", err)
	}

	// Try v2 first.
	var onDisk keyRingOnDisk
	if jerr := json.Unmarshal(data, &onDisk); jerr == nil && onDisk.Version == 2 {
		return kr.loadFromV2(onDisk)
	}

	// Fall back to v1 migration: the file is a single
	// iocKeyOnDiskV1 (from the Task 4 loadOrGenerateIOCKey
	// function in cmd/aegisgate-platform/ioc_wiring.go).
	var v1 iocKeyOnDiskV1
	if jerr := json.Unmarshal(data, &v1); jerr != nil {
		return nil, fmt.Errorf("unmarshal keyring (tried v1 + v2): %w", jerr)
	}
	return kr.loadFromV1(v1)
}

// loadFromV2 populates the keyring from a parsed v2 file.
func (kr *KeyRing) loadFromV2(onDisk keyRingOnDisk) (*KeyRing, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if onDisk.Current == "" {
		return nil, errors.New("v2 keyring: current keyId is empty")
	}
	if len(onDisk.Keys) == 0 {
		return nil, errors.New("v2 keyring: keys array is empty")
	}
	// Verify the current keyId is in the keys array.
	found := false
	for i := range onDisk.Keys {
		rk := &onDisk.Keys[i]
		priv, perr := parseRingKeyPEM(rk.PrivateKeyPEM)
		if perr != nil {
			return nil, fmt.Errorf("key[%s]: %w", rk.KeyID, perr)
		}
		rk.priv = priv
		kr.keys[rk.KeyID] = rk
		if rk.KeyID == onDisk.Current {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("v2 keyring: current keyId %q not in keys", onDisk.Current)
	}
	kr.current = onDisk.Current
	return kr, nil
}

// iocKeyOnDiskV1 is the on-disk format used by the Task 4
// wiring (loadOrGenerateIOCKey in cmd/aegisgate-platform/ioc_wiring.go).
// It is a single key with no version field. The keyring
// migration detects this format and converts it to v2.
//
// This type is duplicated here (rather than imported from
// cmd/aegisgate-platform) because:
//  1. cmd/aegisgate-platform is the main package; pkg/ioc
//     cannot import it without a circular dependency.
//  2. The v1 format is small (4 fields) and stable.
//
// If the v1 format is ever changed, the migration logic in
// loadFromV1 must be updated to handle both the old and new
// v1 shapes (or the v1 file is rejected and the operator is
// told to start fresh).
type iocKeyOnDiskV1 struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"keyId"`
	PrivateKeyPEM string `json:"privateKeyPem"`
	PublicKeySEC1 string `json:"publicKeySec1"`
}

// loadFromV1 migrates a v1 single-key file to a v2 ring with
// one current key. The v1 key keeps its original CreatedAt
// (set to file mtime as a reasonable approximation) and is
// marked as not retired. The file is rewritten in v2 format.
func (kr *KeyRing) loadFromV1(v1 iocKeyOnDiskV1) (*KeyRing, error) {
	priv, err := parseRingKeyPEM(v1.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse v1 key: %w", err)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("v1 key: expected P-256, got %s", priv.Curve.Params().Name)
	}
	//nolint:staticcheck // SA1019: see SignAttestation.
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	rk := &ringKey{
		KeyID:         v1.KeyID,
		PrivateKeyPEM: v1.PrivateKeyPEM,
		PublicKeySEC1: base64.StdEncoding.EncodeToString(pubBytes),
		CreatedAt:     time.Now().UTC(),
		priv:          priv,
	}
	kr.mu.Lock()
	kr.keys[rk.KeyID] = rk
	kr.current = rk.KeyID
	kr.mu.Unlock()
	// Rewrite in v2 format.
	if err := kr.persistLocked(); err != nil {
		return nil, fmt.Errorf("rewrite v2: %w", err)
	}
	return kr, nil
}

// Rotate generates a fresh ECDSA P-256 key, marks the current
// key as retired (with the current timestamp), and sets the
// new key as current. The new keyId is returned.
//
// If a persist path is configured, the keyring is written to
// disk atomically (write-to-temp + rename).
//
// Concurrency: holds the write lock for the entire rotation.
// This is intentional - rotation is rare and we want the
// 'retire old + add new' to be atomic.
//
// v3.4.0+ also prunes retired keys past the TTL on each
// rotation. The prune is best-effort (errors are not
// returned) - the in-memory state is updated regardless of
// whether the on-disk rewrite succeeds.
func (kr *KeyRing) Rotate() (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	now := time.Now().UTC()
	//nolint:staticcheck // SA1019: see SignAttestation.
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	h := sha256.Sum256(pubBytes)
	newKeyID := fmt.Sprintf("k-%s", hex.EncodeToString(h[:8]))
	pemStr, err := encodeRingKeyPEM(priv)
	if err != nil {
		return "", fmt.Errorf("encode key pem: %w", err)
	}
	newRk := &ringKey{
		KeyID:         newKeyID,
		PrivateKeyPEM: pemStr,
		PublicKeySEC1: base64.StdEncoding.EncodeToString(pubBytes),
		CreatedAt:     now,
		priv:          priv,
	}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	// Retire the current key (if any).
	if old, ok := kr.keys[kr.current]; ok && kr.current != "" {
		old.RetiredAt = now
	}
	kr.keys[newKeyID] = newRk
	kr.current = newKeyID
	if err := kr.persistLocked(); err != nil {
		return "", fmt.Errorf("persist rotated keyring: %w", err)
	}
	// Prune any retired keys whose TTL has expired.
	_ = kr.pruneExpiredLocked(now)
	return newKeyID, nil
}

// CurrentKeyID returns the keyId of the current key. Used by
// callers that need to embed the keyId in a signature envelope
// without going through the full Sign() path (e.g., tests).
func (kr *KeyRing) CurrentKeyID() string {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.current
}

// CurrentKey returns the current keyId and the ECDSA private
// key. Used by the wiring layer to construct the IOC sync
// signer. Returns an error if the keyring is empty (which
// should never happen after a successful loadKeyRing).
func (kr *KeyRing) CurrentKey() (string, *ecdsa.PrivateKey, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.current == "" {
		return "", nil, errors.New("keyring: no current key")
	}
	rk, ok := kr.keys[kr.current]
	if !ok {
		return "", nil, fmt.Errorf("keyring: current keyId %q not in keys", kr.current)
	}
	return rk.KeyID, rk.priv, nil
}

// LookupKey returns the public key (as SEC 1 bytes) for a
// given keyId. Returns nil if the keyId is not in the ring.
// Used by Verify() to look up the right key by the
// signature envelope's keyId.
func (kr *KeyRing) LookupKey(keyID string) []byte {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	rk, ok := kr.keys[keyID]
	if !ok {
		return nil
	}
	pubBytes, _ := base64.StdEncoding.DecodeString(rk.PublicKeySEC1)
	return pubBytes
}

// Sign signs a digest with the current key. Returns the
// ASN.1-encoded ECDSA signature and the keyId. The keyId
// goes in the signature envelope; the verifier uses it to
// look up the right public key.
func (kr *KeyRing) Sign(digest []byte) (keyID string, sig []byte, err error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.current == "" {
		return "", nil, errors.New("keyring: no current key")
	}
	rk, ok := kr.keys[kr.current]
	if !ok {
		return "", nil, fmt.Errorf("keyring: current keyId %q not in keys", kr.current)
	}
	sig, err = signASN1(rk.priv, digest)
	if err != nil {
		return "", nil, fmt.Errorf("sign: %w", err)
	}
	return rk.KeyID, sig, nil
}

// Verify verifies a signature against a digest. The keyId
// in the signature envelope selects which public key to use.
// Returns nil if the keyId is in the ring and the signature
// is valid; an error otherwise.
//
// This is the function callers should use instead of
// verifying against an embedded public key. The wire format
// still includes the embedded public key (for auditability
// and for verifiers that do NOT have the keyring), but a
// verifier that has the keyring can do a single lookup
// instead of parsing the embedded key.
func (kr *KeyRing) Verify(keyID string, digest, sig []byte) error {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	rk, ok := kr.keys[keyID]
	if !ok {
		return fmt.Errorf("keyring: unknown keyId %q", keyID)
	}
	if !verifyASN1(&rk.priv.PublicKey, digest, sig) {
		return errors.New("ECDSA P-256 signature verification failed")
	}
	return nil
}

// KeyRing exports
// ----------------------------------------------------------------------------

// LoadKeyRing loads a keyring from disk, or creates a fresh
// one if the file does not exist. The persist path is the
// file the keyring will write to on every rotation.
//
// If the file exists but is in v1 format (the Task 4 format:
// a single key with no "version" field), it is auto-migrated
// to v2: the single key becomes the current key in a v2 ring.
//
// Exported so the wiring layer (cmd/aegisgate-platform/ioc_wiring.go)
// can construct the keyring.
func LoadKeyRing(persist string) (*KeyRing, error) {
	return loadKeyRing(persist)
}

// ----------------------------------------------------------------------------
// KeyRing exports
// ----------------------------------------------------------------------------

// ActiveKeys returns a snapshot of the keyring's keys, sorted
// by CreatedAt. The snapshot includes the KeyID, CreatedAt,
// RetiredAt, and PublicKeySEC1 for each key. The private
// key is NOT included (the snapshot is safe to expose to
// the API or to log).
//
// Used by the admin API to display the current keyring
// state.
func (kr *KeyRing) ActiveKeys() []KeyInfo {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	out := make([]KeyInfo, 0, len(kr.keys))
	for _, rk := range kr.keys {
		out = append(out, KeyInfo{
			KeyID:         rk.KeyID,
			CreatedAt:     rk.CreatedAt,
			RetiredAt:     rk.RetiredAt,
			PublicKeySEC1: rk.PublicKeySEC1,
			IsCurrent:     rk.KeyID == kr.current,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// KeyInfo is a public, redacted view of a key in the
// keyring. Used by the admin API.
type KeyInfo struct {
	KeyID         string    `json:"keyId"`
	CreatedAt     time.Time `json:"createdAt"`
	RetiredAt     time.Time `json:"retiredAt,omitempty"`
	PublicKeySEC1 string    `json:"publicKeySec1"`
	IsCurrent     bool      `json:"isCurrent"`
}

// persistLocked writes the keyring to disk. Must be called
// with kr.mu held (write lock). The write is atomic
// (write-to-temp + rename) so a crash mid-write leaves the
// previous good file intact.
func (kr *KeyRing) persistLocked() error {
	if kr.persist == "" {
		return nil
	}
	onDisk := keyRingOnDisk{
		Version: KeyRingFileVersion,
		Current: kr.current,
		Keys:    make([]ringKey, 0, len(kr.keys)),
	}
	// Preserve the insertion order of the keys map. Go map
	// iteration is random; we sort by CreatedAt to make the
	// output deterministic for diffing.
	type kvp struct {
		id string
		ts time.Time
		rk *ringKey
	}
	all := make([]kvp, 0, len(kr.keys))
	for id, rk := range kr.keys {
		all = append(all, kvp{id: id, ts: rk.CreatedAt, rk: rk})
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].ts.Before(all[j].ts)
	})
	for _, k := range all {
		onDisk.Keys = append(onDisk.Keys, *k.rk)
	}
	data, err := json.MarshalIndent(onDisk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := kr.persist + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, kr.persist); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// parseRingKeyPEM parses a SEC 1 / "EC PRIVATE KEY" PEM block
// into an *ecdsa.PrivateKey. P-256 is enforced.
func parseRingKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported PEM block type: %q", block.Type)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected P-256, got %s", priv.Curve.Params().Name)
	}
	return priv, nil
}

// encodeRingKeyPEM encodes an ECDSA P-256 private key as a
// SEC 1 / "EC PRIVATE KEY" PEM block.
func encodeRingKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	if priv.Curve != elliptic.P256() {
		return "", fmt.Errorf("expected P-256, got %s", priv.Curve.Params().Name)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	return string(pemBytes), nil
}

// HashSHA256 is a small helper that returns the SHA-256
// digest of b. Used by tests and by callers that want to
// use the keyring's Sign/Verify primitives without
// duplicating the SHA-256 logic.
func HashSHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// SetRetiredKeyTTL overrides the default retired-key TTL.
// Useful for tests (use 0 or 1h) and for operators who
// want a longer retention (e.g., 365 days for SOC 2).
// Safe to call at runtime; takes a write lock briefly.
func (kr *KeyRing) SetRetiredKeyTTL(ttl time.Duration) {
	if kr == nil {
		return
	}
	kr.mu.Lock()
	kr.retiredKeyTTL = ttl
	kr.mu.Unlock()
}

// pruneExpiredLocked is the lock-free variant of PruneExpired.
// The caller MUST already hold kr.mu (write lock). Used by
// Rotate(), which already holds the lock for the duration
// of the rotation. Calling PruneExpired from inside the
// lock would deadlock - this is the unlocked variant.
func (kr *KeyRing) pruneExpiredLocked(now time.Time) []string {
	if kr == nil {
		return nil
	}
	tt := kr.retiredKeyTTL
	if tt == 0 {
		tt = DefaultRetiredKeyTTL
	}
	removed := []string{}
	for id, rk := range kr.keys {
		if id == kr.current {
			continue
		}
		if rk.RetiredAt.IsZero() {
			continue
		}
		if now.Sub(rk.RetiredAt) > tt {
			delete(kr.keys, id)
			removed = append(removed, id)
		}
	}
	if len(removed) > 0 && kr.persist != "" {
		_ = kr.persistLocked()
	}
	return removed
}

// PruneExpired removes retired keys whose RetiredAt is
// more than RetiredKeyTTL in the past. The current key is
// never pruned. The on-disk file is rewritten if any keys
// were removed. Safe to call periodically (e.g., on
// every Rotate, or from a background goroutine).
//
// Returns the list of keyIds that were removed. An empty
// list means nothing was expired (the common case).
//
// v3.4.0+ primitive. Closes the retired-keys-live-forever
// gap that the keyring documentation has flagged since v0.1.
func (kr *KeyRing) PruneExpired(now time.Time) []string {
	if kr == nil {
		return nil
	}
	tt := kr.retiredKeyTTL
	if tt == 0 {
		tt = DefaultRetiredKeyTTL
	}
	kr.mu.Lock()
	defer kr.mu.Unlock()
	removed := []string{}
	for id, rk := range kr.keys {
		if id == kr.current {
			continue
		}
		if rk.RetiredAt.IsZero() {
			continue
		}
		if now.Sub(rk.RetiredAt) > tt {
			delete(kr.keys, id)
			removed = append(removed, id)
		}
	}
	if len(removed) > 0 && kr.persist != "" {
		_ = kr.persistLocked()
	}
	return removed
}
