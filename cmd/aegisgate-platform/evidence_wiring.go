// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Evidence Package wiring to live Scanner (v3.3.0+)
// =========================================================================
//
// evidence_wiring.go provides the helpers that main.go uses to
// construct the evidence API on the live platform. The wiring is
// deliberately isolated in this file so main.go stays small and
// the evidence integration is auditable in one place.
//
// v3.3.0+ Track 2 wiring.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/evidence"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// newEvidenceAPIForPlatform constructs the live evidence API bound
// to the platform Scanner, License manager, and a persistent signing
// key. Returns an http.Handler that main.go can mount on its mux.
//
// signingKeyPath is the file used to persist the ECDSA P-256 key.
// If the file does not exist, a fresh key is generated and persisted.
// If it exists but is malformed, returns an error - we never silently
// overwrite a customer's signing key (that would invalidate all
// previously issued evidence manifests).
func newEvidenceAPIForPlatform(complianceSc *compliance.Scanner, licenseMgr *license.Manager, auditRing *logging.RingBuffer, dataDir string) (apiHandler http.Handler, wellKnownHandler http.Handler, err error) {
	if dataDir == "" {
		dataDir = "./var"
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("evidence: create data dir: %w", err)
	}
	keyPath := filepath.Join(dataDir, "evidence-signing-key.pem")
	signingKey, keyID, err := loadOrCreateEvidenceKey(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: signing key: %w", err)
	}
	store, err := evidence.NewStore(filepath.Join(dataDir, "evidence"))
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: store: %w", err)
	}
	builder, err := evidence.NewBuilder(evidence.BuilderDeps{
		Scanner:        complianceSc,
		LicenseMgr:     licenseMgr,
		SigningKey:     signingKey,
		KeyID:          keyID,
		BuilderVersion: platformEvidenceVersion(),
		EventSource:    auditRing, // may be nil - manifest builds with source="unavailable"
	})
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: new builder: %w", err)
	}
	api := evidence.NewAPI(builder, store)
	// Well-known public key handler. The auditor workflow is:
	// 1. Fetch /.well-known/aegisgate-evidence-pubkey.pem
	// 2. Decode the PEM to get the platform's evidence-signing public key
	// 3. Use VerifyWithKey (CLI or HTTP ?expected_key_id=) to verify manifests
	// against that canonical key, not the embedded one.
	wkh, whErr := evidence.WellKnownHandler(&signingKey.PublicKey)
	if whErr != nil {
		return nil, nil, fmt.Errorf("evidence: well-known handler: %w", whErr)
	}
	return api, wkh, nil
}

// loadOrCreateEvidenceKey loads the ECDSA P-256 signing key from
// disk, or generates and persists a fresh one if the file does not
// exist. The keyID is a stable fingerprint derived from the public
// key bytes (the same algorithm the CLI uses).
//
// Persistence format: 32-byte big-endian scalar (hex-encoded).
// We use hex rather than PEM for simplicity - this is not a
// public-format artifact, only the platform reads it.
//
// For multi-host deployments, mount the same dataDir on every host
// so the signing key is shared (or accept per-host keys, which means
// manifests verify only on the host that signed them - v0.2 work).
func loadOrCreateEvidenceKey(path string) (*ecdsa.PrivateKey, string, error) {
	// G304 (CodeQL): sanitize the path. The path is
	// a server-controlled config value (from --data-dir
	// or the default ./var directory), not user input,
	// but CodeQL's taint analysis still flags it. The
	// safeFilePath call satisfies the linter and
	// rejects path-traversal patterns defensively.
	cleanPath, err := safeFilePath(path)
	if err != nil {
		return nil, "", err
	}
	path = cleanPath
	if data, err := os.ReadFile(path); err == nil {
		hexStr := string(data)
		dBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, "", fmt.Errorf("malformed signing key file %s: %w", path, err)
		}
		if len(dBytes) != 32 {
			return nil, "", fmt.Errorf("malformed signing key file %s: expected 32 bytes, got %d", path, len(dBytes))
		}
		//nolint:staticcheck // SA1019: see migration note in builder.go
		priv := new(ecdsa.PrivateKey)
		priv.Curve = elliptic.P256()
		//nolint:staticcheck // SA1019: priv.D deprecated as of Go 1.26
		priv.D = new(big.Int).SetBytes(dBytes)
		//nolint:staticcheck // SA1019: priv.PublicKey.X/Y deprecated as of Go 1.26
		priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(dBytes)
		return priv, evidenceKeyID(priv), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate key: %w", err)
	}
	//nolint:staticcheck // SA1019: key.D.Bytes() is deprecated as of Go 1.26.
	// See the migration note in loadOrCreateEvidenceKey above.
	dBytes := key.D.Bytes()
	hexStr := hex.EncodeToString(dBytes)
	if err := os.WriteFile(path, []byte(hexStr), 0o600); err != nil {
		return nil, "", fmt.Errorf("persist key: %w", err)
	}
	return key, evidenceKeyID(key), nil
}

// evidenceKeyID returns a short, stable fingerprint of the signing key.
// Format: "platform-<first12hex>" - the first 6 bytes of SHA-256 over
// the SEC 1 public key encoding. Stable across restarts (same key =
// same keyID) so manifests remain verifiable after a restart.
func evidenceKeyID(key *ecdsa.PrivateKey) string {
	//nolint:staticcheck // SA1019: elliptic.Marshal deprecated since Go 1.21.
	pubBytes := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	h := sha256.Sum256(pubBytes)
	return "platform-" + hex.EncodeToString(h[:6])
}

// platformEvidenceVersion returns the version string for manifests
// produced by the live platform binary.
func platformEvidenceVersion() string {
	if version == "" {
		return "v3.3.0-platform"
	}
	return version
}
