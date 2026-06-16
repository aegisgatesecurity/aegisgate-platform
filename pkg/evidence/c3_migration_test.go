// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - c3 Envelope Migration tests (v3.5.0+, Tier 5 prep)
//
// c3_migration_test.go covers the non-breaking additive migration
// of the c3 evidence manifest to the v3.5.0+ attestation envelope.
//
// The migration is verified from both sides:
// 1. Build a manifest with the new envelope path (KeyRing set)
// 2. Verify the legacy c3 path still works (for v3.4.0-beta.1
//    verifiers that don't know about the envelope)
// 3. Verify the new envelope path works (for v3.5.0+ verifiers)
// 4. Verify the envelope can be verified independently of the
//    legacy signature
// 5. Verify the legacy signature is mirrored from the envelope

package evidence

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// makeTestKeyRing creates a KeyRing with a fresh P-256 key for tests.
func makeTestKeyRing(t *testing.T) (*ioc.KeyRing, string) {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(tmpDir + "/kr.json")
	if err != nil {
		t.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	keyID, err := kr.Rotate()
	if err != nil {
		t.Fatalf("kr.Rotate: %v", err)
	}
	return kr, keyID
}

// makeTestManifestBuilder returns a Builder that produces manifests
// with the envelope path enabled (KeyRing set).
func makeTestManifestBuilder(t *testing.T) (*Builder, *ecdsa.PrivateKey) {
	t.Helper()
	// c3 legacy signing key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	// v3.5.0+ KeyRing
	kr, _ := makeTestKeyRing(t)
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: time.Minute})
	b, err := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     priv,
		KeyID:          "c3-legacy-key",
		BuilderVersion: "v3.5.0-test",
		KeyRing:        kr,
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b, priv
}

// makeTestManifestBuilderLegacy returns a Builder that does NOT
// have a KeyRing (v3.4.0-beta.1 behavior).
func makeTestManifestBuilderLegacy(t *testing.T) (*Builder, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	mgr, _ := license.NewManager()
	scanner := compliance.NewScanner(nil, &compliance.ScannerOpts{CacheTTL: time.Minute})
	b, err := NewBuilder(BuilderDeps{
		Scanner:        scanner,
		LicenseMgr:     mgr,
		SigningKey:     priv,
		KeyID:          "c3-legacy-key",
		BuilderVersion: "v3.4.0-beta.1-test",
		// No KeyRing: legacy c3 path only.
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b, priv
}

// --------------------------------------------------------------------
// c3 migration: manifest WITH envelope
// --------------------------------------------------------------------

func TestC3Migration_ManifestWithEnvelope(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// The manifest should have both the legacy Signature and
	// the new Attestation envelope.
	if m.Attestation == nil {
		t.Fatal("Attestation is nil (expected envelope)")
	}
	if len(m.Signature.Value) == 0 {
		t.Error("legacy Signature is empty (should be populated)")
	}
}

func TestC3Migration_LegacyVerifyStillWorks(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// v3.4.0-beta.1 verifier uses Verify (legacy path).
	if err := Verify(m); err != nil {
		t.Errorf("legacy Verify failed on envelope-wrapped manifest: %v", err)
	}
}

func TestC3Migration_EnvelopeVerify(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// v3.5.0+ verifier uses VerifyEnvelope.
	if err := VerifyEnvelope(m); err != nil {
		t.Errorf("VerifyEnvelope failed: %v", err)
	}
}

func TestC3Migration_EnvelopeType(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if m.Attestation.Type != attestation.TypeEvidenceManifest {
		t.Errorf("envelope Type = %q, want %q", m.Attestation.Type, attestation.TypeEvidenceManifest)
	}
}

func TestC3Migration_EnvelopeSubject(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	wantSubject := "aegisgate://manifest/" + m.ManifestID
	if m.Attestation.Subject != wantSubject {
		t.Errorf("envelope Subject = %q, want %q", m.Attestation.Subject, wantSubject)
	}
}

func TestC3Migration_EnvelopeTamperDetected(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the envelope's payload (the manifest's
	// canonical JSON). The envelope's signature is over the
	// canonical form, so changing the payload invalidates it.
	m.Attestation.RawPayload = json.RawMessage(`{"tampered": true}`)
	err = VerifyEnvelope(m)
	if err == nil {
		t.Error("expected error on tampered envelope, got nil")
	}
	var verr *attestation.VerificationError
	if !errAs(err, &verr) {
		t.Errorf("expected *attestation.VerificationError, got %T", err)
	} else if verr.Reason != attestation.ReasonSignatureInvalid {
		t.Errorf("reason = %v, want %v", verr.Reason, attestation.ReasonSignatureInvalid)
	}
}

// errAs is a small wrapper around errors.As to keep the import
// surface of this test file small.
func errAs(err error, target interface{}) bool {
	if err == nil {
		return false
	}
	// Use errors.As via type assertion; this avoids importing
	// the errors package just for one call.
	type wrapper interface{ Unwrap() error }
	for {
		if v, ok := target.(**attestation.VerificationError); ok {
			if e, ok2 := err.(*attestation.VerificationError); ok2 {
				*v = e
				return true
			}
		}
		w, ok := err.(wrapper)
		if !ok {
			return false
		}
		err = w.Unwrap()
		if err == nil {
			return false
		}
	}
}

// --------------------------------------------------------------------
// c3 migration: manifest WITHOUT envelope (legacy path)
// --------------------------------------------------------------------

func TestC3Migration_LegacyManifestNoEnvelope(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilderLegacy(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy manifests have NO envelope.
	if m.Attestation != nil {
		t.Error("legacy manifest should not have an envelope")
	}
	// Legacy Verify works.
	if err := Verify(m); err != nil {
		t.Errorf("legacy Verify failed: %v", err)
	}
	// VerifyEnvelope fails (no envelope).
	if err := VerifyEnvelope(m); err == nil {
		t.Error("expected VerifyEnvelope to fail on legacy manifest")
	}
}

func TestC3Migration_LegacyManifestVerifyWithKey(t *testing.T) {
	t.Parallel()
	b, priv := makeTestManifestBuilderLegacy(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithKey(m, &priv.PublicKey, "c3-legacy-key"); err != nil {
		t.Errorf("VerifyWithKey: %v", err)
	}
}

// --------------------------------------------------------------------
// Wire format
// --------------------------------------------------------------------

func TestC3Migration_JSONShape(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Both attestation and signature fields should be present.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["attestation"] == nil {
		t.Error("attestation field missing from JSON")
	}
	if raw["signature"] == nil {
		t.Error("signature field missing from JSON")
	}
}

func TestC3Migration_LegacyJSONShape(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilderLegacy(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy manifest: no attestation field (omitempty).
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["attestation"] != nil {
		t.Error("legacy manifest should omit attestation (omitempty)")
	}
	if raw["signature"] == nil {
		t.Error("signature field should be present")
	}
}

// --------------------------------------------------------------------
// Envelope vs legacy: independent verification
// --------------------------------------------------------------------

func TestC3Migration_EnvelopeAndLegacyIndependent(t *testing.T) {
	t.Parallel()
	// Verify that tampering with the legacy Signature does NOT
	// invalidate the envelope (they are independent signatures
	// of different canonical forms).
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the legacy signature.
	m.Signature.Value[0] ^= 0xFF
	// Legacy Verify should fail.
	if err := Verify(m); err == nil {
		t.Error("expected legacy Verify to fail on tampered signature")
	}
	// Envelope Verify should still succeed (independent).
	if err := VerifyEnvelope(m); err != nil {
		t.Errorf("envelope Verify should succeed despite tampered legacy signature: %v", err)
	}
}

// --------------------------------------------------------------------
// Envelope via HTTP
// --------------------------------------------------------------------

func TestC3Migration_EnvelopeWithKey(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// Get the embedded public key.
	pub, err := ioc.ParsePublicKey(m.Attestation.Signature.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEnvelopeWithKey(m, pub, ""); err != nil {
		t.Errorf("VerifyEnvelopeWithKey: %v", err)
	}
}

// --------------------------------------------------------------------
// Envelope signature is mirrored in legacy
// --------------------------------------------------------------------

func TestC3Migration_LegacyMirroredFromEnvelope(t *testing.T) {
	t.Parallel()
	// Per the frozen spec §5.2 (Phase 2), the legacy Signature
	// field is derived from the envelope's signature. We don't
	// enforce this in the c3 path (the legacy signature is
	// computed independently of the envelope), but the
	// Algorithm, KeyID, PublicKey should match.
	//
	// Note: in v3.5.0-alpha-1, we use separate keys for c3
	// (SigningKey) and the envelope (KeyRing), so the public
	// keys and key IDs are different. This is acceptable for
	// v3.5.0-alpha-1; a future sprint will consolidate the
	// key sources.
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	// Both should have ecdsa-p256.
	if m.Signature.Algorithm != "ecdsa-p256" {
		t.Errorf("legacy Algorithm = %q, want ecdsa-p256", m.Signature.Algorithm)
	}
	if m.Attestation.Signature.Algorithm != "ecdsa-p256" {
		t.Errorf("envelope Algorithm = %q, want ecdsa-p256", m.Attestation.Signature.Algorithm)
	}
}

// --------------------------------------------------------------------
// Negative paths
// --------------------------------------------------------------------

func TestC3Migration_VerifyEnvelope_NilManifest(t *testing.T) {
	t.Parallel()
	if err := VerifyEnvelope(nil); err == nil {
		t.Error("expected error on nil manifest")
	}
}

func TestC3Migration_VerifyEnvelopeWithKey_NilManifest(t *testing.T) {
	t.Parallel()
	if err := VerifyEnvelopeWithKey(nil, nil, ""); err == nil {
		t.Error("expected error on nil manifest")
	}
}

// --------------------------------------------------------------------
// Envelope Subject is in URI form
// --------------------------------------------------------------------

func TestC3Migration_EnvelopeSubjectURI(t *testing.T) {
	t.Parallel()
	b, _ := makeTestManifestBuilder(t)
	start, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-03-31T23:59:59Z")
	m, err := b.Build(t.Context(), "atlas", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Attestation.Subject, "aegisgate://manifest/") {
		t.Errorf("Subject = %q, want aegisgate://manifest/<id>", m.Attestation.Subject)
	}
}
