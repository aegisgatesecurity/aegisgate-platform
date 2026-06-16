// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AIBOM sign/verify tests (TODO-302)
//
// sign_test.go and verify_test.go cover the envelope wrapping:
// roundtrip, tamper detection, type/subject checks, and
// the JSON output shape used by the CLI.

package aibom

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// makeTestKeyRing creates an in-memory keyring for tests.
// Same pattern as pkg/evaluator tests.
func makeTestKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	tmpDir := t.TempDir()
	kr, err := ioc.LoadKeyRing(filepath.Join(tmpDir, "kr.json"))
	if err != nil {
		t.Fatalf("ioc.LoadKeyRing: %v", err)
	}
	if _, err := kr.Rotate(); err != nil {
		t.Fatalf("kr.Rotate: %v", err)
	}
	return kr
}

func makeTestBOM(t *testing.T) *BOM {
	t.Helper()
	a := &AIBOM{
		DeploymentID:    "test-deploy-001",
		PlatformVersion: "3.4.0-beta.1",
		PlatformTier:    "professional",
		GeneratedAt:     time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC),
	}
	bom, err := GenerateFromAIBOM(a)
	if err != nil {
		t.Fatalf("GenerateFromAIBOM: %v", err)
	}
	return bom
}

// --------------------------------------------------------------------
// Sign tests
// --------------------------------------------------------------------

func TestSign_NilBOM(t *testing.T) {
	kr := makeTestKeyRing(t)
	if _, err := Sign(nil, kr); err == nil {
		t.Error("nil BOM: expected error")
	}
}

func TestSign_NilKeyRing(t *testing.T) {
	bom := makeTestBOM(t)
	if _, err := Sign(bom, nil); err == nil {
		t.Error("nil keyring: expected error")
	}
}

func TestSign_HappyPath(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, err := Sign(bom, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Type and subject checks.
	if env.Type != attestation.TypeAIBOM {
		t.Errorf("type: got %q, want %q", env.Type, attestation.TypeAIBOM)
	}
	if env.Subject != "aegisgate://deployment/test-deploy-001" {
		t.Errorf("subject: got %q, want aegisgate://deployment/test-deploy-001", env.Subject)
	}
	// Issuer is non-empty and contains the key id.
	if env.Issuer == "" {
		t.Error("issuer is empty")
	}
	// Verify via attestation.Verify.
	if err := attestation.Verify(env); err != nil {
		t.Errorf("attestation.Verify: %v", err)
	}
}

func TestSign_WithCustomOptions(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	// WithIssuer takes precedence over the auto-generated
	// issuer. The keyID is appended to the custom issuer
	// (C1 fix). The notes are appended after the keyID.
	env, err := Sign(bom, kr,
		WithSubjectKind("deployment"),
		WithIssuer("custom:issuer:here"),
		WithKeyID("k-test123"),
		WithNotes("test notes"),
		WithTTL(0), // no expiration
	)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// C1 fix: the keyID is appended to the custom issuer.
	if env.Issuer != "custom:issuer:here:k-test123:test notes" {
		t.Errorf("issuer: got %q, want %q", env.Issuer, "custom:issuer:here:k-test123:test notes")
	}
	// Verify the envelope.
	if err := attestation.Verify(env); err != nil {
		t.Errorf("attestation.Verify: %v", err)
	}
}

func TestSign_WithCustomIssuer_ButNoKeyID(t *testing.T) {
	// C1 fix: when the caller provides a custom issuer
	// BUT no keyID, the keyID is NOT appended (no double-
	// append; the caller is responsible for the format).
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, err := Sign(bom, kr,
		WithIssuer("custom:only:issuer"),
		WithNotes("test notes"),
	)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.Issuer != "custom:only:issuer:test notes" {
		t.Errorf("issuer: got %q, want %q", env.Issuer, "custom:only:issuer:test notes")
	}
}

func TestSign_AutoIssuer_WithKeyID(t *testing.T) {
	// C1 fix: when the caller does NOT provide a custom
	// issuer but DOES provide a keyID, the keyID is used
	// in the auto-generated path.
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, err := Sign(bom, kr,
		WithKeyID("k-custom"),
	)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// The auto-generated issuer is "aibom:shortfp:<16-hex>:k-custom".
	if !strings.Contains(env.Issuer, ":k-custom") {
		t.Errorf("issuer: got %q, want :k-custom suffix", env.Issuer)
	}
}

func TestSign_WithTTL(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, err := Sign(bom, kr, WithTTL(1*time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.ValidUntil.IsZero() {
		t.Error("ValidUntil is zero (TTL not applied)")
	}
}

func TestSign_TamperDetection(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, err := Sign(bom, kr)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Tamper: modify the serial number in the payload.
	original := string(env.RawPayload)
	if !strings.Contains(original, "test-deploy-001") {
		t.Fatalf("payload does not contain expected id: %s", original)
	}
	env.RawPayload = []byte(strings.ReplaceAll(original, "test-deploy-001", "tampered-id"))
	// Verify must now fail.
	if err := attestation.Verify(env); err == nil {
		t.Error("tampered envelope verified successfully (expected failure)")
	}
}

// --------------------------------------------------------------------
// Verify tests
// --------------------------------------------------------------------

func TestVerifyEnvelope_Nil(t *testing.T) {
	vr := VerifyEnvelope(context.Background(), nil)
	if vr.Valid {
		t.Error("nil envelope: expected Valid=false")
	}
	if vr.Reason == "" {
		t.Error("nil envelope: expected non-empty Reason")
	}
}

func TestVerifyEnvelope_HappyPath(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, _ := Sign(bom, kr)
	vr := VerifyEnvelope(context.Background(), env)
	if !vr.Valid {
		t.Errorf("VerifyEnvelope: expected valid, got invalid (reason=%s)", vr.Reason)
	}
	if vr.BOM == nil {
		t.Error("VerifyEnvelope: BOM is nil")
	}
	if vr.BOM.SerialNumber != bom.SerialNumber {
		t.Errorf("BOM serialNumber mismatch: got %q, want %q", vr.BOM.SerialNumber, bom.SerialNumber)
	}
}

func TestVerifyEnvelope_WrongType(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, _ := Sign(bom, kr)
	env.Type = attestation.TypeEvaluatorRun
	vr := VerifyEnvelope(context.Background(), env)
	if vr.Valid {
		t.Error("wrong type: expected Valid=false")
	}
}

func TestVerifyEnvelope_WrongSubject(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	// Sign with a non-deployment subject. The envelope
	// signature will verify (the subject is part of the
	// signed bytes, so a valid signature on a wrong-subject
	// envelope proves the auditor can detect cross-kind
	// envelopes).
	env2, err := Sign(bom, kr, WithSubjectKind("manifest"))
	if err != nil {
		t.Fatalf("re-sign: %v", err)
	}
	vr := VerifyEnvelope(context.Background(), env2)
	if vr.Valid {
		t.Error("wrong subject kind: expected Valid=false")
	}
}

func TestVerifyEnvelope_TamperedPayload(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, _ := Sign(bom, kr)
	env.RawPayload = []byte(strings.ReplaceAll(string(env.RawPayload), "test-deploy-001", "tampered"))
	vr := VerifyEnvelope(context.Background(), env)
	if vr.Valid {
		t.Error("tampered payload: expected Valid=false")
	}
}

func TestVerifyEnvelopeJSON_HappyPath(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, _ := Sign(bom, kr)
	// Roundtrip through JSON.
	js, _ := json.Marshal(env)
	vr, err := VerifyEnvelopeJSON(context.Background(), js)
	if err != nil {
		t.Fatalf("VerifyEnvelopeJSON: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid, got invalid: %s", vr.Reason)
	}
}

func TestVerifyEnvelopeJSON_InvalidJSON(t *testing.T) {
	if _, err := VerifyEnvelopeJSON(context.Background(), []byte("not json")); err == nil {
		t.Error("expected error for non-JSON input")
	}
}

func TestVerifyResult_ToJSON(t *testing.T) {
	bom := makeTestBOM(t)
	kr := makeTestKeyRing(t)
	env, _ := Sign(bom, kr)
	vr := VerifyEnvelope(context.Background(), env)
	out := vr.ToJSON()
	if !out.Valid {
		t.Errorf("ToJSON: Valid=false (reason=%s)", out.Reason)
	}
	if out.Type != string(attestation.TypeAIBOM) {
		t.Errorf("ToJSON: type got %q, want %q", out.Type, attestation.TypeAIBOM)
	}
	if out.Subject != "aegisgate://deployment/test-deploy-001" {
		t.Errorf("ToJSON: subject got %q", out.Subject)
	}
	if out.DeploymentID != "test-deploy-001" {
		t.Errorf("ToJSON: deployment_id got %q, want test-deploy-001", out.DeploymentID)
	}
	if out.PlatformTier != "professional" {
		t.Errorf("ToJSON: platform_tier got %q, want professional", out.PlatformTier)
	}
	if out.PlatformVer != "3.4.0-beta.1" {
		t.Errorf("ToJSON: platform_version got %q, want 3.4.0-beta.1", out.PlatformVer)
	}
	if len(out.ComponentRefs) < 5 {
		t.Errorf("ToJSON: component_refs got %d, want >= 5", len(out.ComponentRefs))
	}
}

// --------------------------------------------------------------------
// validateBOM tests
// --------------------------------------------------------------------

func TestValidateBOM_RequiredFields(t *testing.T) {
	bom := &BOM{} // all missing
	if err := validateBOM(bom); err == nil {
		t.Error("empty BOM: expected error")
	}
}

func TestValidateBOM_MissingPillar(t *testing.T) {
	a := &AIBOM{DeploymentID: "test"}
	bom, _ := GenerateFromAIBOM(a)
	// Remove the HTTP pillar.
	filtered := bom.Components[:0]
	for _, c := range bom.Components {
		if c.BOMRef != "aegisgate-http" {
			filtered = append(filtered, c)
		}
	}
	bom.Components = filtered
	if err := validateBOM(bom); err == nil {
		t.Error("missing HTTP pillar: expected error")
	}
}

func TestValidateBOM_HappyPath(t *testing.T) {
	a := &AIBOM{DeploymentID: "test", PlatformVersion: "3.4.0-beta.1", PlatformTier: "professional"}
	bom, _ := GenerateFromAIBOM(a)
	if err := validateBOM(bom); err != nil {
		t.Errorf("validateBOM: %v", err)
	}
}

// --------------------------------------------------------------------
// ParseBOM tests
// --------------------------------------------------------------------

func TestParseBOM(t *testing.T) {
	a := &AIBOM{DeploymentID: "parse-test", PlatformVersion: "3.4.0-beta.1", PlatformTier: "professional"}
	bom, _ := GenerateFromAIBOM(a)
	js, _ := json.Marshal(bom)
	parsed, err := ParseBOM(js)
	if err != nil {
		t.Fatalf("ParseBOM: %v", err)
	}
	if parsed.SerialNumber != bom.SerialNumber {
		t.Errorf("roundtrip: serialNumber mismatch")
	}
}

// --------------------------------------------------------------------
// buildSubject, buildIssuer, sanitizeNotes tests
// --------------------------------------------------------------------

func TestBuildSubject(t *testing.T) {
	bom := makeTestBOM(t)
	subject := buildSubject("deployment", bom)
	if subject != "aegisgate://deployment/test-deploy-001" {
		t.Errorf("buildSubject: got %q", subject)
	}
}

func TestBuildSubject_NoSerial(t *testing.T) {
	bom := &BOM{} // no serial number
	if got := buildSubject("deployment", bom); got != "" {
		t.Errorf("buildSubject with no serial: got %q, want empty", got)
	}
}

func TestDeploymentIDFromBOM(t *testing.T) {
	bom := makeTestBOM(t)
	id := deploymentIDFromBOM(bom)
	if id != "test-deploy-001" {
		t.Errorf("deploymentIDFromBOM: got %q, want test-deploy-001", id)
	}
	// No prefix.
	bom2 := &BOM{SerialNumber: "not-urn:uuid:foo"}
	if id := deploymentIDFromBOM(bom2); id != "" {
		t.Errorf("non-urn serial: got %q, want empty", id)
	}
}

func TestBuildIssuer(t *testing.T) {
	bom := makeTestBOM(t)
	issuer := buildIssuer(bom, "k-test123")
	// Format: aibom:shortfp:<16-hex>:k-test123
	if !strings.Contains(issuer, "aibom:shortfp:") {
		t.Errorf("issuer: got %q, want aibom:shortfp: prefix", issuer)
	}
	if !strings.Contains(issuer, ":k-test123") {
		t.Errorf("issuer: got %q, want :k-test123 suffix", issuer)
	}
}

func TestBuildIssuer_NoSerial(t *testing.T) {
	bom := &BOM{}
	issuer := buildIssuer(bom, "k-test")
	if issuer != "aibom:unknown:k-test" {
		t.Errorf("issuer: got %q, want aibom:unknown:k-test", issuer)
	}
}

func TestSanitizeNotes(t *testing.T) {
	cases := map[string]string{
		"hello":                  "hello",
		"hello:world":            "hello_world",           // colon replaced
		"hello\nworld":           "hello world",           // newline replaced
		"hello\rworld":           "hello world",           // CR replaced
		strings.Repeat("x", 100): strings.Repeat("x", 32), // truncated
	}
	for input, want := range cases {
		if got := sanitizeNotes(input); got != want {
			t.Errorf("sanitizeNotes(%q): got %q, want %q", input, got, want)
		}
	}
}

func TestApplySignerOptions_Empty(t *testing.T) {
	o := applySignerOptions(nil)
	if o.subjectKind != "" || o.issuer != "" || o.keyID != "" {
		t.Errorf("empty options: %+v", o)
	}
}
