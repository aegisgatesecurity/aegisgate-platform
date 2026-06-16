// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - AR-EaaS verify tests (TODO-301)
//
// verify_test.go tests the high-level verify-side helpers:
// the VerifyResult struct, the VerifyEnvelope wrapper, and
// the JSON serialization shape.

package evaluator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
)

func TestVerifyEnvelope_NilEnvelope(t *testing.T) {
	vr := VerifyEnvelope(context.Background(), nil)
	if vr.Valid {
		t.Error("nil envelope: expected Valid=false")
	}
	if vr.Reason == "" {
		t.Error("nil envelope: expected non-empty Reason")
	}
}

func TestVerifyEnvelope_HappyPath(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:verify-happy",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	vr := VerifyEnvelope(context.Background(), out.Envelope)
	if !vr.Valid {
		t.Errorf("expected valid, got invalid: %s", vr.Reason)
	}
	if vr.Result == nil {
		t.Error("expected non-nil Result")
	}
	if vr.Result.RunID != out.Result.RunID {
		t.Errorf("RunID mismatch: got %q, want %q", vr.Result.RunID, out.Result.RunID)
	}
}

func TestVerifyEnvelope_WrongType(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:verify-wrong-type",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Mutate the envelope type to a non-Evaluator one.
	out.Envelope.Type = attestation.TypeEvidenceManifest
	vr := VerifyEnvelope(context.Background(), out.Envelope)
	if vr.Valid {
		t.Error("wrong type: expected Valid=false")
	}
	if vr.Reason == "" {
		t.Error("wrong type: expected non-empty Reason")
	}
}

func TestVerifyEnvelopeJSON(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:verify-json",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Round-trip through JSON.
	jsonBytes, err := json.Marshal(out.Envelope)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	vr, err := VerifyEnvelopeJSON(context.Background(), jsonBytes)
	if err != nil {
		t.Fatalf("VerifyEnvelopeJSON: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid, got invalid: %s", vr.Reason)
	}
}

func TestVerifyEnvelopeJSON_InvalidJSON(t *testing.T) {
	_, err := VerifyEnvelopeJSON(context.Background(), []byte("not json"))
	if err == nil {
		t.Error("expected error for non-JSON input, got nil")
	}
}

func TestVerifyResult_ToJSON(t *testing.T) {
	c := DefaultCorpus()
	kr := makeTestKeyRing(t)
	r, _ := NewRunner(c, kr)
	out, err := r.Run(context.Background(), makeAlwaysRefuseTarget(), RunRequest{
		TargetRef: "test:to-json",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	vr := VerifyEnvelope(context.Background(), out.Envelope)
	js := vr.ToJSON()
	if !js.Valid {
		t.Errorf("ToJSON: Valid=false (reason=%s)", js.Reason)
	}
	if js.RunID != out.Result.RunID {
		t.Errorf("ToJSON: RunID mismatch (got %q, want %q)", js.RunID, out.Result.RunID)
	}
	if js.PatternCount != 10 {
		t.Errorf("ToJSON: PatternCount got %d, want 10", js.PatternCount)
	}
	if js.KeyID == "" {
		t.Error("ToJSON: KeyID is empty")
	}
	if js.Issuer == "" {
		t.Error("ToJSON: Issuer is empty")
	}
	if js.Subject == "" {
		t.Error("ToJSON: Subject is empty")
	}
}

// --------------------------------------------------------------------
// validateRunResult edge cases
// --------------------------------------------------------------------

func TestValidateRunResult_MissingFields(t *testing.T) {
	cases := []*RunResult{
		{},                                    // all missing
		{RunID: "r1"},                         // missing everything else
		{RunID: "r1", CorpusID: "atlas-v0.1"}, // missing corpus_version
		{RunID: "r1", CorpusID: "atlas-v0.1", CorpusVersion: "0.1.0"}, // missing target_*
		{RunID: "r1", CorpusID: "atlas-v0.1", CorpusVersion: "0.1.0",
			TargetRef: "t", TargetFingerprint: "f"}, // missing results
		{RunID: "r1", CorpusID: "atlas-v0.1", CorpusVersion: "0.1.0",
			TargetRef: "t", TargetFingerprint: "f",
			Results:      []PatternResult{{PatternID: "p1"}},
			PatternCount: 2, PassCount: 0, FailCount: 0}, // PatternCount mismatch
	}
	for i, r := range cases {
		err := validateRunResult(r)
		if err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestValidateRunResult_HappyPath(t *testing.T) {
	r := &RunResult{
		RunID:             "r1",
		CorpusID:          "atlas-v0.1",
		CorpusVersion:     "0.1.0",
		TargetRef:         "t",
		TargetFingerprint: "f",
		Results:           []PatternResult{{PatternID: "p1"}, {PatternID: "p2"}},
		PatternCount:      2,
		PassCount:         1,
		FailCount:         1,
		RunTimestamp:      nowish(),
	}
	if err := validateRunResult(r); err != nil {
		t.Errorf("validateRunResult: %v", err)
	}
}

// nowish returns a non-zero time for tests that need one.
func nowish() (t time.Time) {
	return time.Now().UTC()
}
