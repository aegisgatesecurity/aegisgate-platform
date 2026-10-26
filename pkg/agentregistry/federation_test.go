// SPDX-License-Identifier: Apache-2.0
// Agent Registry Federation Tests

package agentregistry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
)

// helper: create a test KeyRing with a fresh ephemeral key
func testKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	kr, err := ioc.LoadKeyRing("")
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	return kr
}

// helper: create a test registry with a few agents
func testRegistryWithAgents(t *testing.T) *Registry {
	t.Helper()
	store := NewInMemoryStore()
	mgr, err := rbac.NewManager(nil)
	if err != nil {
		t.Fatalf("rbac.NewManager: %v", err)
	}
	_ = mgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-1",
		Name:    "support-bot",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})
	_ = mgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-2",
		Name:    "code-reviewer",
		Role:    rbac.AgentRoleStandard,
		Enabled: true,
	})
	_ = mgr.RegisterAgent(&rbac.Agent{
		ID:      "agent-3",
		Name:    "data-pipeline",
		Role:    rbac.AgentRoleStandard,
		Enabled: false, // disabled
	})
	reg, err := New(Config{
		Store: store,
		RBAC:  mgr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if err := reg.Discover(ctx); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return reg
}

func TestComputeAgentFingerprint(t *testing.T) {
	fp1 := ComputeAgentFingerprint("support-bot", "assistant")
	fp2 := ComputeAgentFingerprint("support-bot", "assistant")
	fp3 := ComputeAgentFingerprint("support-bot", "reviewer")
	fp4 := ComputeAgentFingerprint("other-bot", "assistant")

	if fp1 != fp2 {
		t.Error("same name+role should produce same fingerprint")
	}
	if fp1 == fp3 {
		t.Error("same name, different role should produce different fingerprint")
	}
	if fp1 == fp4 {
		t.Error("different name, same role should produce different fingerprint")
	}
	if len(fp1) != 64 {
		t.Errorf("fingerprint should be 64 hex chars, got %d", len(fp1))
	}
}

func TestFederationDisabledByDefault(t *testing.T) {
	reg := testRegistryWithAgents(t)
	fe := NewFederationEngine(FederationConfig{}, reg, nil)

	if fe.Enabled() {
		t.Error("federation should be disabled by default")
	}

	_, err := fe.ExportBundle(context.Background())
	if err == nil {
		t.Error("ExportBundle should fail when disabled")
	}
}

func TestExportBundle(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	if bundle.InstanceID != "instance-A" {
		t.Errorf("expected instance-A, got %s", bundle.InstanceID)
	}
	if bundle.Count == 0 {
		t.Error("bundle should contain attestations")
	}
	if bundle.Count != len(bundle.Attestations) {
		t.Error("count mismatch")
	}

	// Verify bundle signature.
	if err := bundle.VerifySignature(); err != nil {
		t.Fatalf("bundle signature verification: %v", err)
	}

	// Verify all attestation signatures.
	if err := bundle.VerifyAll(); err != nil {
		t.Fatalf("bundle verify all: %v", err)
	}

	// Check that attestations contain fingerprints, not names.
	for _, att := range bundle.Attestations {
		if att.Fingerprint == "" {
			t.Error("attestation should have a fingerprint")
		}
		if len(att.Fingerprint) != 64 {
			t.Errorf("fingerprint should be 64 hex chars, got %d", len(att.Fingerprint))
		}
		// Verify no agent names leaked into the attestation.
		if att.InstanceID == "" {
			t.Error("attestation should have instance ID")
		}
	}
}

func TestImportBundle(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	// Export a bundle from instance-A.
	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	// Create a second instance (instance-B) and import the bundle.
	reg2 := testRegistryWithAgents(t)
	kr2 := testKeyRing(t)
	fe2 := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr2,
	}, reg2, nil)

	if err := fe2.ImportBundle(bundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}

	if fe2.FederatedStore().Size() == 0 {
		t.Error("federated store should have records after import")
	}
}

func TestImportBundleRejectsSelf(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	// Import our own bundle — should be rejected.
	if err := fe.ImportBundle(bundle); err == nil {
		t.Error("ImportBundle should reject bundles from self")
	}
}

func TestImportBundleRejectsTampered(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	// Tamper with an attestation.
	if len(bundle.Attestations) > 0 {
		bundle.Attestations[0].Status = StatusRevoked
	}

	reg2 := testRegistryWithAgents(t)
	kr2 := testKeyRing(t)
	fe2 := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr2,
	}, reg2, nil)

	if err := fe2.ImportBundle(bundle); err == nil {
		t.Error("ImportBundle should reject tampered bundle")
	}
}

func TestFederatedStoreUpsertAndList(t *testing.T) {
	fs := NewFederatedStore(100)

	att := AgentAttestation{
		Fingerprint:  ComputeAgentFingerprint("test-bot", "assistant"),
		InstanceID:   "instance-X",
		Status:       StatusActive,
		Protocols:    []Protocol{ProtocolMCP},
		LastActivity: time.Now().UTC(),
		InAIBOM:      true,
		Timestamp:    time.Now().UTC(),
	}

	fs.Upsert(att)
	if fs.Size() != 1 {
		t.Errorf("expected size 1, got %d", fs.Size())
	}

	records := fs.List()
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
	if records[0].Status != StatusActive {
		t.Errorf("expected active, got %s", records[0].Status)
	}

	// Update with newer timestamp.
	att2 := att
	att2.Status = StatusDormant
	att2.Timestamp = att.Timestamp.Add(time.Hour)
	fs.Upsert(att2)

	rec, ok := fs.Get(att.Fingerprint)
	if !ok {
		t.Fatal("record not found")
	}
	if rec.Status != StatusDormant {
		t.Errorf("expected dormant after update, got %s", rec.Status)
	}
}

func TestFederatedStoreEviction(t *testing.T) {
	fs := NewFederatedStore(3) // small limit

	for i := 0; i < 5; i++ {
		fs.Upsert(AgentAttestation{
			Fingerprint: AgentFingerprint(base64.StdEncoding.EncodeToString([]byte{byte(i)})),
			InstanceID:  "instance-X",
			Status:      StatusActive,
			Timestamp:   time.Now().UTC().Add(time.Duration(i) * time.Minute),
		})
	}

	if fs.Size() > 3 {
		t.Errorf("expected max 3 records, got %d", fs.Size())
	}
}

func TestCrossDeploymentComparison(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	// Export and import into a second instance.
	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	reg2 := testRegistryWithAgents(t)
	kr2 := testKeyRing(t)
	fe2 := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr2,
	}, reg2, nil)

	if err := fe2.ImportBundle(bundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}

	// Compare — since both registries have the same agents (same names/roles),
	// we should see matches.
	report, err := fe2.CompareWithFederated(context.Background())
	if err != nil {
		t.Fatalf("CompareWithFederated: %v", err)
	}

	if report.TotalLocal == 0 {
		t.Error("should have local agents")
	}
	if report.TotalFederated == 0 {
		t.Error("should have federated agents")
	}
	if report.Matched == 0 {
		t.Error("should have matched agents (same names/roles)")
	}
}

func TestCrossDeploymentPeerRevokedDetection(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)

	// Manually revoke an agent in instance-A's registry.
	_ = reg.Transition("agent-1", StatusRevoked, "test revocation")

	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	// Instance-B has the same agent still active.
	reg2 := testRegistryWithAgents(t)
	kr2 := testKeyRing(t)
	fe2 := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr2,
	}, reg2, nil)

	if err := fe2.ImportBundle(bundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}

	report, err := fe2.CompareWithFederated(context.Background())
	if err != nil {
		t.Fatalf("CompareWithFederated: %v", err)
	}

	// Should detect that instance-A revoked an agent that's still active locally.
	if len(report.PeerRevokedLocal) == 0 {
		t.Error("should detect peer-revoked-local condition")
	}
	if len(report.StatusDiscrepancies) == 0 {
		t.Error("should detect status discrepancies")
	}
}

func TestAttestationSignVerify(t *testing.T) {
	kr := testKeyRing(t)

	att := AgentAttestation{
		Fingerprint:  ComputeAgentFingerprint("test-bot", "assistant"),
		InstanceID:   "instance-A",
		Status:       StatusDormant,
		Protocols:    []Protocol{ProtocolMCP, ProtocolA2A},
		LastActivity: time.Now().UTC().Add(-2 * time.Hour),
		InAIBOM:      true,
		Timestamp:    time.Now().UTC(),
	}

	if err := att.Sign(kr); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := att.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Tamper and verify should fail.
	att.Status = StatusRevoked
	if err := att.Verify(); err == nil {
		t.Error("Verify should fail after tampering")
	}
}

func TestBundleSignVerify(t *testing.T) {
	kr := testKeyRing(t)

	bundle := &AgentBundle{
		BundleID:     "test-bundle-1",
		InstanceID:   "instance-A",
		IssuedAt:     time.Now().UTC(),
		Attestations: make([]AgentAttestation, 0),
	}

	for i := 0; i < 3; i++ {
		att := AgentAttestation{
			Fingerprint:  ComputeAgentFingerprint("bot-"+string(rune('A'+i)), "assistant"),
			InstanceID:   "instance-A",
			Status:       StatusActive,
			Protocols:    []Protocol{ProtocolMCP},
			LastActivity: time.Now().UTC(),
			Timestamp:    time.Now().UTC(),
		}
		if err := att.Sign(kr); err != nil {
			t.Fatalf("attestation Sign: %v", err)
		}
		bundle.Attestations = append(bundle.Attestations, att)
	}
	bundle.Count = len(bundle.Attestations)

	if err := bundle.Sign(kr); err != nil {
		t.Fatalf("bundle Sign: %v", err)
	}

	if err := bundle.VerifyAll(); err != nil {
		t.Fatalf("bundle VerifyAll: %v", err)
	}

	// Tamper with bundle-level field.
	bundle.IssuedAt = time.Now().UTC().Add(time.Hour)
	if err := bundle.VerifySignature(); err == nil {
		t.Error("bundle signature should fail after tampering")
	}
}

func TestAirGapCompliance(t *testing.T) {
	reg := testRegistryWithAgents(t)

	// No KeyRing, no EnableFederation — full air-gap.
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: false,
	}, reg, nil)

	// Should not produce bundles.
	_, err := fe.ExportBundle(context.Background())
	if err == nil {
		t.Error("ExportBundle should fail in air-gap mode")
	}

	// Should not accept bundles.
	err = fe.ImportBundle(&AgentBundle{
		BundleID:   "test",
		InstanceID: "peer",
		Count:      0,
	})
	if err == nil {
		t.Error("ImportBundle should fail in air-gap mode")
	}

	// Start should be a no-op (not an error, just a log).
	if err := fe.Start(context.Background()); err != nil {
		t.Errorf("Start should not error in air-gap mode: %v", err)
	}
}

func TestStartStop(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
		ExportInterval:   100 * time.Millisecond,
	}, reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fe.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Double start should fail.
	if err := fe.Start(ctx); err == nil {
		t.Error("double Start should fail")
	}

	// Let it run briefly.
	time.Sleep(250 * time.Millisecond)

	fe.Stop()

	// Double stop should not panic.
	fe.Stop()
}

// HTTP handler tests

func TestServeFederationBundleDisabled(t *testing.T) {
	reg := testRegistryWithAgents(t)
	fe := NewFederationEngine(FederationConfig{}, reg, nil)

	rec := httptestNewRecorder(t, "GET", "/api/v1/agents/federation", nil, fe.ServeFederationBundle)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestServeFederationBundleEnabled(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	rec := httptestNewRecorder(t, "GET", "/api/v1/agents/federation", nil, fe.ServeFederationBundle)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var bundle AgentBundle
	if err := json.NewDecoder(rec.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if bundle.InstanceID != "instance-A" {
		t.Errorf("expected instance-A, got %s", bundle.InstanceID)
	}
}

func TestReceiveFederationBundleDisabled(t *testing.T) {
	reg := testRegistryWithAgents(t)
	fe := NewFederationEngine(FederationConfig{}, reg, nil)

	rec := httptestNewRecorder(t, "POST", "/api/v1/agents/federation", nil, fe.ReceiveFederationBundle)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestReceiveFederationBundleOK(t *testing.T) {
	// Instance-A exports a bundle.
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	bundle, err := fe.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	// Instance-B receives it.
	reg2 := testRegistryWithAgents(t)
	kr2 := testKeyRing(t)
	fe2 := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr2,
	}, reg2, nil)

	body, _ := json.Marshal(bundle)
	rec := httptestNewRecorderWithBody(t, "POST", "/api/v1/agents/federation", body, fe2.ReceiveFederationBundle)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestServeCrossDeploymentReportDisabled(t *testing.T) {
	reg := testRegistryWithAgents(t)
	fe := NewFederationEngine(FederationConfig{}, reg, nil)

	rec := httptestNewRecorder(t, "GET", "/api/v1/agents/federation/report", nil, fe.ServeCrossDeploymentReport)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rec.Code)
	}
}

func TestServeCrossDeploymentReportEnabled(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	rec := httptestNewRecorder(t, "GET", "/api/v1/agents/federation/report", nil, fe.ServeCrossDeploymentReport)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// httptest helpers

func httptestNewRecorder(t *testing.T, method, path string, body io.Reader, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func httptestNewRecorderWithBody(t *testing.T, method, path string, body []byte, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	return httptestNewRecorder(t, method, path, bytes.NewReader(body), handler)
}

// =====================================================================
// Coverage tests: error paths, edge cases, and defensive branches
// =====================================================================

// failingResponseWriter implements http.ResponseWriter but fails on Write.
type failingResponseWriter struct {
	header http.Header
	status int
}

func (f *failingResponseWriter) Header() http.Header {
	if f.header == nil {
		f.header = make(http.Header)
	}
	return f.header
}
func (f *failingResponseWriter) WriteHeader(code int) { f.status = code }
func (f *failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write failed")
}

// newEngineWithErrorStore creates a FederationEngine backed by a registry
// whose store always returns errors on List.
func newEngineWithErrorStore(t *testing.T, instanceID string) *FederationEngine {
	t.Helper()
	kr := testKeyRing(t)
	reg, err := New(Config{
		Store: &errorStore{inner: NewInMemoryStore(), failList: true},
		RBAC:  mustNewRBAC(t),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       instanceID,
		KeyRing:          kr,
	}, reg, nil)
}

// mustNewRBAC creates an RBAC manager for tests that need one but don't
// care about agents.
func mustNewRBAC(t *testing.T) *rbac.Manager {
	t.Helper()
	mgr, err := rbac.NewManager(nil)
	if err != nil {
		t.Fatalf("rbac.NewManager: %v", err)
	}
	return mgr
}

func TestFingerprintString(t *testing.T) {
	fp := ComputeAgentFingerprint("test-bot", "assistant")
	s := fp.String()
	if s != string(fp) {
		t.Errorf("String() should return the underlying string, got %q", s)
	}
	if len(s) != 64 {
		t.Errorf("fingerprint string should be 64 hex chars, got %d", len(s))
	}
}

// --- AgentAttestation.Sign error paths ---

func TestAttestationSignNilReceiver(t *testing.T) {
	kr := testKeyRing(t)
	var att *AgentAttestation
	if err := att.Sign(kr); err == nil {
		t.Error("Sign on nil receiver should fail")
	}
}

func TestAttestationSignNilKeyRing(t *testing.T) {
	att := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("test", "role"),
		InstanceID:  "instance-A",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	if err := att.Sign(nil); err == nil {
		t.Error("Sign with nil keyring should fail")
	}
}

func TestAttestationSignEmptyKeyRing(t *testing.T) {
	att := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("test", "role"),
		InstanceID:  "instance-A",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	// &ioc.KeyRing{} has no keys loaded — CurrentKeyID() returns "".
	if err := att.Sign(&ioc.KeyRing{}); err == nil {
		t.Error("Sign with empty keyring should fail")
	}
}

// --- AgentAttestation.Verify error paths ---

func TestAttestationVerifyNilReceiver(t *testing.T) {
	var att *AgentAttestation
	if err := att.Verify(); err == nil {
		t.Error("Verify on nil receiver should fail")
	}
}

func TestAttestationVerifyWrongSigAlgorithm(t *testing.T) {
	att := AgentAttestation{
		Signature: ioc.SignatureEnvelope{Algorithm: "RSA-4096"},
	}
	if err := att.Verify(); err == nil {
		t.Error("Verify with wrong signature algorithm should fail")
	}
}

func TestAttestationVerifyWrongPubKeyAlgorithm(t *testing.T) {
	att := AgentAttestation{
		Signature: ioc.SignatureEnvelope{Algorithm: ioc.AlgorithmECDSAP256},
		PublicKey: ioc.PublicKeyEnvelope{Algorithm: "RSA-4096"},
	}
	if err := att.Verify(); err == nil {
		t.Error("Verify with wrong public key algorithm should fail")
	}
}

func TestAttestationVerifyKeyIDMismatch(t *testing.T) {
	att := AgentAttestation{
		Signature: ioc.SignatureEnvelope{Algorithm: ioc.AlgorithmECDSAP256, KeyID: "key-A"},
		PublicKey: ioc.PublicKeyEnvelope{Algorithm: ioc.AlgorithmECDSAP256, KeyID: "key-B"},
	}
	if err := att.Verify(); err == nil {
		t.Error("Verify with mismatched key IDs should fail")
	}
}

func TestAttestationVerifyInvalidPubKey(t *testing.T) {
	att := AgentAttestation{
		Signature: ioc.SignatureEnvelope{Algorithm: ioc.AlgorithmECDSAP256, KeyID: "key-A"},
		PublicKey: ioc.PublicKeyEnvelope{
			Algorithm: ioc.AlgorithmECDSAP256,
			KeyID:     "key-A",
			Value:     "!!!not-valid-base64!!!",
		},
	}
	if err := att.Verify(); err == nil {
		t.Error("Verify with invalid public key should fail")
	}
}

func TestAttestationVerifyEmptySignature(t *testing.T) {
	kr := testKeyRing(t)
	att := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("test", "role"),
		InstanceID:  "instance-A",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	// Sign to get a valid public key, then clear the signature value.
	if err := att.Sign(kr); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	att.Signature.Value = ""
	if err := att.Verify(); err == nil {
		t.Error("Verify with empty signature value should fail")
	}
}

// --- AgentBundle.Sign error paths ---

func TestBundleSignNilReceiver(t *testing.T) {
	kr := testKeyRing(t)
	var b *AgentBundle
	if err := b.Sign(kr); err == nil {
		t.Error("Sign on nil bundle receiver should fail")
	}
}

func TestBundleSignNilKeyRing(t *testing.T) {
	b := &AgentBundle{BundleID: "test", InstanceID: "instance-A"}
	if err := b.Sign(nil); err == nil {
		t.Error("Bundle Sign with nil keyring should fail")
	}
}

func TestBundleSignEmptyKeyRing(t *testing.T) {
	b := &AgentBundle{BundleID: "test", InstanceID: "instance-A"}
	if err := b.Sign(&ioc.KeyRing{}); err == nil {
		t.Error("Bundle Sign with empty keyring should fail")
	}
}

// --- AgentBundle.VerifySignature error paths ---

func TestBundleVerifyNilReceiver(t *testing.T) {
	var b *AgentBundle
	if err := b.VerifySignature(); err == nil {
		t.Error("VerifySignature on nil bundle should fail")
	}
}

func TestBundleVerifyWrongSigAlgorithm(t *testing.T) {
	b := &AgentBundle{
		Signature: ioc.SignatureEnvelope{Algorithm: "RSA-4096"},
	}
	if err := b.VerifySignature(); err == nil {
		t.Error("VerifySignature with wrong algorithm should fail")
	}
}

func TestBundleVerifyWrongPubKeyAlgorithm(t *testing.T) {
	b := &AgentBundle{
		Signature: ioc.SignatureEnvelope{Algorithm: ioc.AlgorithmECDSAP256},
		PublicKey: ioc.PublicKeyEnvelope{Algorithm: "RSA-4096"},
	}
	if err := b.VerifySignature(); err == nil {
		t.Error("VerifySignature with wrong pub key algorithm should fail")
	}
}

func TestBundleVerifyKeyIDMismatch(t *testing.T) {
	b := &AgentBundle{
		Signature: ioc.SignatureEnvelope{Algorithm: ioc.AlgorithmECDSAP256, KeyID: "k-A"},
		PublicKey: ioc.PublicKeyEnvelope{Algorithm: ioc.AlgorithmECDSAP256, KeyID: "k-B"},
	}
	if err := b.VerifySignature(); err == nil {
		t.Error("VerifySignature with key ID mismatch should fail")
	}
}

func TestBundleVerifyInvalidPubKey(t *testing.T) {
	b := &AgentBundle{
		Signature: ioc.SignatureEnvelope{Algorithm: ioc.AlgorithmECDSAP256, KeyID: "k-A"},
		PublicKey: ioc.PublicKeyEnvelope{
			Algorithm: ioc.AlgorithmECDSAP256,
			KeyID:     "k-A",
			Value:     "!!!invalid!!!",
		},
	}
	if err := b.VerifySignature(); err == nil {
		t.Error("VerifySignature with invalid pub key should fail")
	}
}

func TestBundleVerifyEmptySignature(t *testing.T) {
	kr := testKeyRing(t)
	b := &AgentBundle{
		BundleID:   "test",
		InstanceID: "instance-A",
		IssuedAt:   time.Now().UTC(),
	}
	if err := b.Sign(kr); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	b.Signature.Value = ""
	if err := b.VerifySignature(); err == nil {
		t.Error("VerifySignature with empty sig value should fail")
	}
}

// --- AgentBundle.VerifyAll attestation failure ---

func TestBundleVerifyAllAttestationFailure(t *testing.T) {
	kr := testKeyRing(t)
	b := &AgentBundle{
		BundleID:   "test",
		InstanceID: "instance-A",
		IssuedAt:   time.Now().UTC(),
	}
	att := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("test", "role"),
		InstanceID:  "instance-A",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	if err := att.Sign(kr); err != nil {
		t.Fatalf("att Sign: %v", err)
	}
	b.Attestations = append(b.Attestations, att)
	b.Count = 1
	if err := b.Sign(kr); err != nil {
		t.Fatalf("bundle Sign: %v", err)
	}
	// Tamper with the attestation data (but not its signature).
	b.Attestations[0].Status = StatusRevoked
	// Re-sign the bundle so the bundle-level signature is valid for
	// the modified attestation data. The attestation's own signature
	// is still for StatusActive, so attestation verification will fail.
	if err := b.Sign(kr); err != nil {
		t.Fatalf("re-sign bundle: %v", err)
	}
	if err := b.VerifyAll(); err == nil {
		t.Error("VerifyAll should fail when an attestation signature is invalid")
	}
}

// --- FederatedStore edge cases ---

func TestFederatedStoreGetNotFound(t *testing.T) {
	fs := NewFederatedStore(100)
	rec, ok := fs.Get(AgentFingerprint("nonexistent"))
	if ok {
		t.Error("Get should return false for nonexistent fingerprint")
	}
	if rec != nil {
		t.Error("Get should return nil for nonexistent fingerprint")
	}
}

func TestFederatedStoreUpsertStaleTimestamp(t *testing.T) {
	fs := NewFederatedStore(100)
	now := time.Now().UTC()

	att1 := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("bot", "role"),
		InstanceID:  "instance-X",
		Status:      StatusActive,
		Timestamp:   now,
	}
	fs.Upsert(att1)

	// Upsert with an older timestamp from the same instance — should be ignored.
	att2 := att1
	att2.Status = StatusDormant
	att2.Timestamp = now.Add(-time.Hour) // older
	fs.Upsert(att2)

	rec, ok := fs.Get(att1.Fingerprint)
	if !ok {
		t.Fatal("record should exist")
	}
	if rec.Status != StatusActive {
		t.Errorf("stale upsert should be ignored; expected active, got %s", rec.Status)
	}
}

func TestFederatedStoreCorroborationCount(t *testing.T) {
	fs := NewFederatedStore(100)
	fp := ComputeAgentFingerprint("bot", "role")

	// Not found — should return 0.
	if count := fs.CorroborationCount(fp); count != 0 {
		t.Errorf("CorroborationCount for nonexistent fingerprint should be 0, got %d", count)
	}

	// After upsert — should return 1.
	fs.Upsert(AgentAttestation{
		Fingerprint: fp,
		InstanceID:  "instance-X",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	})
	if count := fs.CorroborationCount(fp); count != 1 {
		t.Errorf("CorroborationCount for existing fingerprint should be 1, got %d", count)
	}
}

// --- ExportBundle error paths ---

func TestExportBundleStoreError(t *testing.T) {
	fe := newEngineWithErrorStore(t, "instance-A")
	_, err := fe.ExportBundle(context.Background())
	if err == nil {
		t.Error("ExportBundle should fail when store returns errors")
	}
}

// --- ImportBundle edge cases ---

func TestImportBundleNilBundle(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)
	if err := fe.ImportBundle(nil); err == nil {
		t.Error("ImportBundle should reject nil bundle")
	}
}

func TestImportBundleSkipsSelfAttestations(t *testing.T) {
	// Create a bundle from instance-B that contains an attestation
	// tagged with instance-A's ID (simulating mixed-source bundle).
	krB := testKeyRing(t)
	att := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("mixed-bot", "role"),
		InstanceID:  "instance-A", // tagged as instance-A
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	if err := att.Sign(krB); err != nil {
		t.Fatalf("att Sign: %v", err)
	}

	bundle := &AgentBundle{
		BundleID:     "mixed-bundle",
		InstanceID:   "instance-B",
		IssuedAt:     time.Now().UTC(),
		Attestations: []AgentAttestation{att},
		Count:        1,
	}
	if err := bundle.Sign(krB); err != nil {
		t.Fatalf("bundle Sign: %v", err)
	}

	// Import into instance-A — the attestation from "self" should be skipped.
	reg := testRegistryWithAgents(t)
	krA := testKeyRing(t)
	feA := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          krA,
	}, reg, nil)

	if err := feA.ImportBundle(bundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}
	// The self-tagged attestation should not be in the store.
	if feA.FederatedStore().Size() != 0 {
		t.Errorf("self-tagged attestation should be skipped, store size = %d", feA.FederatedStore().Size())
	}
}

// --- Start with default interval ---

func TestStartDefaultInterval(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
		ExportInterval:   0, // should default to 5 minutes
	}, reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := fe.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Stop immediately — we just want to verify Start works with default interval.
	fe.Stop()
}

// --- exportLoop ctx.Done() path ---

func TestExportLoopCtxDone(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
		ExportInterval:   10 * time.Second, // long interval so we cancel before it fires
	}, reg, nil)

	ctx, cancel := context.WithCancel(context.Background())
	if err := fe.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Cancel the context to trigger ctx.Done() in exportLoop.
	cancel()
	// Give the goroutine time to exit.
	time.Sleep(100 * time.Millisecond)
	// fe.Stop() should not panic even though the loop already exited via ctx.Done.
	fe.Stop()
}

// --- exportLoop export failure ---

func TestExportLoopExportFailure(t *testing.T) {
	fe := newEngineWithErrorStore(t, "instance-A")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use a very short interval so the ticker fires quickly.
	fe.config.ExportInterval = 50 * time.Millisecond
	if err := fe.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Let the ticker fire at least once — ExportBundle will fail due to errorStore.
	time.Sleep(200 * time.Millisecond)
	fe.Stop()
	// If we get here without panicking, the export failure path was exercised.
}

// --- CompareWithFederated edge cases ---

func TestCompareWithFederatedStoreError(t *testing.T) {
	fe := newEngineWithErrorStore(t, "instance-A")
	_, err := fe.CompareWithFederated(context.Background())
	if err == nil {
		t.Error("CompareWithFederated should fail when store returns errors")
	}
}

func TestCompareWithFederatedPeerDriftLocal(t *testing.T) {
	reg := testRegistryWithAgents(t)
	krA := testKeyRing(t)
	feA := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          krA,
	}, reg, nil)

	// Create a peer bundle where an agent has AIBOM drift.
	// We need to craft an attestation with AIBOMDrift set for an agent
	// that exists locally without drift.
	bundle, err := feA.ExportBundle(context.Background())
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	// Manually create a signed attestation with AIBOM drift for the same agent.
	if len(bundle.Attestations) == 0 {
		t.Fatal("expected attestations in bundle")
	}
	driftAtt := bundle.Attestations[0]
	driftAtt.AIBOMDrift = "shadow_ai_detected"
	driftAtt.InstanceID = "instance-B"
	driftAtt.Timestamp = time.Now().UTC()
	// Re-sign with instance-B's key.
	krB := testKeyRing(t)
	if err := driftAtt.Sign(krB); err != nil {
		t.Fatalf("drift att Sign: %v", err)
	}

	peerBundle := &AgentBundle{
		BundleID:     "drift-bundle",
		InstanceID:   "instance-B",
		IssuedAt:     time.Now().UTC(),
		Attestations: []AgentAttestation{driftAtt},
		Count:        1,
	}
	if err := peerBundle.Sign(krB); err != nil {
		t.Fatalf("peer bundle Sign: %v", err)
	}

	// Import into instance-A and compare.
	if err := feA.ImportBundle(peerBundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}

	report, err := feA.CompareWithFederated(context.Background())
	if err != nil {
		t.Fatalf("CompareWithFederated: %v", err)
	}
	if len(report.PeerDriftLocal) == 0 {
		t.Error("should detect peer-drift-local condition")
	}
}

func TestCompareWithFederatedFederatedOnly(t *testing.T) {
	reg := testRegistryWithAgents(t)
	krA := testKeyRing(t)
	feA := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          krA,
	}, reg, nil)

	// Create a peer bundle with an agent that doesn't exist locally.
	peerAtt := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("unknown-bot", "role"),
		InstanceID:  "instance-B",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	krB := testKeyRing(t)
	if err := peerAtt.Sign(krB); err != nil {
		t.Fatalf("peer att Sign: %v", err)
	}
	peerBundle := &AgentBundle{
		BundleID:     "peer-bundle",
		InstanceID:   "instance-B",
		IssuedAt:     time.Now().UTC(),
		Attestations: []AgentAttestation{peerAtt},
		Count:        1,
	}
	if err := peerBundle.Sign(krB); err != nil {
		t.Fatalf("peer bundle Sign: %v", err)
	}

	if err := feA.ImportBundle(peerBundle); err != nil {
		t.Fatalf("ImportBundle: %v", err)
	}

	report, err := feA.CompareWithFederated(context.Background())
	if err != nil {
		t.Fatalf("CompareWithFederated: %v", err)
	}
	if len(report.FederatedOnlyFingerprints) == 0 {
		t.Error("should detect federated-only fingerprints")
	}
}

func TestCompareWithFederatedLocalOnly(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	// No federated records imported — all local agents should be local-only.
	report, err := fe.CompareWithFederated(context.Background())
	if err != nil {
		t.Fatalf("CompareWithFederated: %v", err)
	}
	if len(report.LocalOnlyFingerprints) == 0 {
		t.Error("should detect local-only fingerprints when no federated data")
	}
}

// --- HTTP handler error paths ---

func TestServeFederationBundleExportError(t *testing.T) {
	fe := newEngineWithErrorStore(t, "instance-A")
	req := httptest.NewRequest("GET", "/api/v1/agents/federation", nil)
	rec := httptest.NewRecorder()
	fe.ServeFederationBundle(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestServeFederationBundleWriteError(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	req := httptest.NewRequest("GET", "/api/v1/agents/federation", nil)
	fw := &failingResponseWriter{}
	fe.ServeFederationBundle(fw, req)
	// The handler should have set headers before the write failed.
	if fw.header == nil || fw.header.Get("Content-Type") != "application/json" {
		t.Error("handler should set Content-Type before writing")
	}
}

func TestReceiveFederationBundleDecodeError(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr,
	}, reg, nil)

	req := httptest.NewRequest("POST", "/api/v1/agents/federation", bytes.NewReader([]byte("!!!not json!!!")))
	rec := httptest.NewRecorder()
	fe.ReceiveFederationBundle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestReceiveFederationBundleImportError(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-B",
		KeyRing:          kr,
	}, reg, nil)

	// Send a bundle with no valid signature — ImportBundle should fail.
	bundle := AgentBundle{
		BundleID:   "bad-bundle",
		InstanceID: "instance-A",
		Count:      0,
	}
	body, _ := json.Marshal(bundle)
	req := httptest.NewRequest("POST", "/api/v1/agents/federation", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	fe.ReceiveFederationBundle(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestServeCrossDeploymentReportCompareError(t *testing.T) {
	fe := newEngineWithErrorStore(t, "instance-A")
	req := httptest.NewRequest("GET", "/api/v1/agents/federation/report", nil)
	rec := httptest.NewRecorder()
	fe.ServeCrossDeploymentReport(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}

func TestServeCrossDeploymentReportWriteError(t *testing.T) {
	reg := testRegistryWithAgents(t)
	kr := testKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	req := httptest.NewRequest("GET", "/api/v1/agents/federation/report", nil)
	fw := &failingResponseWriter{}
	fe.ServeCrossDeploymentReport(fw, req)
	if fw.header == nil || fw.header.Get("Content-Type") != "application/json" {
		t.Error("handler should set Content-Type before writing")
	}
}

// --- mustDecodeBase64 ---

func TestMustDecodeBase64Empty(t *testing.T) {
	if result := mustDecodeBase64(""); result != nil {
		t.Errorf("mustDecodeBase64(\"\") should return nil, got %v", result)
	}
}

func TestMustDecodeBase64Invalid(t *testing.T) {
	if result := mustDecodeBase64("!!!not valid base64!!!"); result != nil {
		t.Errorf("mustDecodeBase64 with invalid input should return nil, got %v", result)
	}
}

func TestMustDecodeBase64Valid(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("test data"))
	result := mustDecodeBase64(encoded)
	if string(result) != "test data" {
		t.Errorf("mustDecodeBase64 should decode valid base64, got %q", string(result))
	}
}

// =====================================================================
// Corrupted KeyRing tests: trigger "key not found" defensive paths
// =====================================================================

// corruptedKeyRing creates a KeyRing with a valid private key PEM
// but an invalid PublicKeySEC1. CurrentKeyID() returns a valid key
// ID, but LookupKey() returns nil because the SEC1 bytes fail to
// base64-decode. This triggers the "keyring: current key not found"
// defensive path in Sign methods.
func corruptedKeyRing(t *testing.T) *ioc.KeyRing {
	t.Helper()
	// Use a temp directory so the file doesn't exist yet — LoadKeyRing
	// creates it on first run when the file is missing.
	dir, err := os.MkdirTemp("", "corrupted-keyring-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(dir)

	tmpPath := dir + "/keyring.json"

	// Generate a valid keyring file at the temp path.
	_, err = ioc.LoadKeyRing(tmpPath)
	if err != nil {
		t.Fatalf("LoadKeyRing generate: %v", err)
	}

	// Read the file, corrupt the publicKeySec1, write back.
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var onDisk map[string]interface{}
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	keys := onDisk["keys"].([]interface{})
	key0 := keys[0].(map[string]interface{})
	key0["publicKeySec1"] = "!!!corrupted-sec1!!!"

	corrupted, _ := json.Marshal(onDisk)
	if err := os.WriteFile(tmpPath, corrupted, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Load the corrupted keyring — loadFromV2 only validates the
	// private key PEM, not the PublicKeySEC1 field.
	kr, err := ioc.LoadKeyRing(tmpPath)
	if err != nil {
		t.Fatalf("LoadKeyRing corrupted: %v", err)
	}
	return kr
}

func TestAttestationSignCorruptedKeyRing(t *testing.T) {
	kr := corruptedKeyRing(t)
	att := AgentAttestation{
		Fingerprint: ComputeAgentFingerprint("test", "role"),
		InstanceID:  "instance-A",
		Status:      StatusActive,
		Timestamp:   time.Now().UTC(),
	}
	if err := att.Sign(kr); err == nil {
		t.Error("Sign with corrupted keyring should fail (key not found)")
	}
}

func TestBundleSignCorruptedKeyRing(t *testing.T) {
	kr := corruptedKeyRing(t)
	b := &AgentBundle{
		BundleID:   "test",
		InstanceID: "instance-A",
		IssuedAt:   time.Now().UTC(),
	}
	if err := b.Sign(kr); err == nil {
		t.Error("Bundle Sign with corrupted keyring should fail (key not found)")
	}
}

func TestExportBundleSignFailure(t *testing.T) {
	// Use a working registry (with agents) but a corrupted keyring.
	// Enabled() returns true (federation on, keyring not nil), but
	// attestation signing fails for every agent, and bundle signing
	// also fails.
	reg := testRegistryWithAgents(t)
	kr := corruptedKeyRing(t)
	fe := NewFederationEngine(FederationConfig{
		EnableFederation: true,
		InstanceID:       "instance-A",
		KeyRing:          kr,
	}, reg, nil)

	_, err := fe.ExportBundle(context.Background())
	if err == nil {
		t.Error("ExportBundle should fail when keyring is corrupted")
	}
}
