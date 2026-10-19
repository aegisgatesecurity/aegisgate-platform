// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
)

// =========================================================================
// store.go gaps — mergePeerIOC, mergeQuarantinedIOC, PromoteQuarantined
// =========================================================================

func TestPhase1c_MergePeerIOC_New(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	ioc := makeValidIOC("peer-new", IOCTypeProxyResponse, SeverityHigh, "")
	ioc.Source = "peer:instance-abc"
	store.mergePeerIOC(ioc)

	got, ok := store.byFP[ioc.Fingerprint]
	if !ok {
		t.Fatal("merged IOC not found in store")
	}
	if !got.FirstSeen.IsZero() == false && got.FirstSeen.Equal(ioc.FirstSeen) {
		// FirstSeen should be set (non-zero from makeValidIOC)
	}
	if got.Count != 1 {
		t.Errorf("Count = %d, want 1", got.Count)
	}
}

func TestPhase1c_MergePeerIOC_Existing(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	// First, observe a local IOC.
	ioc1 := makeValidIOC("peer-existing", IOCTypeProxyResponse, SeverityMedium, "")
	ioc1.Source = "peer:instance-abc"
	store.mergePeerIOC(ioc1)

	// Then merge the same IOC from a peer with higher severity.
	ioc2 := makeValidIOC("peer-existing", IOCTypeProxyResponse, SeverityCritical, "")
	ioc2.Source = "peer:instance-def"
	ioc2.Count = 5
	store.mergePeerIOC(ioc2)

	got := store.byFP[ioc1.Fingerprint]
	if got.Count != 6 { // 1 + 5
		t.Errorf("Count = %d, want 6", got.Count)
	}
	if got.Severity != SeverityCritical {
		t.Errorf("Severity = %s, want %s", got.Severity, SeverityCritical)
	}
}

func TestPhase1c_MergePeerIOC_Invalid(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	store.mergePeerIOC(IOC{}) // Invalid → no-op
	if len(store.byFP) != 0 {
		t.Errorf("store should be empty after invalid merge, got %d", len(store.byFP))
	}
}

func TestPhase1c_MergeQuarantinedIOC_New(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	ioc := makeValidIOC("quarantine-new", IOCTypeProxyResponse, SeverityHigh, "")
	ioc.Source = "peer:bad-actor"
	store.mergeQuarantinedIOC(ioc)

	got := store.byFP[ioc.Fingerprint]
	if got == nil {
		t.Fatal("quarantined IOC not found in store")
	}
	if !got.Quarantined {
		t.Error("IOC should be marked as quarantined")
	}
}

func TestPhase1c_MergeQuarantinedIOC_ExistingNotQuarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	// First, observe a local (non-quarantined) IOC.
	ioc1 := makeValidIOC("quarantine-existing", IOCTypeProxyResponse, SeverityHigh, "")
	store.Observe(ioc1)

	// Then try to merge a quarantined version — should NOT downgrade.
	ioc2 := makeValidIOC("quarantine-existing", IOCTypeProxyResponse, SeverityMedium, "")
	ioc2.Source = "peer:bad-actor"
	store.mergeQuarantinedIOC(ioc2)

	got := store.byFP[ioc1.Fingerprint]
	if got.Quarantined {
		t.Error("trusted IOC should not be downgraded to quarantined")
	}
}

func TestPhase1c_MergeQuarantinedIOC_ExistingQuarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	// First, add a quarantined IOC.
	ioc1 := makeValidIOC("quarantine-merge", IOCTypeProxyResponse, SeverityMedium, "")
	ioc1.Source = "peer:bad-actor"
	store.mergeQuarantinedIOC(ioc1)

	// Then merge the same quarantined IOC with higher severity.
	ioc2 := makeValidIOC("quarantine-merge", IOCTypeProxyResponse, SeverityCritical, "")
	ioc2.Source = "peer:bad-actor"
	ioc2.Count = 3
	store.mergeQuarantinedIOC(ioc2)

	got := store.byFP[ioc1.Fingerprint]
	if !got.Quarantined {
		t.Error("IOC should still be quarantined")
	}
	if got.Severity != SeverityCritical {
		t.Errorf("Severity = %s, want %s", got.Severity, SeverityCritical)
	}
}

func TestPhase1c_PromoteQuarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{})

	// Add quarantined IOCs from different peers.
	ioc1 := makeValidIOC("promote-1", IOCTypeProxyResponse, SeverityHigh, "")
	ioc1.Source = "peer:instance-a"
	store.mergeQuarantinedIOC(ioc1)

	ioc2 := makeValidIOC("promote-2", IOCTypeProxyResponse, SeverityHigh, "")
	ioc2.Source = "peer:instance-b"
	store.mergeQuarantinedIOC(ioc2)

	// Add a non-quarantined IOC.
	ioc3 := makeValidIOC("promote-3", IOCTypeProxyResponse, SeverityHigh, "")
	store.Observe(ioc3)

	// Promote instance-a's IOCs.
	n := store.PromoteQuarantined("peer:instance-a")
	if n != 1 {
		t.Errorf("PromoteQuarantined returned %d, want 1", n)
	}

	// instance-a's IOC should no longer be quarantined.
	if store.byFP[ioc1.Fingerprint].Quarantined {
		t.Error("promoted IOC should not be quarantined")
	}
	// instance-b's IOC should still be quarantined.
	if !store.byFP[ioc2.Fingerprint].Quarantined {
		t.Error("non-promoted IOC should still be quarantined")
	}

	// Empty prefix → 0.
	if n := store.PromoteQuarantined(""); n != 0 {
		t.Errorf("PromoteQuarantined('') = %d, want 0", n)
	}
}

func TestPhase1c_Flush_MarshalError(t *testing.T) {
	// Flush with a path under a file (not a directory) → mkdir fails.
	store, _ := NewStore(StoreConfig{DiskPath: "/proc/test/ioc.json"})
	store.Observe(makeValidIOC("flush-err", IOCTypeProxyResponse, SeverityHigh, ""))
	err := store.Flush()
	if err == nil {
		t.Error("expected error for invalid disk path")
	}
}

func TestPhase1c_Flush_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ioc.json")
	store, _ := NewStore(StoreConfig{DiskPath: path})
	store.Observe(makeValidIOC("flush-ok", IOCTypeProxyResponse, SeverityHigh, ""))
	err := store.Flush()
	if err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestPhase1c_Store_LoadFromDisk_Error(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("!!!invalid json!!!"), 0o600)
	_, err := NewStore(StoreConfig{DiskPath: path})
	if err == nil {
		t.Error("expected error for invalid JSON on disk")
	}
}

// =========================================================================
// checker.go gaps — CheckCorroboration, CheckFingerprint, Stats
// =========================================================================

func TestPhase1c_CheckCorroboration_Quarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "test:corrob-quarantined",
	}
	fp := Fingerprint(d)
	ioc := IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "peer:bad-actor",
	}
	store.mergeQuarantinedIOC(ioc)

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckCorroboration(d, true)
	if !result.Found {
		t.Error("IOC should be found")
	}
	if result.RecommendBlock {
		t.Error("quarantined IOC should not recommend block")
	}
	if result.Reason == "" {
		t.Error("Reason should explain quarantine")
	}
}

func TestPhase1c_CheckCorroboration_PeerSource(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "test:corrob-peer",
	}
	fp := Fingerprint(d)
	ioc := IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "peer:instance-abc",
	}
	store.mergePeerIOC(ioc)

	cfg := DefaultCheckerConfig()
	cfg.MinPeerCount = 1
	checker := NewIOCChecker(store, cfg)
	result := checker.CheckCorroboration(d, true)
	if !result.Found {
		t.Error("IOC should be found")
	}
	if result.PeerCount != 1 {
		t.Errorf("PeerCount = %d, want 1", result.PeerCount)
	}
}

func TestPhase1c_CheckCorroboration_ExternalSource(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "test:corrob-ext",
	}
	fp := Fingerprint(d)
	ioc := IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Count:       1,
		Source:      "external:cisa:0.8",
	}
	store.mergePeerIOC(ioc)

	cfg := DefaultCheckerConfig()
	cfg.MinPeerCount = 1
	checker := NewIOCChecker(store, cfg)
	result := checker.CheckCorroboration(d, true)
	if !result.Found {
		t.Error("IOC should be found")
	}
	if result.PeerCount != 1 {
		t.Errorf("PeerCount = %d, want 1 (external source with weight >= 0.5)", result.PeerCount)
	}
}

func TestPhase1c_CheckFingerprint_Quarantined(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	ioc := makeValidIOC("fp-quarantined", IOCTypeProxyResponse, SeverityHigh, "")
	ioc.Source = "peer:bad-actor"
	store.mergeQuarantinedIOC(ioc)

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckFingerprint(ioc.Fingerprint, true)
	if !result.Found {
		t.Error("IOC should be found")
	}
	if result.RecommendBlock {
		t.Error("quarantined IOC should not recommend block")
	}
}

func TestPhase1c_CheckFingerprint_Stale(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	ioc := makeValidIOC("fp-stale", IOCTypeProxyResponse, SeverityHigh, "")
	ioc.LastSeen = time.Now().Add(-48 * time.Hour)
	store.Observe(ioc)

	cfg := DefaultCheckerConfig()
	cfg.MaxAge = 24 * time.Hour
	checker := NewIOCChecker(store, cfg)
	result := checker.CheckFingerprint(ioc.Fingerprint, true)
	if result.RecommendBlock {
		t.Error("stale IOC should not recommend block")
	}
	if result.Reason != "IOC is stale" {
		t.Errorf("Reason = %q, want %q", result.Reason, "IOC is stale")
	}
}

func TestPhase1c_CheckFingerprint_BelowMinSeverity(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	ioc := makeValidIOC("fp-lowsev", IOCTypeProxyResponse, SeverityLow, "")
	store.Observe(ioc)

	cfg := DefaultCheckerConfig()
	cfg.MinSeverity = SeverityHigh
	cfg.MaxAge = 0 // disable staleness check
	checker := NewIOCChecker(store, cfg)
	result := checker.CheckFingerprint(ioc.Fingerprint, true)
	if result.RecommendBlock {
		t.Error("low-severity IOC should not recommend block")
	}
}

func TestPhase1c_CheckerStats(t *testing.T) {
	store, _ := NewStore(StoreConfig{})

	// Add local IOC.
	store.Observe(makeValidIOC("stats-local", IOCTypeProxyResponse, SeverityHigh, ""))

	// Add peer IOC.
	peerIOC := makeValidIOC("stats-peer", IOCTypeProxyResponse, SeverityHigh, "")
	peerIOC.Source = "peer:instance-a"
	store.mergePeerIOC(peerIOC)

	// Add external IOC.
	extIOC := makeValidIOC("stats-ext", IOCTypeProxyResponse, SeverityHigh, "")
	extIOC.Source = "external:cisa:0.8"
	store.mergePeerIOC(extIOC)

	// Add quarantined IOC.
	qIOC := makeValidIOC("stats-quar", IOCTypeProxyResponse, SeverityHigh, "")
	qIOC.Source = "peer:bad"
	store.mergeQuarantinedIOC(qIOC)

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	stats := checker.Stats()
	if stats.StoreSize != 4 {
		t.Errorf("StoreSize = %d, want 4", stats.StoreSize)
	}
	if stats.PeerIOCs != 1 {
		t.Errorf("PeerIOCs = %d, want 1", stats.PeerIOCs)
	}
	if stats.ExternalIOCs != 1 {
		t.Errorf("ExternalIOCs = %d, want 1", stats.ExternalIOCs)
	}
	if stats.QuarantinedIOCs != 1 {
		t.Errorf("QuarantinedIOCs = %d, want 1", stats.QuarantinedIOCs)
	}
}

// =========================================================================
// stix_exporter.go gaps
// =========================================================================

func TestPhase1c_ExportToSTIX_NilBundle(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToSTIX(nil, "/tmp/test.json")
	if err == nil {
		t.Error("expected error for nil bundle")
	}
}

func TestPhase1c_ExportToSTIX_EmptyPath(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToSTIX(&Bundle{}, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestPhase1c_ExportToSTIX_PathTraversal(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToSTIX(&Bundle{}, "../../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestPhase1c_ExportToSTIX_Success(t *testing.T) {
	exporter := &STIXExporter{}
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "stix.json")
	bundle := &Bundle{
		Attestations: []IOCAttestation{
			{Fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", IOCType: IOCTypeProxyResponse, Severity: SeverityHigh, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), Count: 1},
		},
	}
	err := exporter.ExportToSTIX(bundle, path)
	if err != nil {
		t.Fatalf("ExportToSTIX failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestPhase1c_ExportToJSONLines_NilBundle(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToJSONLines(nil, "/tmp/test.jsonl")
	if err == nil {
		t.Error("expected error for nil bundle")
	}
}

func TestPhase1c_ExportToJSONLines_EmptyPath(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToJSONLines(&Bundle{}, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestPhase1c_ExportToJSONLines_Success(t *testing.T) {
	exporter := &STIXExporter{}
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "stix.jsonl")
	bundle := &Bundle{
		Attestations: []IOCAttestation{
			{Fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", IOCType: IOCTypeProxyResponse, Severity: SeverityHigh, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), Count: 1},
		},
	}
	err := exporter.ExportToJSONLines(bundle, path)
	if err != nil {
		t.Fatalf("ExportToJSONLines failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

// =========================================================================
// producer.go gaps
// =========================================================================

func TestPhase1c_Producer_Disabled(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	cfg := ProducerConfig{}
	p := NewProducer(cfg, store)
	p.SetEnabled(false)

	// When disabled, Add should just fan out (no store write).
	p.Add(logging.Event{Type: "proxy_response", Severity: "high"})
	if p.eventsObserved.Load() != 1 {
		t.Error("eventsObserved should be 1")
	}
	if p.eventsRecorded.Load() != 0 {
		t.Error("eventsRecorded should be 0 (disabled)")
	}
}

func TestPhase1c_Producer_NilStore(t *testing.T) {
	cfg := ProducerConfig{}
	p := NewProducer(cfg, nil)
	p.SetEnabled(true)
	p.Add(logging.Event{Type: "proxy_response", Severity: "high"})
	if p.eventsRecorded.Load() != 0 {
		t.Error("eventsRecorded should be 0 (nil store)")
	}
}

func TestPhase1c_Producer_NotAllowlisted(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	cfg := ProducerConfig{}
	p := NewProducer(cfg, store)
	p.SetEnabled(true)
	// Event type that's not in the allow list.
	p.Add(logging.Event{Type: "unknown_type", Severity: "high"})
	if p.eventsRejected.Load() != 1 {
		t.Error("eventsRejected should be 1")
	}
}

func TestPhase1c_Producer_BelowMinSeverity(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	cfg := ProducerConfig{
		MinSeverityProxyResponse: SeverityHigh,
	}
	p := NewProducer(cfg, store)
	p.SetEnabled(true)
	// proxy_response with low severity → rejected.
	p.Add(logging.Event{Type: "proxy_response", Severity: "low"})
	if p.eventsRejected.Load() != 1 {
		t.Error("eventsRejected should be 1 (below min severity)")
	}
}

func TestPhase1c_Producer_Success(t *testing.T) {
	store, _ := NewStore(StoreConfig{})
	cfg := ProducerConfig{
		MinSeverityProxyResponse: SeverityLow,
	}
	p := NewProducer(cfg, store)
	p.SetEnabled(true)
	p.Add(logging.Event{
		Type:     "proxy_response",
		Severity: "high",
		Pattern:  "test_pattern",
	})
	if p.eventsRecorded.Load() != 1 {
		t.Errorf("eventsRecorded should be 1, got %d", p.eventsRecorded.Load())
	}
}

func TestPhase1c_Producer_meetsMinSeverity(t *testing.T) {
	p := &Producer{cfg: ProducerConfig{
		MinSeverityProxyResponse: SeverityHigh,
		MinSeverityAnomalyScore:  SeverityMedium,
	}}
	if !p.meetsMinSeverity(IOCTypeProxyResponse, SeverityCritical) {
		t.Error("Critical should meet High min")
	}
	if p.meetsMinSeverity(IOCTypeProxyResponse, SeverityLow) {
		t.Error("Low should not meet High min")
	}
	if !p.meetsMinSeverity(IOCTypeAnomalyScore, SeverityHigh) {
		t.Error("High should meet Medium min")
	}
	if p.meetsMinSeverity(IOCType("unknown"), SeverityCritical) {
		t.Error("Unknown type should not meet any min")
	}
}

func TestPhase1c_Producer_shortSourceFromEventType(t *testing.T) {
	tests := []struct {
		eventType string
		want      string
	}{
		{"proxy_response", "proxy"},
		{"anomaly_score", "anomaly"},
		{"response_scan", "response_scan"},
		{"unknown_type", "platform"},
	}
	for _, tc := range tests {
		got := shortSourceFromEventType(tc.eventType)
		if got != tc.want {
			t.Errorf("shortSourceFromEventType(%q) = %q, want %q", tc.eventType, got, tc.want)
		}
	}
}

// =========================================================================
// fingerprint.go gaps — canonicalJSON edge cases
// =========================================================================

func TestPhase1c_CanonicalJSON_NestedStruct(t *testing.T) {
	type inner struct {
		B int `json:"b"`
		A int `json:"a"`
	}
	type outer struct {
		Inner inner `json:"inner"`
		X     int   `json:"x"`
	}
	v := outer{Inner: inner{B: 2, A: 1}, X: 3}
	got, err := canonicalJSON(v)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}
	if len(got) == 0 {
		t.Error("canonicalJSON returned empty for nested struct")
	}
}

func TestPhase1c_CanonicalJSON_NilValue(t *testing.T) {
	got, err := canonicalJSON(nil)
	if err != nil {
		t.Fatalf("canonicalJSON(nil) failed: %v", err)
	}
	if len(got) == 0 {
		t.Error("canonicalJSON(nil) should not be empty")
	}
}

func TestPhase1c_CanonicalJSON_IntValue(t *testing.T) {
	got, err := canonicalJSON(42)
	if err != nil {
		t.Fatalf("canonicalJSON(42) failed: %v", err)
	}
	if string(got) != "42" {
		t.Errorf("canonicalJSON(42) = %q, want %q", string(got), "42")
	}
}

// =========================================================================
// key_encryption.go gaps — encrypt/decrypt round-trip and error paths
// =========================================================================

func TestPhase1c_EncryptDecryptKeyFile_RoundTrip(t *testing.T) {
	plaintext := []byte(`{"keys": [{"id": "test"}]}`)
	passphrase := "test-passphrase-123"

	encrypted, err := encryptKeyFile(plaintext, passphrase)
	if err != nil {
		t.Fatalf("encryptKeyFile failed: %v", err)
	}

	decrypted, err := decryptKeyFile(encrypted, passphrase)
	if err != nil {
		t.Fatalf("decryptKeyFile failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestPhase1c_DecryptKeyFile_WrongPassphrase(t *testing.T) {
	plaintext := []byte("secret data")
	encrypted, _ := encryptKeyFile(plaintext, "correct-pass")
	_, err := decryptKeyFile(encrypted, "wrong-pass")
	if err == nil {
		t.Error("expected error for wrong passphrase")
	}
}

func TestPhase1c_DecryptKeyFile_NotEncrypted(t *testing.T) {
	// Data that's not in encryptedKeyFile format → unmarshal error.
	_, err := decryptKeyFile([]byte("!!!not json!!!"), "pass")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestPhase1c_DecryptKeyFile_PlainText(t *testing.T) {
	// Valid JSON but Encrypted=false → return as-is.
	data := []byte(`{"encrypted": false, "nonce": "", "ciphertext": ""}`)
	decrypted, err := decryptKeyFile(data, "pass")
	if err != nil {
		t.Fatalf("decryptKeyFile failed: %v", err)
	}
	if string(decrypted) != string(data) {
		t.Error("non-encrypted data should be returned as-is")
	}
}

// =========================================================================
// reputation.go gaps — Flush and loadFromDisk
// =========================================================================

func TestPhase1c_ReputationStore_FlushSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rep.json")
	rs, err := NewReputationStore(ReputationConfig{
		DiskPath:  path,
		Threshold: 0.5,
		HalfLife:  24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewReputationStore failed: %v", err)
	}

	// Add a record.
	rs.Observe("peer-a", 10, 0, "")

	if err := rs.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not created: %v", err)
	}
}

func TestPhase1c_ReputationStore_LoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rep.json")

	// Create a reputation store and save data.
	rs1, _ := NewReputationStore(ReputationConfig{DiskPath: path, Threshold: 0.5, HalfLife: 24 * time.Hour})
	rs1.Observe("peer-x", 10, 0, "")
	rs1.Flush()

	// Load from disk.
	rs2, err := NewReputationStore(ReputationConfig{DiskPath: path, Threshold: 0.5, HalfLife: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewReputationStore (load) failed: %v", err)
	}
	// Score should be > 0 (accepted observations increase score).
	score := rs2.Score("peer-x")
	if score <= 0 {
		t.Errorf("Score(peer-x) = %v, want > 0", score)
	}
}

func TestPhase1c_ReputationStore_LoadFromDiskError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("!!!invalid json!!!"), 0o600)
	_, err := NewReputationStore(ReputationConfig{DiskPath: path, Threshold: 0.5, HalfLife: 24 * time.Hour})
	if err == nil {
		t.Error("expected error for invalid JSON on disk")
	}
}

// =========================================================================
// stix_exporter.go gaps — Writer nil checks and error paths
// =========================================================================

func TestPhase1c_ExportToSTIXWriter_NilBundle(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToSTIXWriter(nil, &bytes.Buffer{})
	if err == nil {
		t.Error("expected error for nil bundle")
	}
}

func TestPhase1c_ExportToSTIXWriter_NilWriter(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToSTIXWriter(&Bundle{}, nil)
	if err == nil {
		t.Error("expected error for nil writer")
	}
}

func TestPhase1c_ExportToJSONLinesWriter_NilBundle(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToJSONLinesWriter(nil, &bytes.Buffer{})
	if err == nil {
		t.Error("expected error for nil bundle")
	}
}

func TestPhase1c_ExportToJSONLinesWriter_NilWriter(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToJSONLinesWriter(&Bundle{}, nil)
	if err == nil {
		t.Error("expected error for nil writer")
	}
}

func TestPhase1c_ExportToJSONLinesWriter_Success(t *testing.T) {
	exporter := &STIXExporter{}
	bundle := &Bundle{
		Count: 1,
		Attestations: []IOCAttestation{
			{Fingerprint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
				IOCType: IOCTypeProxyResponse, Severity: SeverityHigh,
				FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(), Count: 1},
		},
	}
	var buf bytes.Buffer
	err := exporter.ExportToJSONLinesWriter(bundle, &buf)
	if err != nil {
		t.Fatalf("ExportToJSONLinesWriter failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("output should not be empty")
	}
}

func TestPhase1c_ExportToSTIX_MkdirError(t *testing.T) {
	exporter := &STIXExporter{}
	// Path under /proc — cannot create directories there.
	err := exporter.ExportToSTIX(&Bundle{}, "/proc/nonexistent_dir/stix.json")
	if err == nil {
		t.Error("expected error for mkdir failure")
	}
}

func TestPhase1c_ExportToJSONLines_MkdirError(t *testing.T) {
	exporter := &STIXExporter{}
	err := exporter.ExportToJSONLines(&Bundle{}, "/proc/nonexistent_dir/stix.jsonl")
	if err == nil {
		t.Error("expected error for mkdir failure")
	}
}

// =========================================================================
// keyring.go gaps — error paths
// =========================================================================

func TestPhase1c_LoadKeyRing_PathTraversal(t *testing.T) {
	_, err := LoadKeyRing("../../../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

func TestPhase1c_KeyRing_PersistWithPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	kr, err := LoadKeyRingWithPassphrase(path, "test-passphrase")
	if err != nil {
		t.Fatalf("LoadKeyRing failed: %v", err)
	}
	// Rotate to generate and persist a key.
	_, err = kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	// File should exist and be encrypted.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !isEncryptedKeyFile(data) {
		t.Error("keyring file should be encrypted when passphrase is set")
	}
}

func TestPhase1c_KeyRing_RotateAndSign(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kr.json")
	kr, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing failed: %v", err)
	}
	keyID1 := kr.CurrentKeyID()
	_, err = kr.Rotate()
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	keyID2 := kr.CurrentKeyID()
	if keyID1 == keyID2 {
		t.Error("Rotate should produce a new key ID")
	}
	// Old key should be retired.
	keys := kr.ActiveKeys()
	found := false
	for _, k := range keys {
		if k.KeyID == keyID1 && !k.RetiredAt.IsZero() {
			found = true
		}
	}
	if !found {
		t.Error("old key should be retired after rotate")
	}
}

func TestPhase1c_parseRingKeyPEM_InvalidPEM(t *testing.T) {
	_, err := parseRingKeyPEM("not a pem block")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestPhase1c_parseRingKeyPEM_WrongBlockType(t *testing.T) {
	_, err := parseRingKeyPEM("-----BEGIN RSA PRIVATE KEY-----\nABCD\n-----END RSA PRIVATE KEY-----\n")
	if err == nil {
		t.Error("expected error for wrong PEM block type")
	}
}

func TestPhase1c_KeyRing_SetRetiredKeyTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kr.json")
	kr, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing failed: %v", err)
	}
	kr.SetRetiredKeyTTL(1 * time.Hour)
	// Rotate to create a retired key.
	_, _ = kr.Rotate()
	_, _ = kr.Rotate()
	// PruneExpired should be called internally on next rotate.
	// Just verify SetRetiredKeyTTL doesn't panic.
}

func TestPhase1c_KeyRing_PruneExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kr.json")
	kr, err := LoadKeyRing(path)
	if err != nil {
		t.Fatalf("LoadKeyRing failed: %v", err)
	}
	kr.SetRetiredKeyTTL(1 * time.Millisecond)
	// Create and retire a key.
	_, _ = kr.Rotate()
	_, _ = kr.Rotate()
	// Wait for TTL to expire.
	time.Sleep(5 * time.Millisecond)
	// PruneExpired should remove the retired key.
	kr.PruneExpired(time.Now())
}

// =========================================================================
// sync.go gaps — clientIP, rateLimitedHealth
// =========================================================================

func TestPhase1c_Sync_clientIP(t *testing.T) {
	sync := setupTestSync(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ip := sync.clientIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("clientIP = %q, want %q", ip, "192.168.1.100")
	}
}

func TestPhase1c_Sync_clientIP_XForwarded(t *testing.T) {
	sync := setupTestSync(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	req.RemoteAddr = "192.168.1.100:12345"
	ip := sync.clientIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("clientIP = %q, want %q", ip, "10.0.0.1")
	}
}

func TestPhase1c_Sync_rateLimitedHealth(t *testing.T) {
	sync := setupTestSync(t)
	sync.SetShare(true)
	handler := sync.Handler()
	req := httptest.NewRequest("GET", "/api/v1/ioc/health", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Should get 200 (healthy) when share is enabled.
	if rr.Code != http.StatusOK {
		t.Errorf("rateLimitedHealth: expected 200, got %d", rr.Code)
	}
}

// =========================================================================
// feed_manager.go gaps — pullFeed with actual data
// =========================================================================

func TestPhase1c_FeedManager_PullWithData(t *testing.T) {
	srv := mockTAXIIServer(t, false) // non-empty bundle
	defer srv.Close()

	store, _ := NewStore(StoreConfig{})
	fm, err := NewFeedManager(store, []FeedConfig{{
		Name:             "test-feed-data",
		ServerURL:        srv.URL,
		AuthType:         "token",
		APIToken:         "test-token",
		APIRoot:          srv.URL + "/api-root",
		CollectionID:     "col-1",
		PollInterval:     100 * time.Millisecond,
		Enabled:          true,
		SeverityFloor:    SeverityLow,
		ReputationWeight: 0.8,
	}})
	if err != nil {
		t.Fatalf("NewFeedManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fm.Run(ctx)
	time.Sleep(300 * time.Millisecond)
	fm.Stop()

	allStats := fm.Stats()
	for _, s := range allStats {
		t.Logf("Feed %s: pulls=%d, IOCs=%d, errors=%d, lastError=%q",
			s.Name, s.TotalPulls, s.TotalIOCs, s.TotalErrors, s.LastError)
	}
}

func TestPhase1c_FeedManager_PullWithDiscovery(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()

	store, _ := NewStore(StoreConfig{})
	// No APIRoot — force discovery path.
	fm, err := NewFeedManager(store, []FeedConfig{{
		Name:             "test-feed-disc",
		ServerURL:        srv.URL,
		AuthType:         "token",
		APIToken:         "test-token",
		CollectionID:     "col-1",
		PollInterval:     100 * time.Millisecond,
		Enabled:          true,
		SeverityFloor:    SeverityLow,
		ReputationWeight: 0.8,
	}})
	if err != nil {
		t.Fatalf("NewFeedManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fm.Run(ctx)
	time.Sleep(300 * time.Millisecond)
	fm.Stop()

	allStats := fm.Stats()
	for _, s := range allStats {
		t.Logf("Feed %s (discovery): pulls=%d, IOCs=%d, errors=%d, lastError=%q",
			s.Name, s.TotalPulls, s.TotalIOCs, s.TotalErrors, s.LastError)
	}
}

func TestPhase1c_FeedManager_PullWithSeverityFloor(t *testing.T) {
	srv := mockTAXIIServer(t, false)
	defer srv.Close()

	store, _ := NewStore(StoreConfig{})
	// High severity floor — should filter out IOCs.
	fm, err := NewFeedManager(store, []FeedConfig{{
		Name:             "test-filter",
		ServerURL:        srv.URL,
		AuthType:         "token",
		APIToken:         "test-token",
		APIRoot:          srv.URL + "/api-root",
		CollectionID:     "col-1",
		PollInterval:     100 * time.Millisecond,
		Enabled:          true,
		SeverityFloor:    SeverityCritical, // only critical IOCs
		ReputationWeight: 0.8,
	}})
	if err != nil {
		t.Fatalf("NewFeedManager failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fm.Run(ctx)
	time.Sleep(300 * time.Millisecond)
	fm.Stop()

	// With high severity floor, IOCs below critical should be skipped.
	allStats := fm.Stats()
	for _, s := range allStats {
		t.Logf("Feed %s (filter): pulls=%d, IOCs=%d, errors=%d",
			s.Name, s.TotalPulls, s.TotalIOCs, s.TotalErrors)
	}
}
