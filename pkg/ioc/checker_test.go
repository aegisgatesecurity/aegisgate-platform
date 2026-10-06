// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - IOC Feedback Loop Checker Tests
// =========================================================================

package ioc

import (
	"testing"
	"time"
)

func TestIOCChecker_NovelDetection(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	checker := NewIOCChecker(store, DefaultCheckerConfig())

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_access_key",
	}

	result := checker.CheckCorroboration(d, true)
	if result.Found {
		t.Errorf("novel detection should not be found in store")
	}
	if result.RecommendBlock {
		t.Errorf("novel detection should not recommend block")
	}
	if result.PeerCount != 0 {
		t.Errorf("novel detection peer count = %d, want 0", result.PeerCount)
	}
}

func TestIOCChecker_LocalOnlyNoCorroboration(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_access_key",
	}
	fp := Fingerprint(d)

	// Store a local-only IOC (Source = "proxy").
	now := time.Now().UTC()
	_, err = store.Observe(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now.Add(-1 * time.Hour),
		LastSeen:    now,
		Count:       5,
		Source:      "proxy",
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckCorroboration(d, true)

	if !result.Found {
		t.Errorf("IOC should be found in store")
	}
	if result.PeerCount != 0 {
		t.Errorf("local-only IOC peer count = %d, want 0", result.PeerCount)
	}
	if result.RecommendBlock {
		t.Errorf("local-only IOC should not recommend block (no peer corroboration)")
	}
	if result.LocalCount != 5 {
		t.Errorf("local count = %d, want 5", result.LocalCount)
	}
}

func TestIOCChecker_PeerCorroborated_RecommendsBlock(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_access_key",
	}
	fp := Fingerprint(d)

	// Store a peer-sourced IOC with high severity.
	now := time.Now().UTC()
	store.mergePeerIOC(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now.Add(-2 * time.Hour),
		LastSeen:    now,
		Count:       10,
		Source:      "peer:instance-abc",
	})

	checker := NewIOCChecker(store, DefaultCheckerConfig())

	// With local detection = true, peer corroboration should recommend block.
	result := checker.CheckCorroboration(d, true)

	if !result.Found {
		t.Errorf("IOC should be found in store")
	}
	if result.PeerCount < 1 {
		t.Errorf("peer count = %d, want >= 1", result.PeerCount)
	}
	if !result.RecommendBlock {
		t.Errorf("peer-corroborated IOC with local detection should recommend block")
	}
	if result.Reason == "" {
		t.Errorf("recommend block should have a reason")
	}
}

func TestIOCChecker_PeerCorroborated_NoLocalDetection_ConservativeMode(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_access_key",
	}
	fp := Fingerprint(d)

	now := time.Now().UTC()
	store.mergePeerIOC(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now.Add(-2 * time.Hour),
		LastSeen:    now,
		Count:       10,
		Source:      "peer:instance-abc",
	})

	// Conservative mode: RequireLocalDetection = true
	cfg := DefaultCheckerConfig()
	cfg.RequireLocalDetection = true
	checker := NewIOCChecker(store, cfg)

	// No local detection → should NOT recommend block in conservative mode.
	result := checker.CheckCorroboration(d, false)

	if !result.Found {
		t.Errorf("IOC should be found")
	}
	if result.RecommendBlock {
		t.Errorf("conservative mode should not block without local detection")
	}
}

func TestIOCChecker_PeerCorroborated_AggressiveMode(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_access_key",
	}
	fp := Fingerprint(d)

	now := time.Now().UTC()
	store.mergePeerIOC(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   now.Add(-2 * time.Hour),
		LastSeen:    now,
		Count:       10,
		Source:      "peer:instance-abc",
	})

	// Aggressive mode: RequireLocalDetection = false, MinPeerCount = 1
	cfg := DefaultCheckerConfig()
	cfg.RequireLocalDetection = false
	cfg.MinPeerCount = 1
	checker := NewIOCChecker(store, cfg)

	// No local detection, but aggressive mode should still block.
	result := checker.CheckCorroboration(d, false)

	if !result.Found {
		t.Errorf("IOC should be found")
	}
	if !result.RecommendBlock {
		t.Errorf("aggressive mode should block on peer IOCs alone")
	}
}

func TestIOCChecker_LowSeverityPeerIOC_DoesNotBlock(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityLow,
		Pattern:  "email_address",
	}
	fp := Fingerprint(d)

	now := time.Now().UTC()
	store.mergePeerIOC(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityLow,
		FirstSeen:   now.Add(-2 * time.Hour),
		LastSeen:    now,
		Count:       3,
		Source:      "peer:instance-abc",
	})

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckCorroboration(d, true)

	if !result.Found {
		t.Errorf("IOC should be found")
	}
	if result.RecommendBlock {
		t.Errorf("low-severity IOC should not recommend block (below MinSeverity)")
	}
}

func TestIOCChecker_StaleIOC_DoesNotBlock(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_access_key",
	}
	fp := Fingerprint(d)

	// Store a very old peer IOC.
	old := time.Now().UTC().Add(-60 * 24 * time.Hour) // 60 days ago
	store.mergePeerIOC(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   old,
		LastSeen:    old,
		Count:       10,
		Source:      "peer:instance-abc",
	})

	cfg := DefaultCheckerConfig()
	cfg.MaxAge = 30 * 24 * time.Hour // 30 days
	checker := NewIOCChecker(store, cfg)

	result := checker.CheckCorroboration(d, true)

	if !result.Found {
		t.Errorf("IOC should be found")
	}
	if result.RecommendBlock {
		t.Errorf("stale IOC should not recommend block")
	}
}

func TestIOCChecker_CheckFingerprint(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fp := Fingerprint(Detection{
		Type:     "prompt_injection",
		Severity: SeverityCritical,
		Pattern:  "jailbreak_v3",
	})

	now := time.Now().UTC()
	store.mergePeerIOC(IOC{
		Fingerprint: fp,
		Type:        IOCTypePromptInjection,
		Severity:    SeverityCritical,
		FirstSeen:   now.Add(-1 * time.Hour),
		LastSeen:    now,
		Count:       20,
		Source:      "peer:instance-xyz",
	})

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckFingerprint(fp, true)

	if !result.Found {
		t.Errorf("IOC should be found")
	}
	if result.PeerCount < 1 {
		t.Errorf("peer count = %d, want >= 1", result.PeerCount)
	}
	if !result.RecommendBlock {
		t.Errorf("critical peer-corroborated IOC should recommend block")
	}
}

func TestIOCChecker_Stats(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now().UTC()

	// Add 2 local IOCs and 1 peer IOC.
	for i := 0; i < 2; i++ {
		fp := Fingerprint(Detection{
			Type:     "proxy_response",
			Severity: SeverityHigh,
			Pattern:  string(rune('a' + i)),
		})
		_, err = store.Observe(IOC{
			Fingerprint: fp,
			Type:        IOCTypeProxyResponse,
			Severity:    SeverityHigh,
			FirstSeen:   now,
			LastSeen:    now,
			Count:       1,
			Source:      "proxy",
		})
		if err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	peerFP := Fingerprint(Detection{
		Type:     "prompt_injection",
		Severity: SeverityCritical,
		Pattern:  "jailbreak_v3",
	})
	store.mergePeerIOC(IOC{
		Fingerprint: peerFP,
		Type:        IOCTypePromptInjection,
		Severity:    SeverityCritical,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       5,
		Source:      "peer:instance-xyz",
	})

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	stats := checker.Stats()

	if stats.StoreSize != 3 {
		t.Errorf("store size = %d, want 3", stats.StoreSize)
	}
	if stats.LocalIOCs != 2 {
		t.Errorf("local IOCs = %d, want 2", stats.LocalIOCs)
	}
	if stats.PeerIOCs != 1 {
		t.Errorf("peer IOCs = %d, want 1", stats.PeerIOCs)
	}
	if stats.Config.MinPeerCount != 2 {
		t.Errorf("config MinPeerCount = %d, want 2", stats.Config.MinPeerCount)
	}
}

func TestIOCChecker_NilStore(t *testing.T) {
	checker := NewIOCChecker(nil, DefaultCheckerConfig())
	result := checker.CheckCorroboration(Detection{}, true)

	if result.Found {
		t.Errorf("nil store should not find anything")
	}
	if result.RecommendBlock {
		t.Errorf("nil store should not recommend block")
	}
}

func TestIOCChecker_EmptyFingerprint(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	checker := NewIOCChecker(store, DefaultCheckerConfig())

	// Empty Detection produces empty fingerprint.
	result := checker.CheckCorroboration(Detection{}, true)

	if result.Found {
		t.Errorf("empty detection should not find anything")
	}
}
