// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - External TAXII Feed Manager Tests (v4.5.1+ Phase 2)
// =========================================================================

package ioc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIsExternalSource verifies the external source detection.
func TestIsExternalSource(t *testing.T) {
	tests := []struct {
		source string
		want   bool
	}{
		{"external:cisa-acs:1.0", true},
		{"external:misp-community:0.7", true},
		{"external:anomali:0.5", true},
		{"peer:testlab-server", false},
		{"proxy", false},
		{"scanner", false},
		{"", false},
	}
	for _, tt := range tests {
		got := IsExternalSource(tt.source)
		if got != tt.want {
			t.Errorf("IsExternalSource(%q) = %v, want %v", tt.source, got, tt.want)
		}
	}
}

// TestParseExternalSource verifies parsing of external source labels.
func TestParseExternalSource(t *testing.T) {
	tests := []struct {
		source       string
		wantName     string
		wantWeight   float64
		wantExternal bool
	}{
		{"external:cisa-acs:1.0", "cisa-acs", 1.0, true},
		{"external:misp:0.7", "misp", 0.7, true},
		{"external:anomali:0.3", "anomali", 0.3, true},
		{"external:test-feed", "test-feed", 0.7, true}, // default weight
		{"peer:server", "", 0, false},
		{"proxy", "", 0, false},
	}
	for _, tt := range tests {
		name, weight, isExt := ParseExternalSource(tt.source)
		if name != tt.wantName || weight != tt.wantWeight || isExt != tt.wantExternal {
			t.Errorf("ParseExternalSource(%q) = (%q, %f, %v), want (%q, %f, %v)",
				tt.source, name, weight, isExt, tt.wantName, tt.wantWeight, tt.wantExternal)
		}
	}
}

// TestFeedManager_New verifies construction and validation.
func TestFeedManager_New(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Valid config.
	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:         "test-feed",
			ServerURL:    "http://localhost:9999",
			AuthType:     "token",
			APIToken:     "test-token",
			Enabled:      true,
			PollInterval: 5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}
	if fm == nil {
		t.Fatal("NewFeedManager returned nil")
	}
	names := fm.FeedNames()
	if len(names) != 1 || names[0] != "test-feed" {
		t.Errorf("FeedNames = %v, want [test-feed]", names)
	}

	// Duplicate name.
	_, err = NewFeedManager(store, []FeedConfig{
		{Name: "dup", ServerURL: "http://a", AuthType: "token"},
		{Name: "dup", ServerURL: "http://b", AuthType: "token"},
	})
	if err == nil {
		t.Error("expected error for duplicate feed name, got nil")
	}

	// Missing ServerURL.
	_, err = NewFeedManager(store, []FeedConfig{
		{Name: "bad", ServerURL: "", AuthType: "token"},
	})
	if err == nil {
		t.Error("expected error for missing ServerURL, got nil")
	}

	// Missing AuthType.
	_, err = NewFeedManager(store, []FeedConfig{
		{Name: "bad", ServerURL: "http://a", AuthType: ""},
	})
	if err == nil {
		t.Error("expected error for missing AuthType, got nil")
	}

	// Empty Name.
	_, err = NewFeedManager(store, []FeedConfig{
		{Name: "", ServerURL: "http://a", AuthType: "token"},
	})
	if err == nil {
		t.Error("expected error for empty Name, got nil")
	}

	// Nil store.
	_, err = NewFeedManager(nil, nil)
	if err == nil {
		t.Error("expected error for nil store, got nil")
	}
}

// TestFeedManager_PullNow_MockTAXII tests PullNow against a mock
// TAXII server. The mock server returns a STIX bundle with
// indicators that the feed manager should convert and ingest.
func TestFeedManager_PullNow_MockTAXII(t *testing.T) {
	// Create a mock TAXII server that returns a discovery response
	// and a collection with STIX indicators.
	mux := http.NewServeMux()

	// Discovery endpoint.
	mux.HandleFunc("/taxii2/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		w.Write([]byte(`{
			"title": "Mock TAXII Server",
			"description": "Test server",
			"api_roots": ["http://` + r.Host + `/api1/"]
		}`))
	})

	// Collections endpoint.
	mux.HandleFunc("/api1/collections/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		w.Write([]byte(`{
			"collections": [{
				"id": "test-collection",
				"title": "Test Collection",
				"can_read": true,
				"can_write": false,
				"media_types": ["application/stix+json;version=2.1"]
			}]
		}`))
	})

	// Objects endpoint — returns STIX indicators.
	mux.HandleFunc("/api1/collections/test-collection/objects/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		// Return a STIX bundle with one indicator.
		// The pattern uses a SHA-256 hash so STIXIndicatorToIOC
		// can parse it.
		fp := strings.Repeat("a", 64)
		w.Write([]byte(`{
			"more": false,
			"objects": [{
				"type": "indicator",
				"spec_version": "2.1",
				"id": "indicator--00000000-0000-4000-8000-000000000001",
				"created": "2026-01-01T00:00:00.000Z",
				"modified": "2026-01-01T00:00:00.000Z",
				"pattern": "[file:hashes.SHA-256 = '` + fp + `']",
				"pattern_type": "stix",
				"valid_from": "2026-01-01T00:00:00Z",
				"valid_until": "2026-12-31T00:00:00Z",
				"indicator_types": ["malicious-activity"],
				"confidence": 85,
				"labels": ["aegisgate", "type:proxy_response", "source:mock", "count:3"]
			}]
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	store, err := NewStore(StoreConfig{Capacity: 1000})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:             "mock-feed",
			ServerURL:        server.URL,
			AuthType:         "token",
			APIToken:         "test",
			PollInterval:     5 * time.Minute,
			Enabled:          true,
			APIRoot:          server.URL + "/api1/",
			CollectionID:     "test-collection",
			ReputationWeight: 1.0,
			SeverityFloor:    SeverityLow,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	// Pull now.
	ingested, err := fm.PullNow(t.Context(), "mock-feed")
	if err != nil {
		t.Fatalf("PullNow: %v", err)
	}

	if ingested != 1 {
		t.Errorf("ingested = %d, want 1", ingested)
	}

	// Verify the IOC is in the store with external source.
	fp := strings.Repeat("a", 64)
	stored := store.Get(fp)
	if stored == nil {
		t.Fatalf("IOC not in store")
	}
	if !IsExternalSource(stored.Source) {
		t.Errorf("IOC source = %q, want external:*", stored.Source)
	}
	feedName, weight, isExt := ParseExternalSource(stored.Source)
	if !isExt || feedName != "mock-feed" {
		t.Errorf("ParseExternalSource: name=%q, isExt=%v", feedName, isExt)
	}
	if weight != 1.0 {
		t.Errorf("weight = %f, want 1.0", weight)
	}

	t.Logf("PullNow OK: ingested=%d, source=%q, severity=%q", ingested, stored.Source, stored.Severity)

	// Check stats.
	stats := fm.Stats()
	if len(stats) != 1 {
		t.Fatalf("Stats len = %d, want 1", len(stats))
	}
	if stats[0].Name != "mock-feed" {
		t.Errorf("stats[0].Name = %q, want mock-feed", stats[0].Name)
	}
	if stats[0].LastPullCount != 1 {
		t.Errorf("LastPullCount = %d, want 1", stats[0].LastPullCount)
	}
	if stats[0].TotalIOCs != 1 {
		t.Errorf("TotalIOCs = %d, want 1", stats[0].TotalIOCs)
	}
	if stats[0].LastError != "" {
		t.Errorf("LastError = %q, want empty", stats[0].LastError)
	}

	t.Logf("Stats OK: totalPulls=%d, totalIOCs=%d, totalErrors=%d",
		stats[0].TotalPulls, stats[0].TotalIOCs, stats[0].TotalErrors)
}

// TestFeedManager_SeverityFloor verifies that IOCs below the
// feed's severity floor are dropped during pull.
func TestFeedManager_SeverityFloor(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api1/collections/col/objects/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/taxii+json")
		// Return two indicators: one high confidence (maps to high
		// severity) and one low confidence (maps to low severity).
		fp1 := strings.Repeat("b", 64)
		fp2 := strings.Repeat("c", 64)
		w.Write([]byte(`{
			"more": false,
			"objects": [
				{
					"type": "indicator",
					"spec_version": "2.1",
					"id": "indicator--00000000-0000-4000-8000-000000000001",
					"created": "2026-01-01T00:00:00.000Z",
					"modified": "2026-01-01T00:00:00.000Z",
					"pattern": "[file:hashes.SHA-256 = '` + fp1 + `']",
					"pattern_type": "stix",
					"valid_from": "2026-01-01T00:00:00Z",
					"valid_until": "2026-12-31T00:00:00Z",
					"indicator_types": ["malicious-activity"],
					"confidence": 85,
					"labels": ["type:proxy_response"]
				},
				{
					"type": "indicator",
					"spec_version": "2.1",
					"id": "indicator--00000000-0000-4000-8000-000000000002",
					"created": "2026-01-01T00:00:00.000Z",
					"modified": "2026-01-01T00:00:00Z",
					"pattern": "[file:hashes.SHA-256 = '` + fp2 + `']",
					"pattern_type": "stix",
					"valid_from": "2026-01-01T00:00:00Z",
					"valid_until": "2026-12-31T00:00:00Z",
					"indicator_types": ["malicious-activity"],
					"confidence": 25,
					"labels": ["type:proxy_response"]
				}
			]
		}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	store, err := NewStore(StoreConfig{Capacity: 1000})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:          "floor-test",
			ServerURL:     server.URL,
			AuthType:      "token",
			APIToken:      "test",
			APIRoot:       server.URL + "/api1/",
			CollectionID:  "col",
			Enabled:       true,
			SeverityFloor: SeverityMedium, // drop low and info
			PollInterval:  5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	ingested, err := fm.PullNow(t.Context(), "floor-test")
	if err != nil {
		t.Fatalf("PullNow: %v", err)
	}

	// fp1 has confidence 85 -> severity high (>= medium floor) -> ingested.
	// fp2 has confidence 25 -> severity info (< medium floor) -> dropped.
	if ingested != 1 {
		t.Errorf("ingested = %d, want 1 (severity floor should drop 1)", ingested)
	}

	// Verify fp1 is in store, fp2 is not.
	if store.Get(strings.Repeat("b", 64)) == nil {
		t.Error("fp1 (high severity) should be in store")
	}
	if store.Get(strings.Repeat("c", 64)) != nil {
		t.Error("fp2 (low severity) should be dropped by severity floor")
	}

	t.Logf("SeverityFloor OK: ingested=%d (1 dropped by floor)", ingested)
}

// TestFeedManager_PullNow_FeedNotFound verifies that pulling a
// non-existent feed returns an error.
func TestFeedManager_PullNow_FeedNotFound(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	fm, err := NewFeedManager(store, []FeedConfig{
		{Name: "real", ServerURL: "http://localhost:1", AuthType: "token"},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	_, err = fm.PullNow(t.Context(), "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent feed, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should contain 'not found', got: %v", err)
	}
}

// TestFeedManager_ExternalIOC_Corroboration verifies that an
// external feed IOC with high reputation weight counts as
// corroboration in the IOCChecker, enabling the feedback loop.
func TestFeedManager_ExternalIOC_Corroboration(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Simulate an external feed IOC being ingested.
	fp := strings.Repeat("d", 64)
	_, err = store.Observe(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().Add(-1 * time.Hour),
		LastSeen:    time.Now(),
		Count:       10,
		Source:      "external:cisa-acs:1.0", // high trust
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	// The IOC was inserted with a known fingerprint, so we use
	// CheckFingerprint directly rather than CheckCorroboration
	// (which would compute a different fingerprint from a Detection).
	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckFingerprint(fp, true)

	if !result.Found {
		t.Errorf("Found = false, want true")
	}
	if result.PeerCount < 1 {
		t.Errorf("PeerCount = %d, want >= 1 (external feed with weight >= 0.5 should count as corroboration)", result.PeerCount)
	}
	if !result.RecommendBlock {
		t.Errorf("RecommendBlock = false, want true (local detection + external corroboration)")
	}

	t.Logf("External IOC corroboration OK: peers=%d, recommendBlock=%v, reason=%q",
		result.PeerCount, result.RecommendBlock, result.Reason)
}

// TestFeedManager_LowTrustExternal_NoCorroboration verifies that
// an external feed IOC with low reputation weight (< 0.5) does
// NOT count as corroboration in conservative mode.
func TestFeedManager_LowTrustExternal_NoCorroboration(t *testing.T) {
	store, err := NewStore(StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fp := strings.Repeat("e", 64)
	_, err = store.Observe(IOC{
		Fingerprint: fp,
		Type:        IOCTypeProxyResponse,
		Severity:    SeverityHigh,
		FirstSeen:   time.Now().Add(-1 * time.Hour),
		LastSeen:    time.Now(),
		Count:       1,
		Source:      "external:untrusted-feed:0.3", // low trust
	})
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}

	checker := NewIOCChecker(store, DefaultCheckerConfig())
	result := checker.CheckFingerprint(fp, true)

	if !result.Found {
		t.Errorf("Found = false, want true")
	}
	if result.PeerCount != 0 {
		t.Errorf("PeerCount = %d, want 0 (low-trust external feed should not count as corroboration)", result.PeerCount)
	}
	if result.RecommendBlock {
		t.Errorf("RecommendBlock = true, want false (low-trust external + local detection but no peer corroboration)")
	}

	t.Logf("Low-trust external OK: peers=%d, recommendBlock=%v, reason=%q",
		result.PeerCount, result.RecommendBlock, result.Reason)
}

// TestFeedManager_DefaultFeedConfig verifies the defaults.
func TestFeedManager_DefaultFeedConfig(t *testing.T) {
	cfg := DefaultFeedConfig("my-feed")
	if cfg.Name != "my-feed" {
		t.Errorf("Name = %q, want my-feed", cfg.Name)
	}
	if cfg.AuthType != "token" {
		t.Errorf("AuthType = %q, want token", cfg.AuthType)
	}
	if cfg.PollInterval != 1*time.Hour {
		t.Errorf("PollInterval = %v, want 1h", cfg.PollInterval)
	}
	if cfg.ReputationWeight != 0.7 {
		t.Errorf("ReputationWeight = %f, want 0.7", cfg.ReputationWeight)
	}
	if cfg.SeverityFloor != SeverityLow {
		t.Errorf("SeverityFloor = %q, want %q", cfg.SeverityFloor, SeverityLow)
	}
	if !cfg.Enabled {
		t.Errorf("Enabled = false, want true")
	}
}

// TestFeedManager_PollIntervalMinimum verifies that poll intervals
// below 5 minutes are clamped to 5 minutes.
func TestFeedManager_PollIntervalMinimum(t *testing.T) {
	store, _ := NewStore(StoreConfig{Capacity: 100})
	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:         "fast-feed",
			ServerURL:    "http://localhost:1",
			AuthType:     "token",
			PollInterval: 30 * time.Second, // too fast
			Enabled:      true,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}
	stats := fm.Stats()
	if stats[0].PollInterval != 5*time.Minute {
		t.Errorf("PollInterval = %v, want 5m (clamped)", stats[0].PollInterval)
	}
}
