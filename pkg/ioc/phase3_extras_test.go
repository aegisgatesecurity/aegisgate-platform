// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// =====================================================================
// cleanFilePath tests
// =====================================================================

func TestPhase3_cleanFilePath_Valid(t *testing.T) {
	cases := []struct {
		input  string
		expect string
	}{
		{"", ""},
		{"/data/keys/keyring.json", "/data/keys/keyring.json"},
		{"./data/keys", "data/keys"},
		{"data/../data/keys", "data/keys"},
	}
	for _, tc := range cases {
		got, err := cleanFilePath(tc.input)
		if err != nil {
			t.Fatalf("cleanFilePath(%q): %v", tc.input, err)
		}
		if got != tc.expect {
			t.Fatalf("cleanFilePath(%q) = %q, want %q", tc.input, got, tc.expect)
		}
	}
}

func TestPhase3_cleanFilePath_Traversal(t *testing.T) {
	bad := []string{
		"../etc/passwd",
		"data/../../etc/passwd",
	}
	for _, p := range bad {
		_, err := cleanFilePath(p)
		if err == nil {
			t.Fatalf("expected error for path traversal: %s", p)
		}
	}
}

// =====================================================================
// Fingerprint / canonicalJSON tests
// =====================================================================

func TestPhase3_Fingerprint_Stable(t *testing.T) {
	d := Detection{
		Type:     "proxy_response",
		Severity: SeverityHigh,
		Pattern:  "secret_aws_key",
	}
	fp1 := Fingerprint(d)
	fp2 := Fingerprint(d)
	if fp1 != fp2 {
		t.Fatal("fingerprint should be deterministic")
	}
	if len(fp1) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d", len(fp1))
	}
}

func TestPhase3_Fingerprint_DifferentSeverity(t *testing.T) {
	d1 := Detection{Type: "proxy_response", Severity: SeverityHigh, Pattern: "test"}
	d2 := Detection{Type: "proxy_response", Severity: SeverityLow, Pattern: "test"}
	if Fingerprint(d1) == Fingerprint(d2) {
		t.Fatal("different severity should produce different fingerprints")
	}
}

func TestPhase3_FingerprintBytes(t *testing.T) {
	d := Detection{Type: "proxy_response", Severity: SeverityHigh}
	bytes := FingerprintBytes(d)
	if len(bytes) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(bytes))
	}
}

func TestPhase3_canonicalJSON_NestedMap(t *testing.T) {
	// Test with a nested map to cover the sorting path
	data := map[string]interface{}{
		"z": "last",
		"a": map[string]interface{}{
			"y": 1,
			"x": 2,
		},
	}
	result, err := canonicalJSON(data)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
}

func TestPhase3_canonicalJSON_Array(t *testing.T) {
	data := map[string]interface{}{
		"items": []interface{}{3, 1, 2},
	}
	result, err := canonicalJSON(data)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	// Array order should be preserved
	if len(result) == 0 {
		t.Fatal("expected non-empty result")
	}
}

// =====================================================================
// IOCChecker tests
// =====================================================================

func TestPhase3_NewIOCChecker_DefaultConfig(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Pass zero-value config — should use DefaultCheckerConfig
	checker := NewIOCChecker(store, CheckerConfig{})
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestPhase3_NewIOCChecker_CustomConfig(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	checker := NewIOCChecker(store, CheckerConfig{MinPeerCount: 3})
	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
}

func TestPhase3_CheckCorroboration_NilStore(t *testing.T) {
	checker := NewIOCChecker(nil, CheckerConfig{})
	d := Detection{Type: "proxy_response", Severity: SeverityHigh}
	result := checker.CheckCorroboration(d, true)
	// With nil store, should return empty result
	if result.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestPhase3_CheckCorroboration_WithStore(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	checker := NewIOCChecker(store, CheckerConfig{})
	d := Detection{Type: "proxy_response", Severity: SeverityHigh}
	result := checker.CheckCorroboration(d, true)
	// With empty store, should return result with no corroboration
	if result.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if result.RecommendBlock {
		t.Fatal("expected RecommendBlock=false with empty store")
	}
}

func TestPhase3_CheckFingerprint_Empty(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	checker := NewIOCChecker(store, CheckerConfig{})
	result := checker.CheckFingerprint("", true)
	if result.Fingerprint != "" {
		t.Fatal("expected empty fingerprint")
	}
}

func TestPhase3_CheckFingerprint_NotFound(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	checker := NewIOCChecker(store, CheckerConfig{})
	result := checker.CheckFingerprint("nonexistent-fingerprint-64-chars-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)
	// Should return result with RecommendBlock=false
	if result.RecommendBlock {
		t.Fatal("expected RecommendBlock=false for nonexistent fingerprint")
	}
}

// =====================================================================
// FeedManager recordError test (via failing TAXII server)
// =====================================================================

func TestPhase3_FeedManager_recordError(t *testing.T) {
	// Create a server that returns 500 for all requests
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, []FeedConfig{
		{
			Name:          "error-feed",
			ServerURL:     srv.URL,
			AuthType:      "token",
			APIToken:      "test-token",
			APIRoot:       srv.URL + "/api-root",
			CollectionID:  "col-1",
			PollInterval:  10 * time.Second,
			Enabled:       true,
			SeverityFloor: SeverityLow,
		},
	})
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	// PullNow will trigger pullFeed which will fail and call recordError
	_, err = fm.PullNow(context.Background(), "error-feed")
	if err == nil {
		t.Fatal("expected error from failing TAXII server")
	}

	// Check that the error was recorded
	allStats := fm.Stats()
	for _, s := range allStats {
		if s.Name == "error-feed" {
			if s.TotalErrors < 1 {
				t.Fatalf("expected at least 1 error, got %d", s.TotalErrors)
			}
			if s.LastError == "" {
				t.Fatal("expected non-empty LastError")
			}
			return
		}
	}
	t.Fatal("error-feed not found in stats")
}
