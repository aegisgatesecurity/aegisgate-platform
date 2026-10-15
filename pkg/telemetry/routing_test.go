// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Telemetry Routing Tests

package telemetry

import (
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/contracts"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/scanner"
)

func TestEventRouter_Route(t *testing.T) {
	router := NewEventRouter(nil)

	e := contracts.Event{
		ID:              "test-1",
		Source:          contracts.SourceScanner,
		SchemaVersion:   "v1",
		Timestamp:       time.Now().UTC(),
		TotalDetections: 3,
		Blocked:         true,
		Categories:      []string{"secrets", "pii"},
		Severities:      []string{"critical", "high"},
		Rules:           []string{"pii_ssn", "secret_rsa_key"},
		Findings: []contracts.EventFinding{
			{RuleID: "pii_ssn", Severity: "critical"},
		},
	}

	if err := router.Route(e); err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	stats := router.GetSourceStats(contracts.SourceScanner)
	if stats.Events != 1 {
		t.Errorf("expected 1 event, got %d", stats.Events)
	}
	if stats.Detections != 3 {
		t.Errorf("expected 3 detections, got %d", stats.Detections)
	}
	if stats.Blocks != 1 {
		t.Errorf("expected 1 block, got %d", stats.Blocks)
	}
	if stats.Categories["secrets"] != 1 {
		t.Errorf("expected secrets category count 1, got %d", stats.Categories["secrets"])
	}
	if stats.Rules["pii_ssn"] != 1 {
		t.Errorf("expected pii_ssn rule count 1, got %d", stats.Rules["pii_ssn"])
	}
}

func TestEventRouter_MultipleSources(t *testing.T) {
	router := NewEventRouter(nil)

	// Route events from different sources
	sources := []contracts.EventSource{
		contracts.SourceLens,
		contracts.SourceRampart,
		contracts.SourceScanner,
		contracts.SourceMCP,
	}

	for i, src := range sources {
		e := contracts.Event{
			ID:              "test-" + string(src),
			Source:          src,
			SchemaVersion:   "v1",
			Timestamp:       time.Now().UTC(),
			TotalDetections: i + 1,
		}
		if err := router.Route(e); err != nil {
			t.Fatalf("Route failed for %s: %v", src, err)
		}
	}

	allStats := router.GetAllStats()
	if len(allStats) != 4 {
		t.Errorf("expected 4 sources, got %d", len(allStats))
	}

	if router.GetTotalEvents() != 4 {
		t.Errorf("expected 4 total events, got %d", router.GetTotalEvents())
	}

	// Total detections: 1+2+3+4 = 10
	if router.GetTotalDetections() != 10 {
		t.Errorf("expected 10 total detections, got %d", router.GetTotalDetections())
	}
}

func TestEventRouter_Corroboration(t *testing.T) {
	router := NewEventRouter(nil)

	// Two different sources observe the same rule on the same domain
	domain := "hashed-example.com"

	e1 := contracts.Event{
		ID: "test-1", Source: contracts.SourceLens, SchemaVersion: "v1",
		Timestamp:    time.Now().UTC(),
		HashedDomain: domain,
		Findings: []contracts.EventFinding{
			{RuleID: "prompt_injection", Severity: "high"},
		},
	}
	e2 := contracts.Event{
		ID: "test-2", Source: contracts.SourceRampart, SchemaVersion: "v1",
		Timestamp:    time.Now().UTC(),
		HashedDomain: domain,
		Findings: []contracts.EventFinding{
			{RuleID: "prompt_injection", Severity: "high"},
		},
	}

	router.Route(e1)
	router.Route(e2)

	// Should see 2 distinct sources for this fingerprint
	c := router.GetCorroboration("prompt_injection", domain)
	if c != 2 {
		t.Errorf("expected 2 corroborating sources, got %d", c)
	}

	// Different rule on same domain should have 0
	c = router.GetCorroboration("unknown_rule", domain)
	if c != 0 {
		t.Errorf("expected 0 for unknown rule, got %d", c)
	}
}

func TestEventRouter_PruneFingerprints(t *testing.T) {
	router := NewEventRouter(nil)

	// Add an old event
	oldTime := time.Now().UTC().Add(-2 * time.Hour)
	e1 := contracts.Event{
		ID: "old", Source: contracts.SourceLens, SchemaVersion: "v1",
		Timestamp:    oldTime,
		HashedDomain: "old-domain",
		Findings: []contracts.EventFinding{
			{RuleID: "old_rule", Severity: "low"},
		},
	}
	router.Route(e1)

	// Add a recent event
	e2 := contracts.Event{
		ID: "new", Source: contracts.SourceRampart, SchemaVersion: "v1",
		Timestamp:    time.Now().UTC(),
		HashedDomain: "new-domain",
		Findings: []contracts.EventFinding{
			{RuleID: "new_rule", Severity: "high"},
		},
	}
	router.Route(e2)

	// Prune entries older than 1 hour
	router.PruneFingerprints(1 * time.Hour)

	// Old should be gone
	c := router.GetCorroboration("old_rule", "old-domain")
	if c != 0 {
		t.Errorf("expected 0 after prune, got %d", c)
	}

	// New should remain
	c = router.GetCorroboration("new_rule", "new-domain")
	if c != 1 {
		t.Errorf("expected 1 after prune, got %d", c)
	}
}

func TestEventRouter_GetSummary(t *testing.T) {
	router := NewEventRouter(nil)

	e := contracts.Event{
		ID: "test-1", Source: contracts.SourceMCP, SchemaVersion: "v1",
		Timestamp:       time.Now().UTC(),
		TotalDetections: 5,
		Blocked:         true,
		Rules:           []string{"tool_poisoning", "dangerous_eval"},
	}
	router.Route(e)

	summary := router.GetSummary()

	totalEvents, ok := summary["total_events"].(int64)
	if !ok || totalEvents != 1 {
		t.Errorf("expected total_events=1, got %v", summary["total_events"])
	}

	bySource, ok := summary["by_source"].(map[string]interface{})
	if !ok {
		t.Fatal("expected by_source map")
	}

	mcpStats, ok := bySource["mcp"].(map[string]interface{})
	if !ok {
		t.Fatal("expected mcp entry in by_source")
	}

	if mcpStats["events"].(int64) != 1 {
		t.Errorf("expected mcp events=1")
	}
}

func TestLoadPlatformPatterns(t *testing.T) {
	patterns := LoadPlatformPatterns()

	if len(patterns) == 0 {
		t.Fatal("expected non-empty patterns from LoadPlatformPatterns")
	}

	// Check first pattern has expected fields
	p := patterns[0]
	if p.ID == "" {
		t.Error("expected non-empty ID")
	}
	if p.Name == "" {
		t.Error("expected non-empty Name")
	}
	if p.Regex == "" {
		t.Error("expected non-empty Regex (raw string from compiled)")
	}
	if p.Description == "" {
		t.Error("expected non-empty Description")
	}
	if p.Severity == "" {
		t.Error("expected non-empty Severity")
	}
	if p.Category == "" {
		t.Error("expected non-empty Category")
	}
}

func TestHashPatternsSHA256(t *testing.T) {
	patterns := []contracts.Pattern{
		{ID: "rule_a", Regex: `test\d+`},
		{ID: "rule_b", Regex: `secret.*`},
	}

	h1 := HashPatternsSHA256(patterns)
	if h1 == "" {
		t.Fatal("expected non-empty hash")
	}
	if len(h1) < 10 {
		t.Errorf("hash too short: %s", h1)
	}
	if h1[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix, got %s", h1[:7])
	}

	// Same patterns in different order should produce same hash
	reversed := []contracts.Pattern{
		{ID: "rule_b", Regex: `secret.*`},
		{ID: "rule_a", Regex: `test\d+`},
	}
	h2 := HashPatternsSHA256(reversed)
	if h1 != h2 {
		t.Errorf("hash should be order-independent: %s vs %s", h1, h2)
	}

	// Different patterns should produce different hash
	different := []contracts.Pattern{
		{ID: "rule_c", Regex: `different`},
	}
	h3 := HashPatternsSHA256(different)
	if h1 == h3 {
		t.Error("different patterns should produce different hash")
	}
}

func TestSeverityToString(t *testing.T) {
	tests := []struct {
		sev    scanner.Severity
		expect string
	}{
		{scanner.Critical, "critical"},
		{scanner.High, "high"},
		{scanner.Medium, "medium"},
		{scanner.Low, "low"},
		{scanner.Info, "info"},
	}

	for _, tt := range tests {
		result := severityToString(tt.sev)
		if result != tt.expect {
			t.Errorf("expected %s, got %s", tt.expect, result)
		}
	}
}

func TestSanitizeSource(t *testing.T) {
	tests := []struct {
		input    string
		expected contracts.EventSource
		hasError bool
	}{
		{"lens", contracts.SourceLens, false},
		{"rampart", contracts.SourceRampart, false},
		{"scanner", contracts.SourceScanner, false},
		{"mcp", contracts.SourceMCP, false},
		{"platform", contracts.SourcePlatform, false},
		{"LENS", contracts.SourceLens, false}, // case insensitive
		{"unknown", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		result, err := SanitizeSource(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("expected error for %s", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for %s: %v", tt.input, err)
			}
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		}
	}
}

func TestEventStorerAdapter(t *testing.T) {
	called := false
	adapter := NewEventStorerAdapter(func(e contracts.Event) error {
		called = true
		return nil
	})

	e := contracts.Event{ID: "test", Source: contracts.SourceLens, SchemaVersion: "v1"}
	if err := adapter.StoreEvent(e); err != nil {
		t.Fatalf("StoreEvent failed: %v", err)
	}
	if !called {
		t.Error("expected append function to be called")
	}
}
