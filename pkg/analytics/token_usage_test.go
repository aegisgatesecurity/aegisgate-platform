// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Token Usage Analytics Tests
// =========================================================================

package analytics

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestTracker() *TokenUsageTracker {
	alerts := &AlertConfig{
		RateLimitThreshold: 100,
		CostThresholdCents: 5000,
		ErrorRateThreshold: 0.05,
		AlertEndpoints:     []string{"https://hooks.example.com/alert"},
	}
	return NewTokenUsageTracker(alerts)
}

func newTestRecord(orgID, userID, tokenID, endpoint, model string, tokens int, cost float64, success bool, ts time.Time) *UsageRecord {
	return &UsageRecord{
		TokenID:        tokenID,
		UserID:         userID,
		OrganizationID: orgID,
		Endpoint:       endpoint,
		TokensUsed:     tokens,
		CostCents:      cost,
		Timestamp:      ts,
		Model:          model,
		LatencyMs:      100,
		Success:        success,
	}
}

func utcTime(year int, month time.Month, day, hour, min int) time.Time {
	return time.Date(year, month, day, hour, min, 0, 0, time.UTC)
}

// ---------------------------------------------------------------------------
// RecordUsage tests
// ---------------------------------------------------------------------------

func TestRecordUsage_Basic(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	rec := &UsageRecord{
		TokenID:        "tok-001",
		UserID:         "user-001",
		OrganizationID: "org-001",
		Endpoint:       "/api/v1/chat",
		TokensUsed:     500,
		CostCents:      2.5,
		Timestamp:      utcTime(2026, 7, 1, 10, 0),
		Model:          "gpt-4",
		LatencyMs:      200,
		Success:        true,
	}

	if err := tr.RecordUsage(rec); err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	// Verify it was stored.
	tr.mu.RLock()
	recs := tr.records["org-001"]
	tr.mu.RUnlock()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].TokenID != "tok-001" {
		t.Errorf("expected token_id tok-001, got %s", recs[0].TokenID)
	}
}

func TestRecordUsage_NilRecord(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	if err := tr.RecordUsage(nil); err == nil {
		t.Fatal("expected error for nil record")
	}
}

func TestRecordUsage_MissingTokenID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	rec := &UsageRecord{OrganizationID: "org-001"}
	if err := tr.RecordUsage(rec); err == nil {
		t.Fatal("expected error for missing token_id")
	}
}

func TestRecordUsage_MissingOrgID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	rec := &UsageRecord{TokenID: "tok-001"}
	if err := tr.RecordUsage(rec); err == nil {
		t.Fatal("expected error for missing organization_id")
	}
}

func TestRecordUsage_DefaultTimestamp(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	before := time.Now().UTC()
	rec := &UsageRecord{
		TokenID:        "tok-001",
		OrganizationID: "org-001",
	}
	if err := tr.RecordUsage(rec); err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}
	if rec.Timestamp.Before(before) {
		t.Error("expected timestamp to be set automatically")
	}
}

func TestRecordUsage_MultipleRecords(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	for i := 0; i < 100; i++ {
		rec := &UsageRecord{
			TokenID:        "tok-001",
			UserID:         "user-001",
			OrganizationID: "org-001",
			Endpoint:       "/api/v1/chat",
			TokensUsed:     i * 10,
			CostCents:      float64(i) * 0.5,
			Timestamp:      utcTime(2026, 7, 1, 10, i%60),
			Model:          "gpt-4",
			LatencyMs:      100 + i,
			Success:        true,
		}
		if err := tr.RecordUsage(rec); err != nil {
			t.Fatalf("RecordUsage(%d) failed: %v", i, err)
		}
	}

	tr.mu.RLock()
	recs := tr.records["org-001"]
	tr.mu.RUnlock()
	if len(recs) != 100 {
		t.Fatalf("expected 100 records, got %d", len(recs))
	}
}

// ---------------------------------------------------------------------------
// GetSummary tests
// ---------------------------------------------------------------------------

func TestGetSummary_Basic(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := utcTime(2026, 7, 1, 12, 0)
	records := []*UsageRecord{
		newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 500, 2.5, true, now),
		newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 300, 1.5, true, now.Add(1*time.Hour)),
		newTestRecord("org-001", "user-002", "tok-002", "/api/v1/embed", "text-embedding-3", 1000, 5.0, false, now.Add(2*time.Hour)),
	}
	for _, r := range records {
		if err := tr.RecordUsage(r); err != nil {
			t.Fatalf("RecordUsage failed: %v", err)
		}
	}

	start := now.Add(-1 * time.Hour)
	end := now.Add(3 * time.Hour)
	summary, err := tr.GetSummary("org-001", start, end)
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if summary.TotalTokens != 1800 {
		t.Errorf("expected TotalTokens=1800, got %d", summary.TotalTokens)
	}
	if summary.RequestCount != 3 {
		t.Errorf("expected RequestCount=3, got %d", summary.RequestCount)
	}
	if summary.ErrorRate != 1.0/3.0 {
		t.Errorf("expected ErrorRate=%.4f, got %.4f", 1.0/3.0, summary.ErrorRate)
	}
	if len(summary.ByUser) != 2 {
		t.Errorf("expected 2 users, got %d", len(summary.ByUser))
	}
	if len(summary.ByEndpoint) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(summary.ByEndpoint))
	}
	if len(summary.ByModel) != 2 {
		t.Errorf("expected 2 models, got %d", len(summary.ByModel))
	}
}

func TestGetSummary_EmptyOrg(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	summary, err := tr.GetSummary("nonexistent", time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.RequestCount != 0 {
		t.Errorf("expected 0 requests, got %d", summary.RequestCount)
	}
}

func TestGetSummary_InvalidTimeRange(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	_, err := tr.GetSummary("org-001", now, now.Add(-1*time.Hour))
	if err == nil {
		t.Fatal("expected error for end < start")
	}
}

func TestGetSummary_MissingOrgID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, err := tr.GetSummary("", time.Now(), time.Now())
	if err == nil {
		t.Fatal("expected error for empty orgID")
	}
}

func TestGetSummary_ByUserAggregation(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := utcTime(2026, 7, 1, 12, 0)
	records := []*UsageRecord{
		newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, true, now),
		newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 200, 2.0, true, now.Add(1*time.Hour)),
		newTestRecord("org-001", "user-002", "tok-002", "/api/v1/chat", "gpt-4", 300, 3.0, true, now.Add(2*time.Hour)),
	}
	for _, r := range records {
		tr.RecordUsage(r)
	}

	summary, err := tr.GetSummary("org-001", now.Add(-1*time.Hour), now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	u1 := summary.ByUser["user-001"]
	if u1.TokenCount != 300 {
		t.Errorf("user-001: expected TokenCount=300, got %d", u1.TokenCount)
	}
	if u1.CostCents != 3.0 {
		t.Errorf("user-001: expected CostCents=3.0, got %.2f", u1.CostCents)
	}
	if u1.RequestCount != 2 {
		t.Errorf("user-001: expected RequestCount=2, got %d", u1.RequestCount)
	}
}

func TestGetSummary_ByEndpointAggregation(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := utcTime(2026, 7, 1, 12, 0)
	records := []*UsageRecord{
		{TokenID: "tok-001", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: true},
		{TokenID: "tok-001", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 200, CostCents: 2.0, Timestamp: now.Add(time.Hour), Model: "gpt-4", LatencyMs: 200, Success: true},
		{TokenID: "tok-001", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 300, CostCents: 3.0, Timestamp: now.Add(2 * time.Hour), Model: "gpt-4", LatencyMs: 300, Success: false},
	}
	for _, r := range records {
		tr.RecordUsage(r)
	}

	summary, err := tr.GetSummary("org-001", now.Add(-1*time.Hour), now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	ep := summary.ByEndpoint["/api/v1/chat"]
	if ep.RequestCount != 3 {
		t.Errorf("expected RequestCount=3, got %d", ep.RequestCount)
	}
	// Average latency should be (100+200+300)/3 = 200
	if ep.AvgLatencyMs != 200 {
		t.Errorf("expected AvgLatencyMs=200, got %.1f", ep.AvgLatencyMs)
	}
	if ep.ErrorCount != 1 {
		t.Errorf("expected ErrorCount=1, got %d", ep.ErrorCount)
	}
}

func TestGetSummary_ByModelAggregation(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := utcTime(2026, 7, 1, 12, 0)
	records := []*UsageRecord{
		newTestRecord("org-001", "u1", "tok-001", "/api/v1/chat", "gpt-4", 500, 2.5, true, now),
		newTestRecord("org-001", "u1", "tok-001", "/api/v1/chat", "gpt-3.5", 200, 0.5, true, now.Add(time.Hour)),
		newTestRecord("org-001", "u1", "tok-001", "/api/v1/chat", "gpt-4", 300, 1.5, true, now.Add(2*time.Hour)),
	}
	for _, r := range records {
		tr.RecordUsage(r)
	}

	summary, err := tr.GetSummary("org-001", now.Add(-1*time.Hour), now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	gpt4 := summary.ByModel["gpt-4"]
	if gpt4 == nil {
		t.Fatal("expected gpt-4 model in summary")
	}
	if gpt4.TokenCount != 800 {
		t.Errorf("gpt-4: expected TokenCount=800, got %d", gpt4.TokenCount)
	}
	if gpt4.CostCents != 4.0 {
		t.Errorf("gpt-4: expected CostCents=4.0, got %.2f", gpt4.CostCents)
	}
	if gpt4.RequestCount != 2 {
		t.Errorf("gpt-4: expected RequestCount=2, got %d", gpt4.RequestCount)
	}

	gpt35 := summary.ByModel["gpt-3.5"]
	if gpt35 == nil {
		t.Fatal("expected gpt-3.5 model in summary")
	}
	if gpt35.RequestCount != 1 {
		t.Errorf("gpt-3.5: expected RequestCount=1, got %d", gpt35.RequestCount)
	}
}

// ---------------------------------------------------------------------------
// CheckRateLimit tests
// ---------------------------------------------------------------------------

func TestCheckRateLimit_Allowed(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	allowed, remaining, err := tr.CheckRateLimit("tok-001", time.Minute, 100)
	if err != nil {
		t.Fatalf("CheckRateLimit failed: %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed")
	}
	if remaining != 99 {
		t.Errorf("expected remaining=99, got %d", remaining)
	}
}

func TestCheckRateLimit_Exceeded(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	limit := 5
	window := time.Minute

	for i := 0; i < limit; i++ {
		_, _, err := tr.CheckRateLimit("tok-001", window, limit)
		if err != nil {
			t.Fatalf("CheckRateLimit(%d) failed: %v", i, err)
		}
	}

	// Next request should be denied.
	allowed, remaining, err := tr.CheckRateLimit("tok-001", window, limit)
	if err != nil {
		t.Fatalf("CheckRateLimit failed: %v", err)
	}
	if allowed {
		t.Error("expected request to be denied after limit exceeded")
	}
	if remaining != 0 {
		t.Errorf("expected remaining=0, got %d", remaining)
	}
}

func TestCheckRateLimit_DifferentTokens(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	limit := 5
	window := time.Minute

	// Exhaust limit for tok-001.
	for i := 0; i < limit; i++ {
		tr.CheckRateLimit("tok-001", window, limit)
	}

	// tok-002 should still be allowed.
	allowed, _, err := tr.CheckRateLimit("tok-002", window, limit)
	if err != nil {
		t.Fatalf("CheckRateLimit failed: %v", err)
	}
	if !allowed {
		t.Error("expected tok-002 to be allowed (different token)")
	}
}

func TestCheckRateLimit_EmptyTokenID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, _, err := tr.CheckRateLimit("", time.Minute, 100)
	if err == nil {
		t.Fatal("expected error for empty token_id")
	}
}

func TestCheckRateLimit_InvalidLimit(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, _, err := tr.CheckRateLimit("tok-001", time.Minute, 0)
	if err == nil {
		t.Fatal("expected error for zero limit")
	}
}

func TestCheckRateLimit_WindowExpiry(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Manually inject a rate limit window with old data.
	tr.mu.Lock()
	now := time.Now().UTC()
	rw := &rateLimitWindow{
		counts:   make(map[time.Time]int),
		lastSeen: now,
	}
	// Add counts that are outside the 1-minute window.
	for i := 0; i < 5; i++ {
		oldTime := now.Add(-2 * time.Minute).Truncate(time.Second)
		rw.counts[oldTime.Add(time.Duration(i)*time.Second)] = 20
	}
	// Add counts within the window.
	rw.counts[now.Truncate(time.Second)] = 3
	tr.rateLimits["tok-001"] = rw
	tr.mu.Unlock()

	allowed, remaining, err := tr.CheckRateLimit("tok-001", time.Minute, 10)
	if err != nil {
		t.Fatalf("CheckRateLimit failed: %v", err)
	}
	if !allowed {
		t.Error("expected request to be allowed after old entries expired")
	}
	// 3 in current window + 1 for this check = 4 used, remaining = 10 - 4 = 6
	if remaining != 6 {
		t.Errorf("expected remaining=6, got %d", remaining)
	}
}

// ---------------------------------------------------------------------------
// GetCostAttribution tests
// ---------------------------------------------------------------------------

func TestGetCostAttribution_Basic(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := utcTime(2026, 7, 1, 12, 0)
	records := []*UsageRecord{
		newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 500, 10.0, true, now),
		newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 300, 6.0, true, now.Add(time.Hour)),
		newTestRecord("org-001", "user-002", "tok-002", "/api/v1/embed", "text-embedding-3", 1000, 20.0, true, now.Add(2*time.Hour)),
	}
	for _, r := range records {
		tr.RecordUsage(r)
	}

	attribution, err := tr.GetCostAttribution("org-001", now.Add(-1*time.Hour), now.Add(3*time.Hour))
	if err != nil {
		t.Fatalf("GetCostAttribution failed: %v", err)
	}

	if len(attribution) != 2 {
		t.Fatalf("expected 2 users in attribution, got %d", len(attribution))
	}
	if attribution["user-001"] != 16.0 {
		t.Errorf("expected user-001 cost=16.0, got %.2f", attribution["user-001"])
	}
	if attribution["user-002"] != 20.0 {
		t.Errorf("expected user-002 cost=20.0, got %.2f", attribution["user-002"])
	}
}

func TestGetCostAttribution_EmptyOrg(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	attribution, err := tr.GetCostAttribution("nonexistent", time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("GetCostAttribution failed: %v", err)
	}
	if len(attribution) != 0 {
		t.Errorf("expected empty attribution, got %d entries", len(attribution))
	}
}

// ---------------------------------------------------------------------------
// DetectAnomalies tests
// ---------------------------------------------------------------------------

func TestDetectAnomalies_ErrorRateSpike(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Create 100 records with 20% error rate (threshold is 5%).
	for i := 0; i < 80; i++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, true, now.Add(-time.Duration(i)*time.Minute))
		tr.RecordUsage(rec)
	}
	for i := 0; i < 20; i++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, false, now.Add(-time.Duration(80+i)*time.Minute))
		tr.RecordUsage(rec)
	}

	anomalies, err := tr.DetectAnomalies("org-001", 3*time.Hour)
	if err != nil {
		t.Fatalf("DetectAnomalies failed: %v", err)
	}

	found := false
	for _, a := range anomalies {
		if a.Type == "error_rate_spike" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected error_rate_spike anomaly to be detected")
	}
}

func TestDetectAnomalies_CostSpike(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Create 10 normal hours.
	for h := 0; h < 10; h++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, true, now.Add(-time.Duration(10-h)*time.Hour))
		tr.RecordUsage(rec)
	}
	// Create 1 spike hour with 50x cost.
	spikeRec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 50.0, true, now.Add(-30*time.Minute))
	tr.RecordUsage(spikeRec)

	anomalies, err := tr.DetectAnomalies("org-001", 12*time.Hour)
	if err != nil {
		t.Fatalf("DetectAnomalies failed: %v", err)
	}

	found := false
	for _, a := range anomalies {
		if a.Type == "cost_spike" {
			found = true
			if a.Severity == "" {
				t.Error("cost spike anomaly should have a severity")
			}
			break
		}
	}
	if !found {
		t.Error("expected cost_spike anomaly to be detected")
	}
}

func TestDetectAnomalies_RateLimitExceeded(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Create 150 records for the same token (threshold is 100).
	for i := 0; i < 150; i++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 10, 0.1, true, now.Add(-time.Duration(i)*time.Second))
		tr.RecordUsage(rec)
	}

	anomalies, err := tr.DetectAnomalies("org-001", 5*time.Minute)
	if err != nil {
		t.Fatalf("DetectAnomalies failed: %v", err)
	}

	found := false
	for _, a := range anomalies {
		if a.Type == "rate_limit_exceeded" {
			found = true
			if a.Severity != "high" {
				t.Errorf("expected severity=high, got %s", a.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected rate_limit_exceeded anomaly to be detected")
	}
}

func TestDetectAnomalies_NoAnomalies(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Create normal usage — 10 records, all successful.
	for i := 0; i < 10; i++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, true, now.Add(-time.Duration(i)*time.Minute))
		tr.RecordUsage(rec)
	}

	anomalies, err := tr.DetectAnomalies("org-001", time.Hour)
	if err != nil {
		t.Fatalf("DetectAnomalies failed: %v", err)
	}
	// May have latency spikes depending on data, but should not have error rate or rate limit anomalies.
	for _, a := range anomalies {
		if a.Type == "error_rate_spike" || a.Type == "rate_limit_exceeded" {
			t.Errorf("unexpected anomaly: %s", a.Type)
		}
	}
}

func TestDetectAnomalies_EmptyOrgID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, err := tr.DetectAnomalies("", time.Hour)
	if err == nil {
		t.Fatal("expected error for empty orgID")
	}
}

func TestDetectAnomalies_LatencySpike(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Create 10 records with normal latency (100ms).
	for i := 0; i < 10; i++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, true, now.Add(-time.Duration(i)*time.Minute))
		rec.LatencyMs = 100
		tr.RecordUsage(rec)
	}
	// Add 1 record with extreme latency (10000ms = 100x average).
	spikeRec := &UsageRecord{
		TokenID:        "tok-001",
		UserID:         "user-001",
		OrganizationID: "org-001",
		Endpoint:       "/api/v1/chat",
		TokensUsed:     100,
		CostCents:      1.0,
		Timestamp:      now.Add(-30 * time.Second),
		Model:          "gpt-4",
		LatencyMs:      10000,
		Success:        true,
	}
	tr.RecordUsage(spikeRec)

	anomalies, err := tr.DetectAnomalies("org-001", time.Hour)
	if err != nil {
		t.Fatalf("DetectAnomalies failed: %v", err)
	}

	found := false
	for _, a := range anomalies {
		if a.Type == "latency_spike" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected latency_spike anomaly to be detected")
	}
}

// ---------------------------------------------------------------------------
// Dashboard tests
// ---------------------------------------------------------------------------

func TestGetDashboardData_Basic(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Add some recent records.
	for i := 0; i < 10; i++ {
		rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, 1.0, true, now.Add(-time.Duration(i)*time.Hour))
		tr.RecordUsage(rec)
	}

	data, err := tr.GetDashboardData("org-001")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if data.RealTimeMetrics == nil {
		t.Error("expected RealTimeMetrics to be non-nil")
	}
	if data.AlertThresholds == nil {
		t.Error("expected AlertThresholds to be non-nil")
	}
	if len(data.HourlyUsage) == 0 {
		t.Error("expected HourlyUsage to be non-empty")
	}
	if len(data.TopUsers) == 0 {
		t.Error("expected TopUsers to be non-empty")
	}
}

func TestGetDashboardData_EmptyOrg(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	data, err := tr.GetDashboardData("nonexistent")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}
	if data.RealTimeMetrics == nil {
		t.Error("expected RealTimeMetrics to be non-nil even for empty org")
	}
}

func TestGetDashboardData_MissingOrgID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, err := tr.GetDashboardData("")
	if err == nil {
		t.Fatal("expected error for empty orgID")
	}
}

func TestGetDashboardData_HourlyBuckets(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Add 3 records across 3 distinct hours.
	hour0 := now.Truncate(time.Hour).Add(-2 * time.Hour)
	hour1 := now.Truncate(time.Hour).Add(-1 * time.Hour)
	hour2 := now.Truncate(time.Hour)

	tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: hour0.Add(10 * time.Minute), Model: "gpt-4", LatencyMs: 100, Success: true})
	tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 200, CostCents: 2.0, Timestamp: hour0.Add(30 * time.Minute), Model: "gpt-4", LatencyMs: 100, Success: true})
	tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 300, CostCents: 3.0, Timestamp: hour1.Add(15 * time.Minute), Model: "gpt-4", LatencyMs: 100, Success: true})
	tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 50, CostCents: 0.5, Timestamp: hour2.Add(5 * time.Minute), Model: "gpt-4", LatencyMs: 100, Success: true})

	data, err := tr.GetDashboardData("org-001")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if len(data.HourlyUsage) == 0 {
		t.Fatal("expected HourlyUsage to be non-empty")
	}

	// Find the bucket with 2 requests (hour0).
	found := false
	for _, bucket := range data.HourlyUsage {
		if bucket.RequestCount == 2 {
			found = true
			if bucket.TokenCount != 300 {
				t.Errorf("expected TokenCount=300, got %d", bucket.TokenCount)
			}
			if bucket.CostCents != 3.0 {
				t.Errorf("expected CostCents=3.0, got %.2f", bucket.CostCents)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find a bucket with 2 requests")
	}
}

func TestGetDashboardData_CostTrend(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// Add records over 3 days.
	for d := 0; d < 3; d++ {
		for h := 0; h < 3; h++ {
			rec := newTestRecord("org-001", "user-001", "tok-001", "/api/v1/chat", "gpt-4", 100, float64(d+1)*10.0, true, now.Add(-time.Duration(d*24+h)*time.Hour))
			tr.RecordUsage(rec)
		}
	}

	data, err := tr.GetDashboardData("org-001")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if len(data.CostTrend) == 0 {
		t.Fatal("expected CostTrend to be non-empty")
	}

	// Cost trend should be sorted by date ascending.
	for i := 1; i < len(data.CostTrend); i++ {
		if data.CostTrend[i].Date.Before(data.CostTrend[i-1].Date) {
			t.Error("cost trend should be sorted by date ascending")
		}
	}
}

func TestGetDashboardData_TopUsers(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// user-001: $3.00, user-002: $1.00, user-003: $5.00
	tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "user-001", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 300.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: true})
	tr.RecordUsage(&UsageRecord{TokenID: "t2", UserID: "user-002", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 100.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: true})
	tr.RecordUsage(&UsageRecord{TokenID: "t3", UserID: "user-003", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 500.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: true})

	data, err := tr.GetDashboardData("org-001")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if len(data.TopUsers) == 0 {
		t.Fatal("expected TopUsers to be non-empty")
	}

	// Top user should be user-003 ($5.00).
	if data.TopUsers[0].UserID != "user-003" {
		t.Errorf("expected top user to be user-003, got %s", data.TopUsers[0].UserID)
	}
	if data.TopUsers[0].CostCents != 500.0 {
		t.Errorf("expected top user cost 500.0, got %.2f", data.TopUsers[0].CostCents)
	}
}

func TestGetDashboardData_TopEndpoints(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	// /api/v1/chat: 5 requests, /api/v1/embed: 2 requests
	for i := 0; i < 5; i++ {
		tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now.Add(-time.Duration(i) * time.Minute), Model: "gpt-4", LatencyMs: 100, Success: true})
	}
	for i := 0; i < 2; i++ {
		tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/embed", TokensUsed: 50, CostCents: 0.5, Timestamp: now.Add(-time.Duration(i) * time.Minute), Model: "text-embedding-3", LatencyMs: 50, Success: true})
	}

	data, err := tr.GetDashboardData("org-001")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if len(data.TopEndpoints) == 0 {
		t.Fatal("expected TopEndpoints to be non-empty")
	}
	if data.TopEndpoints[0].Endpoint != "/api/v1/chat" {
		t.Errorf("expected top endpoint /api/v1/chat, got %s", data.TopEndpoints[0].Endpoint)
	}
	if data.TopEndpoints[0].RequestCount != 5 {
		t.Errorf("expected 5 requests for top endpoint, got %d", data.TopEndpoints[0].RequestCount)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access tests
// ---------------------------------------------------------------------------

func TestConcurrentRecordUsage(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	var wg sync.WaitGroup
	numGoroutines := 50
	recordsPerGoroutine := 20

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < recordsPerGoroutine; i++ {
				rec := &UsageRecord{
					TokenID:        fmt.Sprintf("tok-%d", goroutineID),
					UserID:         fmt.Sprintf("user-%d", goroutineID),
					OrganizationID: "org-001",
					Endpoint:       "/api/v1/chat",
					TokensUsed:     100,
					CostCents:      1.0,
					Timestamp:      time.Now().UTC(),
					Model:          "gpt-4",
					LatencyMs:      100,
					Success:        true,
				}
				if err := tr.RecordUsage(rec); err != nil {
					t.Errorf("RecordUsage failed: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	tr.mu.RLock()
	recs := tr.records["org-001"]
	tr.mu.RUnlock()
	expected := numGoroutines * recordsPerGoroutine
	if len(recs) != expected {
		t.Errorf("expected %d records, got %d", expected, len(recs))
	}
}

func TestConcurrentReadAndWrite(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Seed some data.
	now := time.Now().UTC()
	for i := 0; i < 100; i++ {
		rec := &UsageRecord{
			TokenID:        "tok-001",
			UserID:         "user-001",
			OrganizationID: "org-001",
			Endpoint:       "/api/v1/chat",
			TokensUsed:     100,
			CostCents:      1.0,
			Timestamp:      now.Add(-time.Duration(i) * time.Minute),
			Model:          "gpt-4",
			LatencyMs:      100,
			Success:        true,
		}
		tr.RecordUsage(rec)
	}

	var wg sync.WaitGroup
	// Concurrent reads.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tr.GetSummary("org-001", now.Add(-2*time.Hour), now)
			if err != nil {
				t.Errorf("GetSummary failed: %v", err)
			}
		}()
	}
	// Concurrent writes.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := &UsageRecord{
				TokenID:        "tok-002",
				UserID:         "user-002",
				OrganizationID: "org-001",
				Endpoint:       "/api/v1/chat",
				TokensUsed:     50,
				CostCents:      0.5,
				Timestamp:      now,
				Model:          "gpt-3.5",
				LatencyMs:      50,
				Success:        true,
			}
			if err := tr.RecordUsage(rec); err != nil {
				t.Errorf("RecordUsage failed: %v", err)
			}
		}(i)
	}
	// Concurrent rate limit checks.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := tr.CheckRateLimit("tok-001", time.Minute, 1000)
			if err != nil {
				t.Errorf("CheckRateLimit failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Close / lifecycle tests
// ---------------------------------------------------------------------------

func TestTracker_Close(t *testing.T) {
	tr := newTestTracker()
	if err := tr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestTracker_DoubleClose(t *testing.T) {
	tr := newTestTracker()
	if err := tr.Close(); err != nil {
		t.Fatalf("first Close failed: %v", err)
	}
	// Second Close should be safe (idempotent).
	if err := tr.Close(); err != nil {
		t.Fatalf("second Close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Alert config defaults
// ---------------------------------------------------------------------------

func TestDefaultAlertConfig(t *testing.T) {
	tr := NewTokenUsageTracker(nil)
	defer tr.Close()

	if tr.alerts.RateLimitThreshold != 1000 {
		t.Errorf("expected default RateLimitThreshold=1000, got %d", tr.alerts.RateLimitThreshold)
	}
	if tr.alerts.CostThresholdCents != 50000 {
		t.Errorf("expected default CostThresholdCents=50000, got %.2f", tr.alerts.CostThresholdCents)
	}
	if tr.alerts.ErrorRateThreshold != 0.05 {
		t.Errorf("expected default ErrorRateThreshold=0.05, got %.4f", tr.alerts.ErrorRateThreshold)
	}
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestMaskToken(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"short", "****"},
		{"abc", "****"},
		{"12345678", "****"},
		{"123456789", "1234****6789"},
		{"sk-proj-abc123def456", "sk-p****f456"},
	}
	for _, tc := range tests {
		result := maskToken(tc.input)
		if result != tc.expected {
			t.Errorf("maskToken(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	if severityOrder("critical") >= severityOrder("high") {
		t.Error("critical should be ordered before high")
	}
	if severityOrder("high") >= severityOrder("medium") {
		t.Error("high should be ordered before medium")
	}
	if severityOrder("medium") >= severityOrder("low") {
		t.Error("medium should be ordered before low")
	}
}

func TestSeverityForRatio(t *testing.T) {
	tests := []struct {
		ratio    float64
		expected string
	}{
		{15, "critical"},
		{7, "high"},
		{4, "medium"},
		{2, "low"},
	}
	for _, tc := range tests {
		result := severityForRatio(tc.ratio)
		if result != tc.expected {
			t.Errorf("severityForRatio(%.1f) = %q, want %q", tc.ratio, result, tc.expected)
		}
	}
}

func TestSeverityForThreshold(t *testing.T) {
	if severityForThreshold(0.3, 0.05) != "critical" {
		t.Error("expected critical for 6x threshold")
	}
	if severityForThreshold(0.15, 0.05) != "high" {
		t.Error("expected high for 3x threshold")
	}
	if severityForThreshold(0.1, 0.05) != "medium" {
		t.Error("expected medium for 2x threshold")
	}
}

func TestRoundToCent(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{1.025, 1.03}, // rounds up
		{1.004, 1.0},  // rounds down
		{0.0, 0.0},
		{99.999, 100.0},
		{123.456, 123.46},
	}
	for _, tc := range tests {
		result := roundToCent(tc.input)
		if result != tc.expected {
			t.Errorf("roundToCent(%.3f) = %.2f, want %.2f", tc.input, result, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// Store interface / external backend tests
// ---------------------------------------------------------------------------

type mockStore struct {
	records []*UsageRecord
	closed  bool
}

func (m *mockStore) Insert(record *UsageRecord) error {
	m.records = append(m.records, record)
	return nil
}

func (m *mockStore) QueryByOrg(orgID string, start, end time.Time) ([]*UsageRecord, error) {
	var result []*UsageRecord
	for _, r := range m.records {
		if r.OrganizationID == orgID && !r.Timestamp.Before(start) && !r.Timestamp.After(end) {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockStore) QueryByToken(tokenID string, start, end time.Time) ([]*UsageRecord, error) {
	var result []*UsageRecord
	for _, r := range m.records {
		if r.TokenID == tokenID && !r.Timestamp.Before(start) && !r.Timestamp.After(end) {
			result = append(result, r)
		}
	}
	return result, nil
}

func (m *mockStore) Close() error {
	m.closed = true
	return nil
}

func TestTokenUsageTrackerWithStore(t *testing.T) {
	store := &mockStore{}
	tr := NewTokenUsageTrackerWithStore(nil, store)
	defer tr.Close()

	rec := &UsageRecord{
		TokenID:        "tok-001",
		UserID:         "user-001",
		OrganizationID: "org-001",
		Endpoint:       "/api/v1/chat",
		TokensUsed:     100,
		CostCents:      1.0,
		Timestamp:      time.Now().UTC(),
		Model:          "gpt-4",
		LatencyMs:      100,
		Success:        true,
	}

	if err := tr.RecordUsage(rec); err != nil {
		t.Fatalf("RecordUsage failed: %v", err)
	}

	if len(store.records) != 1 {
		t.Errorf("expected 1 record in store, got %d", len(store.records))
	}

	if err := tr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !store.closed {
		t.Error("expected store to be closed")
	}
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

func TestGetSummary_TimeRangeFiltering(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	baseTime := utcTime(2026, 7, 1, 12, 0)
	// Record at hour 0, 6, 12, 18.
	tr.RecordUsage(newTestRecord("org-001", "u1", "t1", "/api/v1/chat", "gpt-4", 100, 1.0, true, baseTime))
	tr.RecordUsage(newTestRecord("org-001", "u1", "t1", "/api/v1/chat", "gpt-4", 200, 2.0, true, baseTime.Add(6*time.Hour)))
	tr.RecordUsage(newTestRecord("org-001", "u1", "t1", "/api/v1/chat", "gpt-4", 300, 3.0, true, baseTime.Add(12*time.Hour)))
	tr.RecordUsage(newTestRecord("org-001", "u1", "t1", "/api/v1/chat", "gpt-4", 400, 4.0, true, baseTime.Add(18*time.Hour)))

	// Query for hours 5-13.
	summary, err := tr.GetSummary("org-001", baseTime.Add(5*time.Hour), baseTime.Add(13*time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	// Should include hours 6 and 12 (tokens: 200+300 = 500).
	if summary.TotalTokens != 500 {
		t.Errorf("expected TotalTokens=500, got %d", summary.TotalTokens)
	}
	if summary.RequestCount != 2 {
		t.Errorf("expected RequestCount=2, got %d", summary.RequestCount)
	}
}

func TestGetSummary_AvgLatencyCalculation(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	recs := []*UsageRecord{
		{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: true},
		{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now, Model: "gpt-4", LatencyMs: 200, Success: true},
		{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now, Model: "gpt-4", LatencyMs: 300, Success: true},
	}
	for _, r := range recs {
		tr.RecordUsage(r)
	}

	summary, err := tr.GetSummary("org-001", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if summary.AvgLatencyMs != 200.0 {
		t.Errorf("expected AvgLatencyMs=200.0, got %.1f", summary.AvgLatencyMs)
	}
}

func TestGetSummary_ErrorRateCalculation(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: true})
	}
	for i := 0; i < 2; i++ {
		tr.RecordUsage(&UsageRecord{TokenID: "t1", UserID: "u1", OrganizationID: "org-001", Endpoint: "/api/v1/chat", TokensUsed: 100, CostCents: 1.0, Timestamp: now, Model: "gpt-4", LatencyMs: 100, Success: false})
	}

	summary, err := tr.GetSummary("org-001", now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if summary.ErrorRate != 0.2 {
		t.Errorf("expected ErrorRate=0.2, got %.4f", summary.ErrorRate)
	}
}

func TestTopNUsers(t *testing.T) {
	byUser := map[string]*UserUsage{
		"user-3": {UserID: "user-3", TokenCount: 100, CostCents: 300, RequestCount: 10},
		"user-1": {UserID: "user-1", TokenCount: 500, CostCents: 100, RequestCount: 50},
		"user-2": {UserID: "user-2", TokenCount: 200, CostCents: 200, RequestCount: 20},
	}

	top2 := topNUsers(byUser, 2)
	if len(top2) != 2 {
		t.Fatalf("expected 2 users, got %d", len(top2))
	}
	// Sorted by cost descending.
	if top2[0].UserID != "user-3" {
		t.Errorf("expected top user user-3, got %s", top2[0].UserID)
	}
	if top2[1].UserID != "user-2" {
		t.Errorf("expected second user user-2, got %s", top2[1].UserID)
	}
}

func TestTopNEndpoints(t *testing.T) {
	byEndpoint := map[string]*EndpointUsage{
		"/api/v1/chat":   {Endpoint: "/api/v1/chat", RequestCount: 500, AvgLatencyMs: 100, ErrorCount: 10},
		"/api/v1/embed":  {Endpoint: "/api/v1/embed", RequestCount: 200, AvgLatencyMs: 50, ErrorCount: 2},
		"/api/v1/models": {Endpoint: "/api/v1/models", RequestCount: 1000, AvgLatencyMs: 10, ErrorCount: 1},
	}

	top2 := topNEndpoints(byEndpoint, 2)
	if len(top2) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(top2))
	}
	// Sorted by request count descending.
	if top2[0].Endpoint != "/api/v1/models" {
		t.Errorf("expected top endpoint /api/v1/models, got %s", top2[0].Endpoint)
	}
}

func TestDashboardData_AlertThresholds(t *testing.T) {
	alerts := &AlertConfig{
		RateLimitThreshold: 500,
		CostThresholdCents: 10000,
		ErrorRateThreshold: 0.1,
		AlertEndpoints:     []string{"https://hooks.example.com"},
	}
	tr := NewTokenUsageTracker(alerts)
	defer tr.Close()

	data, err := tr.GetDashboardData("org-001")
	if err != nil {
		t.Fatalf("GetDashboardData failed: %v", err)
	}

	if data.AlertThresholds.RateLimitThreshold != 500 {
		t.Errorf("expected RateLimitThreshold=500, got %d", data.AlertThresholds.RateLimitThreshold)
	}
	if data.AlertThresholds.CostThresholdCents != 10000 {
		t.Errorf("expected CostThresholdCents=10000, got %.2f", data.AlertThresholds.CostThresholdCents)
	}
	if data.AlertThresholds.ErrorRateThreshold != 0.1 {
		t.Errorf("expected ErrorRateThreshold=0.1, got %.4f", data.AlertThresholds.ErrorRateThreshold)
	}
}

// ---------------------------------------------------------------------------
// RecordUsageFromRequest tests — proxy/bridge wiring
// ---------------------------------------------------------------------------

func TestRecordUsageFromRequest_Basic(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	info := RequestInfo{
		TokenID:        "tok-proxy-001",
		UserID:         "user-bridge-001",
		OrganizationID: "org-proxy-001",
		Endpoint:       "/v1/chat/completions",
		Model:          "gpt-4",
		TokensUsed:     1500,
		CostCents:      7.5,
		LatencyMs:      350,
		Success:        true,
	}

	if err := tr.RecordUsageFromRequest(info); err != nil {
		t.Fatalf("RecordUsageFromRequest failed: %v", err)
	}

	// Verify the record was stored correctly.
	tr.mu.RLock()
	recs := tr.records["org-proxy-001"]
	tr.mu.RUnlock()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.TokenID != "tok-proxy-001" {
		t.Errorf("expected TokenID=tok-proxy-001, got %s", r.TokenID)
	}
	if r.Endpoint != "/v1/chat/completions" {
		t.Errorf("expected Endpoint=/v1/chat/completions, got %s", r.Endpoint)
	}
	if r.Model != "gpt-4" {
		t.Errorf("expected Model=gpt-4, got %s", r.Model)
	}
	if r.TokensUsed != 1500 {
		t.Errorf("expected TokensUsed=1500, got %d", r.TokensUsed)
	}
	if r.CostCents != 7.5 {
		t.Errorf("expected CostCents=7.5, got %.2f", r.CostCents)
	}
	if r.LatencyMs != 350 {
		t.Errorf("expected LatencyMs=350, got %d", r.LatencyMs)
	}
	if !r.Success {
		t.Error("expected Success=true")
	}
	if r.Timestamp.IsZero() {
		t.Error("expected timestamp to be auto-populated")
	}
}

func TestRecordUsageFromRequest_FailedRequest(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	info := RequestInfo{
		TokenID:        "tok-err-001",
		UserID:         "user-err",
		OrganizationID: "org-001",
		Endpoint:       "/v1/chat/completions",
		Model:          "gpt-3.5",
		TokensUsed:     0,
		CostCents:      0,
		LatencyMs:      5000,
		Success:        false,
	}

	if err := tr.RecordUsageFromRequest(info); err != nil {
		t.Fatalf("RecordUsageFromRequest failed: %v", err)
	}

	// Verify it shows up as a failed request.
	summary, err := tr.GetSummary("org-001", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.RequestCount != 1 {
		t.Errorf("expected 1 request, got %d", summary.RequestCount)
	}
	if summary.ErrorRate != 1.0 {
		t.Errorf("expected ErrorRate=1.0, got %.4f", summary.ErrorRate)
	}
}

func TestRecordUsageFromRequest_MissingTokenID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	info := RequestInfo{
		UserID:         "user-001",
		OrganizationID: "org-001",
	}
	if err := tr.RecordUsageFromRequest(info); err == nil {
		t.Fatal("expected error for missing token_id")
	}
}

func TestRecordUsageFromRequest_MissingOrgID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	info := RequestInfo{
		TokenID: "tok-001",
	}
	if err := tr.RecordUsageFromRequest(info); err == nil {
		t.Fatal("expected error for missing organization_id")
	}
}

func TestRecordUsageFromRequest_Concurrent(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	var wg sync.WaitGroup
	numGoroutines := 50
	recordsPerGoroutine := 10

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < recordsPerGoroutine; i++ {
				info := RequestInfo{
					TokenID:        fmt.Sprintf("tok-%d", goroutineID),
					UserID:         fmt.Sprintf("user-%d", goroutineID),
					OrganizationID: "org-proxy",
					Endpoint:       "/v1/chat/completions",
					Model:          "gpt-4",
					TokensUsed:     100,
					CostCents:      0.5,
					LatencyMs:      200,
					Success:        true,
				}
				if err := tr.RecordUsageFromRequest(info); err != nil {
					t.Errorf("RecordUsageFromRequest failed: %v", err)
				}
			}
		}(g)
	}
	wg.Wait()

	tr.mu.RLock()
	recs := tr.records["org-proxy"]
	tr.mu.RUnlock()
	expected := numGoroutines * recordsPerGoroutine
	if len(recs) != expected {
		t.Errorf("expected %d records, got %d", expected, len(recs))
	}
}

// ---------------------------------------------------------------------------
// RecordBridgeUsage tests — bridge LLM request wiring
// ---------------------------------------------------------------------------

func TestRecordBridgeUsage_Basic(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	err := tr.RecordBridgeUsage(
		"org-bridge-001", // orgID
		"tok-bridge-001", // tokenID
		"user-bridge-001", // userID
		"gpt-4",          // model
		"/v1/chat/completions", // endpoint
		2000,             // tokensUsed
		10.0,             // costCents
		450,              // latencyMs
		true,             // success
	)
	if err != nil {
		t.Fatalf("RecordBridgeUsage failed: %v", err)
	}

	// Verify the record was stored correctly.
	tr.mu.RLock()
	recs := tr.records["org-bridge-001"]
	tr.mu.RUnlock()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.TokenID != "tok-bridge-001" {
		t.Errorf("expected TokenID=tok-bridge-001, got %s", r.TokenID)
	}
	if r.UserID != "user-bridge-001" {
		t.Errorf("expected UserID=user-bridge-001, got %s", r.UserID)
	}
	if r.OrganizationID != "org-bridge-001" {
		t.Errorf("expected OrganizationID=org-bridge-001, got %s", r.OrganizationID)
	}
	if r.Model != "gpt-4" {
		t.Errorf("expected Model=gpt-4, got %s", r.Model)
	}
	if r.Endpoint != "/v1/chat/completions" {
		t.Errorf("expected Endpoint=/v1/chat/completions, got %s", r.Endpoint)
	}
	if r.TokensUsed != 2000 {
		t.Errorf("expected TokensUsed=2000, got %d", r.TokensUsed)
	}
	if r.CostCents != 10.0 {
		t.Errorf("expected CostCents=10.0, got %.2f", r.CostCents)
	}
	if r.LatencyMs != 450 {
		t.Errorf("expected LatencyMs=450, got %d", r.LatencyMs)
	}
	if !r.Success {
		t.Error("expected Success=true")
	}
	if r.Timestamp.IsZero() {
		t.Error("expected timestamp to be auto-populated")
	}
}

func TestRecordBridgeUsage_FailedRequest(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	err := tr.RecordBridgeUsage(
		"org-fail",       // orgID
		"tok-fail",       // tokenID
		"user-fail",      // userID
		"claude-3",       // model
		"/v1/messages",   // endpoint
		0,                // tokensUsed (failed, no tokens consumed)
		0,                // costCents
		12000,            // latencyMs (high latency before failure)
		false,            // success
	)
	if err != nil {
		t.Fatalf("RecordBridgeUsage failed: %v", err)
	}

	summary, err := tr.GetSummary("org-fail", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.ErrorRate != 1.0 {
		t.Errorf("expected ErrorRate=1.0 for failed request, got %.4f", summary.ErrorRate)
	}
	if summary.AvgLatencyMs != 12000 {
		t.Errorf("expected AvgLatencyMs=12000, got %.1f", summary.AvgLatencyMs)
	}
}

func TestRecordBridgeUsage_MissingOrgID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	err := tr.RecordBridgeUsage("", "tok-001", "user-001", "gpt-4", "/v1/chat", 100, 1.0, 200, true)
	if err == nil {
		t.Fatal("expected error for missing organization_id")
	}
}

func TestRecordBridgeUsage_MissingTokenID(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	err := tr.RecordBridgeUsage("org-001", "", "user-001", "gpt-4", "/v1/chat", 100, 1.0, 200, true)
	if err == nil {
		t.Fatal("expected error for missing token_id")
	}
}

func TestRecordBridgeUsage_MultipleBridgedRequests(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	models := []string{"gpt-4", "gpt-3.5", "claude-3", "text-embedding-3"}
	endpoints := []string{"/v1/chat/completions", "/v1/chat/completions", "/v1/messages", "/v1/embeddings"}
	tokens := []int{1500, 800, 2000, 500}
	costs := []float64{7.5, 2.0, 10.0, 1.0}

	for i := range models {
		err := tr.RecordBridgeUsage(
			"org-multi",
			fmt.Sprintf("tok-%d", i),
			"user-001",
			models[i],
			endpoints[i],
			tokens[i],
			costs[i],
			100+i*50,
			true,
		)
		if err != nil {
			t.Fatalf("RecordBridgeUsage(%d) failed: %v", i, err)
		}
	}

	summary, err := tr.GetSummary("org-multi", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}
	if summary.RequestCount != 4 {
		t.Errorf("expected 4 requests, got %d", summary.RequestCount)
	}
	if summary.TotalTokens != 4800 {
		t.Errorf("expected TotalTokens=4800, got %d", summary.TotalTokens)
	}
	if len(summary.ByModel) != 4 {
		t.Errorf("expected 4 models, got %d", len(summary.ByModel))
	}
	if len(summary.ByEndpoint) != 3 {
		t.Errorf("expected 3 endpoints (/v1/chat/completions appears twice), got %d", len(summary.ByEndpoint))
	}
}

func TestRecordBridgeUsage_Concurrent(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	var wg sync.WaitGroup
	numGoroutines := 30

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			err := tr.RecordBridgeUsage(
				"org-concurrent",
				fmt.Sprintf("tok-concurrent-%d", id),
				fmt.Sprintf("user-%d", id),
				"gpt-4",
				"/v1/chat/completions",
				100,
				0.5,
				200,
				true,
			)
			if err != nil {
				t.Errorf("RecordBridgeUsage(%d) failed: %v", id, err)
			}
		}(g)
	}
	wg.Wait()

	tr.mu.RLock()
	recs := tr.records["org-concurrent"]
	tr.mu.RUnlock()
	if len(recs) != numGoroutines {
		t.Errorf("expected %d records, got %d", numGoroutines, len(recs))
	}
}

// ---------------------------------------------------------------------------
// CheckTierRateLimit tests — tier-aware rate limiting
// ---------------------------------------------------------------------------

func TestCheckTierRateLimit_Unlimited(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// -1 means unlimited (Community/Enterprise soft-throttle policy)
	allowed, remaining, err := tr.CheckTierRateLimit("tok-unlimited", -1)
	if err != nil {
		t.Fatalf("CheckTierRateLimit failed: %v", err)
	}
	if !allowed {
		t.Error("expected unlimited requests to be allowed")
	}
	if remaining != math.MaxInt {
		t.Errorf("expected remaining=MaxInt for unlimited, got %d", remaining)
	}
}

func TestCheckTierRateLimit_ZeroLimit(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	_, _, err := tr.CheckTierRateLimit("tok-zero", 0)
	if err == nil {
		t.Fatal("expected error for zero rate limit")
	}
}

func TestCheckTierRateLimit_DeveloperLimit(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Developer tier: 1000 RPM proxy limit
	allowed, remaining, err := tr.CheckTierRateLimit("tok-dev", 1000)
	if err != nil {
		t.Fatalf("CheckTierRateLimit failed: %v", err)
	}
	if !allowed {
		t.Error("expected first request to be allowed")
	}
	if remaining != 999 {
		t.Errorf("expected remaining=999, got %d", remaining)
	}
}

func TestCheckTierRateLimit_ProfessionalLimit(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Professional tier: 10000 RPM proxy limit
	allowed, remaining, err := tr.CheckTierRateLimit("tok-pro", 10000)
	if err != nil {
		t.Fatalf("CheckTierRateLimit failed: %v", err)
	}
	if !allowed {
		t.Error("expected first request to be allowed")
	}
	if remaining != 9999 {
		t.Errorf("expected remaining=9999, got %d", remaining)
	}
}

func TestCheckTierRateLimit_Exceeded(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Small limit for testing
	limit := 3
	for i := 0; i < limit; i++ {
		_, _, err := tr.CheckTierRateLimit("tok-small", limit)
		if err != nil {
			t.Fatalf("CheckTierRateLimit(%d) failed: %v", i, err)
		}
	}

	// Next request should be denied
	allowed, remaining, err := tr.CheckTierRateLimit("tok-small", limit)
	if err != nil {
		t.Fatalf("CheckTierRateLimit failed: %v", err)
	}
	if allowed {
		t.Error("expected request to be denied after limit exceeded")
	}
	if remaining != 0 {
		t.Errorf("expected remaining=0, got %d", remaining)
	}
}

func TestCheckTierRateLimit_DifferentTokensDifferentLimits(t *testing.T) {
	tr := newTestTracker()
	defer tr.Close()

	// Exhaust a small limit for one token.
	smallLimit := 2
	for i := 0; i < smallLimit; i++ {
		_, _, err := tr.CheckTierRateLimit("tok-A", smallLimit)
		if err != nil {
			t.Fatalf("CheckTierRateLimit(A) failed: %v", err)
		}
	}

	// A different token with a different (larger) limit should still be allowed.
	allowed, _, err := tr.CheckTierRateLimit("tok-B", 1000)
	if err != nil {
		t.Fatalf("CheckTierRateLimit(B) failed: %v", err)
	}
	if !allowed {
		t.Error("expected tok-B to be allowed (different token, different limit)")
	}
}
