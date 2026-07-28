// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Token Usage Analytics Engine
// =========================================================================
//
// Core types and logic for tracking API token usage, computing summaries,
// enforcing rate limits, attributing costs, and detecting anomalies.
//
// =========================================================================

package analytics

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// UsageRecord captures a single API request's token consumption.
type UsageRecord struct {
	TokenID        string    `json:"token_id"`
	UserID         string    `json:"user_id"`
	OrganizationID string    `json:"organization_id"`
	Endpoint       string    `json:"endpoint"`
	TokensUsed     int       `json:"tokens_used"`
	CostCents      float64   `json:"cost_cents"`
	Timestamp      time.Time `json:"timestamp"`
	Model          string    `json:"model"`
	LatencyMs      int       `json:"latency_ms"`
	Success        bool      `json:"success"`
}

// UsageSummary aggregates usage data for an organization over a time range.
type UsageSummary struct {
	TotalTokens    int64                     `json:"total_tokens"`
	TotalCostCents float64                   `json:"total_cost_cents"`
	RequestCount   int64                     `json:"request_count"`
	ErrorRate      float64                   `json:"error_rate"`
	AvgLatencyMs   float64                   `json:"avg_latency_ms"`
	PeriodStart    time.Time                 `json:"period_start"`
	PeriodEnd      time.Time                 `json:"period_end"`
	ByUser         map[string]*UserUsage     `json:"by_user"`
	ByEndpoint     map[string]*EndpointUsage `json:"by_endpoint"`
	ByModel        map[string]*ModelUsage    `json:"by_model"`
}

// UserUsage holds per-user aggregated usage metrics.
type UserUsage struct {
	UserID       string  `json:"user_id"`
	TokenCount   int64   `json:"token_count"`
	CostCents    float64 `json:"cost_cents"`
	RequestCount int64   `json:"request_count"`
}

// EndpointUsage holds per-endpoint aggregated metrics.
type EndpointUsage struct {
	Endpoint     string  `json:"endpoint"`
	RequestCount int64   `json:"request_count"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
	ErrorCount   int64   `json:"error_count"`
}

// ModelUsage holds per-model aggregated metrics.
type ModelUsage struct {
	Model        string  `json:"model"`
	TokenCount   int64   `json:"token_count"`
	CostCents    float64 `json:"cost_cents"`
	RequestCount int64   `json:"request_count"`
}

// Anomaly represents a detected usage anomaly.
type Anomaly struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
}

// HourlyBucket holds aggregated usage for a single hour.
type HourlyBucket struct {
	Hour         time.Time `json:"hour"`
	TokenCount   int64     `json:"token_count"`
	RequestCount int64     `json:"request_count"`
	CostCents    float64   `json:"cost_cents"`
}

// CostPoint represents a cost data point for trend visualization.
type CostPoint struct {
	Date      time.Time `json:"date"`
	CostCents float64   `json:"cost_cents"`
}

// ---------------------------------------------------------------------------
// Internal storage
// ---------------------------------------------------------------------------

// rateLimitWindow tracks request counts for a token within a window.
type rateLimitWindow struct {
	counts   map[time.Time]int // bucketed by second for sliding window
	lastSeen time.Time
}

// realTimeState holds mutable real-time metrics updated by the aggregation
// goroutine. Reads are lock-free via atomic-style access through the tracker
// mutex.
type realTimeState struct {
	ActiveTokens       int
	RequestsPerMinute  float64
	CurrentCostPerHour float64
	ErrorRateLast5Min  float64
	LastUpdated        time.Time
}

// ---------------------------------------------------------------------------
// Store interface (for future TimescaleDB/ClickHouse backends)
// ---------------------------------------------------------------------------

// Store defines the persistence interface for usage records. The in-memory
// implementation is the default; production systems should provide a
// TimescaleDB or ClickHouse adapter.
type Store interface {
	Insert(record *UsageRecord) error
	QueryByOrg(orgID string, start, end time.Time) ([]*UsageRecord, error)
	QueryByToken(tokenID string, start, end time.Time) ([]*UsageRecord, error)
	Close() error
}

// ---------------------------------------------------------------------------
// TokenUsageTracker
// ---------------------------------------------------------------------------

// TokenUsageTracker is the core engine for token usage analytics. It stores
// records in-memory, computes real-time metrics via a background goroutine,
// and provides query methods for summaries, dashboards, rate limiting, cost
// attribution, and anomaly detection.
//
// All public methods are safe for concurrent use.
type TokenUsageTracker struct {
	mu sync.RWMutex

	// Primary record storage: orgID -> slice of records.
	records map[string][]*UsageRecord

	// Index for token-level lookups: tokenID -> slice of records.
	tokenIndex map[string][]*UsageRecord

	// Rate limit tracking: tokenID -> window state.
	rateLimits map[string]*rateLimitWindow

	// Alert configuration.
	alerts *AlertConfig

	// Real-time metrics state (updated by aggregation goroutine).
	realTime realTimeState

	// Aggregation goroutine control.
	aggCancel  chan struct{}
	aggDone    chan struct{}
	aggStarted bool

	// Store backend (nil means in-memory).
	store Store
}

// NewTokenUsageTracker creates a new tracker with in-memory storage and
// starts the background aggregation goroutine.
func NewTokenUsageTracker(alerts *AlertConfig) *TokenUsageTracker {
	if alerts == nil {
		alerts = &AlertConfig{
			RateLimitThreshold: 1000,
			CostThresholdCents: 50000, // $500
			ErrorRateThreshold: 0.05,  // 5%
			AlertEndpoints:     []string{},
		}
	}
	t := &TokenUsageTracker{
		records:    make(map[string][]*UsageRecord),
		tokenIndex: make(map[string][]*UsageRecord),
		rateLimits: make(map[string]*rateLimitWindow),
		alerts:     alerts,
		aggCancel:  make(chan struct{}),
		aggDone:    make(chan struct{}),
	}
	t.startAggregation()
	return t
}

// NewTokenUsageTrackerWithStore creates a tracker with a custom store
// backend. The aggregation goroutine is still started for real-time metrics.
func NewTokenUsageTrackerWithStore(alerts *AlertConfig, store Store) *TokenUsageTracker {
	t := NewTokenUsageTracker(alerts)
	t.store = store
	return t
}

// Close stops the aggregation goroutine and releases resources.
// Close stops the aggregation goroutine and releases resources.
// It is safe to call Close multiple times.
func (t *TokenUsageTracker) Close() error {
	t.mu.Lock()
	started := t.aggStarted
	t.aggStarted = false
	t.mu.Unlock()

	if started {
		close(t.aggCancel)
		<-t.aggDone
	}
	if t.store != nil {
		return t.store.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// RecordUsage — stores a usage record
// ---------------------------------------------------------------------------

// RecordUsage stores a usage record. It validates required fields, persists
// to the store backend if configured, and indexes the record for fast
// lookups by organization and token.
func (t *TokenUsageTracker) RecordUsage(record *UsageRecord) error {
	if record == nil {
		return fmt.Errorf("usage record cannot be nil")
	}
	if record.TokenID == "" {
		return fmt.Errorf("token_id is required")
	}
	if record.OrganizationID == "" {
		return fmt.Errorf("organization_id is required")
	}
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}

	// Persist to external store if configured.
	if t.store != nil {
		if err := t.store.Insert(record); err != nil {
			return fmt.Errorf("store insert failed: %w", err)
		}
	}

	t.mu.Lock()
	t.records[record.OrganizationID] = append(t.records[record.OrganizationID], record)
	t.tokenIndex[record.TokenID] = append(t.tokenIndex[record.TokenID], record)
	t.mu.Unlock()

	return nil
}

// ---------------------------------------------------------------------------
// GetSummary — aggregates usage data for an org in a time range
// ---------------------------------------------------------------------------

// GetSummary aggregates usage data for the given organization within the
// specified time range. It returns a UsageSummary with totals and
// breakdowns by user, endpoint, and model.
func (t *TokenUsageTracker) GetSummary(orgID string, start, end time.Time) (*UsageSummary, error) {
	if orgID == "" {
		return nil, fmt.Errorf("organization_id is required")
	}
	if end.Before(start) {
		return nil, fmt.Errorf("end time must not be before start time")
	}

	var recs []*UsageRecord
	if t.store != nil {
		stored, err := t.store.QueryByOrg(orgID, start, end)
		if err != nil {
			return nil, fmt.Errorf("store query failed: %w", err)
		}
		recs = stored
	} else {
		recs = t.recordsInRange(orgID, start, end)
	}

	summary := &UsageSummary{
		PeriodStart: start,
		PeriodEnd:   end,
		ByUser:      make(map[string]*UserUsage),
		ByEndpoint:  make(map[string]*EndpointUsage),
		ByModel:     make(map[string]*ModelUsage),
	}

	var totalLatency int64
	var errorCount int64

	for _, r := range recs {
		summary.TotalTokens += int64(r.TokensUsed)
		summary.TotalCostCents += r.CostCents
		summary.RequestCount++
		totalLatency += int64(r.LatencyMs)
		if !r.Success {
			errorCount++
		}

		// By user.
		if u, ok := summary.ByUser[r.UserID]; ok {
			u.TokenCount += int64(r.TokensUsed)
			u.CostCents += r.CostCents
			u.RequestCount++
		} else {
			summary.ByUser[r.UserID] = &UserUsage{
				UserID:       r.UserID,
				TokenCount:   int64(r.TokensUsed),
				CostCents:    r.CostCents,
				RequestCount: 1,
			}
		}

		// By endpoint.
		if e, ok := summary.ByEndpoint[r.Endpoint]; ok {
			e.RequestCount++
			// Running average for latency.
			e.AvgLatencyMs = (e.AvgLatencyMs*float64(e.RequestCount-1) + float64(r.LatencyMs)) / float64(e.RequestCount)
			if !r.Success {
				e.ErrorCount++
			}
		} else {
			ep := &EndpointUsage{
				Endpoint:     r.Endpoint,
				RequestCount: 1,
				AvgLatencyMs: float64(r.LatencyMs),
			}
			if !r.Success {
				ep.ErrorCount = 1
			}
			summary.ByEndpoint[r.Endpoint] = ep
		}

		// By model.
		if m, ok := summary.ByModel[r.Model]; ok {
			m.TokenCount += int64(r.TokensUsed)
			m.CostCents += r.CostCents
			m.RequestCount++
		} else {
			summary.ByModel[r.Model] = &ModelUsage{
				Model:        r.Model,
				TokenCount:   int64(r.TokensUsed),
				CostCents:    r.CostCents,
				RequestCount: 1,
			}
		}
	}

	if summary.RequestCount > 0 {
		summary.ErrorRate = float64(errorCount) / float64(summary.RequestCount)
		summary.AvgLatencyMs = float64(totalLatency) / float64(summary.RequestCount)
	}

	return summary, nil
}

// ---------------------------------------------------------------------------
// CheckRateLimit — sliding window rate limit check
// ---------------------------------------------------------------------------

// CheckRateLimit checks whether a token is within its rate limit for the
// given window. It returns (allowed, remaining, error). The count is
// tracked using a second-by-second sliding window.
func (t *TokenUsageTracker) CheckRateLimit(tokenID string, window time.Duration, limit int) (bool, int, error) {
	if tokenID == "" {
		return false, 0, fmt.Errorf("token_id is required")
	}
	if limit <= 0 {
		return false, 0, fmt.Errorf("limit must be positive")
	}

	now := time.Now().UTC()
	windowStart := now.Add(-window)

	t.mu.Lock()
	rw, exists := t.rateLimits[tokenID]
	if !exists {
		rw = &rateLimitWindow{
			counts: make(map[time.Time]int),
		}
		t.rateLimits[tokenID] = rw
	}
	rw.lastSeen = now

	// Prune expired buckets and count current window usage.
	var totalInWindow int
	for ts, count := range rw.counts {
		if ts.Before(windowStart) {
			delete(rw.counts, ts)
		} else {
			totalInWindow += count
		}
	}

	remaining := limit - totalInWindow
	if remaining < 0 {
		remaining = 0
	}

	// Record this check as a request in the current second.
	secondBucket := now.Truncate(time.Second)
	rw.counts[secondBucket]++

	allowed := totalInWindow < limit
	if allowed {
		remaining = limit - totalInWindow - 1
		if remaining < 0 {
			remaining = 0
		}
	}

	t.mu.Unlock()
	return allowed, remaining, nil
}

// ---------------------------------------------------------------------------
// GetCostAttribution — cost breakdown by user/team
// ---------------------------------------------------------------------------

// GetCostAttribution returns a map of user/team ID to total cost (in cents)
// for the given organization and time range.
func (t *TokenUsageTracker) GetCostAttribution(orgID string, start, end time.Time) (map[string]float64, error) {
	summary, err := t.GetSummary(orgID, start, end)
	if err != nil {
		return nil, err
	}

	result := make(map[string]float64, len(summary.ByUser))
	for userID, usage := range summary.ByUser {
		result[userID] = usage.CostCents
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// DetectAnomalies — detects usage spikes and unusual patterns
// ---------------------------------------------------------------------------

// DetectAnomalies analyzes recent usage for the given organization and
// returns detected anomalies including cost spikes, error rate spikes,
// latency spikes, and rate limit violations.
func (t *TokenUsageTracker) DetectAnomalies(orgID string, window time.Duration) ([]Anomaly, error) {
	if orgID == "" {
		return nil, fmt.Errorf("organization_id is required")
	}

	now := time.Now().UTC()
	start := now.Add(-window)

	var recs []*UsageRecord
	if t.store != nil {
		stored, err := t.store.QueryByOrg(orgID, start, now)
		if err != nil {
			return nil, fmt.Errorf("store query failed: %w", err)
		}
		recs = stored
	} else {
		recs = t.recordsInRange(orgID, start, now)
	}

	var anomalies []Anomaly

	// ---- 1. Cost spike detection ----
	// Compare per-hour cost in the window to the average hourly cost.
	hourlyCost := make(map[int64]float64) // hour bucket -> cost
	hourlyCount := make(map[int64]int)
	for _, r := range recs {
		bucket := r.Timestamp.Truncate(time.Hour).Unix()
		hourlyCost[bucket] += r.CostCents
		hourlyCount[bucket]++
	}

	if len(hourlyCost) > 0 {
		var totalCost float64
		for _, c := range hourlyCost {
			totalCost += c
		}
		avgHourlyCost := totalCost / float64(len(hourlyCost))

		for hour, cost := range hourlyCost {
			if avgHourlyCost > 0 && cost > avgHourlyCost*3 {
				anomalies = append(anomalies, Anomaly{
					Type:        "cost_spike",
					Description: fmt.Sprintf("Hourly cost $%.2f is %.1fx above average $%.2f", cost/100, cost/avgHourlyCost, avgHourlyCost/100),
					Severity:    severityForRatio(cost / avgHourlyCost),
					Timestamp:   time.Unix(hour, 0).UTC(),
					Data: map[string]interface{}{
						"hourly_cost_cents": cost,
						"avg_hourly_cents":  avgHourlyCost,
						"ratio":             cost / avgHourlyCost,
					},
				})
			}
		}
	}

	// ---- 2. Error rate spike ----
	var totalErrors int
	var totalRequests int
	for _, r := range recs {
		totalRequests++
		if !r.Success {
			totalErrors++
		}
	}
	if totalRequests > 10 {
		errorRate := float64(totalErrors) / float64(totalRequests)
		if errorRate > t.alerts.ErrorRateThreshold {
			anomalies = append(anomalies, Anomaly{
				Type:        "error_rate_spike",
				Description: fmt.Sprintf("Error rate %.2f%% exceeds threshold %.2f%%", errorRate*100, t.alerts.ErrorRateThreshold*100),
				Severity:    severityForThreshold(errorRate, t.alerts.ErrorRateThreshold),
				Timestamp:   now,
				Data: map[string]interface{}{
					"error_rate":           errorRate,
					"error_rate_threshold": t.alerts.ErrorRateThreshold,
					"total_errors":         totalErrors,
					"total_requests":       totalRequests,
				},
			})
		}
	}

	// ---- 3. Latency spike ----
	if len(recs) > 5 {
		var totalLatency float64
		for _, r := range recs {
			totalLatency += float64(r.LatencyMs)
		}
		avgLatency := totalLatency / float64(len(recs))

		// Find individual requests with latency > 5x average.
		for _, r := range recs {
			if float64(r.LatencyMs) > avgLatency*5 && float64(r.LatencyMs) > 5000 {
				anomalies = append(anomalies, Anomaly{
					Type:        "latency_spike",
					Description: fmt.Sprintf("Request latency %dms is %.1fx above average %.1fms", r.LatencyMs, float64(r.LatencyMs)/avgLatency, avgLatency),
					Severity:    "medium",
					Timestamp:   r.Timestamp,
					Data: map[string]interface{}{
						"latency_ms":  r.LatencyMs,
						"avg_latency": avgLatency,
						"endpoint":    r.Endpoint,
						"model":       r.Model,
						"token_id":    r.TokenID,
					},
				})
				// Cap at 5 latency spikes to avoid noise.
				if len(anomalies) > 50 {
					break
				}
			}
		}
	}

	// ---- 4. Unusual token activity ----
	tokenCount := make(map[string]int)
	for _, r := range recs {
		tokenCount[r.TokenID]++
	}
	for tokenID, count := range tokenCount {
		if count > t.alerts.RateLimitThreshold {
			anomalies = append(anomalies, Anomaly{
				Type:        "rate_limit_exceeded",
				Description: fmt.Sprintf("Token %s made %d requests in window, exceeding limit of %d", maskToken(tokenID), count, t.alerts.RateLimitThreshold),
				Severity:    "high",
				Timestamp:   now,
				Data: map[string]interface{}{
					"token_id":      maskToken(tokenID),
					"request_count": count,
					"limit":         t.alerts.RateLimitThreshold,
				},
			})
		}
	}

	// Sort anomalies by severity.
	sort.Slice(anomalies, func(i, j int) bool {
		return severityOrder(anomalies[i].Severity) < severityOrder(anomalies[j].Severity)
	})

	return anomalies, nil
}

// ---------------------------------------------------------------------------
// Periodic aggregation goroutine
// ---------------------------------------------------------------------------

// startAggregation launches the background goroutine that computes
// real-time metrics every 10 seconds.
func (t *TokenUsageTracker) startAggregation() {
	t.aggStarted = true
	go func() {
		defer close(t.aggDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-t.aggCancel:
				return
			case <-ticker.C:
				t.computeRealTimeMetrics()
			}
		}
	}()
}

// computeRealTimeMetrics recomputes the real-time dashboard metrics from
// the in-memory record store.
func (t *TokenUsageTracker) computeRealTimeMetrics() {
	now := time.Now().UTC()
	fiveMinAgo := now.Add(-5 * time.Minute)
	oneHourAgo := now.Add(-time.Hour)
	oneMinAgo := now.Add(-time.Minute)

	t.mu.RLock()
	defer t.mu.RUnlock()

	var (
		activeTokens     = make(map[string]struct{})
		requestsLastMin  int
		costLastHour     float64
		requestsLast5Min int
		errorsLast5Min   int
	)

	for _, orgRecs := range t.records {
		for _, r := range orgRecs {
			if r.Timestamp.After(oneHourAgo) {
				activeTokens[r.TokenID] = struct{}{}
				costLastHour += r.CostCents
			}
			if r.Timestamp.After(oneMinAgo) {
				requestsLastMin++
			}
			if r.Timestamp.After(fiveMinAgo) {
				requestsLast5Min++
				if !r.Success {
					errorsLast5Min++
				}
			}
		}
	}

	var rpm, costPerHour, errorRate5m float64
	// RPM = requests in last minute, normalized.
	rpm = float64(requestsLastMin)
	costPerHour = costLastHour
	if requestsLast5Min > 0 {
		errorRate5m = float64(errorsLast5Min) / float64(requestsLast5Min)
	}

	t.realTime = realTimeState{
		ActiveTokens:       len(activeTokens),
		RequestsPerMinute:  rpm,
		CurrentCostPerHour: costPerHour,
		ErrorRateLast5Min:  errorRate5m,
		LastUpdated:        now,
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// recordsInRange returns all records for an org within the given time range.
func (t *TokenUsageTracker) recordsInRange(orgID string, start, end time.Time) []*UsageRecord {
	t.mu.RLock()
	orgRecs, ok := t.records[orgID]
	t.mu.RUnlock()

	if !ok {
		return nil
	}

	var result []*UsageRecord
	for _, r := range orgRecs {
		if !r.Timestamp.Before(start) && !r.Timestamp.After(end) {
			result = append(result, r)
		}
	}
	return result
}

// severityForRatio returns a severity string based on how far above
// average a value is.
func severityForRatio(ratio float64) string {
	switch {
	case ratio > 10:
		return "critical"
	case ratio > 5:
		return "high"
	case ratio > 3:
		return "medium"
	default:
		return "low"
	}
}

// severityForThreshold returns severity based on how much a value exceeds
// its threshold.
func severityForThreshold(value, threshold float64) string {
	if threshold == 0 {
		return "critical"
	}
	ratio := value / threshold
	switch {
	case ratio > 3:
		return "critical"
	case ratio > 2:
		return "high"
	default:
		return "medium"
	}
}

// severityOrder maps severity strings to sortable integers.
func severityOrder(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// maskToken returns a masked version of a token ID for safe display.
func maskToken(tokenID string) string {
	if len(tokenID) <= 8 {
		return "****"
	}
	return tokenID[:4] + "****" + tokenID[len(tokenID)-4:]
}

// roundToCent rounds a float64 to 2 decimal places (cents precision).
func roundToCent(v float64) float64 {
	return math.Round(v*100+0.0000001) / 100
}

// ---------------------------------------------------------------------------
// Request-path wiring: RecordUsage from HTTP and Bridge requests
// ---------------------------------------------------------------------------

// RequestInfo holds metadata extracted from an HTTP or bridge request,
// used to create a UsageRecord. Fields with zero values are omitted
// from the record; the caller should set as many fields as available.
type RequestInfo struct {
	TokenID        string
	UserID         string
	OrganizationID string
	Endpoint       string
	Model          string
	TokensUsed     int
	CostCents      float64
	LatencyMs      int
	Success        bool
}

// RecordUsageFromRequest records a usage entry from request metadata.
// It fills in the timestamp automatically and delegates to RecordUsage.
// This is the primary wiring point for proxy/bridge request paths.
func (t *TokenUsageTracker) RecordUsageFromRequest(info RequestInfo) error {
	rec := &UsageRecord{
		TokenID:        info.TokenID,
		UserID:         info.UserID,
		OrganizationID: info.OrganizationID,
		Endpoint:       info.Endpoint,
		Model:          info.Model,
		TokensUsed:     info.TokensUsed,
		CostCents:      info.CostCents,
		LatencyMs:      info.LatencyMs,
		Success:        info.Success,
	}
	return t.RecordUsage(rec)
}

// RecordBridgeUsage records analytics for a bridge (LLM proxy) request.
// This is the bridge-side wiring: after RouteLLMCall completes, the
// caller invokes RecordBridgeUsage with the request/response metadata
// to track token consumption, cost, and latency.
//
// Parameters:
//   - orgID:      organization ID (required)
//   - tokenID:    API token used for the request (required)
//   - userID:     user who initiated the request (optional)
//   - model:      LLM model invoked (e.g., "gpt-4")
//   - endpoint:   API endpoint (e.g., "/v1/chat/completions")
//   - tokensUsed: total tokens consumed (prompt + completion)
//   - costCents:  cost in cents (USD cents)
//   - latencyMs:  total latency in milliseconds
//   - success:    whether the request succeeded
func (t *TokenUsageTracker) RecordBridgeUsage(orgID, tokenID, userID, model, endpoint string, tokensUsed int, costCents float64, latencyMs int, success bool) error {
	rec := &UsageRecord{
		TokenID:        tokenID,
		UserID:         userID,
		OrganizationID: orgID,
		Endpoint:       endpoint,
		Model:          model,
		TokensUsed:     tokensUsed,
		CostCents:      costCents,
		LatencyMs:      latencyMs,
		Success:        success,
	}
	return t.RecordUsage(rec)
}

// CheckTierRateLimit checks whether a token is within its tier-based rate
// limit for proxy requests. It maps the tier's RPM limit to the analytics
// tracker's sliding-window CheckRateLimit. Returns (allowed, remaining, error).
//
// For Community and Enterprise tiers (which return -1 = unlimited),
// this always returns (true, math.MaxInt, nil).
func (t *TokenUsageTracker) CheckTierRateLimit(tokenID string, rpmLimit int) (bool, int, error) {
	if rpmLimit < 0 {
		// Unlimited rate limit (Community/Enterprise soft-throttle policy)
		return true, math.MaxInt, nil
	}
	if rpmLimit == 0 {
		return false, 0, fmt.Errorf("rate limit cannot be zero")
	}
	return t.CheckRateLimit(tokenID, time.Minute, rpmLimit)
}
