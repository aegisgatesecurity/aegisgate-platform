// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Dashboard Data Aggregation
// =========================================================================
//
// Dashboard types and aggregation logic for the token usage analytics
// dashboard. The TokenUsageTracker.GetDashboardData() method assembles
// real-time metrics, hourly usage buckets, top users/endpoints, cost
// trends, and alert configuration into a single DashboardData payload.
//
// =========================================================================

package analytics

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// ---------------------------------------------------------------------------
// Dashboard types
// ---------------------------------------------------------------------------

// DashboardData is the top-level payload for the analytics dashboard.
type DashboardData struct {
	RealTimeMetrics *RealTimeMetrics `json:"real_time_metrics"`
	HourlyUsage     []HourlyBucket   `json:"hourly_usage"`
	TopUsers        []UserUsage      `json:"top_users"`
	TopEndpoints    []EndpointUsage  `json:"top_endpoints"`
	CostTrend       []CostPoint      `json:"cost_trend"`
	AlertThresholds *AlertConfig     `json:"alert_thresholds"`
}

// RealTimeMetrics holds live metrics computed by the aggregation goroutine.
type RealTimeMetrics struct {
	ActiveTokens       int     `json:"active_tokens"`
	RequestsPerMinute  float64 `json:"requests_per_minute"`
	CurrentCostPerHour float64 `json:"current_cost_per_hour"`
	ErrorRateLast5Min  float64 `json:"error_rate_last_5min"`
}

// AlertConfig defines thresholds for usage alerts.
type AlertConfig struct {
	RateLimitThreshold int      `json:"rate_limit_threshold"`
	CostThresholdCents float64  `json:"cost_threshold_cents"`
	ErrorRateThreshold float64  `json:"error_rate_threshold"`
	AlertEndpoints     []string `json:"alert_endpoints"`
}

// ---------------------------------------------------------------------------
// GetDashboardData — assembles the full dashboard payload
// ---------------------------------------------------------------------------

// GetDashboardData returns real-time dashboard data for the given organization.
// It aggregates the last 24 hours of data into hourly buckets, ranks top users
// and endpoints, computes a daily cost trend, and includes current alert
// thresholds.
func (t *TokenUsageTracker) GetDashboardData(orgID string) (*DashboardData, error) {
	if orgID == "" {
		return nil, fmt.Errorf("organization_id is required")
	}

	now := time.Now().UTC()
	last24h := now.Add(-24 * time.Hour)
	last7d := now.Add(-7 * 24 * time.Hour)

	// Get summary for the last 24 hours for top users/endpoints.
	summary, err := t.GetSummary(orgID, last24h, now)
	if err != nil {
		return nil, err
	}

	// Assemble real-time metrics from aggregation goroutine state.
	t.mu.RLock()
	rt := RealTimeMetrics{
		ActiveTokens:       t.realTime.ActiveTokens,
		RequestsPerMinute:  roundToCent(t.realTime.RequestsPerMinute),
		CurrentCostPerHour: roundToCent(t.realTime.CurrentCostPerHour),
		ErrorRateLast5Min:  roundToCent(t.realTime.ErrorRateLast5Min),
	}
	alerts := *t.alerts // copy
	t.mu.RUnlock()

	// Build hourly buckets from raw records.
	hourlyBuckets := t.buildHourlyBuckets(orgID, last24h, now)

	// Top users (by cost, capped at 10).
	topUsers := topNUsers(summary.ByUser, 10)

	// Top endpoints (by request count, capped at 10).
	topEndpoints := topNEndpoints(summary.ByEndpoint, 10)

	// Cost trend (daily over last 7 days).
	costTrend := t.buildCostTrend(orgID, last7d, now)

	return &DashboardData{
		RealTimeMetrics: &rt,
		HourlyUsage:     hourlyBuckets,
		TopUsers:        topUsers,
		TopEndpoints:    topEndpoints,
		CostTrend:       costTrend,
		AlertThresholds: &alerts,
	}, nil
}

// ---------------------------------------------------------------------------
// Hourly bucket aggregation
// ---------------------------------------------------------------------------

// buildHourlyBuckets creates hourly usage buckets for the given org and time
// range. Each bucket aggregates token count, request count, and cost.
func (t *TokenUsageTracker) buildHourlyBuckets(orgID string, start, end time.Time) []HourlyBucket {
	recs := t.recordsInRange(orgID, start, end)
	if len(recs) == 0 {
		return []HourlyBucket{}
	}

	// Bucket records by hour.
	buckets := make(map[int64]*HourlyBucket)
	for _, r := range recs {
		hour := r.Timestamp.Truncate(time.Hour).Unix()
		if b, ok := buckets[hour]; ok {
			b.TokenCount += int64(r.TokensUsed)
			b.RequestCount++
			b.CostCents += r.CostCents
		} else {
			buckets[hour] = &HourlyBucket{
				Hour:         r.Timestamp.Truncate(time.Hour),
				TokenCount:   int64(r.TokensUsed),
				RequestCount: 1,
				CostCents:    r.CostCents,
			}
		}
	}

	// Convert to sorted slice, filling gaps with zero buckets.
	result := make([]HourlyBucket, 0, len(buckets))
	// Find min/max hours.
	var minHour, maxHour int64 = math.MaxInt64, 0
	for h := range buckets {
		if h < minHour {
			minHour = h
		}
		if h > maxHour {
			maxHour = h
		}
	}

	for h := minHour; h <= maxHour; h++ {
		if b, ok := buckets[h]; ok {
			result = append(result, *b)
		} else {
			result = append(result, HourlyBucket{
				Hour:         time.Unix(h, 0).UTC(),
				TokenCount:   0,
				RequestCount: 0,
				CostCents:    0,
			})
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Cost trend (daily)
// ---------------------------------------------------------------------------

// buildCostTrend creates daily cost points for the last 7 days.
func (t *TokenUsageTracker) buildCostTrend(orgID string, start, end time.Time) []CostPoint {
	recs := t.recordsInRange(orgID, start, end)
	if len(recs) == 0 {
		return []CostPoint{}
	}

	// Bucket by day.
	dailyCost := make(map[int64]float64)
	for _, r := range recs {
		day := r.Timestamp.Truncate(24 * time.Hour).Unix()
		dailyCost[day] += r.CostCents
	}

	// Sort by day.
	var days []int64
	for d := range dailyCost {
		days = append(days, d)
	}
	sort.Slice(days, func(i, j int) bool { return days[i] < days[j] })

	result := make([]CostPoint, 0, len(days))
	for _, d := range days {
		result = append(result, CostPoint{
			Date:      time.Unix(d, 0).UTC(),
			CostCents: roundToCent(dailyCost[d]),
		})
	}
	return result
}

// ---------------------------------------------------------------------------
// Top-N helpers
// ---------------------------------------------------------------------------

// topNUsers returns the top N users sorted by cost (descending).
func topNUsers(byUser map[string]*UserUsage, n int) []UserUsage {
	users := make([]UserUsage, 0, len(byUser))
	for _, u := range byUser {
		users = append(users, *u)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].CostCents > users[j].CostCents
	})
	if len(users) > n {
		users = users[:n]
	}
	return users
}

// topNEndpoints returns the top N endpoints sorted by request count (descending).
func topNEndpoints(byEndpoint map[string]*EndpointUsage, n int) []EndpointUsage {
	endpoints := make([]EndpointUsage, 0, len(byEndpoint))
	for _, e := range byEndpoint {
		endpoints = append(endpoints, *e)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].RequestCount > endpoints[j].RequestCount
	})
	if len(endpoints) > n {
		endpoints = endpoints[:n]
	}
	return endpoints
}
