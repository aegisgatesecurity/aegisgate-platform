// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Token Usage Analytics
// =========================================================================
//
// The analytics package provides real-time token usage tracking, cost
// attribution, rate limiting, and anomaly detection for the AegisGate
// platform's API token ecosystem.
//
// Components:
//   - token_usage.go:  core TokenUsageTracker, UsageRecord, and summary types
//   - dashboard.go:    DashboardData aggregation, real-time metrics, alerts
//
// Data flow:
//   1. API proxy records each request as a UsageRecord via RecordUsage()
//   2. Periodic aggregation goroutine computes RealTimeMetrics every 10s
//   3. Dashboard consumers call GetDashboardData() for live views
//   4. Billing system calls GetCostAttribution() for invoicing
//   5. Security pipeline calls DetectAnomalies() for spike detection
//
// Storage:
//   v1 uses in-memory ring buffers protected by sync.RWMutex.
//   Production deployments should swap the store interface for
//   TimescaleDB or ClickHouse (see Store interface in token_usage.go).
//
// Thread safety:
//   All public methods on TokenUsageTracker are goroutine-safe.
//   Read-heavy paths use RWMutex for concurrent read access.
//   Write paths (RecordUsage, aggregation) acquire full locks.
//
// =========================================================================

package analytics
