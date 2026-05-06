// SPDX-License-Identifier: Apache-2.0
package sla

import "github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"

// SLADefinition defines the service level objectives for a given tier.
type SLADefinition struct {
	Tier             tier.Tier
	UptimeTarget     float64 // Percentage (e.g., 99.5)
	SupportResponse  string  // Human-readable support response time
	SupportChannel   string  // Support channel description
	IncidentResponse string  // Incident response time
	DataRetention    int     // Days of log retention
}

// SLO defines a specific service level objective with a metric name, target,
// measurement window, and description.
type SLO struct {
	Name        string  // e.g., "api_availability"
	Target      float64 // e.g., 99.5
	Window      string  // e.g., "30d"
	Metric      string  // e.g., "successful_requests / total_requests"
	Description string  // Human-readable description
}

// Definitions per tier. These are published on the website and enforceable
// via the /health and /metrics endpoints.
var Definitions = map[tier.Tier]SLADefinition{
	tier.TierCommunity: {
		Tier:             tier.TierCommunity,
		UptimeTarget:     99.0,
		SupportResponse:  "Best-effort (community forum)",
		SupportChannel:   "GitHub Issues",
		IncidentResponse: "No SLA — best effort",
		DataRetention:    7,
	},
	tier.TierDeveloper: {
		Tier:             tier.TierDeveloper,
		UptimeTarget:     99.9,
		SupportResponse:  "24 hours",
		SupportChannel:   "Email + Priority GitHub Issues",
		IncidentResponse: "8 hours (P1), 24 hours (P2)",
		DataRetention:    90,
	},
	tier.TierProfessional: {
		Tier:             tier.TierProfessional,
		UptimeTarget:     99.95,
		SupportResponse:  "4 hours",
		SupportChannel:   "Dedicated support channel",
		IncidentResponse: "2 hours (P1), 8 hours (P2)",
		DataRetention:    365,
	},
	tier.TierEnterprise: {
		Tier:             tier.TierEnterprise,
		UptimeTarget:     99.99,
		SupportResponse:  "1 hour",
		SupportChannel:   "24/7 dedicated support + Slack",
		IncidentResponse: "30 minutes (P1), 2 hours (P2)",
		DataRetention:    0, // Custom (negotiated)
	},
}

// SLOs defines measurable service level objectives.
var SLOs = []SLO{
	{
		Name:        "api_availability",
		Target:      99.5,
		Window:      "30d",
		Metric:      "successful_requests / total_requests",
		Description: "API request success rate (non-5xx responses / total responses)",
	},
	{
		Name:        "request_latency_p99",
		Target:      100, // ms
		Window:      "30d",
		Metric:      "histogram_quantile(0.99, request_duration_seconds)",
		Description: "99th percentile request latency under 100ms",
	},
	{
		Name:        "mcp_session_availability",
		Target:      99.9,
		Window:      "30d",
		Metric:      "active_mcp_sessions / attempted_sessions",
		Description: "MCP session establishment success rate",
	},
	{
		Name:        "a2a_auth_success_rate",
		Target:      99.9,
		Window:      "30d",
		Metric:      "a2a_auth_success / a2a_auth_total",
		Description: "A2A mTLS authentication success rate (excluding invalid certs)",
	},
	{
		Name:        "guardrail_enforcement_rate",
		Target:      100, // % — guardrails MUST always enforce
		Window:      "30d",
		Metric:      "guardrail_enforced / guardrail_evaluated",
		Description: "Guardrail enforcement rate — must be 100%",
	},
	{
		Name:        "audit_log_completeness",
		Target:      100, // % — every request must be logged
		Window:      "30d",
		Metric:      "audit_entries / total_requests",
		Description: "Audit log completeness — every request must be recorded",
	},
}

// GetSLA returns the SLA definition for a given tier.
func GetSLA(t tier.Tier) SLADefinition {
	if def, ok := Definitions[t]; ok {
		return def
	}
	// Default to Community tier SLA for unknown tiers
	return Definitions[tier.TierCommunity]
}
