// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Incident Response Performance Benchmarks

package incident

import (
	"context"
	"fmt"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/correlation"
)

func BenchmarkProcessEvent(b *testing.B) {
	incidentStore := NewInMemoryIncidentStore()
	playbookStore := NewInMemoryPlaybookStore()
	ruleStore := NewInMemoryDetectionRuleStore()
	engine := NewEngine(incidentStore, playbookStore, ruleStore)
	ctx := context.Background()

	event := correlation.NewEvent("http", "prompt_injection", "bench-agent", "bench-session")
	event.Severity = "high"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.ProcessEvent(ctx, event)
	}
}

func BenchmarkCreateIncident(b *testing.B) {
	store := NewInMemoryIncidentStore()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inc := &Incident{
			ID:       fmt.Sprintf("bench-inc-%d", i),
			Title:    "Benchmark Incident",
			Severity: SeverityHigh,
			Status:   StatusNew,
			AgentID:  "bench-agent",
		}
		store.CreateIncident(ctx, inc)
	}
}

func BenchmarkListIncidents(b *testing.B) {
	store := NewInMemoryIncidentStore()
	ctx := context.Background()

	// Pre-populate
	for i := 0; i < 100; i++ {
		inc := &Incident{
			ID:       fmt.Sprintf("bench-inc-%d", i),
			Title:    "Benchmark Incident",
			Severity: SeverityMedium,
			Status:   StatusNew,
			AgentID:  "bench-agent",
		}
		store.CreateIncident(ctx, inc)
	}

	query := &IncidentQuery{Status: []IncidentStatus{StatusNew}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ListIncidents(ctx, query)
	}
}

func BenchmarkDetectionRuleEvaluation(b *testing.B) {
	s := NewInMemoryDetectionRuleStore()
	ctx := context.Background()

	for i := 0; i < 50; i++ {
		s.CreateRule(ctx, &DetectionRule{
			ID:         fmt.Sprintf("rule-%d", i),
			Name:       fmt.Sprintf("Benchmark Rule %d", i),
			Enabled:    true,
			EventTypes: []string{"prompt_injection"},
			Severity:   SeverityHigh,
			AutoCreate: true,
		})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ListRules(ctx, true)
	}
}
