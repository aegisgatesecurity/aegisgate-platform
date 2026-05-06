// SPDX-License-Identifier: Apache-2.0
package sla

import (
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

func TestGetSLA_AllTiers(t *testing.T) {
	tiers := []tier.Tier{
		tier.TierCommunity,
		tier.TierDeveloper,
		tier.TierProfessional,
		tier.TierEnterprise,
	}

	for _, t2 := range tiers {
		sla := GetSLA(t2)
		if sla.Tier != t2 {
			t.Errorf("GetSLA(%v).Tier = %v, want %v", t2, sla.Tier, t2)
		}
		if sla.UptimeTarget <= 0 || sla.UptimeTarget > 100 {
			t.Errorf("GetSLA(%v).UptimeTarget = %v, want (0, 100]", t2, sla.UptimeTarget)
		}
		if sla.SupportResponse == "" {
			t.Errorf("GetSLA(%v).SupportResponse is empty", t2)
		}
		if sla.SupportChannel == "" {
			t.Errorf("GetSLA(%v).SupportChannel is empty", t2)
		}
		if sla.IncidentResponse == "" {
			t.Errorf("GetSLA(%v).IncidentResponse is empty", t2)
		}
	}

	// Verify uptime targets increase with tier
	slaCommunity := GetSLA(tier.TierCommunity)
	slaDeveloper := GetSLA(tier.TierDeveloper)
	slaProfessional := GetSLA(tier.TierProfessional)
	slaEnterprise := GetSLA(tier.TierEnterprise)

	if slaDeveloper.UptimeTarget <= slaCommunity.UptimeTarget {
		t.Errorf("Developer uptime (%v) should exceed Community (%v)", slaDeveloper.UptimeTarget, slaCommunity.UptimeTarget)
	}
	if slaProfessional.UptimeTarget <= slaDeveloper.UptimeTarget {
		t.Errorf("Professional uptime (%v) should exceed Developer (%v)", slaProfessional.UptimeTarget, slaDeveloper.UptimeTarget)
	}
	if slaEnterprise.UptimeTarget <= slaProfessional.UptimeTarget {
		t.Errorf("Enterprise uptime (%v) should exceed Professional (%v)", slaEnterprise.UptimeTarget, slaProfessional.UptimeTarget)
	}
}

func TestGetSLA_UnknownTier(t *testing.T) {
	// Unknown tier should default to Community
	sla := GetSLA(tier.Tier(99))
	if sla.Tier != tier.TierCommunity {
		t.Errorf("GetSLA(unknown).Tier = %v, want Community", sla.Tier)
	}
	if sla.UptimeTarget != 99.0 {
		t.Errorf("GetSLA(unknown).UptimeTarget = %v, want 99.0", sla.UptimeTarget)
	}
}

func TestSLOs_Defined(t *testing.T) {
	if len(SLOs) == 0 {
		t.Error("SLOs should not be empty")
	}

	requiredNames := []string{"api_availability", "request_latency_p99", "mcp_session_availability", "a2a_auth_success_rate", "guardrail_enforcement_rate", "audit_log_completeness"}
	found := make(map[string]bool)
	for _, slo := range SLOs {
		found[slo.Name] = true
		if slo.Target <= 0 {
			t.Errorf("SLO %q has invalid target: %v", slo.Name, slo.Target)
		}
		if slo.Window == "" {
			t.Errorf("SLO %q has empty window", slo.Name)
		}
		if slo.Metric == "" {
			t.Errorf("SLO %q has empty metric", slo.Name)
		}
		if slo.Description == "" {
			t.Errorf("SLO %q has empty description", slo.Name)
		}
	}

	for _, name := range requiredNames {
		if !found[name] {
			t.Errorf("Missing required SLO: %s", name)
		}
	}
}

func TestDefinitions_DataRetention(t *testing.T) {
	// Community retains less than Developer, Developer less than Professional
	c := Definitions[tier.TierCommunity]
	d := Definitions[tier.TierDeveloper]
	p := Definitions[tier.TierProfessional]
	e := Definitions[tier.TierEnterprise]

	if c.DataRetention >= d.DataRetention {
		t.Errorf("Community retention (%d) should be less than Developer (%d)", c.DataRetention, d.DataRetention)
	}
	if d.DataRetention >= p.DataRetention {
		t.Errorf("Developer retention (%d) should be less than Professional (%d)", d.DataRetention, p.DataRetention)
	}
	// Enterprise is 0 (custom), skip that comparison
	if e.DataRetention != 0 {
		t.Errorf("Enterprise retention should be 0 (custom), got %d", e.DataRetention)
	}
}
