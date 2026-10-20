// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - NIST AI RMF Gap Tests
// =========================================================================
// Targets functions below 100% coverage to push from 84.2% to 90%+.
// Covers partial and non_compliant paths for 62.5% functions,
// non_compliant paths for 80% functions, and all sub-paths for
// checkAIBusinessRisk (45.5%).
// =========================================================================

package nist_ai_rmf

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// GOVERN (GV) — 62.5% functions
// ---------------------------------------------------------------------------

func TestGap_GV15_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (legal only, no AI)", func(t *testing.T) {
		r, err := m.checkGV15(ctx, []byte(`{"legal": true, "regulatory": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkGV15(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_GV23_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (ai_risk only, no integration)", func(t *testing.T) {
		r, err := m.checkGV23(ctx, []byte(`{"ai_risk": true, "risk_assessment": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkGV23(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_GV42_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (policy only, no harmonized)", func(t *testing.T) {
		r, err := m.checkGV42(ctx, []byte(`{"standard": true, "ai_policy": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkGV42(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

// ---------------------------------------------------------------------------
// MAP (MP) — 62.5% functions
// ---------------------------------------------------------------------------

func TestGap_MP12_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (lifecycle only, no stages)", func(t *testing.T) {
		r, err := m.checkMP12(ctx, []byte(`{"lifecycle": true, "lifecycle_stage": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMP12(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MP22_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (capabilities only, no limitations)", func(t *testing.T) {
		r, err := m.checkMP22(ctx, []byte(`{"capabilities": true, "features": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMP22(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MP23_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (reliability only)", func(t *testing.T) {
		r, err := m.checkMP23(ctx, []byte(`{"reliability": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("partial (validity only)", func(t *testing.T) {
		r, err := m.checkMP23(ctx, []byte(`{"validity": true, "validation": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMP23(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MP33_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (risk_assessment only, no review)", func(t *testing.T) {
		r, err := m.checkMP33(ctx, []byte(`{"risk_assessment": true, "risk_register": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMP33(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

// ---------------------------------------------------------------------------
// MEASURE (MS) — 62.5% functions
// ---------------------------------------------------------------------------

func TestGap_MS12_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (reliability only, no tracking)", func(t *testing.T) {
		r, err := m.checkMS12(ctx, []byte(`{"reliability": true, "uptime": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMS12(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MS13_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (safety only, no tracking)", func(t *testing.T) {
		r, err := m.checkMS13(ctx, []byte(`{"safety": true, "safety_metric": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMS13(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MS24_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (security only, no tracking)", func(t *testing.T) {
		r, err := m.checkMS24(ctx, []byte(`{"security": true, "security_metric": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMS24(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MS25_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (privacy only, no tracking)", func(t *testing.T) {
		r, err := m.checkMS25(ctx, []byte(`{"privacy": true, "pii": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMS25(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MS26_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (fairness only, no tracking)", func(t *testing.T) {
		r, err := m.checkMS26(ctx, []byte(`{"fairness": true, "bias": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMS26(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

// ---------------------------------------------------------------------------
// MANAGE (MG) — 62.5% functions
// ---------------------------------------------------------------------------

func TestGap_MG23_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (ir_plan only, no testing)", func(t *testing.T) {
		r, err := m.checkMG23(ctx, []byte(`{"incident_response": true, "ir_plan": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMG23(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MG33_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (lessons_learned only, no org)", func(t *testing.T) {
		r, err := m.checkMG33(ctx, []byte(`{"lessons_learned": true, "shared": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMG33(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_MG41_PartialAndNonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("partial (docs only, no maintained)", func(t *testing.T) {
		r, err := m.checkMG41(ctx, []byte(`{"documentation": true, "model_card": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "partial" {
			t.Errorf("status=%s, want partial, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (empty)", func(t *testing.T) {
		r, err := m.checkMG41(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

// ---------------------------------------------------------------------------
// Promoted CheckFunc implementations — 80% and 45.5% functions
// ---------------------------------------------------------------------------

func TestGap_AIBusinessRisk_AllPaths(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	t.Run("compliant (both value and risk)", func(t *testing.T) {
		r, err := m.checkAIBusinessRisk(ctx, []byte(`{"ai_business_value": true, "ai_risk_documented": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "compliant" {
			t.Errorf("status=%s, want compliant, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (value only, no risk)", func(t *testing.T) {
		r, err := m.checkAIBusinessRisk(ctx, []byte(`{"ai_business_value": true, "business_value": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (risk only, no value)", func(t *testing.T) {
		r, err := m.checkAIBusinessRisk(ctx, []byte(`{"ai_risk_documented": true, "risk_documented": true}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})

	t.Run("non_compliant (neither)", func(t *testing.T) {
		r, err := m.checkAIBusinessRisk(ctx, []byte(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Status) != "non_compliant" {
			t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap_AccountabilityMetrics_NonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	r, err := m.checkAccountabilityMetrics(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
	}
}

func TestGap_TransparencyMetrics_NonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	r, err := m.checkTransparencyMetrics(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
	}
}

func TestGap_AIRiskPrioritization_NonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	r, err := m.checkAIRiskPrioritization(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
	}
}

func TestGap_AIRiskTreatment_NonCompliant(t *testing.T) {
	m := NewNISTAIRMFModule()
	ctx := context.Background()

	r, err := m.checkAIRiskTreatment(ctx, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Status) != "non_compliant" {
		t.Errorf("status=%s, want non_compliant, msg=%s", r.Status, r.Message)
	}
}
