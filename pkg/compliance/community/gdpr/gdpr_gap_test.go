// SPDX-License-Identifier: Apache-2.0
// GDPR coverage gap tests — tests compliant paths for 80% functions

package gdpr

import (
	"context"
	"testing"
)

func TestCheckConsentConditions_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkConsentConditions(context.Background(), []byte(`{"opt-in": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "GDPR-Art7" {
		t.Errorf("ControlID = %q, want GDPR-Art7", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckSpecialCategories_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkSpecialCategories(context.Background(), []byte(`{"health": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "GDPR-Art9" {
		t.Errorf("ControlID = %q, want GDPR-Art9", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckDataCollectionNotices_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkDataCollectionNotices(context.Background(), []byte(`{"data_collection": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAutomatedDecisionMaking_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkAutomatedDecisionMaking(context.Background(), []byte(`{"automated_decision": true, "human_review": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckDataProtectionByDesign_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkDataProtectionByDesign(context.Background(), []byte(`{"privacy_by_design": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckChildConsent_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkChildConsent(context.Background(), []byte(`{"child_consent": true, "age_verification": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckCriminalConvictionData_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkCriminalConvictionData(context.Background(), []byte(`{"criminal_data": true, "safeguards": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAnonymization_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkAnonymization(context.Background(), []byte(`{"anonymization": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "GDPR-Art11" {
		t.Errorf("ControlID = %q, want GDPR-Art11", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckDataSourceNotices_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkDataSourceNotices(context.Background(), []byte(`{"data_source": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckRightOfAccess_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkRightOfAccess(context.Background(), []byte(`{"access_request": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckRightToRectification_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkRightToRectification(context.Background(), []byte(`{"rectification": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckRightToErasure_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkRightToErasure(context.Background(), []byte(`{"erasure": true, "right_to_be_forgotten": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckRightToRestriction_Compliant(t *testing.T) {
	m := NewGDPRModule()
	r, err := m.checkRightToRestriction(context.Background(), []byte(`{"processing_restriction": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}
