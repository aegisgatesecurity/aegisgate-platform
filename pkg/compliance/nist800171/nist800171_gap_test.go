// SPDX-License-Identifier: Apache-2.0
// Coverage gap tests for NIST 800-171 compliance module.

package nist800171

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// =====================================================================
// 0% functions: checkResourcePriority, checkCollaborativeComputing,
// checkMobileCode — three-condition checks
// =====================================================================

func TestGapCheckResourcePriority(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant: all three conditions.
	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkResourcePriority(ctx, []byte("resource_priority protection enforcement"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SC-6" {
			t.Errorf("ControlID = %q, want NIST800171-SC-6", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant: none present.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkResourcePriority(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Partial: only priority, missing protection + enforcement.
	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkResourcePriority(ctx, []byte("qos"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGapCheckCollaborativeComputing(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkCollaborativeComputing(ctx, []byte("collaborative_computing authentication access_control"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SC-15" {
			t.Errorf("ControlID = %q, want NIST800171-SC-15", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkCollaborativeComputing(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkCollaborativeComputing(ctx, []byte("session_collaboration"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

func TestGapCheckMobileCode(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkMobileCode(ctx, []byte("mobile_code policy enforcement"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SC-18" {
			t.Errorf("ControlID = %q, want NIST800171-SC-18", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkMobileCode(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkMobileCode(ctx, []byte("code_execution"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

// =====================================================================
// 50% functions: checkAuditReduction, checkSystemMonitoring,
// checkRiskMonitoring, checkSecurityAssessments, checkMediaTransport
// =====================================================================

func TestGapCheckAuditReduction(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant via search + reporting.
	t.Run("CompliantSearchReport", func(t *testing.T) {
		r, err := m.checkAuditReduction(ctx, []byte("audit_search report"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-AU-7" {
			t.Errorf("ControlID = %q, want NIST800171-AU-7", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via aggregation + reporting (second path).
	t.Run("CompliantAggregationReport", func(t *testing.T) {
		r, err := m.checkAuditReduction(ctx, []byte("log_aggregation dashboard"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant: nothing present.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkAuditReduction(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	// Partial: has search but no reporting.
	t.Run("PartialSearchOnly", func(t *testing.T) {
		r, err := m.checkAuditReduction(ctx, []byte("query"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

func TestGapCheckSystemMonitoring(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant via monitoring + alerting.
	t.Run("CompliantMonitoringAlert", func(t *testing.T) {
		r, err := m.checkSystemMonitoring(ctx, []byte("monitoring alert"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SI-4" {
			t.Errorf("ControlID = %q, want NIST800171-SI-4", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via IDS + alerting (second path).
	t.Run("CompliantIDSAlert", func(t *testing.T) {
		r, err := m.checkSystemMonitoring(ctx, []byte("ids notification"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant: nothing present.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkSystemMonitoring(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	// Partial: has monitoring but no alerting.
	t.Run("PartialMonitoringOnly", func(t *testing.T) {
		r, err := m.checkSystemMonitoring(ctx, []byte("siem"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

func TestGapCheckRiskMonitoring(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant via monitoring + assessment.
	t.Run("CompliantMonitoringAssessment", func(t *testing.T) {
		r, err := m.checkRiskMonitoring(ctx, []byte("risk_monitoring assessment"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-RA-4" {
			t.Errorf("ControlID = %q, want NIST800171-RA-4", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via monitoring + tracking (second path).
	t.Run("CompliantMonitoringTracking", func(t *testing.T) {
		r, err := m.checkRiskMonitoring(ctx, []byte("continuous_monitoring risk_register"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkRiskMonitoring(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	// Partial: has monitoring but no assessment or tracking.
	t.Run("PartialMonitoringOnly", func(t *testing.T) {
		r, err := m.checkRiskMonitoring(ctx, []byte("monitoring"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

func TestGapCheckSecurityAssessments(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant via assessment + schedule.
	t.Run("CompliantAssessmentSchedule", func(t *testing.T) {
		r, err := m.checkSecurityAssessments(ctx, []byte("assessment schedule"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SA-2" {
			t.Errorf("ControlID = %q, want NIST800171-SA-2", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via assessment + results (second path).
	t.Run("CompliantAssessmentResults", func(t *testing.T) {
		r, err := m.checkSecurityAssessments(ctx, []byte("security_assessment findings"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkSecurityAssessments(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	// Partial: has assessment but no schedule or results.
	t.Run("PartialAssessmentOnly", func(t *testing.T) {
		r, err := m.checkSecurityAssessments(ctx, []byte("audit"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

func TestGapCheckMediaTransport(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant via encryption + chain_of_custody.
	t.Run("CompliantEncryptionCustody", func(t *testing.T) {
		r, err := m.checkMediaTransport(ctx, []byte("encryption chain_of_custody"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-MP-5" {
			t.Errorf("ControlID = %q, want NIST800171-MP-5", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via encryption + transport (second path).
	t.Run("CompliantEncryptionTransport", func(t *testing.T) {
		r, err := m.checkMediaTransport(ctx, []byte("encrypted media_transport"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	// Non-compliant.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkMediaTransport(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})

	// Partial: has encryption but no custody or transport.
	t.Run("PartialEncryptionOnly", func(t *testing.T) {
		r, err := m.checkMediaTransport(ctx, []byte("tls"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}

// =====================================================================
// 80% function: checkTransmissionIntegrity
// =====================================================================

func TestGapCheckTransmissionIntegrity(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	// Compliant via integrity check only.
	t.Run("CompliantIntegrity", func(t *testing.T) {
		r, err := m.checkTransmissionIntegrity(ctx, []byte("integrity_check"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SC-9" {
			t.Errorf("ControlID = %q, want NIST800171-SC-9", r.ControlID)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via TLS only.
	t.Run("CompliantTLS", func(t *testing.T) {
		r, err := m.checkTransmissionIntegrity(ctx, []byte("tls"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Compliant via digital signing only.
	t.Run("CompliantSigning", func(t *testing.T) {
		r, err := m.checkTransmissionIntegrity(ctx, []byte("digital_signature"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusCompliant {
			t.Errorf("Status = %q, want compliant", r.Status)
		}
	})

	// Non-compliant: nothing present.
	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkTransmissionIntegrity(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != compliance.StatusNonCompliant {
			t.Errorf("Status = %q, want non_compliant", r.Status)
		}
	})
}
