// SPDX-License-Identifier: Apache-2.0
// SOC 2 Type II Compliance Module v2.0 - Unit Tests
//
// Test coverage for the 64-control SOC 2 module (32 automated, 32 manual).
// Tests verify module metadata, control registration, automated check
// functions, and framework-level operations (CheckAll, CheckControl,
// GenerateAssessment, Dependencies, Provides).

package soc2

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSOC2Module verifies module construction and metadata.
func TestNewSOC2Module(t *testing.T) {
	m := NewSOC2Module()
	require.NotNil(t, m, "NewSOC2Module returned nil")

	assert.Equal(t, "soc2", m.Framework(), "Framework() mismatch")
	assert.Equal(t, "2.0", m.Version(), "Version() mismatch")

	// Verify pattern caches initialized
	require.NotNil(t, m.piiPatterns, "piiPatterns should be initialized")
	require.NotEmpty(t, m.piiPatterns, "piiPatterns should not be empty")
	require.NotNil(t, m.mTLSConfigPatterns, "mTLSConfigPatterns should be initialized")
	require.NotEmpty(t, m.mTLSConfigPatterns, "mTLSConfigPatterns should not be empty")
	require.NotNil(t, m.auditLogPatterns, "auditLogPatterns should be initialized")
	require.NotEmpty(t, m.auditLogPatterns, "auditLogPatterns should not be empty")
}

// TestSOC2ModuleControls verifies all 64 controls are registered with
// the expected automated/manual split.
func TestSOC2ModuleControls(t *testing.T) {
	m := NewSOC2Module()
	controls := m.Controls()

	require.Len(t, controls, 64, "expected 64 controls")

	var automated, manual int
	for _, c := range controls {
		assert.NotEmpty(t, c.ID, "control ID should not be empty")
		assert.NotEmpty(t, c.Name, "control Name should not be empty for %s", c.ID)
		if c.Automated {
			automated++
		} else {
			manual++
		}
	}

	assert.Equal(t, 32, automated, "expected 32 automated controls")
	assert.Equal(t, 32, manual, "expected 32 manual controls")
}

// TestSOC2CheckAll verifies CheckAll runs all automated checks without error.
func TestSOC2CheckAll(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("ValidInput", func(t *testing.T) {
		input := []byte("training competency risk_assessment authentication rbac session_timeout audit_log")
		results, err := m.CheckAll(ctx, input)
		require.NoError(t, err)
		assert.NotEmpty(t, results, "CheckAll should return results for valid input")
	})

	t.Run("EmptyInput", func(t *testing.T) {
		results, err := m.CheckAll(ctx, []byte{})
		require.NoError(t, err)
		assert.NotEmpty(t, results, "CheckAll should return results even for empty input")
	})
}

// TestCompetenceCheck tests CC1.4 competence check.
func TestCompetenceCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("training competency skills_assessment")
		result, err := m.CheckControl(ctx, "SOC2-CC1.4", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-CC1.4", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// TestRiskAssessCheck tests CC3.1 risk assessment check.
func TestRiskAssessCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("risk_assessment risk_analysis threat_modeling")
		result, err := m.CheckControl(ctx, "SOC2-CC3.1", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-CC3.1", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// TestFraudRiskCheck tests CC3.2 fraud risk check.
func TestFraudRiskCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("fraud_detection fraud_risk anti_fraud")
		result, err := m.CheckControl(ctx, "SOC2-CC3.2", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-CC3.2", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// TestLogicalAccessCheck tests CC6.1 logical access check.
func TestLogicalAccessCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("authentication rbac session_timeout")
	result, err := m.CheckControl(ctx, "SOC2-CC6.1", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestUserRegistrationCheck tests CC6.2 user registration check.
func TestUserRegistrationCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("user_registration user_provisioning de-registration account_lifecycle")
	result, err := m.CheckControl(ctx, "SOC2-CC6.2", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestLeastPrivilegeCheck tests CC6.5 least privilege check.
// Note: CC6.5 is registered as a manual control (Automated: false),
// so CheckControl returns StatusNotApplicable for any input.
func TestLeastPrivilegeCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("ReturnsResult", func(t *testing.T) {
		input := []byte("least_privilege minimum_access")
		result, err := m.CheckControl(ctx, "SOC2-CC6.5", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		// CC6.5 is a manual control — CheckFunc is nil, so it returns NotApplicable
		assert.Equal(t, compliance.StatusNotApplicable, result.Status)
	})

	t.Run("NonCompliantInput", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-CC6.5", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNotApplicable, result.Status)
	})
}

// TestIncidentDetectionCheck tests CC7.2 incident detection check.
func TestIncidentDetectionCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("audit_log ioc_store anomaly alerting")
	result, err := m.CheckControl(ctx, "SOC2-CC7.2", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestEventEvaluationCheck tests CC7.3 event evaluation check.
func TestEventEvaluationCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("audit_log ioc_store attestation investigation")
	result, err := m.CheckControl(ctx, "SOC2-CC7.3", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestIncidentResponsePlanCheck tests CC7.4 incident response plan check.
func TestIncidentResponsePlanCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("incident_response_plan ir_tested ir_roles ir_communication")
	result, err := m.CheckControl(ctx, "SOC2-CC7.4", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestChangeManagementCheck tests CC8.1 change management check.
func TestChangeManagementCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("change_management change_control change_approval")
		result, err := m.CheckControl(ctx, "SOC2-CC8.1", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-CC8.1", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// TestVendorRiskCheck tests CC9.1 vendor risk check.
func TestVendorRiskCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("vendor_risk third_party_risk supplier_assessment")
		result, err := m.CheckControl(ctx, "SOC2-CC9.1", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-CC9.1", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// TestConfidentialityControlsCheck tests C1.2 confidentiality controls check.
func TestConfidentialityControlsCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("confidentiality data_classification need_to_know")
		result, err := m.CheckControl(ctx, "SOC2-C1.2", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "SOC2-C1.2", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// TestProcessingErrorsCheck tests PI1.2 processing errors check.
func TestProcessingErrorsCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("processing_error error_detection data_validation error_correction")
	result, err := m.CheckControl(ctx, "SOC2-PI1.2", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestAIModelSecurityCheck tests AI-01 AI model security check.
func TestAIModelSecurityCheck(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("model_security adversarial_defense model_robustness prompt_injection_defense")
	result, err := m.CheckControl(ctx, "SOC2-AI-01", input)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.ControlID)
}

// TestDependencies verifies the module's dependency list.
func TestDependencies(t *testing.T) {
	m := NewSOC2Module()
	deps := m.Dependencies()

	assert.Contains(t, deps, "scanner")
	assert.Contains(t, deps, "persistence")
	assert.Len(t, deps, 2)
}

// TestCheckControl tests CheckControl for existing and non-existent controls.
func TestCheckControl(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	t.Run("ExistingControl", func(t *testing.T) {
		result, err := m.CheckControl(ctx, "SOC2-CC1.4", []byte("training competency skills_assessment"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "SOC2-CC1.4", result.ControlID)
	})

	t.Run("NonExistentControl", func(t *testing.T) {
		result, err := m.CheckControl(ctx, "SOC2-NONEXISTENT", []byte("test"))
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

// TestGenerateAssessment verifies GenerateAssessment produces a report.
func TestGenerateAssessment(t *testing.T) {
	m := NewSOC2Module()
	ctx := context.Background()

	input := []byte("training competency risk_assessment authentication rbac session_timeout audit_log")
	assessment, err := m.GenerateAssessment(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, assessment)
	assert.Equal(t, "soc2", assessment.Framework)
	assert.Equal(t, "2.0", assessment.Version)
	assert.NotEmpty(t, assessment.Results)
}

// TestModuleProvisions verifies Provides returns non-empty capabilities.
func TestModuleProvisions(t *testing.T) {
	m := NewSOC2Module()
	provides := m.Provides()
	assert.NotEmpty(t, provides)
	assert.Contains(t, provides, "compliance")
	assert.Contains(t, provides, "soc2_compliance")
}
