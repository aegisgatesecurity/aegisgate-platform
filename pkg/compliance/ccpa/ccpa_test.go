// SPDX-License-Identifier: Apache-2.0

package ccpa

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// 1. TestNewCCPAModule
// ---------------------------------------------------------------------------

func TestNewCCPAModule(t *testing.T) {
	m := NewCCPAModule()

	t.Run("FrameworkIsCCPA", func(t *testing.T) {
		assert.Equal(t, "ccpa", m.Framework())
	})

	t.Run("VersionIs20", func(t *testing.T) {
		assert.Equal(t, "2.0", m.Version())
	})

	t.Run("PatternCachesInitialized", func(t *testing.T) {
		assert.NotEmpty(t, m.privacyPatterns, "privacyPatterns should be initialized")
		assert.NotEmpty(t, m.consentPatterns, "consentPatterns should be initialized")
		assert.NotEmpty(t, m.deletionPatterns, "deletionPatterns should be initialized")
	})
}

// ---------------------------------------------------------------------------
// 2. TestCCPAModuleControls
// ---------------------------------------------------------------------------

func TestCCPAModuleControls(t *testing.T) {
	m := NewCCPAModule()
	controls := m.Controls()

	t.Run("ControlCountIs26", func(t *testing.T) {
		assert.Len(t, controls, 26, "expected 26 controls registered")
	})

	t.Run("AllControlsHaveIDAndName", func(t *testing.T) {
		for _, c := range controls {
			assert.NotEmpty(t, c.ID, "control ID should not be empty")
			assert.NotEmpty(t, c.Name, "control Name should not be empty")
		}
	})

	t.Run("AutomatedCountIs14", func(t *testing.T) {
		automated := 0
		for _, c := range controls {
			if c.Automated {
				automated++
			}
		}
		assert.Equal(t, 14, automated, "expected 14 automated controls")
	})

	t.Run("ManualCountIs12", func(t *testing.T) {
		manual := 0
		for _, c := range controls {
			if !c.Automated {
				manual++
			}
		}
		assert.Equal(t, 12, manual, "expected 12 manual controls")
	})

	t.Run("AllExpectedControlIDsPresent", func(t *testing.T) {
		expected := []string{
			"CCPA-CR-01", "CCPA-CR-02", "CCPA-CR-03", "CCPA-CR-04",
			"CCPA-CR-05", "CCPA-CR-06", "CCPA-CR-07", "CCPA-CR-08",
			"CCPA-OS-01", "CCPA-OS-02", "CCPA-OS-03", "CCPA-OS-04",
			"CCPA-OS-05", "CCPA-OS-06",
			"CCPA-PR-01", "CCPA-PR-02", "CCPA-PR-03", "CCPA-PR-04",
			"CCPA-DH-01", "CCPA-DH-02", "CCPA-DH-03", "CCPA-DH-04",
			"CCPA-CE-01", "CCPA-CE-02", "CCPA-CE-03", "CCPA-CE-04",
		}
		ids := make(map[string]bool, len(controls))
		for _, c := range controls {
			ids[c.ID] = true
		}
		for _, id := range expected {
			assert.True(t, ids[id], "expected control ID %s to be present", id)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. TestCCPACheckAll
// ---------------------------------------------------------------------------

func TestCCPACheckAll(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("ValidInput", func(t *testing.T) {
		input := []byte("privacy_policy data_collection right_to_know opt_out do_not_sell deletion consumer_rights")
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

// ---------------------------------------------------------------------------
// 4. TestRightToKnowCheck (CR-01)
// ---------------------------------------------------------------------------

func TestRightToKnowCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("privacy_policy data_collection right_to_know consumer_rights")
		result, err := m.CheckControl(ctx, "CCPA-CR-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-CR-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 5. TestRightToDeleteCheck (CR-05)
// ---------------------------------------------------------------------------

func TestRightToDeleteCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("right_to_delete deletion data_deletion deletion_process consumer_rights")
		result, err := m.CheckControl(ctx, "CCPA-CR-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-CR-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 6. TestRightToOptOutCheck (OS-01)
// ---------------------------------------------------------------------------

func TestRightToOptOutCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("opt_out do_not_sell consumer_rights consent")
		result, err := m.CheckControl(ctx, "CCPA-OS-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-OS-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 7. TestDoNotSellLinkCheck (OS-02)
// ---------------------------------------------------------------------------

func TestDoNotSellLinkCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("do_not_sell homepage opt_out_link")
		result, err := m.CheckControl(ctx, "CCPA-OS-02", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-OS-02", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 8. TestNonDiscriminationCheck (PR-01)
// ---------------------------------------------------------------------------

func TestNonDiscriminationCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("non_discrimination equal_service privacy_policy consumer_rights")
		result, err := m.CheckControl(ctx, "CCPA-PR-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-PR-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 9. TestBreachNotificationCheck (CE-01)
// ---------------------------------------------------------------------------

func TestBreachNotificationCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("breach_notification data_breach breach_response incident_response")
		result, err := m.CheckControl(ctx, "CCPA-CE-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-CE-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 10. TestRequestTimeframeCheck (CE-03)
// ---------------------------------------------------------------------------

func TestRequestTimeframeCheck(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("request_response_time 45_days consumer_request request_handling")
		result, err := m.CheckControl(ctx, "CCPA-CE-03", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "CCPA-CE-03", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// 11. TestDependencies
// ---------------------------------------------------------------------------

func TestDependencies(t *testing.T) {
	m := NewCCPAModule()
	deps := m.Dependencies()

	expected := []string{"gdpr", "soc2", "ioc", "trust"}
	assert.ElementsMatch(t, expected, deps)
}

// ---------------------------------------------------------------------------
// 12. TestCheckControl
// ---------------------------------------------------------------------------

func TestCheckControl(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	t.Run("ExistingControl", func(t *testing.T) {
		result, err := m.CheckControl(ctx, "CCPA-CR-01", []byte("privacy_policy data_collection right_to_know"))
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "CCPA-CR-01", result.ControlID)
	})

	t.Run("NonExistentControl", func(t *testing.T) {
		result, err := m.CheckControl(ctx, "CCPA-XX-99", []byte("test"))
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

// ---------------------------------------------------------------------------
// 13. TestGenerateAssessment
// ---------------------------------------------------------------------------

func TestGenerateAssessment(t *testing.T) {
	m := NewCCPAModule()
	ctx := context.Background()

	input := []byte("privacy_policy data_collection right_to_know opt_out do_not_sell deletion consumer_rights")

	assessment, err := m.GenerateAssessment(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, assessment)
	assert.Equal(t, "ccpa", assessment.Framework)
	assert.Equal(t, "2.0", assessment.Version)
	assert.NotEmpty(t, assessment.Results)
	assert.Equal(t, len(assessment.Results), assessment.Summary.Total)
}

// ---------------------------------------------------------------------------
// 14. TestModuleProvisions
// ---------------------------------------------------------------------------

func TestModuleProvisions(t *testing.T) {
	m := NewCCPAModule()
	provides := m.Provides()
	assert.NotEmpty(t, provides, "Provides() should return non-empty list")
}
