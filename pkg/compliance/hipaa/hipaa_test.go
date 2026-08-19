// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - HIPAA Compliance Module Tests
// =========================================================================
//
// Tests for the HIPAA Security Rule compliance module (54 controls, 24
// automated). Covers module creation, control registration, PHI detection,
// and all 24 automated CheckFunc implementations.
//
// Reference: HIPAA Security Rule, 45 CFR Part 164, Subpart C
// =========================================================================

package hipaa

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Module creation & metadata
// ---------------------------------------------------------------------------

func TestNewHIPAAModule(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)

	t.Run("Framework", func(t *testing.T) {
		assert.Equal(t, "hipaa", m.Framework())
	})

	t.Run("Version", func(t *testing.T) {
		assert.Equal(t, "2.2", m.Version())
	})

	t.Run("PHIPatternsInitialized", func(t *testing.T) {
		assert.NotEmpty(t, m.phiPatterns, "phiPatterns should be initialized")
	})
}

// ---------------------------------------------------------------------------
// Control registration
// ---------------------------------------------------------------------------

func TestHIPAAModuleControls(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)

	controls := m.Controls()

	t.Run("Has54Controls", func(t *testing.T) {
		assert.Equal(t, 54, len(controls), "expected 54 controls")
	})

	t.Run("AllControlsHaveIDAndName", func(t *testing.T) {
		for _, c := range controls {
			assert.NotEmpty(t, c.ID, "control should have non-empty ID")
			assert.NotEmpty(t, c.Name, "control %s should have non-empty Name", c.ID)
		}
	})

	t.Run("AllControlIDsInExpectedSet", func(t *testing.T) {
		expected := map[string]bool{
			// Security Standards
			"HIPAA-SS-01": true, "HIPAA-SS-02": true, "HIPAA-SS-03": true, "HIPAA-SS-04": true,
			// Administrative Safeguards
			"HIPAA-AS-01": true, "HIPAA-AS-02": true, "HIPAA-AS-03": true, "HIPAA-AS-04": true,
			"HIPAA-AS-05": true, "HIPAA-AS-06": true, "HIPAA-AS-07": true, "HIPAA-AS-08": true,
			"HIPAA-AS-09": true, "HIPAA-AS-10": true, "HIPAA-AS-11": true, "HIPAA-AS-12": true,
			"HIPAA-AS-13": true, "HIPAA-AS-14": true, "HIPAA-AS-15": true, "HIPAA-AS-16": true,
			"HIPAA-AS-17": true, "HIPAA-AS-18": true, "HIPAA-AS-19": true, "HIPAA-AS-20": true,
			"HIPAA-AS-21": true, "HIPAA-AS-22": true,
			// Physical Safeguards
			"HIPAA-PS-01": true, "HIPAA-PS-02": true, "HIPAA-PS-03": true, "HIPAA-PS-04": true,
			"HIPAA-PS-05": true, "HIPAA-PS-06": true, "HIPAA-PS-07": true, "HIPAA-PS-08": true,
			"HIPAA-PS-09": true, "HIPAA-PS-10": true,
			// Technical Safeguards
			"HIPAA-TS-01": true, "HIPAA-TS-02": true, "HIPAA-TS-03": true, "HIPAA-TS-04": true,
			"HIPAA-TS-05": true, "HIPAA-TS-06": true, "HIPAA-TS-07": true, "HIPAA-TS-08": true,
			"HIPAA-TS-09": true,
			// Organizational Requirements
			"HIPAA-OR-01": true, "HIPAA-OR-02": true,
			// Documentation Requirements
			"HIPAA-DR-01": true, "HIPAA-DR-02": true, "HIPAA-DR-03": true,
			// AI Controls
			"HIPAA-AI-01": true, "HIPAA-AI-02": true,
			// Breach Notification
			"HIPAA-BN-01": true, "HIPAA-BN-02": true,
		}

		assert.Equal(t, 54, len(expected), "expected set must contain 54 IDs")

		for _, c := range controls {
			assert.Contains(t, expected, c.ID, "unexpected control ID %s", c.ID)
		}
	})

	t.Run("AutomatedCount", func(t *testing.T) {
		automated := 0
		for _, c := range controls {
			if c.Automated {
				automated++
			}
		}
		assert.Equal(t, 24, automated, "expected 24 automated controls")
	})

	t.Run("ManualCount", func(t *testing.T) {
		manual := 0
		for _, c := range controls {
			if !c.Automated {
				manual++
			}
		}
		assert.Equal(t, 30, manual, "expected 30 manual controls")
	})
}

// ---------------------------------------------------------------------------
// CheckAll
// ---------------------------------------------------------------------------

func TestHIPAACheckAll(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("ValidInput", func(t *testing.T) {
		input := []byte(`risk_analysis risk_assessment risk_management risk_treatment`)
		results, err := m.CheckAll(ctx, input)
		require.NoError(t, err)
		assert.NotEmpty(t, results, "CheckAll should return results for valid input")
	})

	t.Run("EmptyInput", func(t *testing.T) {
		input := []byte("")
		results, err := m.CheckAll(ctx, input)
		require.NoError(t, err)
		assert.NotEmpty(t, results, "CheckAll should return results even for empty input")
	})
}

// ---------------------------------------------------------------------------
// PHI detection
// ---------------------------------------------------------------------------

func TestPHIDetection(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)

	t.Run("CleanContent", func(t *testing.T) {
		found := m.detectPHI("this is safe content with no phi patterns")
		assert.Empty(t, found, "clean content should not trigger PHI detection")
	})

	t.Run("SSNDetected", func(t *testing.T) {
		found := m.detectPHI("patient SSN is 123-45-6789")
		assert.NotEmpty(t, found, "SSN should trigger PHI detection")
	})

	t.Run("EmailDetected", func(t *testing.T) {
		found := m.detectPHI("contact: patient@example.com")
		assert.NotEmpty(t, found, "email should trigger PHI detection")
	})

	t.Run("PhoneDetected", func(t *testing.T) {
		found := m.detectPHI("call 555-123-4567 for records")
		assert.NotEmpty(t, found, "phone number should trigger PHI detection")
	})
}

// ---------------------------------------------------------------------------
// Administrative Safeguards — automated checks
// ---------------------------------------------------------------------------

func TestRiskAnalysisCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("risk_analysis risk_assessment")
		result, err := m.CheckControl(ctx, "HIPAA-AS-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no risk keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestRiskManagementCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("risk_management risk_treatment risk_mitigation")
		result, err := m.CheckControl(ctx, "HIPAA-AS-02", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no risk management keywords")
		result, err := m.CheckControl(ctx, "HIPAA-AS-02", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestLogInMonitoringCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("audit_log login_tracking anomaly alerting")
		result, err := m.CheckControl(ctx, "HIPAA-AS-04", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("Partial", func(t *testing.T) {
		input := []byte("audit_log login_tracking")
		result, err := m.CheckControl(ctx, "HIPAA-AS-04", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusPartial, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("nothing_here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-04", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestMaliciousSoftwareCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("antivirus anti-malware malware_protection endpoint_protection")
		result, err := m.CheckControl(ctx, "HIPAA-AS-12", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no malware protection keywords")
		result, err := m.CheckControl(ctx, "HIPAA-AS-12", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestPasswordManagementCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("password_policy password_complexity password_rotation password_management")
		result, err := m.CheckControl(ctx, "HIPAA-AS-14", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no password keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-14", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestSecurityIncidentCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("incident_response incident_procedure incident_handling")
		result, err := m.CheckControl(ctx, "HIPAA-AS-15", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no incident keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-15", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestDataBackupCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("backup_plan data_backup backup_strategy")
		result, err := m.CheckControl(ctx, "HIPAA-AS-16", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no backup keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-16", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestDisasterRecoveryCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("disaster_recovery recovery_plan dr_plan")
		result, err := m.CheckControl(ctx, "HIPAA-AS-17", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no dr keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-17", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestEmergencyModeCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("emergency_mode emergency_operations business_continuity")
		result, err := m.CheckControl(ctx, "HIPAA-AS-18", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no emergency keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-18", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestContingencyTestingCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("contingency_test disaster_recovery_test failover_test")
		result, err := m.CheckControl(ctx, "HIPAA-AS-19", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no testing keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-AS-19", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// Physical Safeguards — automated checks
// ---------------------------------------------------------------------------

func TestWorkstationUseCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("workstation_use workstation_policy workstation_standard")
		result, err := m.CheckControl(ctx, "HIPAA-PS-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no workstation use keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-PS-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestWorkstationSecurityCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("workstation_security workstation_lock screen_lock workstation_restriction")
		result, err := m.CheckControl(ctx, "HIPAA-PS-06", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no workstation security keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-PS-06", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestMediaDisposalCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("media_disposal data_destruction sanitization secure_disposal")
		result, err := m.CheckControl(ctx, "HIPAA-PS-07", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no disposal keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-PS-07", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestMediaReuseCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("media_reuse media_sanitization wipe_media")
		result, err := m.CheckControl(ctx, "HIPAA-PS-08", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no reuse keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-PS-08", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// Technical Safeguards — automated checks
// ---------------------------------------------------------------------------

func TestUniqueUserIDCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("unique_user_id unique_identification user_identification")
		result, err := m.CheckControl(ctx, "HIPAA-TS-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no user id keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-TS-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestAutoLogoffCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("auto_logoff session_timeout idle_timeout automatic_logoff")
		result, err := m.CheckControl(ctx, "HIPAA-TS-03", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no logoff keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-TS-03", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestEncryptionDecryptionCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("encryption decryption aes encrypt")
		result, err := m.CheckControl(ctx, "HIPAA-TS-04", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no_security_config")
		result, err := m.CheckControl(ctx, "HIPAA-TS-04", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestAuditControlsCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("audit_log log_integrity signed_logs")
		result, err := m.CheckControl(ctx, "HIPAA-TS-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("Partial", func(t *testing.T) {
		// Only audit_log is present, no integrity verification
		input := []byte("audit_log")
		result, err := m.CheckControl(ctx, "HIPAA-TS-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusPartial, result.Status)
	})

	t.Run("NoKeywordsReturnsPartial", func(t *testing.T) {
		// checkAuditControls always returns at least Partial (no NonCompliant path)
		input := []byte("no audit keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-TS-05", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusPartial, result.Status)
	})
}

func TestIntegrityControlsCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("CompliantWithHashing", func(t *testing.T) {
		input := []byte("hash checksum")
		result, err := m.CheckControl(ctx, "HIPAA-TS-06", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("CompliantWithSigning", func(t *testing.T) {
		input := []byte("signature sign")
		result, err := m.CheckControl(ctx, "HIPAA-TS-06", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no integrity keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-TS-06", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestAuthenticationCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("authentication auth_method mfa multi_factor")
		result, err := m.CheckControl(ctx, "HIPAA-TS-07", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no auth keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-TS-07", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestTransmissionIntegrityCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		input := []byte("tls integrity_check transmission_integrity hmac")
		result, err := m.CheckControl(ctx, "HIPAA-TS-08", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("no transmission integrity keywords here")
		result, err := m.CheckControl(ctx, "HIPAA-TS-08", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestTransmissionEncryptionCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("TLS13Compliant", func(t *testing.T) {
		input := []byte("tls1.3 https")
		result, err := m.CheckControl(ctx, "HIPAA-TS-09", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("TLSPartial", func(t *testing.T) {
		input := []byte("tls ssl")
		result, err := m.CheckControl(ctx, "HIPAA-TS-09", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusPartial, result.Status)
	})

	t.Run("NonCompliant", func(t *testing.T) {
		input := []byte("http_only")
		result, err := m.CheckControl(ctx, "HIPAA-TS-09", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// AI Controls — automated checks
// ---------------------------------------------------------------------------

func TestAIPHIProtectionCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("NoPHI", func(t *testing.T) {
		input := []byte("safe_ai_data with no phi")
		result, err := m.CheckControl(ctx, "HIPAA-AI-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("PHIDetected", func(t *testing.T) {
		input := []byte("patient SSN is 123-45-6789 in ai model")
		result, err := m.CheckControl(ctx, "HIPAA-AI-01", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

func TestAITrainingDataCheck(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("DeIdentified", func(t *testing.T) {
		input := []byte("de_identified anonymized training data")
		result, err := m.CheckControl(ctx, "HIPAA-AI-02", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusCompliant, result.Status)
	})

	t.Run("PHIInTrainingData", func(t *testing.T) {
		input := []byte("training data with patient@example.com email")
		result, err := m.CheckControl(ctx, "HIPAA-AI-02", input)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, compliance.StatusNonCompliant, result.Status)
	})
}

// ---------------------------------------------------------------------------
// Module-level tests
// ---------------------------------------------------------------------------

func TestDependencies(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)

	deps := m.Dependencies()
	assert.Contains(t, deps, "scanner")
}

func TestCheckControl(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	t.Run("ExistingControl", func(t *testing.T) {
		controls := m.Controls()
		require.NotEmpty(t, controls)
		firstID := controls[0].ID

		result, err := m.CheckControl(ctx, firstID, []byte("test input"))
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("NonExistentControl", func(t *testing.T) {
		result, err := m.CheckControl(ctx, "HIPAA-XX-99", []byte("test input"))
		require.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestGenerateAssessment(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)
	ctx := context.Background()

	input := []byte("risk_analysis risk_assessment encryption aes tls1.3 https")

	assessment, err := m.GenerateAssessment(ctx, input)
	require.NoError(t, err)
	require.NotNil(t, assessment)

	assert.Equal(t, "hipaa", assessment.Framework)
	assert.Equal(t, "2.2", assessment.Version)
	assert.NotEmpty(t, assessment.Results)
	assert.Greater(t, assessment.Summary.Total, 0)
}

func TestModuleProvisions(t *testing.T) {
	m := NewHIPAAModule()
	require.NotNil(t, m)

	provides := m.Provides()
	assert.NotEmpty(t, provides, "Provides() should return non-empty list")
}
