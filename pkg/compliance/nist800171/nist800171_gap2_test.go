// SPDX-License-Identifier: Apache-2.0
// Coverage gap tests (round 2) for NIST 800-171 compliance module.
// Targets functions below 100% to push coverage from 82.1% to 90%+.

package nist800171

import (
	"context"
	"testing"
)

// =====================================================================
// ac.go: checkInformationFlowEnforcement, checkSeparationOfDuties,
// checkExternalSystems — three-condition checks at 42.9%
// =====================================================================

func TestGap2InformationFlowEnforcement(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkInformationFlowEnforcement(ctx, []byte("information_flow flow_policy enforcement"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-AC-4" {
			t.Errorf("ControlID = %q, want NIST800171-AC-4", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkInformationFlowEnforcement(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SeparationOfDuties(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSeparationOfDuties(ctx, []byte("separation_of_duties rbac dual_approval"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-AC-5" {
			t.Errorf("ControlID = %q, want NIST800171-AC-5", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkSeparationOfDuties(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2ExternalSystems(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkExternalSystems(ctx, []byte("external_systems restriction audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-AC-20" {
			t.Errorf("ControlID = %q, want NIST800171-AC-20", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkExternalSystems(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// additional_controls.go: multiple functions with partial/compliant
// paths missing
// =====================================================================

func TestGap2UnsuccessfulLoginAttempts(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkUnsuccessfulLoginAttempts(ctx, []byte("lockout login_policy"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkUnsuccessfulLoginAttempts(ctx, []byte("account_lockout"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SystemUseNotification(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSystemUseNotification(ctx, []byte("login_banner consent"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantConsentOnly", func(t *testing.T) {
		r, err := m.checkSystemUseNotification(ctx, []byte("acceptable_use"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2PreviousLogonNotification(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkPreviousLogonNotification(ctx, []byte("logon_history"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkPreviousLogonNotification(ctx, []byte("login_notification"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2ConcurrentSessionControl(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkConcurrentSessionControl(ctx, []byte("max_sessions"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkConcurrentSessionControl(ctx, []byte("session_control"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SessionLock(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSessionLock(ctx, []byte("idle_timeout reauth"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkSessionLock(ctx, []byte("session_timeout"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkSessionLock(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SessionTermination(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSessionTermination(ctx, []byte("session_timeout"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantTermination", func(t *testing.T) {
		r, err := m.checkSessionTermination(ctx, []byte("session_termination"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2AuditStorageCapacity(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkAuditStorageCapacity(ctx, []byte("audit_capacity capacity_alert"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkAuditStorageCapacity(ctx, []byte("storage_capacity"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2AuditProcessingFailures(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkAuditProcessingFailures(ctx, []byte("audit_failure failover"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkAuditProcessingFailures(ctx, []byte("failure_alert"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkAuditProcessingFailures(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2Timestamps(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkTimestamps(ctx, []byte("ntp timestamp"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkTimestamps(ctx, []byte("time_sync"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2ChangeControlImplementation(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkChangeControlImplementation(ctx, []byte("change_control testing"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantRollback", func(t *testing.T) {
		r, err := m.checkChangeControlImplementation(ctx, []byte("approval rollback"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2LeastFunctionality(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkLeastFunctionality(ctx, []byte("minimal unnecessary_disabled"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkLeastFunctionality(ctx, []byte("hardening"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SystemComponentInventory(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSystemComponentInventory(ctx, []byte("inventory verification"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkSystemComponentInventory(ctx, []byte("sbom"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SecurityAlerts(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSecurityAlerts(ctx, []byte("advisory response"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkSecurityAlerts(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SoftwareIntegrity(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSoftwareIntegrity(ctx, []byte("integrity_check verification"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkSoftwareIntegrity(ctx, []byte("hash"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2IdentifierManagement(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkIdentifierManagement(ctx, []byte("unique_id deactivation"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkIdentifierManagement(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2PasswordConstraints(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkPasswordConstraints(ctx, []byte("password_policy min_length"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkPasswordConstraints(ctx, []byte("password"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2CryptoModuleAuth(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("CompliantFIPSAndModule", func(t *testing.T) {
		r, err := m.checkCryptoModuleAuth(ctx, []byte("fips_140 crypto_module"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantFIPSOnly", func(t *testing.T) {
		r, err := m.checkCryptoModuleAuth(ctx, []byte("fips mode"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkCryptoModuleAuth(ctx, []byte("encryption"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkCryptoModuleAuth(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2IncidentResponseAssistance(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkIncidentResponseAssistance(ctx, []byte("help_desk tracking"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkIncidentResponseAssistance(ctx, []byte("playbook"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkIncidentResponseAssistance(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2DoSProtection(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkDoSProtection(ctx, []byte("rate_limit"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkDoSProtection(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2NetworkDisconnect(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkNetworkDisconnect(ctx, []byte("network_disconnect"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkNetworkDisconnect(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2TransmissionSecurity(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("CompliantE2EE", func(t *testing.T) {
		r, err := m.checkTransmissionSecurity(ctx, []byte("end_to_end_encryption"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantTLSAndEncryption", func(t *testing.T) {
		r, err := m.checkTransmissionSecurity(ctx, []byte("tls tls_1_2"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkTransmissionSecurity(ctx, []byte("tls"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2SecureNameResolution(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSecureNameResolution(ctx, []byte("dnssec"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkSecureNameResolution(ctx, []byte("dns_over_https"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2AlternateStorage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkAlternateStorage(ctx, []byte("backup geo_redundant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkAlternateStorage(ctx, []byte("data_backup"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2MaintenanceTools(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkMaintenanceTools(ctx, []byte("approved_tools audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkMaintenanceTools(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// at.go: checkRoleBasedTraining, checkTrainingRecords
// =====================================================================

func TestGap2RoleBasedTraining(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("CompliantRoles", func(t *testing.T) {
		r, err := m.checkRoleBasedTraining(ctx, []byte("role_training roles"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantTracking", func(t *testing.T) {
		r, err := m.checkRoleBasedTraining(ctx, []byte("specialized_training training_records"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2TrainingRecords(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkTrainingRecords(ctx, []byte("training_records audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkTrainingRecords(ctx, []byte("completion_records"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// au.go: checkAuditPolicy
// =====================================================================

func TestGap2AuditPolicy(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkAuditPolicy(ctx, []byte("audit_policy audit_log review"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-AU-1" {
			t.Errorf("ControlID = %q, want NIST800171-AU-1", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkAuditPolicy(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// cm_si.go: checkChangeControlImpl
// =====================================================================

func TestGap2ChangeControlImpl(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkChangeControlImpl(ctx, []byte("configuration_change review audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-CM-3" {
			t.Errorf("ControlID = %q, want NIST800171-CM-3", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkChangeControlImpl(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// cp_ma_sa.go: checkControlledMaintenance, checkAcquisitionProcess
// =====================================================================

func TestGap2ControlledMaintenance(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkControlledMaintenance(ctx, []byte("controlled_maintenance approval audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-MA-2" {
			t.Errorf("ControlID = %q, want NIST800171-MA-2", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkControlledMaintenance(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2AcquisitionProcess(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkAcquisitionProcess(ctx, []byte("acquisition_security policy review"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SA-4" {
			t.Errorf("ControlID = %q, want NIST800171-SA-4", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkAcquisitionProcess(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// ia.go: checkAuthenticatorFeedback, checkReAuthentication
// =====================================================================

func TestGap2AuthenticatorFeedback(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkAuthenticatorFeedback(ctx, []byte("authenticator_feedback authentication policy"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-IA-6" {
			t.Errorf("ControlID = %q, want NIST800171-IA-6", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkAuthenticatorFeedback(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2ReAuthentication(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkReAuthentication(ctx, []byte("re_authentication authentication session_timeout"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-IA-11" {
			t.Errorf("ControlID = %q, want NIST800171-IA-11", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkReAuthentication(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// ir_ra.go: checkRAPolicy, checkRiskAssessment, checkThreatIntel,
// checkIRPolicy, checkIRPlan
// =====================================================================

func TestGap2RAPolicy(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkRAPolicy(ctx, []byte("risk_assessment_policy scheduled risk_assessment"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-RA-1" {
			t.Errorf("ControlID = %q, want NIST800171-RA-1", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkRAPolicy(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2RiskAssessment(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkRiskAssessment(ctx, []byte("risk_assessment vulnerability tracking"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-RA-3" {
			t.Errorf("ControlID = %q, want NIST800171-RA-3", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkRiskAssessment(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2ThreatIntel(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkThreatIntel(ctx, []byte("threat_intel monitoring alerting"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-RA-7" {
			t.Errorf("ControlID = %q, want NIST800171-RA-7", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkThreatIntel(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2IRPolicy(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkIRPolicy(ctx, []byte("incident_response_policy incident_response procedures"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-IR-1" {
			t.Errorf("ControlID = %q, want NIST800171-IR-1", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkIRPolicy(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2IRPlan(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkIRPlan(ctx, []byte("incident_response_plan procedures roles"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-IR-8" {
			t.Errorf("ControlID = %q, want NIST800171-IR-8", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkIRPlan(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// mp.go: checkMediaAccess, checkMediaStorage, checkMediaSanitization
// =====================================================================

func TestGap2MediaAccess(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("CompliantAccessControl", func(t *testing.T) {
		r, err := m.checkMediaAccess(ctx, []byte("media_access audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-MP-2" {
			t.Errorf("ControlID = %q, want NIST800171-MP-2", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantRestriction", func(t *testing.T) {
		r, err := m.checkMediaAccess(ctx, []byte("restricted logging"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkMediaAccess(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2MediaStorage(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkMediaStorage(ctx, []byte("encryption_at_rest media_storage"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-MP-4" {
			t.Errorf("ControlID = %q, want NIST800171-MP-4", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkMediaStorage(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2MediaSanitization(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkMediaSanitization(ctx, []byte("sanitization verification"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkMediaSanitization(ctx, []byte("wipe disposal_policy"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// pe.go: checkPhysicalAccessAuthorization
// =====================================================================

func TestGap2PhysicalAccessAuthorization(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("CompliantRBAC", func(t *testing.T) {
		r, err := m.checkPhysicalAccessAuthorization(ctx, []byte("access_list rbac"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-PE-2" {
			t.Errorf("ControlID = %q, want NIST800171-PE-2", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantLogging", func(t *testing.T) {
		r, err := m.checkPhysicalAccessAuthorization(ctx, []byte("authorized_personnel audit_log"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// ps.go: checkPersonnelScreening, checkPersonnelTermination
// =====================================================================

func TestGap2PersonnelScreening(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkPersonnelScreening(ctx, []byte("background_check verification"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-PS-2" {
			t.Errorf("ControlID = %q, want NIST800171-PS-2", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkPersonnelScreening(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

func TestGap2PersonnelTermination(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkPersonnelTermination(ctx, []byte("termination access_revocation"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-PS-3" {
			t.Errorf("ControlID = %q, want NIST800171-PS-3", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("Partial", func(t *testing.T) {
		r, err := m.checkPersonnelTermination(ctx, []byte("offboarding logging"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "partial" {
			t.Errorf("Status = %q, want partial; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// sa.go: checkContinuousMonitoring
// =====================================================================

func TestGap2ContinuousMonitoring(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("CompliantScanning", func(t *testing.T) {
		r, err := m.checkContinuousMonitoring(ctx, []byte("continuous_monitoring vulnerability"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SA-3" {
			t.Errorf("ControlID = %q, want NIST800171-SA-3", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("CompliantAlerting", func(t *testing.T) {
		r, err := m.checkContinuousMonitoring(ctx, []byte("monitoring alert"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkContinuousMonitoring(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}

// =====================================================================
// sc.go: checkSessionAuthenticity
// =====================================================================

func TestGap2SessionAuthenticity(t *testing.T) {
	m := NewNIST800171Module()
	ctx := context.Background()

	t.Run("Compliant", func(t *testing.T) {
		r, err := m.checkSessionAuthenticity(ctx, []byte("session_authenticity authentication tls"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.ControlID != "NIST800171-SC-23" {
			t.Errorf("ControlID = %q, want NIST800171-SC-23", r.ControlID)
		}
		if r.Status != "compliant" {
			t.Errorf("Status = %q, want compliant; msg=%s", r.Status, r.Message)
		}
	})

	t.Run("NonCompliant", func(t *testing.T) {
		r, err := m.checkSessionAuthenticity(ctx, []byte("nothing_relevant"))
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if r.Status != "non_compliant" {
			t.Errorf("Status = %q, want non_compliant; msg=%s", r.Status, r.Message)
		}
	})
}
