// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - FIPS 140 Coverage Gap Tests (Phase 2)
// =========================================================================
// Tests for the 18+ check functions at 0% coverage. Each 3-keyword
// function is tested across all three paths: compliant (>=2 found),
// partial (1 found), and non-compliant (0 found). Functions with
// 4 checks or a self-test component have adjusted expectations.
// =========================================================================

package fips

import (
	"context"
	"testing"
)

// =====================================================================
// checkInterfaceSeparation — FIPS-140-016
// =====================================================================

func TestCheckInterfaceSeparation_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"interface_separation": true, "data_port": "eth0", "control_port": "eth1"}`)
	r, err := m.checkInterfaceSeparation(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-016" {
		t.Errorf("ControlID = %q, want FIPS-140-016", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckInterfaceSeparation_Partial(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"interface_separation": true}`)
	r, err := m.checkInterfaceSeparation(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckInterfaceSeparation_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"description": "no interface config"}`)
	r, err := m.checkInterfaceSeparation(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkServiceAuth — FIPS-140-018
// =====================================================================

func TestCheckServiceAuth_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"role_based": true, "service_auth": "enabled", "authorized_role": "admin"}`)
	r, err := m.checkServiceAuth(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-018" {
		t.Errorf("ControlID = %q, want FIPS-140-018", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckServiceAuth_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkServiceAuth(context.Background(), []byte(`{"role based": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckServiceAuth_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkServiceAuth(context.Background(), []byte(`{"auth": "basic"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkIdentityAuth — FIPS-140-019
// =====================================================================

func TestCheckIdentityAuth_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"identity_auth": true, "operator_auth": "cert", "mfa": "required"}`)
	r, err := m.checkIdentityAuth(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-019" {
		t.Errorf("ControlID = %q, want FIPS-140-019", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckIdentityAuth_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkIdentityAuth(context.Background(), []byte(`{"multi_factor": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckIdentityAuth_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkIdentityAuth(context.Background(), []byte(`{"auth": "password"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkFirmwareIntegrity — FIPS-140-020
// =====================================================================

func TestCheckFirmwareIntegrity_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"firmware_integrity": true, "code_signing": "ecdsa", "secure_boot": true}`)
	r, err := m.checkFirmwareIntegrity(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-020" {
		t.Errorf("ControlID = %q, want FIPS-140-020", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckFirmwareIntegrity_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFirmwareIntegrity(context.Background(), []byte(`{"code signing": "enabled"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckFirmwareIntegrity_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFirmwareIntegrity(context.Background(), []byte(`{"boot": "standard"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkConfigManagement — FIPS-140-024
// =====================================================================

func TestCheckConfigManagement_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"configuration_management": true, "cmdb": "svc_now", "baseline_config": "locked"}`)
	r, err := m.checkConfigManagement(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-024" {
		t.Errorf("ControlID = %q, want FIPS-140-024", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckConfigManagement_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkConfigManagement(context.Background(), []byte(`{"cmdb": "present"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckConfigManagement_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkConfigManagement(context.Background(), []byte(`{"config": "manual"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkKeyGeneration — FIPS-140-025
// (4th check: fipscrypto.IsEnabled())
// =====================================================================

func TestCheckKeyGeneration_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"key_generation": true, "random_number": "nist_approved"}`)
	r, err := m.checkKeyGeneration(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-025" {
		t.Errorf("ControlID = %q, want FIPS-140-025", r.ControlID)
	}
	if r.Status == "non_compliant" {
		t.Errorf("Expected at least partial, got non_compliant: %s", r.Message)
	}
}

func TestCheckKeyGeneration_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkKeyGeneration(context.Background(), []byte(`{"key gen": "enabled"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-025" {
		t.Errorf("ControlID = %q, want FIPS-140-025", r.ControlID)
	}
}

func TestCheckKeyGeneration_NoConfig(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkKeyGeneration(context.Background(), []byte(`{"crypto": "basic"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-025" {
		t.Errorf("ControlID = %q, want FIPS-140-025", r.ControlID)
	}
}

// =====================================================================
// checkKeyStorage — FIPS-140-027
// =====================================================================

func TestCheckKeyStorage_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"key_storage": true, "key_vault": "azure", "hsm_storage": true}`)
	r, err := m.checkKeyStorage(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-027" {
		t.Errorf("ControlID = %q, want FIPS-140-027", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckKeyStorage_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkKeyStorage(context.Background(), []byte(`{"key vault": "aws_kms"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckKeyStorage_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkKeyStorage(context.Background(), []byte(`{"storage": "file"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkKeyZeroization — FIPS-140-029
// =====================================================================

func TestCheckKeyZeroization_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"zeroization": true, "key_destruction": "overwrite", "secure_wipe": true}`)
	r, err := m.checkKeyZeroization(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-029" {
		t.Errorf("ControlID = %q, want FIPS-140-029", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckKeyZeroization_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkKeyZeroization(context.Background(), []byte(`{"zeroisation": "enabled"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckKeyZeroization_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkKeyZeroization(context.Background(), []byte(`{"wipe": "none"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkPowerUpTests — FIPS-140-030
// (4th check: fipscrypto.SelfTest() — passes in test env)
// =====================================================================

func TestCheckPowerUpTests_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"power_up_test": true, "startup_test": true, "known_answer_test": true}`)
	r, err := m.checkPowerUpTests(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-030" {
		t.Errorf("ControlID = %q, want FIPS-140-030", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckPowerUpTests_Partial(t *testing.T) {
	m := NewFIPS140Module()
	// With 0 config keywords, selfTest pass gives 1/4 = partial
	r, err := m.checkPowerUpTests(context.Background(), []byte(`{"tests": "none"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial (selfTest passes, 1/4) (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkConditionalTests — FIPS-140-031
// =====================================================================

func TestCheckConditionalTests_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"conditional_test": true, "rng_test": true, "pairwise_test": true}`)
	r, err := m.checkConditionalTests(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-031" {
		t.Errorf("ControlID = %q, want FIPS-140-031", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckConditionalTests_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkConditionalTests(context.Background(), []byte(`{"rng test": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckConditionalTests_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkConditionalTests(context.Background(), []byte(`{"tests": "manual"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkSelfTestFailure — FIPS-140-032
// =====================================================================

func TestCheckSelfTestFailure_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"self_test_failure": true, "fail_safe": true, "error_state": "halt"}`)
	r, err := m.checkSelfTestFailure(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-032" {
		t.Errorf("ControlID = %q, want FIPS-140-032", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckSelfTestFailure_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSelfTestFailure(context.Background(), []byte(`{"fail safe": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckSelfTestFailure_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSelfTestFailure(context.Background(), []byte(`{"behavior": "continue"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkSideChannel — FIPS-140-035
// =====================================================================

func TestCheckSideChannel_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"constant_time": true, "side_channel": "mitigated", "timing_attack": "prevented"}`)
	r, err := m.checkSideChannel(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-035" {
		t.Errorf("ControlID = %q, want FIPS-140-035", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckSideChannel_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSideChannel(context.Background(), []byte(`{"constant time": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckSideChannel_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSideChannel(context.Background(), []byte(`{"crypto": "standard"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkAlgorithmStandard — FIPS-140-037
// =====================================================================

func TestCheckAlgorithmStandard_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"approved_algorithm": true, "nist_standard": "SP800-90A", "standardized": true}`)
	r, err := m.checkAlgorithmStandard(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-037" {
		t.Errorf("ControlID = %q, want FIPS-140-037", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckAlgorithmStandard_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkAlgorithmStandard(context.Background(), []byte(`{"standardized": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckAlgorithmStandard_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkAlgorithmStandard(context.Background(), []byte(`{"algorithms": "custom"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkUpdateVerification — FIPS-140-039
// =====================================================================

func TestCheckUpdateVerification_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"update_verification": true, "signature_verification": "ecdsa", "signed_update": true}`)
	r, err := m.checkUpdateVerification(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-039" {
		t.Errorf("ControlID = %q, want FIPS-140-039", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckUpdateVerification_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkUpdateVerification(context.Background(), []byte(`{"signature verification": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckUpdateVerification_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkUpdateVerification(context.Background(), []byte(`{"updates": "automatic"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkCSPProtection — FIPS-140-040
// =====================================================================

func TestCheckCSPProtection_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"csp_protection": true, "critical_parameter": true, "sensitive_parameter": true}`)
	r, err := m.checkCSPProtection(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-040" {
		t.Errorf("ControlID = %q, want FIPS-140-040", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckCSPProtection_Partial(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkCSPProtection(context.Background(), []byte(`{"critical parameter": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial", r.Status)
	}
}

func TestCheckCSPProtection_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkCSPProtection(context.Background(), []byte(`{"protection": "basic"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkModuleBoundary — FIPS-140-013 (2-path)
// =====================================================================

func TestCheckModuleBoundary_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkModuleBoundary(context.Background(), []byte(`{"module_boundary": "defined"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-013" {
		t.Errorf("ControlID = %q, want FIPS-140-013", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckModuleBoundary_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkModuleBoundary(context.Background(), []byte(`{"module": "undefined"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-013" {
		t.Errorf("ControlID = %q, want FIPS-140-013", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkFIPSConfigMgmt — FIPS-140-033 (2-path)
// =====================================================================

func TestCheckFIPSConfigMgmt_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFIPSConfigMgmt(context.Background(), []byte(`{"configuration_management_plan": "v2.0"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-033" {
		t.Errorf("ControlID = %q, want FIPS-140-033", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckFIPSConfigMgmt_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFIPSConfigMgmt(context.Background(), []byte(`{"plan": "none"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-033" {
		t.Errorf("ControlID = %q, want FIPS-140-033", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkSecurityFunctionInit — FIPS-140-038 (2-path)
// =====================================================================

func TestCheckSecurityFunctionInit_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSecurityFunctionInit(context.Background(), []byte(`{"security_function_init": true}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-038" {
		t.Errorf("ControlID = %q, want FIPS-140-038", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant", r.Status)
	}
}

func TestCheckSecurityFunctionInit_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSecurityFunctionInit(context.Background(), []byte(`{"init": "standard"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-038" {
		t.Errorf("ControlID = %q, want FIPS-140-038", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant", r.Status)
	}
}

// =====================================================================
// checkDesignAssurance — FIPS-140-010 (4 keywords)
// =====================================================================

func TestCheckDesignAssurance_Compliant(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"sbom": "cyclonedx", "coverage": "go test -cover", "govulncheck": true, "signed": "dco"}`)
	r, err := m.checkDesignAssurance(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-010" {
		t.Errorf("ControlID = %q, want FIPS-140-010", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckDesignAssurance_Partial(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"sbom": true}`)
	r, err := m.checkDesignAssurance(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-010" {
		t.Errorf("ControlID = %q, want FIPS-140-010", r.ControlID)
	}
	if r.Status != "partial" {
		t.Errorf("Status = %q, want partial (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckDesignAssurance_NonCompliant(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkDesignAssurance(context.Background(), []byte(`{"description": "no security practices"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-010" {
		t.Errorf("ControlID = %q, want FIPS-140-010", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkCMVPValidation — FIPS-140-009
// =====================================================================

func TestCheckCMVPValidation_CompliantGap(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"cmvp_number": "1234", "validation_certificate": true, "module_validated": true}`)
	r, err := m.checkCMVPValidation(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-009" {
		t.Errorf("ControlID = %q, want FIPS-140-009", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkHSMIntegration — FIPS-140-012
// =====================================================================

func TestCheckHSMIntegration_CompliantGap(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"hsm": true, "pkcs11": true, "hsm_endpoint": "tcp://hsm:3000"}`)
	r, err := m.checkHSMIntegration(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-012" {
		t.Errorf("ControlID = %q, want FIPS-140-012", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkApprovedHashes — FIPS-140-005
// =====================================================================

func TestCheckApprovedHashes_CompliantGap(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"hashes": ["SHA-256", "SHA-384", "SHA-512"]}`)
	r, err := m.checkApprovedHashes(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-005" {
		t.Errorf("ControlID = %q, want FIPS-140-005", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckApprovedHashes_DisallowedFoundGap(t *testing.T) {
	m := NewFIPS140Module()
	input := []byte(`{"hashes": ["MD5", "SHA-256"]}`)
	r, err := m.checkApprovedHashes(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-005" {
		t.Errorf("ControlID = %q, want FIPS-140-005", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckApprovedHashes_NoApprovedGap(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkApprovedHashes(context.Background(), []byte(`{"hashes": ["custom"]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-005" {
		t.Errorf("ControlID = %q, want FIPS-140-005", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkMinimumKeySizes — FIPS-140-006
// =====================================================================

func TestCheckMinimumKeySizes_CompliantGap(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkMinimumKeySizes(context.Background(), []byte(`{"rsa": 2048, "ecdsa": "P-256"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-006" {
		t.Errorf("ControlID = %q, want FIPS-140-006", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckMinimumKeySizes_WeakRSAGap(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkMinimumKeySizes(context.Background(), []byte(`rsa1024 weak key`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-006" {
		t.Errorf("ControlID = %q, want FIPS-140-006", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckMinimumKeySizes_WeakECDSAGap(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkMinimumKeySizes(context.Background(), []byte(`{"ecdsa": "ecdsa p128"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-006" {
		t.Errorf("ControlID = %q, want FIPS-140-006", r.ControlID)
	}
	if r.Status != "non_compliant" {
		t.Errorf("Status = %q, want non_compliant (msg: %s)", r.Status, r.Message)
	}
}

func TestCheckMinimumKeySizes_NoKeysGap(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkMinimumKeySizes(context.Background(), []byte(`{"description": "no keys"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.ControlID != "FIPS-140-006" {
		t.Errorf("ControlID = %q, want FIPS-140-006", r.ControlID)
	}
	if r.Status != "compliant" {
		t.Errorf("Status = %q, want compliant (no violations) (msg: %s)", r.Status, r.Message)
	}
}

// =====================================================================
// checkFIPSModeEnabled — FIPS-140-001 (66.7% → higher)
// =====================================================================

func TestCheckFIPSModeEnabled_WithInput(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFIPSModeEnabled(context.Background(), []byte(`{"fips_mode": "enabled"}`))
	if err != nil {
		t.Fatalf("checkFIPSModeEnabled: %v", err)
	}
	if r.ControlID != "FIPS-140-001" {
		t.Errorf("ControlID = %q; want FIPS-140-001", r.ControlID)
	}
	if r.Message == "" {
		t.Error("Message should not be empty")
	}
}

// =====================================================================
// checkFIPSLevel — FIPS-140-002 (75% → higher)
// =====================================================================

func TestCheckFIPSLevel_Level1(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFIPSLevel(context.Background(), []byte(`{"fips_level": "1"}`))
	if err != nil {
		t.Fatalf("checkFIPSLevel: %v", err)
	}
	if r.ControlID != "FIPS-140-002" {
		t.Errorf("ControlID = %q; want FIPS-140-002", r.ControlID)
	}
}

func TestCheckFIPSLevel_Level2(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkFIPSLevel(context.Background(), []byte(`{"security_level": 2}`))
	if err != nil {
		t.Fatalf("checkFIPSLevel: %v", err)
	}
	if r.ControlID != "FIPS-140-002" {
		t.Errorf("ControlID = %q; want FIPS-140-002", r.ControlID)
	}
}

// =====================================================================
// checkSelfTest — FIPS-140-007 (66.7% → higher)
// =====================================================================

func TestCheckSelfTest_WithConfig(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkSelfTest(context.Background(), []byte(`{"self_test": "startup"}`))
	if err != nil {
		t.Fatalf("checkSelfTest: %v", err)
	}
	if r.ControlID != "FIPS-140-007" {
		t.Errorf("ControlID = %q; want FIPS-140-007", r.ControlID)
	}
}

// =====================================================================
// checkAuditLogging — FIPS-140-008 (75% → higher)
// =====================================================================

func TestCheckAuditLogging_Comprehensive(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkAuditLogging(context.Background(), []byte(`{"audit_logging": true, "log_level": "info"}`))
	if err != nil {
		t.Fatalf("checkAuditLogging: %v", err)
	}
	if r.ControlID != "FIPS-140-008" {
		t.Errorf("ControlID = %q; want FIPS-140-008", r.ControlID)
	}
}

func TestCheckAuditLogging_Minimal(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkAuditLogging(context.Background(), []byte(`{"logging": "basic"}`))
	if err != nil {
		t.Fatalf("checkAuditLogging: %v", err)
	}
	if r.ControlID != "FIPS-140-008" {
		t.Errorf("ControlID = %q; want FIPS-140-008", r.ControlID)
	}
}

// =====================================================================
// checkMinimumTLSVersion — FIPS-140-003 (88.2% → higher)
// =====================================================================

func TestCheckMinimumTLSVersion_TLS10(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkMinimumTLSVersion(context.Background(), []byte(`{"tls1.0": true}`))
	if err != nil {
		t.Fatalf("checkMinimumTLSVersion: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("TLS 1.0 should be non_compliant, got %s: %s", r.Status, r.Message)
	}
}

func TestCheckMinimumTLSVersion_TLS11(t *testing.T) {
	m := NewFIPS140Module()
	r, err := m.checkMinimumTLSVersion(context.Background(), []byte(`{"tls1.1": true}`))
	if err != nil {
		t.Fatalf("checkMinimumTLSVersion: %v", err)
	}
	if r.Status != "non_compliant" {
		t.Errorf("TLS 1.1 should be non_compliant, got %s: %s", r.Status, r.Message)
	}
}

// =====================================================================
// intToStr (90% → higher)
// =====================================================================

func TestIntToStr_AllCases(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3} {
		result := intToStr(n)
		if result == "" {
			t.Errorf("intToStr(%d) returned empty string", n)
		}
	}
}
