// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security
// =========================================================================
//
// PCI-DSS Compliance Module Gap Tests
// Coverage gap tests to bring package coverage from 79.5% to 90%+
// =========================================================================

package pci

import (
	"context"
	"testing"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkFunc is the common signature for all PCI check methods.
type checkFunc func(context.Context, []byte) (*compliance.ControlCheckResult, error)

// ============================================================================
// 3-path functions (compliant / partial / non_compliant) at 75% coverage
// Missing: the "partial" path (found > 0 but found < threshold).
// We provide exactly 1 keyword to trigger partial.
// ============================================================================

func TestGapPartialPathThreePathFuncs(t *testing.T) {
	m := NewPCIModule()
	ctx := context.Background()

	tests := []struct {
		name string
		fn   checkFunc
		kw   string // single keyword to trigger partial
	}{
		{"checkNetworkSegmentation", m.checkNetworkSegmentation, "network_segmentation"},
		{"checkDenyTraffic", m.checkDenyTraffic, "deny_traffic"},
		{"checkPortRestriction", m.checkPortRestriction, "port_restriction"},
		{"checkPerimeterFirewall", m.checkPerimeterFirewall, "perimeter_firewall"},
		{"checkWirelessSegmentation", m.checkWirelessSegmentation, "wireless_segmentation"},
		{"checkPublicAccess", m.checkPublicAccess, "no_public_access"},
		{"checkAntiSpoofing", m.checkAntiSpoofing, "anti_spoofing"},
		{"checkUnnecessaryServices", m.checkUnnecessaryServices, "necessary_services"},
		{"checkContainerHardening", m.checkContainerHardening, "container_hardening"},
		{"checkAdminAccess", m.checkAdminAccess, "encrypted_admin"},
		{"checkCentralAuth", m.checkCentralAuth, "centralized_auth"},
		{"checkNoSensitiveAuth", m.checkNoSensitiveAuth, "no_sensitive_auth"},
		{"checkPANUnreadable", m.checkPANUnreadable, "pan_unreadable"},
		{"checkDiskEncryption", m.checkDiskEncryption, "disk_encryption"},
		{"checkTokenization", m.checkTokenization, "tokenization"},
		{"checkTruncation", m.checkTruncation, "first6_last4"},
		{"checkPANHashing", m.checkPANHashing, "pan_hashing"},
		{"checkKeyRotation", m.checkKeyRotation, "key_rotation"},
		{"checkWirelessCrypto", m.checkWirelessCrypto, "wpa3"},
		{"checkCertExpiration", m.checkCertExpiration, "cert_expiration"},
		{"checkCertValidation", m.checkCertValidation, "cert_validation"},
		{"checkCentralizedMalware", m.checkCentralizedMalware, "centralized_malware"},
		{"checkPatchCritical", m.checkPatchCritical, "critical_patch"},
		{"checkPatchHigh", m.checkPatchHigh, "high_patch"},
		{"checkInternalScan", m.checkInternalScan, "internal_scan"},
		{"checkSecureDev", m.checkSecureDev, "secure_dev"},
		{"checkEnvSeparation", m.checkEnvSeparation, "env_separation"},
		{"checkNoProdDataTest", m.checkNoProdDataTest, "no_prod_data"},
		{"checkAutomatedVulnTest", m.checkAutomatedVulnTest, "automated_vuln_test"},
		{"checkWebAppVuln", m.checkWebAppVuln, "web_app_vuln"},
		{"checkWebAppProtection", m.checkWebAppProtection, "waf"},
		{"checkSoftwareScan", m.checkSoftwareScan, "software_scan"},
		{"checkDenyAllModel", m.checkDenyAllModel, "deny_all"},
		{"checkLeastPrivilege", m.checkLeastPrivilege, "least_privilege"},
		{"checkAutoAccessControl", m.checkAutoAccessControl, "automated_access"},
		{"checkRemoteMFA", m.checkRemoteMFA, "remote_mfa"},
		{"checkPrivilegedMFA", m.checkPrivilegedMFA, "privileged_mfa"},
		{"checkAuthCrypto", m.checkAuthCrypto, "auth_crypto"},
		{"checkPasswordComplexity", m.checkPasswordComplexity, "password_complexity"},
		{"checkLockout", m.checkLockout, "account_lockout"},
		{"checkSessionTimeout", m.checkSessionTimeout, "session_timeout"},
		{"checkPhysicalAccess", m.checkPhysicalAccess, "physical_access"},
		{"checkMediaDestruction", m.checkMediaDestruction, "media_destruction"},
		{"checkPaperDestruction", m.checkPaperDestruction, "paper_destruction"},
		{"checkAuditTrails", m.checkAuditTrails, "audit_trail"},
		{"checkUserAccessLog", m.checkUserAccessLog, "user_access_log"},
		{"checkAdminActionsLog", m.checkAdminActionsLog, "admin_actions_log"},
		{"checkTimeSync", m.checkTimeSync, "time_sync"},
		{"checkAutomatedLogReview", m.checkAutomatedLogReview, "automated_log_review"},
		{"checkInternalVulnScan", m.checkInternalVulnScan, "internal_vuln_scan"},
		{"checkExternalVulnScan", m.checkExternalVulnScan, "external_vuln_scan"},
		{"checkPostChangeScan", m.checkPostChangeScan, "post_change_scan"},
		{"checkIntrusionDetection", m.checkIntrusionDetection, "intrusion_detection"},
		{"checkIntrusionPrevention", m.checkIntrusionPrevention, "intrusion_prevention"},
		{"checkAcceptableUse", m.checkAcceptableUse, "acceptable_use"},
		{"checkSecurityTraining", m.checkSecurityTraining, "security_training"},
		{"checkIncidentResponse", m.checkIncidentResponse, "ir_roles"},
		{"checkRiskAssessment", m.checkRiskAssessment, "risk_assessment"},
		{"checkAIModelVuln", m.checkAIModelVuln, "ai_vuln_scan"},
		{"checkAIAccessControl", m.checkAIAccessControl, "ai_access_control"},
		{"checkAIAuditLog", m.checkAIAuditLog, "audit_log"},
		{"checkRuleSetReview", m.checkRuleSetReview, "rule_review"},
		{"checkUnnecessaryConfigs", m.checkUnnecessaryConfigs, "config_cleanup"},
		{"checkInternalIPLegacy", m.checkInternalIPLegacy, "internal_ip_protected"},
		{"checkAdminAccessEncryption", m.checkAdminAccessEncryption, "admin_encryption"},
		{"checkUnnecessaryFunctionality", m.checkUnnecessaryFunctionality, "functionality_removed"},
		{"checkMinimizeDataStorage", m.checkMinimizeDataStorage, "data_minimization"},
		{"checkDataRetentionDisposal", m.checkDataRetentionDisposal, "retention_policy"},
		{"checkAntiMalwareActive", m.checkAntiMalwareActive, "antivirus"},
		{"checkAntiMalwareNonDisableable", m.checkAntiMalwareNonDisableable, "non_disableable"},
		{"checkChangeControl", m.checkChangeControl, "change_control"},
		{"checkAccessRightsReview", m.checkAccessRightsReview, "access_review"},
		{"checkPasswordNotReadable", m.checkPasswordNotReadable, "password_hash"},
		{"checkAuditTrailRetention", m.checkAuditTrailRetention, "audit_retention"},
		{"checkTimeSyncNTP", m.checkTimeSyncNTP, "ntp"},
		{"checkLogIntegrity", m.checkLogIntegrity, "log_integrity"},
		{"checkFileIntegrityMonitoring", m.checkFileIntegrityMonitoring, "fim"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Partial", func(t *testing.T) {
			// Provide exactly 1 keyword so found=1 which is >0 but < threshold.
			input := []byte(tt.kw)
			result, err := tt.fn(ctx, input)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, compliance.StatusPartial, result.Status,
				"expected partial for %s with single keyword %q", tt.name, tt.kw)
		})
	}
}

// ============================================================================
// 3-path functions at 91.7% (partial path reachable, not yet tested)
// ============================================================================

func TestGapPartialPath91PercentFuncs(t *testing.T) {
	m := NewPCIModule()
	ctx := context.Background()

	tests := []struct {
		name string
		fn   checkFunc
		kw   string
	}{
		{"checkPANMasking", m.checkPANMasking, "pan_masking"},
		{"checkMalwareProtection", m.checkMalwareProtection, "antivirus"},
		{"checkVulnScanning", m.checkVulnScanning, "vulnerability_scan"},
		{"checkCodeReview", m.checkCodeReview, "code_review"},
		{"checkAccessControl", m.checkAccessControl, "rbac"},
		{"checkUserAuth", m.checkUserAuth, "authentication"},
		{"checkAuditLogging", m.checkAuditLogging, "audit_log"},
		{"checkAITokenization", m.checkAITokenization, "tokenization"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Partial", func(t *testing.T) {
			input := []byte(tt.kw)
			result, err := tt.fn(ctx, input)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, compliance.StatusPartial, result.Status,
				"expected partial for %s with single keyword %q", tt.name, tt.kw)
		})
	}
}

// ============================================================================
// 2-path functions (compliant / non_compliant) at 75% coverage
// Missing: the "compliant" path. We provide keywords to trigger compliant.
// ============================================================================

func TestGapCompliantPathTwoPathFuncs(t *testing.T) {
	m := NewPCIModule()
	ctx := context.Background()

	tests := []struct {
		name string
		fn   checkFunc
		kw   string // keyword to trigger compliant
	}{
		{"checkRouterConfig", m.checkRouterConfig, "router_config"},
		{"checkSystemHardeningStandard", m.checkSystemHardeningStandard, "system_hardening"},
		{"checkVirtualizationHardening", m.checkVirtualizationHardening, "virtualization_hardening"},
		{"checkWirelessHardening", m.checkWirelessHardening, "wireless_hardening"},
		{"checkConfigStandards", m.checkConfigStandards, "config_standards"},
		{"checkPCIKeyMgmt", m.checkPCIKeyMgmt, "key_management"},
		{"checkPCIKeyStorage", m.checkPCIKeyStorage, "key_storage"},
		{"checkPCIKeyMgmtProcedures", m.checkPCIKeyMgmtProcedures, "key_management_procedure"},
		{"checkPCIKeyProtection", m.checkPCIKeyProtection, "key_protection"},
		{"checkPANMessaging", m.checkPANMessaging, "pan_messaging_block"},
		{"checkTrustedCAs", m.checkTrustedCAs, "trusted_ca"},
		{"checkPANVoIPEncryption", m.checkPANVoIPEncryption, "voip_encryption"},
		{"checkAnomalousKeyMgmt", m.checkAnomalousKeyMgmt, "anomalous_key_mgmt"},
		{"checkPCISDLC", m.checkPCISDLC, "secure_sdlc"},
		{"checkPCISDevProcesses", m.checkPCISDevProcesses, "software_development_process"},
		{"checkPreProdSeparation", m.checkPreProdSeparation, "pre_prod_separation"},
		{"checkPCISOD", m.checkPCISOD, "dev_test_prod_sod"},
		{"checkTestDataRemoved", m.checkTestDataRemoved, "test_data_removed"},
		{"checkPCIChangeDocumentation", m.checkPCIChangeDocumentation, "change_documentation"},
		{"checkPCICodeReview", m.checkPCICodeReview, "code_review"},
		{"checkPCIAccessControlPolicy", m.checkPCIAccessControlPolicy, "access_control_policy"},
		{"checkPCIOffsiteStorageAccess", m.checkPCIOffsiteStorageAccess, "offsite_storage_access"},
		{"checkPCIAccessRevocation", m.checkPCIAccessRevocation, "access_revocation"},
		{"checkPCISharedIDs", m.checkPCISharedIDs, "shared_ids_eliminated"},
		{"checkPCIAuthFactors", m.checkPCIAuthFactors, "auth_factors"},
		{"checkPCIFirstUsePasswords", m.checkPCIFirstUsePasswords, "first_use_password"},
		{"checkPCINoSharedAuth", m.checkPCINoSharedAuth, "no_shared_auth"},
		{"checkPCIIdentityVerification", m.checkPCIIdentityVerification, "identity_verification"},
		{"checkPCIAuthNotReused", m.checkPCIAuthNotReused, "auth_not_reused"},
		{"checkPCIMediaSecured", m.checkPCIMediaSecured, "media_secured"},
		{"checkPCIMediaInventory", m.checkPCIMediaInventory, "media_inventory"},
		{"checkPCIDisplayPAN", m.checkPCIDisplayPAN, "pan_display_protection"},
		{"checkPCILogReviewDaily", m.checkPCILogReviewDaily, "daily_log_review"},
		{"checkPCILogReviewFailed", m.checkPCILogReviewFailed, "failed_access_review"},
		{"checkPCICentralizedLogging", m.checkPCICentralizedLogging, "centralized_logging"},
		{"checkPCIAuthorizedWireless", m.checkPCIAuthorizedWireless, "authorized_wireless"},
		{"checkPCIPublicIPScope", m.checkPCIPublicIPScope, "public_ip_scope"},
		{"checkPCIBCP", m.checkPCIBCP, "business_continuity_plan"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Compliant", func(t *testing.T) {
			input := []byte(tt.kw)
			result, err := tt.fn(ctx, input)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, compliance.StatusCompliant, result.Status,
				"expected compliant for %s with keyword %q", tt.name, tt.kw)
		})
	}
}

// ============================================================================
// pciCount at 0% coverage
// ============================================================================

func TestGapPciCount(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want string
	}{
		{"Zero", 0, "0"},
		{"OneDigit", 5, "5"},
		{"MultiDigit", 123, "123"},
		{"LargeNumber", 999999, "999999"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pciCount(tt.n)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// 3-path functions at 75%: also add compliant path tests for functions
// that are NOT individually tested in pci_test.go (only via CheckAll).
// This ensures both compliant and partial paths are covered.
// ============================================================================

func TestGapCompliantPathThreePathFuncs(t *testing.T) {
	m := NewPCIModule()
	ctx := context.Background()

	// For 3-path functions, threshold = (len(keywords)+1)/2.
	// We provide 2+ keywords to exceed the threshold and trigger compliant.
	tests := []struct {
		name  string
		fn    checkFunc
		input string
	}{
		{"checkNetworkSegmentation", m.checkNetworkSegmentation, "network_segmentation cde_isolated vlan security_group"},
		{"checkDenyTraffic", m.checkDenyTraffic, "deny_traffic default_deny"},
		{"checkPortRestriction", m.checkPortRestriction, "port_restriction restricted_ports"},
		{"checkPerimeterFirewall", m.checkPerimeterFirewall, "perimeter_firewall edge_firewall"},
		{"checkWirelessSegmentation", m.checkWirelessSegmentation, "wireless_segmentation wifi_isolation"},
		{"checkPublicAccess", m.checkPublicAccess, "no_public_access restrict_public_access"},
		{"checkAntiSpoofing", m.checkAntiSpoofing, "anti_spoofing spoofing_protection ip_spoofing"},
		{"checkUnnecessaryServices", m.checkUnnecessaryServices, "necessary_services disabled_services"},
		{"checkContainerHardening", m.checkContainerHardening, "container_hardening docker_security"},
		{"checkAdminAccess", m.checkAdminAccess, "encrypted_admin ssh_access"},
		{"checkCentralAuth", m.checkCentralAuth, "centralized_auth sso ldap"},
		{"checkNoSensitiveAuth", m.checkNoSensitiveAuth, "no_sensitive_auth sensitive_data_deleted"},
		{"checkPANUnreadable", m.checkPANUnreadable, "pan_unreadable pan_encrypted pan_tokenized"},
		{"checkDiskEncryption", m.checkDiskEncryption, "disk_encryption partition_encryption luks"},
		{"checkTokenization", m.checkTokenization, "tokenization tokenized"},
		{"checkTruncation", m.checkTruncation, "pan_truncation truncated_pan"},
		{"checkPANHashing", m.checkPANHashing, "pan_hashing one_way_hash sha256_pan"},
		{"checkKeyRotation", m.checkKeyRotation, "key_rotation rotate_keys"},
		{"checkWirelessCrypto", m.checkWirelessCrypto, "wpa3 wpa2_enterprise"},
		{"checkCertExpiration", m.checkCertExpiration, "cert_expiration certificate_expiry"},
		{"checkCertValidation", m.checkCertValidation, "cert_validation certificate_validation"},
		{"checkCentralizedMalware", m.checkCentralizedMalware, "centralized_malware centralized_antivirus"},
		{"checkPatchCritical", m.checkPatchCritical, "critical_patch 30_day_patch"},
		{"checkPatchHigh", m.checkPatchHigh, "high_patch 90_day_patch"},
		{"checkInternalScan", m.checkInternalScan, "internal_scan internal_vuln_scan"},
		{"checkSecureDev", m.checkSecureDev, "secure_dev secure_coding sast"},
		{"checkEnvSeparation", m.checkEnvSeparation, "env_separation separate_environments"},
		{"checkNoProdDataTest", m.checkNoProdDataTest, "no_prod_data test_data_synthetic"},
		{"checkAutomatedVulnTest", m.checkAutomatedVulnTest, "automated_vuln_test ci_cd_scan"},
		{"checkWebAppVuln", m.checkWebAppVuln, "web_app_vuln sast dast"},
		{"checkWebAppProtection", m.checkWebAppProtection, "waf xss_protection sqli_protection"},
		{"checkSoftwareScan", m.checkSoftwareScan, "software_scan dependency_scan sca"},
		{"checkDenyAllModel", m.checkDenyAllModel, "deny_all default_deny"},
		{"checkLeastPrivilege", m.checkLeastPrivilege, "least_privilege minimal_access"},
		{"checkAutoAccessControl", m.checkAutoAccessControl, "automated_access access_management_system"},
		{"checkRemoteMFA", m.checkRemoteMFA, "remote_mfa vpn_mfa"},
		{"checkPrivilegedMFA", m.checkPrivilegedMFA, "privileged_mfa admin_mfa"},
		{"checkAuthCrypto", m.checkAuthCrypto, "auth_crypto authentication_encryption"},
		{"checkPasswordComplexity", m.checkPasswordComplexity, "password_complexity password_policy"},
		{"checkLockout", m.checkLockout, "account_lockout lockout_enabled"},
		{"checkSessionTimeout", m.checkSessionTimeout, "session_timeout idle_timeout"},
		{"checkPhysicalAccess", m.checkPhysicalAccess, "physical_access badge_access"},
		{"checkMediaDestruction", m.checkMediaDestruction, "media_destruction secure_destruction"},
		{"checkPaperDestruction", m.checkPaperDestruction, "paper_destruction paper_shredding"},
		{"checkAuditTrails", m.checkAuditTrails, "audit_trail audit_trails access_trail"},
		{"checkUserAccessLog", m.checkUserAccessLog, "user_access_log user_activity"},
		{"checkAdminActionsLog", m.checkAdminActionsLog, "admin_actions_log admin_audit"},
		{"checkTimeSync", m.checkTimeSync, "time_sync time_synchronization"},
		{"checkAutomatedLogReview", m.checkAutomatedLogReview, "automated_log_review siem log_analysis"},
		{"checkInternalVulnScan", m.checkInternalVulnScan, "internal_vuln_scan quarterly_internal"},
		{"checkExternalVulnScan", m.checkExternalVulnScan, "external_vuln_scan asv_scan"},
		{"checkPostChangeScan", m.checkPostChangeScan, "post_change_scan change_triggered_scan"},
		{"checkIntrusionDetection", m.checkIntrusionDetection, "intrusion_detection ids network_ids"},
		{"checkIntrusionPrevention", m.checkIntrusionPrevention, "intrusion_prevention ips network_ips"},
		{"checkAcceptableUse", m.checkAcceptableUse, "acceptable_use aup use_policy"},
		{"checkSecurityTraining", m.checkSecurityTraining, "security_training awareness_training"},
		{"checkIncidentResponse", m.checkIncidentResponse, "incident_response_plan ir_plan"},
		{"checkRiskAssessment", m.checkRiskAssessment, "risk_assessment annual_risk_assessment"},
		{"checkAIModelVuln", m.checkAIModelVuln, "ai_vuln_scan model_scan"},
		{"checkAIAccessControl", m.checkAIAccessControl, "ai_access_control ai_rbac"},
		{"checkAIAuditLog", m.checkAIAuditLog, "audit_log audit_trail immutable_log"},
		{"checkRuleSetReview", m.checkRuleSetReview, "rule_review ruleset_review firewall_review"},
		{"checkUnnecessaryConfigs", m.checkUnnecessaryConfigs, "config_cleanup unnecessary_rules_removed rule_cleanup"},
		{"checkInternalIPLegacy", m.checkInternalIPLegacy, "internal_ip_protected nat_configured private_ip"},
		{"checkAdminAccessEncryption", m.checkAdminAccessEncryption, "admin_encryption ssh_tunnel vpn_admin"},
		{"checkUnnecessaryFunctionality", m.checkUnnecessaryFunctionality, "functionality_removed unnecessary_scripts_removed drivers_removed"},
		{"checkMinimizeDataStorage", m.checkMinimizeDataStorage, "data_minimization storage_limit data_reduction"},
		{"checkDataRetentionDisposal", m.checkDataRetentionDisposal, "retention_policy disposal_policy data_retention"},
		{"checkAntiMalwareActive", m.checkAntiMalwareActive, "antivirus anti-malware malware_scanner"},
		{"checkAntiMalwareNonDisableable", m.checkAntiMalwareNonDisableable, "non_disableable tamper_protection admin_only"},
		{"checkChangeControl", m.checkChangeControl, "change_control change_management change_approval"},
		{"checkAccessRightsReview", m.checkAccessRightsReview, "access_review rights_review permission_audit"},
		{"checkPasswordNotReadable", m.checkPasswordNotReadable, "password_hash bcrypt argon2"},
		{"checkAuditTrailRetention", m.checkAuditTrailRetention, "audit_retention log_retention retention_1_year"},
		{"checkTimeSyncNTP", m.checkTimeSyncNTP, "ntp time_sync time_synchronization"},
		{"checkLogIntegrity", m.checkLogIntegrity, "log_integrity log_protection immutable_logs"},
		{"checkFileIntegrityMonitoring", m.checkFileIntegrityMonitoring, "fim file_integrity integrity_monitoring"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Compliant", func(t *testing.T) {
			input := []byte(tt.input)
			result, err := tt.fn(ctx, input)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, compliance.StatusCompliant, result.Status,
				"expected compliant for %s with input %q", tt.name, tt.input)
		})
	}
}
