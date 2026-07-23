// SPDX-License-Identifier: Apache-2.0
// ISO/IEC 27001:2022 — Coverage Gap Tests
package iso27001

import (
	"context"
	"strings"
	"testing"
)

// TestISO27001_StandardCheckCoverage tests all check functions that use standardCheck
// with compliant (3+ keywords), partial (1-2 keywords), and non_compliant (0 keywords) inputs.
func TestISO27001_StandardCheckCoverage(t *testing.T) {
	m := NewISO27001Module()
	ctx := context.Background()

	// Each entry: name, compliant input (3+ keywords), partial input (1-2 keywords)
	tests := []struct {
		name  string
		compl string
		part  string
	}{
		{"A.5.7_ThreatIntelligence", "threat_intel ioc_store ioc_federation threat_feed", "threat_intel ioc_store"},
		{"A.5.10_AcceptableUse", "acceptable_use aup usage_policy documented", "acceptable_use aup"},
		{"A.5.12_DataClassification", "data_classification classification_label data_label public", "data_classification classification_label"},
		{"A.5.13_DataLabeling", "data_labeling labeling tagging classification", "tagging"},
		{"A.5.14_InformationTransfer", "transfer_policy tls encryption secure_transfer", "transfer_policy tls"},
		{"A.5.23_CloudSecurity", "cloud_security csp_assessment cloud_config shared_responsibility", "cloud_security cloud_config"},
		{"A.5.30_BusinessContinuity", "business_continuity disaster_recovery backup redundancy", "business_continuity backup"},
		{"A.5.31_LegalCompliance", "legal_review compliance_check regulatory_requirements contract_review", "legal_review compliance_check"},
		{"A.5.34_PIIProtection", "pii_protection pii_scanner data_masking de_identification", "pii_protection data_masking"},
		{"A.5.37_OperatingProcedures", "operating_procedures runbook sop documented", "operating_procedures sop"},
		{"A.6.3_SecurityAwareness", "security_awareness training_records phishing_test security_training", "security_awareness training_records"},
		{"A.6.4_DisciplinaryProcess", "disciplinary_process policy_violation consequence hr_process", "disciplinary_process policy_violation"},
		{"A.6.6_NDA", "nda confidentiality_agreement non_disclosure signed_agreement", "nda confidentiality_agreement"},
		{"A.6.7_RemoteWorking", "vpn remote_access endpoint_protection device_encryption", "vpn remote_access"},
		{"A.6.8_EventReporting", "event_reporting alerting alert_channel incident_notification", "event_reporting alerting"},
		{"A.8.27_EndpointSecurity", "endpoint_security edr antivirus device_encryption", "endpoint_security antivirus"},
		{"A.7.4_PhysicalSecurityMonitoring", "physical_monitoring cctv badge_access security_log", "physical_monitoring cctv"},
		{"A.7.10_StorageMedia", "retention_policy media_disposal secure_erasure inventory", "retention_policy media_disposal"},
		{"A.7.13_EquipmentMaintenance", "maintenance_log equipment_inventory maintenance_schedule patching", "maintenance_log patching"},
		{"A.7.14_SecureDisposal", "secure_disposal data_erasure asset_sanitization disposal_certificate", "secure_disposal data_erasure"},
		{"A.7.5_PhysicalEnvironmentalThreats", "fire_suppression temperature_monitoring humidity_monitoring environmental_alerts", "fire_suppression temperature_monitoring"},
		{"A.7.6_WorkingInSecureAreas", "secure_area_policy visitor_log escort_required clear_desk", "secure_area_policy visitor_log"},
		{"A.7.9_AssetsOffPremises", "asset_tracking device_encryption remote_wipe asset_inventory", "asset_tracking device_encryption"},
		{"A.8.1_UserEndpointDevices", "endpoint_protection device_encryption edr device_compliance", "endpoint_protection device_encryption"},
		{"A.8.2_PrivilegedAccess", "rbac privileged_access least_privilege pam", "rbac privileged_access"},
		{"A.8.3_AccessRestriction", "access_control rbac least_privilege access_review", "access_control rbac"},
		{"A.8.5_SecureAuth", "authentication mfa multi_factor secure_session", "authentication mfa"},
		{"A.8.7_MalwareProtection", "antivirus edr malware_scanner auto_update", "antivirus edr"},
		{"A.8.8_VulnerabilityManagement", "vulnerability_scan govulncheck trivy patch_management", "vulnerability_scan trivy"},
		{"A.8.9_ConfigManagement", "config_management baseline_config config_drift config_audit", "config_management baseline_config"},
		{"A.8.12_DataLeakage", "dlp data_classification egress_filter data_loss_prevention", "dlp data_classification"},
		{"A.8.16_MonitoringActivities", "network_monitoring anomaly_detection alerting siem", "network_monitoring alerting"},
		{"A.8.18_PrivilegedUtility", "utility_restriction sudo_policy admin_audit privileged_session", "utility_restriction sudo_policy"},
		{"A.8.20_NetworkSecurity", "firewall network_segmentation ids ips", "firewall ids"},
		{"A.8.21_NetworkServices", "network_service_agreement sla network_monitoring service_security", "network_service_agreement sla"},
		{"A.8.22_NetworkSegregation", "network_segmentation vlan dmz security_zone", "network_segmentation vlan"},
		{"A.8.23_WebFiltering", "web_filter url_filter proxy content_filter", "web_filter proxy"},
		{"A.8.24_Cryptography", "aes_256 rsa_2048 tls_1_2 fips", "aes_256 fips"},
		{"A.8.25_SDLC", "sdlc secure_sdlc devsecops code_review", "sdlc code_review"},
		{"A.8.26_AppSecReqs", "app_sec_requirements security_spec threat_modeling abuse_cases", "app_sec_requirements security_spec"},
		{"A.8.28_SecureCoding", "secure_coding coding_guidelines sast code_review", "secure_coding sast"},
		{"A.8.29_SecurityTesting", "security_testing sast dast penetration_test", "security_testing sast"},
		{"A.8.31_EnvironmentSeparation", "environment_separation dev_test_prod namespace_isolation environment_isolation", "environment_separation dev_test_prod"},
		{"A.8.32_ChangeManagement", "change_management change_control approval_workflow change_log", "change_management change_control"},
		{"A.8.33_TestInformation", "test_data_management test_data_protection test_data_disposal test_environment_isolation", "test_data_management test_data_protection"},
		{"A.8.34_AuditTestingDev", "audit_testing security_audit compliance_audit sast_audit", "audit_testing security_audit"},
		{"A.8.35_AcceptanceTesting", "acceptance_testing uat production_readiness qa_signoff", "acceptance_testing uat"},
		{"A.8.17_ClockSync", "ntp chrony time_sync clock_sync", "ntp time_sync"},
		{"A.8.10_InformationDeletion", "deletion_policy data_deletion secure_deletion retention_expiry", "deletion_policy data_deletion"},
		{"A.8.11_DataMasking", "data_masking pii_masking tokenization anonymization", "data_masking tokenization"},
		{"A.8.13_Backup", "backup backup_test backup_retention backup_encryption", "backup backup_test"},
		{"A.8.14_Redundancy", "redundancy high_availability failover multi_zone", "redundancy failover"},
		{"A.8.4_SourceCodeAccess", "source_code_access repo_access_control branch_protection code_review", "source_code_access repo_access_control"},
		{"A.5.19_SupplierSecurity", "vendor_security_requirements supplier_assessment vendor_inventory supplier_monitoring", "vendor_security_requirements supplier_assessment"},
		{"A.5.20_SupplierAgreements", "supplier_agreement dpa security_requirements contract_review", "supplier_agreement dpa"},
		{"A.5.21_SupplyChain", "supply_chain_security sbom vendor_assessment supply_chain_monitoring", "supply_chain_security sbom"},
		{"A.5.22_SupplierMonitoring", "supplier_monitoring vendor_review service_review change_management", "supplier_monitoring vendor_review"},
		{"A.5.24_IRPlanning", "incident_response_plan ir_roles ir_plan ir_procedures", "incident_response_plan ir_roles"},
		{"A.5.25_EventAssessment", "event_assessment event_classification triage severity_classification", "event_assessment triage"},
		{"A.5.26_IRResponse", "incident_response ir_procedure runbook incident_commander", "incident_response runbook"},
		{"A.5.27_IRLearning", "post_mortem lessons_learned ir_review improvement_actions", "post_mortem ir_review"},
		{"A.5.28_EvidenceCollection", "evidence_collection chain_of_custody evidence_preservation forensic_log", "evidence_collection chain_of_custody"},
		{"A.5.29_IRDuringDisruption", "ir_during_disruption continuity_plan dr_site failover_during_incident", "ir_during_disruption continuity_plan"},
		{"A.5.35_IndependentReview", "independent_review external_audit annual_security_review third_party_assessment", "independent_review external_audit"},
		{"A.5.36_ComplianceReview", "compliance_review policy_audit compliance_check audit_log", "compliance_review policy_audit"},
		{"A.5.38_AuditTesting", "audit_testing security_audit compliance_audit audit_scheduled", "audit_testing compliance_audit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _, err := dispatch(m, tt.name, ctx, []byte(tt.compl))
			if err != nil {
				t.Fatalf("compliant: unexpected error: %v", err)
			}
			if strings.ToLower(s) != "compliant" {
				t.Errorf("compliant input: expected compliant, got %s", s)
			}

			s, _, err = dispatch(m, tt.name, ctx, []byte(tt.part))
			if err != nil {
				t.Fatalf("partial: unexpected error: %v", err)
			}
			if strings.ToLower(s) != "partial" {
				t.Errorf("partial input: expected partial, got %s", s)
			}

			s, _, err = dispatch(m, tt.name, ctx, []byte("zzz_nothing_here"))
			if err != nil {
				t.Fatalf("non_compliant: unexpected error: %v", err)
			}
			if strings.ToLower(s) != "non_compliant" {
				t.Errorf("non_compliant input: expected non_compliant, got %s", s)
			}
		})
	}
}

// dispatch calls the right method by name and returns its result.
// Uses string(r.Status) to convert ControlCheckStatus to string without importing compliance.
func dispatch(m *ISO27001Module, name string, ctx context.Context, input []byte) (status string, message string, err error) {
	switch name {
	case "A.5.7_ThreatIntelligence":
		r, e := m.checkThreatIntelligence(ctx, input); return string(r.Status), r.Message, e
	case "A.5.10_AcceptableUse":
		r, e := m.checkAcceptableUse(ctx, input); return string(r.Status), r.Message, e
	case "A.5.12_DataClassification":
		r, e := m.checkDataClassification(ctx, input); return string(r.Status), r.Message, e
	case "A.5.13_DataLabeling":
		r, e := m.checkDataLabeling(ctx, input); return string(r.Status), r.Message, e
	case "A.5.14_InformationTransfer":
		r, e := m.checkInformationTransfer(ctx, input); return string(r.Status), r.Message, e
	case "A.5.23_CloudSecurity":
		r, e := m.checkCloudSecurity(ctx, input); return string(r.Status), r.Message, e
	case "A.5.30_BusinessContinuity":
		r, e := m.checkBusinessContinuity(ctx, input); return string(r.Status), r.Message, e
	case "A.5.31_LegalCompliance":
		r, e := m.checkLegalCompliance(ctx, input); return string(r.Status), r.Message, e
	case "A.5.34_PIIProtection":
		r, e := m.checkPIIProtection(ctx, input); return string(r.Status), r.Message, e
	case "A.5.37_OperatingProcedures":
		r, e := m.checkOperatingProcedures(ctx, input); return string(r.Status), r.Message, e
	case "A.6.3_SecurityAwareness":
		r, e := m.checkSecurityAwareness(ctx, input); return string(r.Status), r.Message, e
	case "A.6.4_DisciplinaryProcess":
		r, e := m.checkDisciplinaryProcess(ctx, input); return string(r.Status), r.Message, e
	case "A.6.6_NDA":
		r, e := m.checkNDA(ctx, input); return string(r.Status), r.Message, e
	case "A.6.7_RemoteWorking":
		r, e := m.checkRemoteWorking(ctx, input); return string(r.Status), r.Message, e
	case "A.6.8_EventReporting":
		r, e := m.checkEventReporting(ctx, input); return string(r.Status), r.Message, e
	case "A.8.27_EndpointSecurity":
		r, e := m.checkEndpointSecurity(ctx, input); return string(r.Status), r.Message, e
	case "A.7.4_PhysicalSecurityMonitoring":
		r, e := m.checkPhysicalSecurityMonitoring(ctx, input); return string(r.Status), r.Message, e
	case "A.7.10_StorageMedia":
		r, e := m.checkStorageMedia(ctx, input); return string(r.Status), r.Message, e
	case "A.7.13_EquipmentMaintenance":
		r, e := m.checkEquipmentMaintenance(ctx, input); return string(r.Status), r.Message, e
	case "A.7.14_SecureDisposal":
		r, e := m.checkSecureDisposal(ctx, input); return string(r.Status), r.Message, e
	case "A.7.5_PhysicalEnvironmentalThreats":
		r, e := m.checkPhysicalEnvironmentalThreats(ctx, input); return string(r.Status), r.Message, e
	case "A.7.6_WorkingInSecureAreas":
		r, e := m.checkWorkingInSecureAreas(ctx, input); return string(r.Status), r.Message, e
	case "A.7.9_AssetsOffPremises":
		r, e := m.checkAssetsOffPremises(ctx, input); return string(r.Status), r.Message, e
	case "A.8.1_UserEndpointDevices":
		r, e := m.checkUserEndpointDevices(ctx, input); return string(r.Status), r.Message, e
	case "A.8.2_PrivilegedAccess":
		r, e := m.checkPrivilegedAccess(ctx, input); return string(r.Status), r.Message, e
	case "A.8.3_AccessRestriction":
		r, e := m.checkAccessRestriction(ctx, input); return string(r.Status), r.Message, e
	case "A.8.5_SecureAuth":
		r, e := m.checkSecureAuth(ctx, input); return string(r.Status), r.Message, e
	case "A.8.7_MalwareProtection":
		r, e := m.checkMalwareProtection(ctx, input); return string(r.Status), r.Message, e
	case "A.8.8_VulnerabilityManagement":
		r, e := m.checkVulnerabilityManagement(ctx, input); return string(r.Status), r.Message, e
	case "A.8.9_ConfigManagement":
		r, e := m.checkConfigManagement(ctx, input); return string(r.Status), r.Message, e
	case "A.8.12_DataLeakage":
		r, e := m.checkDataLeakage(ctx, input); return string(r.Status), r.Message, e
	case "A.8.16_MonitoringActivities":
		r, e := m.checkMonitoringActivities(ctx, input); return string(r.Status), r.Message, e
	case "A.8.18_PrivilegedUtility":
		r, e := m.checkPrivilegedUtility(ctx, input); return string(r.Status), r.Message, e
	case "A.8.20_NetworkSecurity":
		r, e := m.checkNetworkSecurity(ctx, input); return string(r.Status), r.Message, e
	case "A.8.21_NetworkServices":
		r, e := m.checkNetworkServices(ctx, input); return string(r.Status), r.Message, e
	case "A.8.22_NetworkSegregation":
		r, e := m.checkNetworkSegregation(ctx, input); return string(r.Status), r.Message, e
	case "A.8.23_WebFiltering":
		r, e := m.checkWebFiltering(ctx, input); return string(r.Status), r.Message, e
	case "A.8.24_Cryptography":
		r, e := m.checkCryptography(ctx, input); return string(r.Status), r.Message, e
	case "A.8.25_SDLC":
		r, e := m.checkSDLC(ctx, input); return string(r.Status), r.Message, e
	case "A.8.26_AppSecReqs":
		r, e := m.checkAppSecReqs(ctx, input); return string(r.Status), r.Message, e
	case "A.8.28_SecureCoding":
		r, e := m.checkSecureCoding(ctx, input); return string(r.Status), r.Message, e
	case "A.8.29_SecurityTesting":
		r, e := m.checkSecurityTesting(ctx, input); return string(r.Status), r.Message, e
	case "A.8.31_EnvironmentSeparation":
		r, e := m.checkEnvironmentSeparation(ctx, input); return string(r.Status), r.Message, e
	case "A.8.32_ChangeManagement":
		r, e := m.checkChangeManagement(ctx, input); return string(r.Status), r.Message, e
	case "A.8.33_TestInformation":
		r, e := m.checkTestInformation(ctx, input); return string(r.Status), r.Message, e
	case "A.8.34_AuditTestingDev":
		r, e := m.checkAuditTestingDev(ctx, input); return string(r.Status), r.Message, e
	case "A.8.35_AcceptanceTesting":
		r, e := m.checkAcceptanceTesting(ctx, input); return string(r.Status), r.Message, e
	case "A.8.17_ClockSync":
		r, e := m.checkClockSync(ctx, input); return string(r.Status), r.Message, e
	case "A.8.10_InformationDeletion":
		r, e := m.checkInformationDeletion(ctx, input); return string(r.Status), r.Message, e
	case "A.8.11_DataMasking":
		r, e := m.checkDataMasking(ctx, input); return string(r.Status), r.Message, e
	case "A.8.13_Backup":
		r, e := m.checkBackup(ctx, input); return string(r.Status), r.Message, e
	case "A.8.14_Redundancy":
		r, e := m.checkRedundancy(ctx, input); return string(r.Status), r.Message, e
	case "A.8.4_SourceCodeAccess":
		r, e := m.checkSourceCodeAccess(ctx, input); return string(r.Status), r.Message, e
	case "A.5.19_SupplierSecurity":
		r, e := m.checkSupplierSecurity(ctx, input); return string(r.Status), r.Message, e
	case "A.5.20_SupplierAgreements":
		r, e := m.checkSupplierAgreements(ctx, input); return string(r.Status), r.Message, e
	case "A.5.21_SupplyChain":
		r, e := m.checkSupplyChain(ctx, input); return string(r.Status), r.Message, e
	case "A.5.22_SupplierMonitoring":
		r, e := m.checkSupplierMonitoring(ctx, input); return string(r.Status), r.Message, e
	case "A.5.24_IRPlanning":
		r, e := m.checkIRPlanning(ctx, input); return string(r.Status), r.Message, e
	case "A.5.25_EventAssessment":
		r, e := m.checkEventAssessment(ctx, input); return string(r.Status), r.Message, e
	case "A.5.26_IRResponse":
		r, e := m.checkIRResponse(ctx, input); return string(r.Status), r.Message, e
	case "A.5.27_IRLearning":
		r, e := m.checkIRLearning(ctx, input); return string(r.Status), r.Message, e
	case "A.5.28_EvidenceCollection":
		r, e := m.checkEvidenceCollection(ctx, input); return string(r.Status), r.Message, e
	case "A.5.29_IRDuringDisruption":
		r, e := m.checkIRDuringDisruption(ctx, input); return string(r.Status), r.Message, e
	case "A.5.35_IndependentReview":
		r, e := m.checkIndependentReview(ctx, input); return string(r.Status), r.Message, e
	case "A.5.36_ComplianceReview":
		r, e := m.checkComplianceReview(ctx, input); return string(r.Status), r.Message, e
	case "A.5.38_AuditTesting":
		r, e := m.checkAuditTesting(ctx, input); return string(r.Status), r.Message, e
	default:
		return "", "", nil
	}
}

func TestISO27001_Dependencies_Coverage(t *testing.T) {
	m := NewISO27001Module()
	deps := m.Dependencies()
	if len(deps) != 3 {
		t.Errorf("Dependencies() returned %d items, want 3", len(deps))
	}
}

func TestISO27001_LoggingCoverage(t *testing.T) {
	m := NewISO27001Module()
	ctx := context.Background()

	// Test compliant: audit pattern + integrity pattern with hash_chain
	r, err := m.checkLogging(ctx, []byte("audit_log hash_chain log_integrity"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "compliant" {
		t.Errorf("expected compliant, got %s: %s", r.Status, r.Message)
	}

	// Test partial: audit only, no integrity
	r, err = m.checkLogging(ctx, []byte("audit_log logging_enabled"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "partial" {
		t.Errorf("expected partial, got %s: %s", r.Status, r.Message)
	}

	// Test non_compliant
	r, err = m.checkLogging(ctx, []byte("nothing_here"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if strings.ToLower(string(r.Status)) != "non_compliant" {
		t.Errorf("expected non_compliant, got %s: %s", r.Status, r.Message)
	}
}