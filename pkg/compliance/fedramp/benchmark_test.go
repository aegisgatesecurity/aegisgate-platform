// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — FedRAMP Module Performance Benchmarks

package fedramp

import (
	"context"
	"testing"
)

func BenchmarkAllAutomatedChecks(b *testing.B) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	compliantConfig := []byte(`{
		"authentication": true, "auth_enabled": true, "rbac": true, "roles": ["admin", "user"],
		"session_timeout": 1800, "idle_timeout": "5m", "mfa": true, "multi_factor": true, "2fa": true,
		"tls": true, "https": true, "tls1.2": true, "tls1.3": true, "fips_mode": true, "fips_140": true,
		"audit_log": true, "audit_enabled": true, "log_integrity": true, "hash_chain": true,
		"logging_enabled": true, "monitoring": true, "access_policy": true, "policy_enforcement": true,
		"least_privilege": true, "health_check": true, "public_status": true, "trust_portal": true,
		"anomaly_detection": true, "alert": true, "audit_search": true,
		"mtls": true, "device_id": true, "password_policy": true, "key_rotation": true,
		"mask": true, "key_management": true, "multi_tenant": true, "data_segregation": true,
		"proxy": true, "egress_filter": true, "rate_limiting": true, "network_policy": true,
		"encryption_at_rest": true, "csrf_token": true,
		"sbom": true, "aibom": true, "cyclonedx": true, "version": "1.0",
		"scanner": true, "vulnerability": true, "ioc": true, "incident_response": true,
		"tracking": true, "notification": true, "siem": true,
		"ccm": true, "scan": true, "compliance": true, "threat": true,
		"input_validation": true, "prompt_injection": true,
		"change_log": true, "config_audit": true, "secure_default": true,
		"attestation": true, "trust": true, "git": true,
		"safe_errors": true, "error_handling": true, "remediation": true, "sla_enabled": true,
		"backup": true, "persistence": true, "backup_schedule": true, "schedule": true,
		"isolation": true, "security_boundary": true, "sandbox": true,
		"dos_protection": true, "rate_limiting": true, "throttling": true, "circuit_breaker": true,
		"port_restrictions": true, "minimal_services": true,
		"software_usage": true, "license_compliance": true, "information_location": true,
		"data_classification": true, "retention_policy": true,
		"non_disruptive": true, "safe_mode": true
	}`)

	automatedIDs := []string{
		"FedRAMP-AC-2", "FedRAMP-AC-3", "FedRAMP-AC-6", "FedRAMP-AC-14", "FedRAMP-AC-17",
		"FedRAMP-AU-2", "FedRAMP-AU-3", "FedRAMP-AU-6", "FedRAMP-AU-9", "FedRAMP-AU-12",
		"FedRAMP-IA-2", "FedRAMP-IA-3", "FedRAMP-IA-5", "FedRAMP-IA-6", "FedRAMP-IA-7",
		"FedRAMP-SC-3", "FedRAMP-SC-4", "FedRAMP-SC-5", "FedRAMP-SC-7", "FedRAMP-SC-8",
		"FedRAMP-SC-12", "FedRAMP-SC-13", "FedRAMP-SC-23", "FedRAMP-SC-28", "FedRAMP-SC-39",
		"FedRAMP-CM-3", "FedRAMP-CM-5", "FedRAMP-CM-6", "FedRAMP-CM-7", "FedRAMP-CM-8",
		"FedRAMP-CM-10", "FedRAMP-CM-12",
		"FedRAMP-SI-2", "FedRAMP-SI-7", "FedRAMP-SI-10", "FedRAMP-SI-11", "FedRAMP-SI-14",
		"FedRAMP-IR-4", "FedRAMP-IR-5", "FedRAMP-IR-6",
		"FedRAMP-SA-22", "FedRAMP-SR-4",
		"FedRAMP-RA-3", "FedRAMP-RA-4", "FedRAMP-RA-5", "FedRAMP-RA-6",
		"FedRAMP-CA-7",
		"FedRAMP-CP-9", "FedRAMP-MP-6",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, id := range automatedIDs {
			m.CheckControl(ctx, id, compliantConfig)
		}
	}
}

func BenchmarkCheckControlDispatch(b *testing.B) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	input := []byte(`{"rbac": true, "tls": true, "audit_log": true}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.CheckControl(ctx, "FedRAMP-AC-2", input)
	}
}

func BenchmarkModuleInitialization(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewFedRAMPModule()
	}
}

func BenchmarkEvidenceMappedIteration(b *testing.B) {
	m := NewFedRAMPModule()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		controls := m.Controls()
		for _, c := range controls {
			if !c.Automated {
				_ = c.ID
			}
		}
	}
}

func BenchmarkAllControlsParallel(b *testing.B) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	input := []byte(`{"rbac": true, "tls": true, "audit_log": true, "monitoring": true}`)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.CheckControl(ctx, "FedRAMP-AC-2", input)
		}
	})
}
