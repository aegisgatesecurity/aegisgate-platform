// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - ACP Metrics Tests

package acp

import (
	"testing"
)

func TestRecordMessage(t *testing.T) {
	// Test recording an allowed message
	RecordMessage("agent.invoke", true, 1024)
	RecordMessage("agent.invoke", true, 2048)
}

func TestRecordMessageBlocked(t *testing.T) {
	// Test recording a blocked message
	RecordMessage("admin.shutdown", false, 512)
}

func TestRecordHMACVerificationSuccess(t *testing.T) {
	RecordHMACVerification(true, false)
}

func TestRecordHMACVerificationExpired(t *testing.T) {
	RecordHMACVerification(false, true)
}

func TestRecordHMACVerificationFailed(t *testing.T) {
	RecordHMACVerification(false, false)
}

func TestRecordRateLimitHit(t *testing.T) {
	RecordRateLimitHit("user-123")
	RecordRateLimitHit("user-456")
}

func TestRecordScanDuration(t *testing.T) {
	RecordScanDuration("response", 0.025)
	RecordScanDuration("message", 0.050)
}

func TestRecordDetectedPII(t *testing.T) {
	RecordDetectedPII("email")
	RecordDetectedPII("ssn")
	RecordDetectedPII("phone")
}

func TestRecordDetectedSecret(t *testing.T) {
	RecordDetectedSecret("api_key")
	RecordDetectedSecret("password")
	RecordDetectedSecret("token")
}

func TestRecordBlockedMethod(t *testing.T) {
	RecordBlockedMethod("admin.shutdown")
	RecordBlockedMethod("system.reboot")
}

func TestSetGuardEnabledMetric(t *testing.T) {
	SetGuardEnabled(true)
	SetGuardEnabled(false)
}

func TestSetActiveSessionsMetricMetric(t *testing.T) {
	SetActiveSessions(5)
	SetActiveSessions(10)
	SetActiveSessions(0)
}

func TestMetricsIntegration(t *testing.T) {
	// Simulate full ACP message flow with metrics
	RecordMessage("agent.invoke", true, 1024)
	RecordHMACVerification(true, false)
	RecordScanDuration("response", 0.025)
	RecordDetectedPII("email")
	RecordDetectedSecret("api_key")
	SetActiveSessions(1)
}
