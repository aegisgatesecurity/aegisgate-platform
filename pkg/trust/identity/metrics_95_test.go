// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025-2026, AegisGate Security - All rights reserved

package identity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordRegistration(t *testing.T) {
	assert.NotPanics(t, func() { RecordRegistration() })
}

func TestRecordRevocation(t *testing.T) {
	assert.NotPanics(t, func() { RecordRevocation() })
}

func TestRecordSuspension(t *testing.T) {
	assert.NotPanics(t, func() { RecordSuspension() })
}

func TestRecordReactivation(t *testing.T) {
	assert.NotPanics(t, func() { RecordReactivation() })
}

func TestRecordVerification_Success(t *testing.T) {
	assert.NotPanics(t, func() { RecordVerification(true) })
}

func TestRecordVerification_Failure(t *testing.T) {
	assert.NotPanics(t, func() { RecordVerification(false) })
}

func TestRecordVerificationLatency(t *testing.T) {
	assert.NotPanics(t, func() { RecordVerificationLatency(1.0) })
	assert.NotPanics(t, func() { RecordVerificationLatency(0.001) })
	assert.NotPanics(t, func() { RecordVerificationLatency(0.0) })
	assert.NotPanics(t, func() { RecordVerificationLatency(0.5) })
}

func TestRecordKeyRotation(t *testing.T) {
	assert.NotPanics(t, func() { RecordKeyRotation() })
}

func TestMetrics_SequentialCalls(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordRegistration()
		RecordRegistration()
		RecordRegistration()
	})
	assert.NotPanics(t, func() {
		RecordVerification(true)
		RecordVerification(false)
		RecordVerification(true)
	})
}

func TestRecordVerificationLatency_VariousValues(t *testing.T) {
	testValues := []float64{0.0001, 0.001, 0.01, 0.1, 0.5, 1.0, 2.5}
	for _, v := range testValues {
		assert.NotPanics(t, func() { RecordVerificationLatency(v) })
	}
}
