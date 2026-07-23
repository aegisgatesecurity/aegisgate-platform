// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — FedRAMP Module Fuzz Tests
//go:build fuzz

package fedramp

import (
	"context"
	"strings"
	"testing"
)

func FuzzCheckControl(f *testing.F) {
	m := NewFedRAMPModule()
	ctx := context.Background()

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

	seeds := []string{
		`{"rbac": true, "tls": true, "audit_log": true}`,
		`{"mfa": true, "monitoring": true}`,
		``,
		`invalid json`,
		`random text with special chars !@#$%`,
		strings.Repeat("rbac tls audit_log ", 100),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		for _, id := range automatedIDs {
			result, err := m.CheckControl(ctx, id, []byte(input))
			if err != nil {
				t.Errorf("CheckControl(%s) returned error: %v", id, err)
			}
			if result.Status == "" {
				t.Errorf("CheckControl(%s) returned empty status", id)
			}
		}
	})
}

func FuzzAllCheckFuncs(f *testing.F) {
	m := NewFedRAMPModule()
	ctx := context.Background()
	controls := m.Controls()

	seeds := []string{
		`{"rbac": true, "tls": true}`,
		`{}`,
		`not json`,
		`null`,
		strings.Repeat("x", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		for _, c := range controls {
			if c.Automated && c.CheckFunc != nil {
				result, err := c.CheckFunc(ctx, []byte(input))
				if err != nil {
					t.Errorf("CheckFunc(%s) returned error: %v", c.ID, err)
				}
				if result != nil && result.Status == "" {
					t.Errorf("CheckFunc(%s) returned empty status", c.ID)
				}
			}
		}
	})
}

func FuzzControlRegistration(f *testing.F) {
	f.Fuzz(func(t *testing.T, framework string) {
		// Module initialization should never panic regardless of input
		m := NewFedRAMPModule()
		controls := m.Controls()
		if len(controls) != 150 {
			t.Errorf("expected 150 controls, got %d", len(controls))
		}
	})
}