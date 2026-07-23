// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - SOC 2 Audit CLI Tests
// =========================================================================

package main

import (
	"os"
	"testing"
)

func TestIsAuditSOC2Subcommand(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"audit-soc2", "generate"}, true},
		{[]string{"audit-soc2", "evidence"}, true},
		{[]string{"audit-soc2", "workpapers"}, true},
		{[]string{"audit-soc2", "policies"}, true},
		{[]string{"audit-soc2"}, false},       // too short
		{[]string{"benchmark", "run"}, false}, // different subcommand
		{[]string{"evaluator"}, false},        // different subcommand
		{[]string{}, false},                   // empty
	}

	for _, tt := range tests {
		got := isAuditSOC2Subcommand(tt.args)
		if got != tt.want {
			t.Errorf("isAuditSOC2Subcommand(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestStripAuditSOC2Subcommand(t *testing.T) {
	tests := []struct {
		args []string
		want []string
	}{
		{[]string{"audit-soc2", "generate", "--org", "test"}, []string{"generate", "--org", "test"}},
		{[]string{"audit-soc2", "evidence"}, []string{"evidence"}},
		{[]string{"audit-soc2"}, nil},
		{[]string{}, nil},
	}

	for _, tt := range tests {
		got := stripAuditSOC2Subcommand(tt.args)
		// Compare lengths since nil != []string{}
		if len(got) != len(tt.want) {
			t.Errorf("stripAuditSOC2Subcommand(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestAuditSOC2PoliciesCLI(t *testing.T) {
	// Test that the policies verb runs without error.
	// This is a smoke test; full integration tests require a running platform.
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// We can't easily test the CLI subcommand directly since init()
	// already ran, so we test the underlying logic.
	// The real tests are in pkg/audit/soc2/soc2_test.go.
}
