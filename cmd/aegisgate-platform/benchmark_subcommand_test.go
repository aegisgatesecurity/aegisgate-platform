// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Benchmark CLI subcommand tests

package main

import (
	"os"
	"strings"
	"testing"
)

func TestIsBenchmarkSubcommand(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{[]string{"benchmark"}, true},
		{[]string{"benchmark", "run"}, true},
		{[]string{"benchmark", "--help"}, true},
		{[]string{"evaluator"}, false},
		{[]string{"serve"}, false},
		{[]string{}, false},
	}
	for _, tt := range tests {
		got := isBenchmarkSubcommand(tt.args)
		if got != tt.want {
			t.Errorf("isBenchmarkSubcommand(%v): got %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestStripBenchmarkSubcommand(t *testing.T) {
	got := stripBenchmarkSubcommand([]string{"benchmark", "run", "--facet=secrets"})
	if len(got) != 2 || got[0] != "run" || got[1] != "--facet=secrets" {
		t.Errorf("stripBenchmarkSubcommand: got %v, want [run --facet=secrets]", got)
	}
}

func TestBenchmarkListRecords(t *testing.T) {
	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runBenchmarkListRecords([]string{"--facet=xss"})

	w.Close()
	os.Stdout = oldStdout

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "SXC Corpus") {
		t.Errorf("list-records output missing 'SXC Corpus': %s", output[:min(200, len(output))])
	}
	if !strings.Contains(output, "xss_script_tag") {
		t.Errorf("list-records output missing 'xss_script_tag': %s", output[:min(200, len(output))])
	}
}

func BenchmarkRunBenchmarkSubcommand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		isBenchmarkSubcommand([]string{"benchmark", "run"})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}