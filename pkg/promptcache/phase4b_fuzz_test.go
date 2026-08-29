// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Phase 4b Fuzz: Prompt attestation parser
//go:build fuzz

package promptcache

import (
	"testing"
)

// FuzzParseAttestation tests attestation JSON parsing with malformed input
func FuzzParseAttestation(f *testing.F) {
	seeds := []string{
		`{"prompt":"hello","model":"gpt-4"}`,
		`{}`,
		`null`,
		`not json`,
		`{"prompt":"` + string(make([]byte, 10000)) + `"}`,
		`[[[[[`,
		`{"prompt":"test","timestamp":"invalid"}`,
		string([]byte{0x00, 0x01, 0x02, 0x03}),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		_, _ = ParseAttestation([]byte(payload))
	})
}