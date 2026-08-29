// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Phase 4b Extended Fuzz Tests
// Tests CVE entry parsing with arbitrary/malformed JSON payloads
//go:build fuzz

package cve

import (
	"testing"
)

// FuzzParseEntry tests CVE JSON parsing against malformed input
func FuzzParseEntry(f *testing.F) {
	seeds := []string{
		`{"cve_id":"CVE-2024-1234","severity":"high"}`,
		`{"cve_id":"","severity":""}`,
		`{}`,
		`null`,
		`not json`,
		`{"cve_id":"CVE-2024-` + string([]byte{0x00, 0x01, 0x02}) + `"}`,
		`{"cve_id":"CVE-2024-9999","severity":"critical","description":"` + string(make([]byte, 10000)) + `"}`,
		`[[[[[[[[[[`,
		`{"a":"b","c":"d","e":"f","g":"h","i":"j"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		// ParseEntry should handle any input without panicking
		_, _ = ParseEntry([]byte(payload))
	})
}