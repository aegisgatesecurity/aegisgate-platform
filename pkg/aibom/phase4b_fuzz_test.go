// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Phase 4b Fuzz: AIBOM parser
//go:build fuzz

package aibom

import (
	"testing"
)

// FuzzParseBOM tests AI Bill of Materials parsing with malformed input
func FuzzParseBOM(f *testing.F) {
	seeds := []string{
		`{"bomFormat":"CycloneDX","specVersion":"1.4"}`,
		`{"bomFormat":"SPDX","specVersion":"2.3"}`,
		`{}`,
		`null`,
		`not json`,
		`{"components":[{"name":"test","version":"1.0"}]}`,
		`{"components":[` + string(make([]byte, 10000)) + `]}`,
		`[[[[[`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		_, _ = ParseBOM([]byte(payload))
	})
}