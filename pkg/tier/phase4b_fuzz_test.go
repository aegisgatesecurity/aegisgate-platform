// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Phase 4b Fuzz: Tier parser and locale parser
//go:build fuzz

package tier

import (
	"testing"
)

// FuzzParseTier tests tier name parsing with arbitrary input
func FuzzParseTier(f *testing.F) {
	seeds := []string{
		"community",
		"professional",
		"enterprise",
		"",
		"COMMUNITY",
		"invalid",
		string(make([]byte, 1000)),
		"community\x00professional",
		"community;DROP TABLE tiers",
		"' OR '1'='1",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		_, _ = ParseTier(name)
	})
}
