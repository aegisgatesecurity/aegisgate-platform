// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Phase 4b Fuzz: HMAC header parser, tier parser, locale parser
//go:build fuzz

package acp

import (
	"testing"
)

// FuzzParseHMACHeader tests HMAC header parsing with arbitrary input
func FuzzParseHMACHeader(f *testing.F) {
	seeds := []string{
		"t=1234567890,s=abc123def456",
		"t=,s=",
		"",
		"t=abc,s=xyz",
		"no commas here",
		"t=" + string(make([]byte, 1000)) + ",s=short",
		"t=1;s=2",
		"t=1,s=2,extra=3",
		string([]byte{0x00, 0x01, 0x02, 0x03}),
		"t=1234567890,s=" + string(make([]byte, 256)),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		_, _, _ = ParseHMACHeader(header)
	})
}
