// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Phase 4b Fuzz: RBAC user role and permission parsers
//go:build fuzz

package rbac

import (
	"testing"
)

// FuzzParseUserRole tests role parsing with arbitrary input
func FuzzParseUserRole(f *testing.F) {
	seeds := []string{
		"admin",
		"standard",
		"restricted",
		"viewer",
		"",
		"ADMIN",
		"invalid",
		string(make([]byte, 1000)),
		"admin\x00standard",
		"admin;DROP TABLE roles",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = ParseUserRole(s)
	})
}

// FuzzParsePermission tests permission parsing with arbitrary input
func FuzzParsePermission(f *testing.F) {
	seeds := []string{
		"read",
		"write",
		"admin",
		"execute",
		"",
		"READ",
		"invalid",
		string(make([]byte, 1000)),
		"read\x00write",
		"read;DROP TABLE permissions",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = ParsePermission(s)
	})
}