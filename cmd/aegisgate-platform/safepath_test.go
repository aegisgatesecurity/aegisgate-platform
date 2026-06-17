// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CLI file path sanitizer tests
//
// safepath_test.go covers the safeFilePath helper used
// to satisfy CodeQL G304/G703 linter alerts. The
// helper rejects empty paths and paths containing
// ".." segments; it accepts all other paths after
// filepath.Clean normalization.

package main

import (
	"strings"
	"testing"
)

func TestSafeFilePath_Empty(t *testing.T) {
	// CLI subcommands always have a file argument;
	// empty paths are rejected as a programming error.
	if _, err := safeFilePath(""); err == nil {
		t.Errorf("safeFilePath(\"\") should fail")
	}
}

func TestSafeFilePath_Valid(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"foo.json", "foo.json"},
		{"path/to/foo.json", "path/to/foo.json"},
		{"./foo.json", "foo.json"},
		{"path/./to/foo.json", "path/to/foo.json"},
		{"path//to/foo.json", "path/to/foo.json"},
		{"foo/../bar", "bar"},
	}
	for _, c := range cases {
		got, err := safeFilePath(c.input)
		if err != nil {
			t.Errorf("safeFilePath(%q) returned error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("safeFilePath(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestSafeFilePath_Traversal(t *testing.T) {
	// Paths that try to escape via ".." should be
	// rejected. After filepath.Clean:
	//   "../foo" -> "../foo" (still starts with ..)
	//   "foo/../../etc/passwd" -> "../etc/passwd" (starts with ..)
	//   "path/to/../../../etc/passwd" -> "../etc/passwd" (starts with ..)
	//   "foo/../bar" -> "bar" (no longer has ..)  -- ACCEPTED
	cases := []string{
		"..",
		"../foo",
		"path/to/../../../etc/passwd",
	}
	for _, input := range cases {
		_, err := safeFilePath(input)
		if err == nil {
			t.Errorf("safeFilePath(%q) should fail (path traversal)", input)
			continue
		}
		if !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("safeFilePath(%q) error should mention 'path traversal', got: %v", input, err)
		}
	}
}

func TestSafeFilePath_Absolute(t *testing.T) {
	// Absolute paths are accepted (CLI subcommands
	// may receive absolute paths from the user).
	// The ".." check is the actual security control.
	cases := []string{
		"/tmp/foo.json",
		"/etc/passwd", // dangerous in principle, but the CLI runs as the user
	}
	for _, input := range cases {
		got, err := safeFilePath(input)
		if err != nil {
			t.Errorf("safeFilePath(%q) returned error: %v", input, err)
			continue
		}
		if got != input {
			t.Errorf("safeFilePath(%q) = %q, want %q", input, got, input)
		}
	}
}
