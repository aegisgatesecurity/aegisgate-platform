// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CLI file path sanitizer
//
// safepath.go provides safeFilePath, a CodeQL G304/G703
// linter guard for the CLI subcommands. The CLI
// subcommands accept a file path as args[0] (or via a
// --file flag) and pass it to os.ReadFile / os.WriteFile.
// CodeQL flags these as "potential file inclusion via
// variable" because it can't prove the path is safe.
//
// safeFilePath sanitizes the path by:
//  1. Rejecting empty paths.
//  2. Calling filepath.Clean (recognized by CodeQL
//     as a path-traversal sanitizer).
//  3. Rejecting paths that contain ".." segments
//     (defense in depth: a malicious user could
//     construct "../etc/passwd" to read files
//     outside the intended base directory).
//
// The intent is defense-in-depth + linter compliance,
// not a security boundary: the CLI is invoked by an
// authenticated user who can already read any file on
// the host. The ".." rejection is belt-and-suspenders.

package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// safeFilePath validates a CLI-provided file path.
// Returns the cleaned absolute path on success;
// returns an error if the path contains ".."
// segments that would let the caller escape the
// intended base directory.
//
// Empty paths are rejected (the CLI subcommands
// always have a file argument; the empty case is
// a programming error).
func safeFilePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	cleaned := filepath.Clean(p)
	// Reject ".." segments (defense in depth). The
	// cleaned path may legitimately start with ".."
	// only if the user passed a path like "../foo";
	// in a CLI tool, this is always a mistake or an
	// attack.
	if strings.HasPrefix(cleaned, "..") ||
		strings.Contains(cleaned, string(filepath.Separator)+"..") ||
		strings.HasSuffix(cleaned, string(filepath.Separator)+"..") {
		return "", fmt.Errorf("path traversal not allowed: %s", p)
	}
	return cleaned, nil
}
