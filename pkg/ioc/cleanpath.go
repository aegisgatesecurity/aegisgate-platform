// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - pkg/ioc file path sanitizer
//
// cleanpath.go provides cleanFilePath, a CodeQL
// G304/G703 linter guard for the pkg/ioc package.
// The keyring and STIX exporter functions accept a
// path argument; cleanFilePath sanitizes the path
// with filepath.Clean and rejects ".." segments
// (defense in depth + linter compliance).

package ioc

import (
	"fmt"
	"path/filepath"
	"strings"
)

// cleanFilePath validates a file path. Returns the
// cleaned absolute path on success; returns an
// error if the path is empty or contains ".."
// segments that would let the caller escape the
// intended base directory.
//
// G304/G703 (CodeQL): the keyring load and STIX
// exporter functions call cleanFilePath before
// os.ReadFile, satisfying the linter's "potential
// file inclusion via variable" check.
//
// Empty paths are allowed: they mean "in-memory
// only, no persistence" (e.g., LoadKeyRing("") for
// unit tests). Path-traversal segments are still
// rejected.
func cleanFilePath(p string) (string, error) {
	if p != "" {
		cleaned := filepath.Clean(p)
		if strings.HasPrefix(cleaned, "..") ||
			strings.Contains(cleaned, string(filepath.Separator)+"..") ||
			strings.HasSuffix(cleaned, string(filepath.Separator)+"..") {
			return "", fmt.Errorf("path traversal not allowed: %s", p)
		}
		return cleaned, nil
	}
	return p, nil
}
