// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Packager
// =========================================================================
//
// package.go packages the dist/ directory into a single
// ZIP file and emits an INVENTORY.txt listing every file
// in the dist/ directory with its SHA-256 hash. The
// INVENTORY.txt is the source of truth for the release
// artifact identity; any change to the contents of the
// ZIP changes the INVENTORY and the artifact's SHA-256.
//
// The ZIP is a standard `archive/zip` Writer with deflate
// compression level 9 (maximum). The output filename is
//
//   lens-<version>-<short-sha>.zip
//
// (e.g., lens-0.1.0-ca9b16d.zip).
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// package_ packages the dist/ directory into a ZIP. The
// "package" name in Go is taken, so we use "package_" with
// a trailing underscore.
func package_(cfg *Config) error {
	// Compute the output filename.
	shortSHA := cfg.Commit
	if len(shortSHA) > 7 {
		shortSHA = shortSHA[:7]
	}
	zipName := fmt.Sprintf("lens-%s-%s.zip", cfg.Version, shortSHA)
	zipPath := filepath.Join(filepath.Dir(cfg.Dist), zipName)
	// Open the ZIP file. We must Close() the writer before
	// reading the file back for the SHA-256, but the defers
	// would Close() them in the wrong order (file then
	// writer; we need writer then file). We use explicit
	// Close() calls and skip the defers.
	zipSHA, err := writeZipAndHash(cfg.Dist, zipPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "packaged: %s\n  sha256: %s\n", zipPath, zipSHA)
	return nil
}

// writeZipAndHash writes distDir as a ZIP at zipPath and
// returns the SHA-256 of the resulting file.
func writeZipAndHash(distDir, zipPath string) (string, error) {
	zf, err := os.Create(zipPath) // #nosec G304 G306 G703 -- zipPath is built by the build tool from CLI args
	if err != nil {
		return "", fmt.Errorf("create %s: %w", zipPath, err)
	}
	zw := zip.NewWriter(zf)
	err = filepath.Walk(distDir, func(path string, info os.FileInfo, err error) error { // #nosec G122 G703 -- distDir is the build's own output directory, created by this build tool, not a network-reachable or user-writable path
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(distDir, path) // #nosec G304 G703 -- path is from filepath.Walk of this build's own output directory
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		hdr := &zip.FileHeader{
			Name:   rel,
			Method: zip.Deflate,
		}
		hdr.SetMode(0o644) // #nosec G306 -- ZIP entry mode, not a file mode
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return fmt.Errorf("zip header %s: %w", rel, err)
		}
		f, err := os.Open(path) // #nosec G122 G304 G703 -- path is from filepath.Walk of this build's own output directory
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			return fmt.Errorf("copy %s: %w", path, err)
		}
		return nil
	})
	if err != nil {
		_ = zw.Close()
		_ = zf.Close()
		return "", err
	}
	// Close the writer first (flushes the central directory),
	// then close the file.
	if err := zw.Close(); err != nil {
		_ = zf.Close()
		return "", fmt.Errorf("close zip writer: %w", err)
	}
	if err := zf.Close(); err != nil {
		return "", fmt.Errorf("close zip file: %w", err)
	}
	// Now hash the file.
	zipSHA, err := fileSHA256(zipPath)
	if err != nil {
		return "", fmt.Errorf("hash zip: %w", err)
	}
	return zipSHA, nil
}

// emitInventory writes INVENTORY.txt to the dist/ directory.
// INVENTORY.txt lists every file in dist/ with its SHA-256.
// It is the source of truth for the release artifact identity.
func emitInventory(cfg *Config) error {
	type entry struct {
		path string
		sha  string
	}
	var entries []entry
	err := filepath.Walk(cfg.Dist, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		sha, err := fileSHA256(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(cfg.Dist, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		entries = append(entries, entry{path: rel, sha: sha})
		return nil
	})
	if err != nil {
		return err
	}
	// Sort by path for deterministic output.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].path < entries[j].path
	})
	// Write the inventory.
	var b strings.Builder
	b.WriteString("# AegisGate Lens Build Inventory\n")
	b.WriteString("# Build: " + cfg.Version + " (" + cfg.Commit + ")\n")
	b.WriteString("# Time:  " + cfg.BuildTime.Format("2006-01-02T15:04:05Z") + "\n")
	b.WriteString("# Each file's SHA-256 is the source of truth for the release artifact identity.\n")
	b.WriteString("\n")
	for _, e := range entries {
		b.WriteString(e.sha)
		b.WriteString("  ")
		b.WriteString(e.path)
		b.WriteString("\n")
	}
	inventoryPath := filepath.Join(cfg.Dist, "INVENTORY.txt")
	if err := os.WriteFile(inventoryPath, []byte(b.String()), 0o644); err != nil { // #nosec G304 G306 -- INVENTORY.txt is this build's own output; writing to the build output directory
		return fmt.Errorf("write inventory: %w", err)
	}
	return nil
}

// fileSHA256 returns the SHA-256 of a file as a hex string.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- path comes from filepath.Walk of this build's own output directory
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
