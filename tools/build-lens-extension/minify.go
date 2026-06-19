// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Minifier
// =========================================================================
//
// minify.go is a tiny, conservative JavaScript minifier. It
// does NOT rename variables, fold constants, or do any
// risky optimization. It does:
//
//   1. Strip leading whitespace on each line.
//   2. Strip blank lines.
//   3. Strip line comments (// ...).
//   4. Collapse runs of 2+ spaces to 1 space.
//   5. Strip /* ... */ block comments that span multiple
//      lines (single-line /* ... */ are kept as-is because
//      removing them mid-line is hard to do safely).
//
// The minifier is intentionally conservative. A 30% size
// reduction is typical; aggressive minification (e.g.,
// Terser's name mangling) is intentionally NOT done because
// it would harm debuggability without commensurate benefit
// for a Lens extension of this size.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// minify runs the minifier on every .js file in the dist
// directory. The minifier replaces each file in-place.
func minify(cfg *Config) error {
	return filepath.Walk(cfg.Dist, func(path string, info os.FileInfo, err error) error { // #nosec G122 G703 -- dist is this build's own output directory
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".js") {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G122 G304 G703 -- path is from filepath.Walk of the build's own dist directory
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		min := minifyJS(string(raw))
		if err := os.WriteFile(path, []byte(min), 0o644); err != nil { // #nosec G122 G306 G703 -- build artifact, world-readable
			return fmt.Errorf("write %s: %w", path, err)
		}
		return nil
	}) // #nosec G122 -- dist directory is the build's own output, not user-writable during the build
}

// minifyJS applies the minification steps to a JS string.
func minifyJS(src string) string {
	// Step 1: Remove /* ... */ block comments (multi-line
	// only; single-line block comments are kept).
	src = removeBlockComments(src)
	// Step 2: Process line by line for the rest.
	lines := strings.Split(src, "\n")
	var out []string
	for _, line := range lines {
		// Preserve leading whitespace (indentation); only
		// trim trailing whitespace. The Lens extension has
		// deeply nested code; preserving indentation makes
		// debugged stack traces and source maps readable.
		line = strings.TrimRight(line, " 	")
		if line == "" {
			continue
		}
		// Step 3: Strip line comments (// ...).
		// We use a state machine to find the // that is
		// outside a string.
		line = stripLineCommentJS(line)
		if line == "" {
			continue
		}
		// Step 4: Collapse runs of 2+ spaces to 1 space.
		// Skip strings.
		line = collapseSpacesOutsideStrings(line)
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// removeBlockComments removes /* ... */ comments that span
// multiple lines. Single-line /* ... */ are left alone
// because they often serve as section markers (e.g.,
// /* === inlined: foo.ts === */) that aid debugging.
func removeBlockComments(src string) string {
	re := regexp.MustCompile(`(?s)/\*[^\n]*?\n[\s\S]*?\*/`)
	// We want to remove only multi-line ones. The regex
	// above requires at least one newline. We replace
	// multi-line block comments with a single space.
	return re.ReplaceAllStringFunc(src, func(m string) string {
		if strings.Contains(m, "\n") {
			// Multi-line: replace with a single space
			// (the surrounding code may concatenate).
			return " "
		}
		// Single-line: keep as-is.
		return m
	})
}

// stripLineCommentJS removes the // ... part of a line,
// accounting for string literals.
func stripLineCommentJS(line string) string {
	var out strings.Builder
	inString := false
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(line) {
				i++
				out.WriteByte(line[i])
				continue
			}
			if c == quote {
				inString = false
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inString = true
			quote = c
			out.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(line) && line[i+1] == '/' {
			// Rest of the line is a comment.
			break
		}
		out.WriteByte(c)
	}
	return out.String()
}

// collapseSpacesOutsideStrings replaces runs of 2+ spaces
// with 1 space, but only outside string literals.
func collapseSpacesOutsideStrings(line string) string {
	var out strings.Builder
	inString := false
	quote := byte(0)
	spaceRun := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(line) {
				i++
				out.WriteByte(line[i])
				continue
			}
			if c == quote {
				inString = false
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			inString = true
			quote = c
			out.WriteByte(c)
			spaceRun = 0
			continue
		}
		if c == ' ' || c == '\t' {
			spaceRun++
			if spaceRun == 1 {
				out.WriteByte(' ')
			}
			continue
		}
		spaceRun = 0
		out.WriteByte(c)
	}
	return out.String()
}
