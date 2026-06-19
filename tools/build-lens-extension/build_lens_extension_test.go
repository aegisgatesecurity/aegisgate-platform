// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Unit Tests
// =========================================================================
//
// Unit tests for the build tool. These tests use the
// real Lens source tree at /home/chaos/Desktop/AegisGate/
// lens-repo-bootstrap/src when available; otherwise they
// are skipped.
//
// Run: go test -race ./tools/build-lens-extension/...
// =========================================================================

package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStripTypes_BasicCases verifies the type-stripper
// handles the common cases correctly.
func TestStripTypes_BasicCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{
			name: "interface block",
			in: `export interface Foo {
x: number;
y: string;
}
const a = 1;`,
			out: "\nconst a = 1;",
		},
		{
			name: "type alias single line",
			in:   "export type X = number;",
			out:  "",
		},
		{
			name: "type alias multi-line",
			in: `export type X =
  | { a: 1 }
  | { b: 2 };`,
			out: "",
		},
		{
			name: "import type",
			in:   "import type { Foo } from \"./bar.js\";\nconst a = 1;",
			out:  "const a = 1;",
		},
		{
			name: "as cast",
			in:   "const x = foo as string;",
			out:  "const x = foo;",
		},
		{
			name: "var type",
			in:   "let x: number = 1;",
			out:  "let x = 1;",
		},
		{
			// After the build-3 fix, the type stripper correctly
			// removes parameter type annotations (e.g., `: number`)
			// entirely. The previous behavior left the `: ` in
			// place, producing invalid JS like `function f(x:, y:)`.
			name: "param type",
			in:   "function f(x: number, y: string) { return x; }",
			out:  "function f(x, y) { return x; }",
		},
		{
			name: "return type",
			in:   "function f(): number { return 1; }",
			out:  "function f(){ return 1; }",
		},
		{
			// After the build-3 fix, generic type arguments are
			// stripped. Capital-letter identifiers only; lowercase
			// (variable) identifiers with `<` are preserved as
			// less-than operators.
			name: "generic type arg after new",
			in:   "const m = new Map<string, RegexPattern[]>();",
			out:  "const m = new Map();",
		},
		{
			name: "generic type arg after Set",
			in:   "const set = new Set<Category>();",
			out:  "const set = new Set();",
		},
		{
			name: "generic type arg bare",
			in:   "Promise<void>",
			out:  "Promise",
		},
		{
			name: "generic type arg ReadonlyMap",
			in:   "ReadonlyMap<string, ProviderInfo>",
			out:  "ReadonlyMap",
		},
		{
			// Lowercase identifiers with `<` must NOT be stripped.
			// This is a less-than operator.
			name: "lowercase less-than preserved",
			in:   "arr.filter(x => x < 10)",
			out:  "arr.filter(x => x < 10)",
		},
		{
			name: "lowercase less-than with capital ID",
			in:   "if (a < b && c > d) { foo(); }",
			out:  "if (a < b && c > d) { foo(); }",
		},
		{
			name: "object literal with type-like keys (regression for C-2)",
			in:   "chrome.runtime.sendMessage({ type: \"x\", enabled: true });",
			out:  "chrome.runtime.sendMessage({ type: \"x\", enabled: true });",
		},
		{
			name: "template literal with colon in expression (regression for build-1)",
			in:   "return fail(`unknown field: ${key}`);",
			out:  "return fail(`unknown field: ${key}`);",
		},
		{
			name: "array of strings",
			in:   "const arr: string[] = [\"a\", \"b\"];",
			out:  "const arr = [\"a\", \"b\"];",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := stripTypes(c.in)
			if got != c.out {
				t.Errorf("stripTypes mismatch:\n  in:  %q\n  got: %q\n  want: %q", c.in, got, c.out)
			}
		})
	}
}

// TestSchemaCrossCheck verifies the schema cross-check
// accepts matching Go/TS schemas and rejects mismatches.
func TestSchemaCrossCheck(t *testing.T) {
	goSchema := &Schema{
		Title: "Test",
		Fields: map[string]SchemaField{
			"foo": {Name: "foo", Type: "string", Required: true},
			"bar": {Name: "bar", Type: "int64", Required: false},
		},
	}
	tsSchemaMatching := &Schema{
		Title: "Test",
		Fields: map[string]SchemaField{
			"foo": {Name: "foo", Type: "string", Required: true},
			"bar": {Name: "bar", Type: "number", Required: false},
		},
	}
	tsSchemaMissingField := &Schema{
		Title: "Test",
		Fields: map[string]SchemaField{
			"foo": {Name: "foo", Type: "string", Required: true},
		},
	}
	tsSchemaExtraField := &Schema{
		Title: "Test",
		Fields: map[string]SchemaField{
			"foo": {Name: "foo", Type: "string", Required: true},
			"bar": {Name: "bar", Type: "number", Required: false},
			"baz": {Name: "baz", Type: "string", Required: true},
		},
	}
	tsSchemaTypeMismatch := &Schema{
		Title: "Test",
		Fields: map[string]SchemaField{
			"foo": {Name: "foo", Type: "string", Required: true},
			"bar": {Name: "bar", Type: "boolean", Required: false},
		},
	}

	if err := crossCheckSchemas(goSchema, tsSchemaMatching); err != nil {
		t.Errorf("matching schemas should pass: %v", err)
	}
	if err := crossCheckSchemas(goSchema, tsSchemaMissingField); err == nil {
		t.Error("missing field should fail")
	}
	if err := crossCheckSchemas(goSchema, tsSchemaExtraField); err == nil {
		t.Error("extra field should fail")
	}
	if err := crossCheckSchemas(goSchema, tsSchemaTypeMismatch); err == nil {
		t.Error("type mismatch should fail")
	}
}

// TestBuild_Deterministic runs the build twice with the
// same inputs and asserts the inventory is identical.
func TestBuild_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping deterministic build test in -short mode")
	}
	srcDir := findLensSourceDir(t)
	if srcDir == "" {
		t.Skip("Lens source directory not found; skipping")
	}
	dist1 := t.TempDir()
	dist2 := t.TempDir()
	ts, _ := time.Parse(time.RFC3339, "2026-06-18T00:00:00Z")
	cfg1 := &Config{Src: srcDir, Dist: dist1, Version: "0.1.0", Commit: "deterministic-test", BuildTime: ts, Strict: true}
	cfg2 := &Config{Src: srcDir, Dist: dist2, Version: "0.1.0", Commit: "deterministic-test", BuildTime: ts, Strict: true}
	if err := run(cfg1); err != nil {
		t.Fatalf("build 1: %v", err)
	}
	if err := run(cfg2); err != nil {
		t.Fatalf("build 2: %v", err)
	}
	// Compare inventory hashes.
	h1 := inventoryHash(t, dist1)
	h2 := inventoryHash(t, dist2)
	if h1 != h2 {
		t.Errorf("build is not deterministic: %s != %s", h1, h2)
	}
}

// TestBuild_AllJSValidSyntax runs the build and asserts
// that every emitted .js file is valid JavaScript.
func TestBuild_AllJSValidSyntax(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping build test in -short mode")
	}
	srcDir := findLensSourceDir(t)
	if srcDir == "" {
		t.Skip("Lens source directory not found; skipping")
	}
	dist := t.TempDir()
	cfg := &Config{Src: srcDir, Dist: dist, Version: "0.1.0", Commit: "syntax-test", BuildTime: time.Now(), Strict: true}
	if err := run(cfg); err != nil {
		t.Fatalf("build: %v", err)
	}
	// Walk the dist and check each .js file. We shell out
	// to `node --check` for the actual syntax validation.
	err := filepath.Walk(dist, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".js") {
			return nil
		}
		// Skip the test if `node` is not available.
		if _, err := exec.LookPath("node"); err != nil {
			t.Skip("node not available; skipping syntax check")
		}
		cmd := exec.Command("node", "--check", path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("node --check failed for %s: %v\n%s", path, err, out)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestBuild_LintCatchesForbiddenPatterns verifies the
// linter catches eval, innerHTML, etc.
func TestBuild_LintCatchesForbiddenPatterns(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "bad.ts")
	if err := os.WriteFile(srcFile, []byte("const x = eval('1+1');\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := lintFile(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Error("expected at least one violation for eval()")
	}
	found := false
	for _, v := range vs {
		if v.Rule == "no-eval" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected no-eval rule, got: %+v", vs)
	}
}

// TestBuild_LintCleanFilePasses verifies a clean file has
// no violations.
func TestBuild_LintCleanFilePasses(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "good.ts")
	content := `// SPDX-License-Identifier: Apache-2.0
const x = 1;
const y = "hello";
if (x > 0) { console.info("positive"); }
`
	if err := os.WriteFile(srcFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := lintFile(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) > 0 {
		t.Errorf("expected no violations, got: %+v", vs)
	}
}

// TestMinify_StripsCommentsAndBlankLines verifies the
// minifier reduces a file with comments and blank lines.
func TestMinify_StripsCommentsAndBlankLines(t *testing.T) {
	in := `// Header comment
const x = 1;

/* Block comment
   spanning multiple
   lines
*/
const y = 2;
// Trailing comment
`
	out := minifyJS(in)
	if strings.Contains(out, "// Header") {
		t.Errorf("minifier did not strip line comment: %q", out)
	}
	if strings.Contains(out, "/* Block") {
		t.Errorf("minifier did not strip block comment: %q", out)
	}
}

// TestPackage_WritesValidZip verifies the package step
// produces a valid ZIP file.
func TestPackage_WritesValidZip(t *testing.T) {
	dist := t.TempDir()
	if err := os.WriteFile(filepath.Join(dist, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "b.txt"), []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "test.zip")
	sha, err := writeZipAndHash(dist, zipPath)
	if err != nil {
		t.Fatalf("writeZipAndHash: %v", err)
	}
	// Open the zip and verify it.
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()
	if len(r.File) != 2 {
		t.Errorf("expected 2 files in zip, got %d", len(r.File))
	}
	// SHA is a hex string.
	if _, err := hex.DecodeString(sha); err != nil {
		t.Errorf("invalid SHA-256 hex: %s", sha)
	}
}

// findLensSourceDir returns the path to the Lens source
// directory if it exists, or "" if not.
func findLensSourceDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"/home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src",
		"../../lens-repo-bootstrap/src",
		"../lens-repo-bootstrap/src",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

// inventoryHash returns the SHA-256 of the INVENTORY.txt
// in the given dist directory, with the timestamp line
// blanked out (to make the hash stable across runs).
func inventoryHash(t *testing.T, dist string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dist, "INVENTORY.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// Strip the timestamp line (the second line).
	lines := strings.Split(string(data), "\n")
	if len(lines) > 2 {
		lines[1] = ""
	}
	stripped := strings.Join(lines, "\n")
	h := sha256.Sum256([]byte(stripped))
	return hex.EncodeToString(h[:])
}
