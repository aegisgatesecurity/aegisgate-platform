// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Bundler
// =========================================================================
//
// bundle.go reads the TypeScript source files (which are
// hand-written ES2020 with .ts extensions on import paths)
// and emits a single JavaScript file per entry point.
//
// The bundler does NOT transpile. The source is already
// ES2020; the only transformation is:
//   1. Resolve relative imports (./foo, ../bar/foo) and
//      inline the imported file's source.
//   2. Rewrite .ts imports to .js (the convention is that
//      the source uses .ts for type-aware editors but the
//      emitted JS uses .js for the browser).
//   3. Remove TypeScript type annotations (interface, type,
//      as casts) so the JS is valid in a browser.
//
// Step 3 is the most error-prone. We use a regex-based
// type stripper that handles:
//   - `interface Foo { ... }` (block-level removal)
//   - `type Foo = ...;` (line-level removal)
//   - `function f(x: T): U { ... }` (parameter/return type)
//   - `const x: T = ...;` (variable type)
//   - `as Type` casts (expression-level removal)
//   - generic `Foo<T>` after `:` or `as`
//   - `export type` / `export interface`
//   - `/** @type {...} */` JSDoc
//
// The type stripper is intentionally simple. Hand-written
// v0.1 source uses no advanced TypeScript features. If the
// source evolves to use generics in tricky places, the
// stripper may need to be updated. The unit tests assert
// the output is valid JavaScript via `node --check`.
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

// entryPoint describes a single bundled output: the source
// file to bundle, and the output path relative to the dist
// directory.
type entryPoint struct {
	SrcRel string // e.g., "content.ts"
	OutRel string // e.g., "content.js"
}

// entryPoints is the list of bundle outputs in v0.1.
var entryPoints = []entryPoint{
	{"content.ts", "content.js"},
	{"service-worker.ts", "service-worker.js"},
	{"popup.ts", "popup/popup.js"},
	{"welcome.ts", "welcome.js"},
}

// bundle runs the bundling for every entry point. Each
// entry point reads its source file plus all transitively
// imported files, applies the type stripper, and writes
// the result to the output path.
func bundle(cfg *Config) error {
	seen := make(map[string]bool)
	for _, ep := range entryPoints {
		// Reset the seen map for each entry point so we
		// don't share module state across bundles.
		seen = make(map[string]bool)
		src, err := bundleFile(cfg.Src, ep.SrcRel, seen)
		if err != nil {
			return fmt.Errorf("bundle %s: %w", ep.SrcRel, err)
		}
		// Apply the type stripper.
		js := stripTypes(src)
		// Write the output.
		// ep.OutRel is a hardcoded entry-point path (e.g.,
		// "content.js"); the build tool's entryPoints
		// table is the only source. G703 (path traversal)
		// and G304 (file inclusion) are false positives.
		outPath := filepath.Join(cfg.Dist, ep.OutRel)                     // #nosec G304 G703 -- entry-point path is hardcoded in this package
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil { // #nosec G301 G703 -- build artifact directory needs world-readable for upload; outPath is hardcoded
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
		}
		if err := os.WriteFile(outPath, []byte(js), 0o644); err != nil { // #nosec G304 G306 G703 -- build artifact, world-readable; outPath is from hardcoded entryPoints table
			return fmt.Errorf("write %s: %w", outPath, err)
		}
	}
	// Copy the manifest and HTML files verbatim (they are
	// already valid for the browser).
	for _, f := range []string{"manifest.json", "popup.html", "welcome.html"} {
		src, err := os.ReadFile(filepath.Join(cfg.Src, f)) // #nosec G304 G703 -- file list is hardcoded; cfg.Src is a developer CLI arg
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		outPath := filepath.Join(cfg.Dist, f)                             // #nosec G703 -- file list is hardcoded
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil { // #nosec G301 G703 -- build artifact directory; outPath is hardcoded
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
		}
		if err := os.WriteFile(outPath, src, 0o644); err != nil { // #nosec G304 G306 G703 -- build artifact, world-readable, hardcoded path
			return fmt.Errorf("write %s: %w", outPath, err)
		}
	}
	// For popup.html and welcome.html, the <script src="popup.js">
	// tags are already correct (refer to the bundled output).
	// No rewriting needed.
	return nil
}

// bundleFile reads a source file, resolves its imports, and
// returns the bundled source. The seen map prevents infinite
// loops on circular imports (v0.1 has none, but be safe).
//
// Import path resolution:
//   - Relative imports ("./foo", "../bar") are resolved
//     against the directory of the importing file.
//   - The extension is rewritten: the source uses .ts (for
//     type-aware editors) but the bundled output uses .js
//     (which is what the browser sees). When the bundler
//     encounters an import with .js, it strips the .js
//     and looks for the corresponding .ts file.
//   - Bare imports (e.g., "transformers.js") are an error:
//     the Lens has no third-party deps. The bundler fails
//     the build if it sees one.
func bundleFile(srcDir, rel string, seen map[string]bool) (string, error) {
	if seen[rel] {
		return "", nil // already included
	}
	seen[rel] = true
	path := filepath.Join(srcDir, rel)
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- rel is a relative path from a regex match on an `import` line; build tool is developer-controlled
	if err != nil {
		// If the file has a .js extension and the .ts
		// version exists, try that. This handles the case
		// where the source uses .ts imports but the regex
		// captures .js (which we then rewrite).
		if strings.HasSuffix(rel, ".js") {
			tsRel := strings.TrimSuffix(rel, ".js") + ".ts"
			tsPath := filepath.Join(srcDir, tsRel)
			if _, err := os.Stat(tsPath); err == nil { // #nosec G304 G703 -- tsPath is derived from rel from a regex match on an `import` line
				raw, err = os.ReadFile(tsPath)
				if err != nil {
					return "", fmt.Errorf("read %s: %w", tsPath, err)
				}
				rel = tsRel
				path = tsPath
			}
		}
		if raw == nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
	}
	src := string(raw)
	// Find and resolve imports. We use a regex to find
	// `import ... from "./foo.ts"` or `import ... from "../bar.js"`.
	// Type-only imports (`import type`) are stripped entirely
	// (no inlining needed; they're erased at runtime).
	//
	// Multi-line imports are supported: the `...` between
	// `import` and `from` can span newlines.
	importPat := regexp.MustCompile(`(?m)^import\s+(?:\{[\s\S]*?\}|\*\s+as\s+\w+|\w+)(?:\s*,\s*\{[\s\S]*?\})?\s+from\s+["']([^"']+)["'];?\s*$`)
	out := src
	for _, m := range importPat.FindAllStringSubmatch(src, -1) {
		importPath := m[1]
		// Resolve relative to the current file.
		dir := filepath.Dir(rel)
		resolved := filepath.Join(dir, importPath)
		resolved = filepath.Clean(resolved)
		// Normalize path separators (Windows compatibility).
		resolved = filepath.ToSlash(resolved)
		// Recursively bundle.
		nested, err := bundleFile(srcDir, resolved, seen)
		if err != nil {
			return "", fmt.Errorf("resolve import %s in %s: %w", importPath, rel, err)
		}
		// Replace the import line with the inlined source.
		// The replacement is the inlined source plus a comment
		// naming the file, so stack traces in the browser are
		// still debuggable.
		marker := fmt.Sprintf("/* === inlined: %s === */\n", resolved)
		out = strings.Replace(out, m[0], marker+nested, 1)
	}
	// Remove `import type { ... } from "..."` lines entirely
	// (they don't have a value, just a type). Multi-line supported.
	typeImportPat := regexp.MustCompile(`(?m)^import\s+type\s+[\s\S]*?from\s+["'][^"']+["'];?\s*\n`)
	out = typeImportPat.ReplaceAllString(out, "")
	return out, nil
}

// stripTypes removes TypeScript type annotations from a
// JavaScript source. The result is valid ES2020 JavaScript.
//
// The stripper handles:
//   - `interface Foo { ... }` (block-level removal)
//   - `type Foo = ...;` (line-level removal)
//   - `import type { ... } from "..."` (line-level removal)
//   - `import { type Foo } from "..."` (inline type imports)
//   - parameter and return type annotations
//   - variable type annotations
//   - `as Type` casts
//   - `<Type>` casts in expressions
//
// The stripper is intentionally conservative. Anything it
// doesn't understand is left as-is, and `node --check` in
// the test will fail if the result is invalid JS.
func stripTypes(src string) string {
	// Step 1: Remove `interface Foo { ... }` blocks.
	src = removeInterfaceBlocks(src)
	// Step 2: Remove `type Foo = ...;` lines.
	src = removeTypeAliasLines(src)
	// Step 3: Remove `import type { ... }` and `import { type X }` lines.
	src = removeTypeOnlyImports(src)
	// Step 4: Remove `as Type` casts.
	src = regexp.MustCompile(`\s+as\s+[A-Za-z_][A-Za-z0-9_<>,\s\[\]|&]*`).ReplaceAllString(src, "")
	// Step 5: Remove `<Type>` casts in expression position.
	src = removeTypeCasts(src)
	// Step 6: Remove parameter type annotations `(x: T, y: U)`.
	src = stripParamTypes(src)
	// Step 7: Remove variable type annotations `let x: T = ...`.
	src = stripVarTypes(src)
	// Step 8: Remove function return type annotations `): T {`.
	src = stripReturnTypes(src)
	return src
}

// removeInterfaceBlocks removes `interface Foo { ... }` blocks.
func removeInterfaceBlocks(src string) string {
	re := regexp.MustCompile(`(?ms)^export?\s*interface\s+\w+(?:\s+extends\s+[^{]+)?\s*\{.*?^\}`)
	return re.ReplaceAllString(src, "")
}

// removeTypeAliasLines removes `type Foo = ...;` lines.
// Multi-line type alias bodies are supported.
//
// The TypeScript type alias can have a body containing
// `;` (e.g., in a union of object types like
// `type X = { a: 1; b: 2 } | { c: 3; d: 4 };`). We must
// match the OUTER `;` (the one ending the type alias),
// not an inner one.
//
// Strategy: the type alias ends with `;` followed by a
// newline (the `;` is at the end of a line, possibly
// with trailing whitespace). Inner `;` characters are
// always followed by something OTHER than end-of-line
// (e.g., `,`, identifier, `}`).
//
// We use a regex that requires `;` to be the LAST
// non-whitespace character on its line.
func removeTypeAliasLines(src string) string {
	// Match `type X = ` followed by any chars (including
	// newlines) up to `;[ \t]*\n` (the closing `;` at
	// end of line). The body is `(?:.|\n)+?` (any char
	// including newline, one or more, non-greedy).
	// We use `[\s\S]+?` which is equivalent and faster.
	re := regexp.MustCompile(`(?ms)^export?\s*type\s+\w+\s*=[\s\S]+?;[ \t]*$`)
	return re.ReplaceAllString(src, "")
}

// removeTypeOnlyImports removes `import type { ... }` and
// `import { type X }` and `import { type X, Y }` (mixed)
// lines. The mixed-import case is rare; we handle it by
// removing the `type` keyword and the comma, leaving a
// valid `import { X, Y } from "..."`.
//
// Multi-line `import type {` blocks are supported; the
// regex uses `[\s\S]*?` to match across newlines.
func removeTypeOnlyImports(src string) string {
	// Step 1: Remove entire `import type { ... } from "..."` lines.
	// Multi-line: the `{...}` can span newlines.
	re1 := regexp.MustCompile(`(?m)^import\s+type\s+\{[\s\S]*?\}\s+from\s+["'][^"']+["'];?\s*\n`)
	src = re1.ReplaceAllString(src, "")
	// Step 2: Remove entire `import type * as X from "..."` lines.
	re2 := regexp.MustCompile(`(?m)^import\s+type\s+\*\s+as\s+\w+\s+from\s+["'][^"']+["'];?\s*\n`)
	src = re2.ReplaceAllString(src, "")
	// Step 3: Remove entire `import type X from "..."` lines.
	re3 := regexp.MustCompile(`(?m)^import\s+type\s+\w+\s+from\s+["'][^"']+["'];?\s*\n`)
	src = re3.ReplaceAllString(src, "")
	// Step 4: Inline `type` in `import { type X, ... }` -- remove
	// the `type` keyword and the comma that follows.
	re4 := regexp.MustCompile(`\btype\s+(\w+),?\s*`)
	src = re4.ReplaceAllString(src, "$1 ")
	return src
}

// removeTypeCasts removes `<Type>` expressions that are
// type assertions. We use a heuristic: `<X>` is a type
// assertion if `X` is a single identifier or a generic,
// AND the `<` is not preceded by `<` (which would be a
// comparison). The regex is conservative.
func removeTypeCasts(src string) string {
	// `<T>` or `<T<U>>` or `<T[]>` immediately after
	// `=`, `(`, `,`, `return`, `?`, `:`.
	// We do NOT match `<<` (left-shift) or `<=` (less-equal).
	// The look-behind is limited to fixed strings in Go regex.
	pat := regexp.MustCompile(`(?m)([\s=,(?\:])(<[A-Za-z_][A-Za-z0-9_<>,\s\[\]\.\|&\-]*>)(\s*[\(\.\[\{])`)
	return pat.ReplaceAllString(src, "$1$3")
}

// stripParamTypes removes type annotations from function
// parameters. Handles both `function f(x: T, y: U)` and
// `(x: T, y: U) => ...`.
//
// The regex matches `: T` (where T is a type) immediately
// after an identifier inside a parameter list.
func stripParamTypes(src string) string {
	// Match `: Type` inside parens that follow `function`,
	// `=>`, `(`, `,`, or a newline (top-level).
	// We process line-by-line because this is hard to do
	// correctly across multi-line parameter lists with a
	// single regex.
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		// Count parens; we're in a parameter list if the
		// open-paren count exceeds the close-paren count.
		// (Simplified: just strip the obvious cases.)
		lines[i] = stripParamTypesInLine(line)
	}
	return strings.Join(lines, "\n")
}

// stripParamTypesInLine strips parameter types from a single
// line. Handles `(x: T, y: U)` and `(x: T = 1)`.
//
// CRITICAL: the function must NOT confuse an object literal
// property like `{ type: "foo" }` with a parameter like
// `(x: T)`. The distinguishing characteristic: in a parameter
// list, the colon follows an identifier preceded by `,` or
// `(`; in an object literal, the colon follows an identifier
// preceded by `{` or `,` (after `{`).
//
// We track paren depth and brace depth. A colon is treated
// as a parameter type separator only when parenDepth >
// braceDepth.
//
// We also track string state (single quote, double quote,
// backtick/template literal) so we don't mistake
// `{ type: "${key}" }` for a parameter type. Template
// literals with `${...}` expressions are tracked
// separately: the `{` inside `${...}` increments a
// template-brace depth, not the regular brace depth.
func stripParamTypesInLine(line string) string {
	var out strings.Builder
	parenDepth := 0
	braceDepth := 0
	tmplBraceDepth := 0
	inString := byte(0) // 0, '"', '\'', or '`'
	i := 0
	for i < len(line) {
		c := line[i]
		if inString != 0 {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(line) {
				i++
				out.WriteByte(line[i])
				i++
				continue
			}
			if c == inString {
				// End of string. For template literals, we
				// also need to track ${} expressions.
				if inString == '`' && i+1 < len(line) && line[i+1] == '$' && i+2 < len(line) && line[i+2] == '{' {
					// Enter template expression.
					tmplBraceDepth = 1
					// Don't close the string.
					i += 2
					continue
				}
				inString = 0
			}
			i++
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			out.WriteByte(c)
			inString = c
			i++
			continue
		}
		// Inside a template expression like `${...}`.
		if tmplBraceDepth > 0 {
			out.WriteByte(c)
			if c == '{' {
				tmplBraceDepth++
			} else if c == '}' {
				tmplBraceDepth--
				if tmplBraceDepth == 0 {
					// Back to the template literal body.
					inString = '`'
				}
			}
			i++
			continue
		}
		out.WriteByte(c)
		if c == '(' {
			parenDepth++
		} else if c == ')' {
			parenDepth--
			if parenDepth < 0 {
				parenDepth = 0
			}
		} else if c == '{' {
			braceDepth++
		} else if c == '}' {
			braceDepth--
			if braceDepth < 0 {
				braceDepth = 0
			}
		} else if c == ':' && parenDepth > braceDepth {
			if i > 0 && isIdentChar(line[i-1]) {
				// Consume the type.
				i++
				for i < len(line) {
					c2 := line[i]
					if c2 == ',' || c2 == '=' || c2 == ')' {
						break
					}
					i++
				}
				continue
			}
		}
		i++
	}
	return out.String()
}

// isIdentChar reports whether c is part of a JS identifier.
func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_' || c == '$'
}

// stripVarTypes removes `let x: T`, `const x: T`, `var x: T`.
// The colon + type is on the same line as the declaration.
func stripVarTypes(src string) string {
	// Match `let|const|var <ident> : <type> [= ...]` and
	// remove the `: <type>`.
	pat := regexp.MustCompile(`(?m)(\b(?:let|const|var)\s+\w+)\s*:\s*[A-Za-z_][A-Za-z0-9_<>,\s\[\]\.\|&\-]*`)
	return pat.ReplaceAllString(src, "$1")
}

// stripReturnTypes removes function return type annotations
// `: T {` at the end of a function signature.
func stripReturnTypes(src string) string {
	// Match `): T {` or `): T => {`. The `T` is a type.
	pat := regexp.MustCompile(`(\)):\s*[A-Za-z_][A-Za-z0-9_<>,\s\[\]\.\|&\-]*(\s*[\{=])`)
	return pat.ReplaceAllString(src, "$1$2")
}
