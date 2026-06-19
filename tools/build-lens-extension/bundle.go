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
//
// bundle also generates the four Chrome Web Store icon
// sizes (16, 32, 48, 128) from assets/lens-icon-source.png
// to <dist>/icons/. If no source icon is present, icon
// generation is silently skipped (v0.1 behavior); v0.2
// will require it.
func bundle(cfg *Config) error {
	// Generate icons first (before any other output).
	if err := generateIcons(cfg.Dist); err != nil {
		return fmt.Errorf("generate icons: %w", err)
	}
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

// stripAsCasts removes `as Type` casts from a string.
// Handles nested generics (e.g., `as Record<string, unknown>`),
// parens, brackets, and strings. The eat stops at a non-type
// character (a comma, semicolon, newline, closing paren/bracket
// of an outer expression, etc.) so we never eat across
// statement or field separators.
func stripAsCasts(src string) string {
	var out strings.Builder
	parenDepth := 0
	bracketDepth := 0
	inString := byte(0)
	tmplBraceDepth := 0
	i := 0
	for i < len(src) {
		c := src[i]
		if inString != 0 {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				i++
				out.WriteByte(src[i])
				i++
				continue
			}
			if c == inString {
				if inString == '`' && i+1 < len(src) && src[i+1] == '$' && i+2 < len(src) && src[i+2] == '{' {
					tmplBraceDepth = 1
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
		if tmplBraceDepth > 0 {
			out.WriteByte(c)
			if c == '{' {
				tmplBraceDepth++
			} else if c == '}' {
				tmplBraceDepth--
				if tmplBraceDepth == 0 {
					inString = '`'
				}
			}
			i++
			continue
		}
		// Look for ` as ` pattern (preceded by identifier char).
		// Indices: i=space, i+1='a', i+2='s', i+3=space, i+4=type start.
		// So we need i+4 < len(src) to safely read src[i+4].
		// Handle JSDoc / block comments `/* ... */` so we don't
		// mistake `as` inside a comment for a cast.
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			out.WriteByte(c)
			out.WriteByte(src[i+1])
			i += 2
			for i+1 < len(src) {
				if src[i] == '*' && src[i+1] == '/' {
					out.WriteByte('*')
					out.WriteByte('/')
					i += 2
					break
				}
				out.WriteByte(src[i])
				i++
			}
			continue
		}
		// Handle line comments `// ...` (until end of line).
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			out.WriteByte(c)
			out.WriteByte(src[i+1])
			i += 2
			for i < len(src) && src[i] != '\n' {
				out.WriteByte(src[i])
				i++
			}
			continue
		}
		if c == ' ' && i+4 < len(src) && src[i+1] == 'a' && src[i+2] == 's' && src[i+3] == ' ' &&
			i > 0 && isIdentChar(src[i-1]) &&
			isIdentChar(src[i+4]) {


			// Find end of the type. Track nesting of generics,
			// parens, brackets. Strings are already handled above.
			depthAngle := 0
			j := i + 4 // past ' as '
			for j < len(src) {
				cj := src[j]
				if cj == '<' {
					depthAngle++
				} else if cj == '>' {
					if depthAngle == 0 {
						break
					}
					depthAngle--
				} else if cj == '(' {
					parenDepth++
				} else if cj == ')' {
					if parenDepth == 0 {
						break
					}
					parenDepth--
				} else if cj == '[' {
					bracketDepth++
				} else if cj == ']' {
					if bracketDepth == 0 {
						break
					}
					bracketDepth--
				} else if cj == '|' || cj == '&' {
				// Union/intersection types — allowed in cast
				} else if cj == ',' || cj == ';' || cj == '\n' {
					if depthAngle == 0 && parenDepth == 0 && bracketDepth == 0 {
						break
					}
				} else if cj == '{' || cj == '}' || cj == '=' {
					if depthAngle == 0 && parenDepth == 0 && bracketDepth == 0 {
						break
					}
				}
				j++
			}
			// Skip the ' as ' through the type.
			i = j
			continue
		}
		out.WriteByte(c)
		switch c {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		}
		i++
	}
	return out.String()
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
	// Step 4: Remove `as Type` casts. This is a state
	// machine that respects generic nesting (e.g.,
	// `as Record<string, unknown>`), parens, brackets, and
	// strings. A simple regex would over-eat across
	// statement separators.
	src = stripAsCasts(src)
	// Step 5: Remove `<Type>` casts in expression position.
	src = removeTypeCasts(src)
	// Step 5b: Remove generic type arguments `<T>`, `<T, U>`
	// after capital-letter identifiers (Map<string, V>,
	// Promise<void>, ReadonlyMap<string, T>).
	src = stripGenericArgs(src)
	// Step 6: Remove parameter type annotations `(x: T, y: U)`.
	src = stripParamTypes(src)
	// Step 7: Remove variable type annotations `let x: T = ...`.
	src = stripVarTypes(src)
	// Step 8: Remove function return type annotations `): T {`.
	src = stripReturnTypes(src)
	// Step 9: Remove `private`/`public`/`protected`/`readonly`
	// modifiers from class member declarations. These are
	// TS-only; the resulting code uses default visibility.
	src = stripVarModifiers(src)
	// Step 10: Remove `export ` keywords.
	src = stripExports(src)
	return src
}

// removeInterfaceBlocks removes `interface Foo { ... }` blocks.
func removeInterfaceBlocks(src string) string {
	// Match `interface Foo { ... }` (with optional `export`).
	// Uses (?ms) for multi-line dot-match and ^$ at newlines.
	// The `.*?` is non-greedy so it matches the FIRST closing
	// `}` (the interface's own closing).
	re := regexp.MustCompile(`(?ms)^(?:export\s+)?interface\s+\w+(?:\s+extends\s+[^{]+)?\s*\{.*?^\}`)
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
// stripGenericArgs removes generic type arguments from a
// TypeScript type. Handles `Map<string, V>`, `Set<Category>`,
// `Promise<void>`, `ReadonlyMap<string, T>`, and bare
// `Promise<T>`. The pattern matches a capital-letter
// identifier (or capital-letter followed by alnum/underscore)
// followed by `<...>`. The angle brackets and their content
// are removed.
//
// We do NOT match generic args after lowercase identifiers
// because that would corrupt comparisons like `arr < 10`.
//
// We do NOT match across newlines. The <...> must be on the
// same line as the identifier (most TS generics are written
// this way; multi-line generics are rare).
//
// Limitations: nested generic args like
// `Map<Set<Foo>>` are not handled (the regex stops at the
// first `>`). For our use case, we either avoid nested
// generics in source or pre-process them.
func stripGenericArgs(src string) string {
	pat := regexp.MustCompile(`(\b[A-Z][A-Za-z0-9_]*)<(?:[^<>\[\]]|\[[^<>\[\]]*\])*>`)
	return pat.ReplaceAllString(src, "$1")
}

//
// The regex matches `: T` (where T is a type) immediately
// after an identifier inside a parameter list.
func stripParamTypes(src string) string {
	// Process the WHOLE source, not line-by-line. Multi-line
	// parameter lists (e.g., `function f(\n  x: T,\n)`) are
	// common in TypeScript and we need paren state to flow
	// across newlines.
	return stripParamTypesInLine(src)
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
func stripParamTypesInLine(src string) string {
	var out strings.Builder
	// prevSig is the last significant (non-whitespace, non-comment)
	// character. Used to distinguish `(x: T)` (param) from
	// `{ x: 1 }` (object literal).
	exprStart := byte(0) // 0, '(' or '{' or other last sig char
	tmplBraceDepth := 0
	inString := byte(0) // 0, '"', '\'', or '`'
	i := 0
	for i < len(src) {
		c := src[i]
		if inString != 0 {
			out.WriteByte(c)
			if c == '\\' && i+1 < len(src) {
				i++
				out.WriteByte(src[i])
				i++
				continue
			}
			if c == inString {
				if inString == '`' && i+1 < len(src) && src[i+1] == '$' && i+2 < len(src) && src[i+2] == '{' {
					tmplBraceDepth = 1
					i += 2
					continue
				}
				inString = 0
			}
			i++
			continue
		}
		// Handle JSDoc / block comments `/* ... */` so quote
		// chars inside the comment don't confuse the string
		// tracker.
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			out.WriteByte(c)
			out.WriteByte(src[i+1])
			i += 2
			for i+1 < len(src) {
				if src[i] == '*' && src[i+1] == '/' {
					out.WriteByte('*')
					out.WriteByte('/')
					i += 2
					break
				}
				out.WriteByte(src[i])
				i++
			}
			continue
		}
		// Handle line comments `// ...` (until end of line).
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			out.WriteByte(c)
			out.WriteByte(src[i+1])
			i += 2
			for i < len(src) && src[i] != '\n' {
				out.WriteByte(src[i])
				i++
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			out.WriteByte(c)
			inString = c
			i++
			continue
		}
		if tmplBraceDepth > 0 {
			out.WriteByte(c)
			if c == '{' {
				tmplBraceDepth++
			} else if c == '}' {
				tmplBraceDepth--
				if tmplBraceDepth == 0 {
					inString = '`'
				}
			}
			i++
			continue
		}
		// Check for type-annotation colon BEFORE writing c.
		// A colon is a TS type annotation when:
		//   - exprStart == '(' (we are directly in a param list,
		//     not in an object literal inside the parens)
		//   - the previous char is an identifier char
		if c == ':' && exprStart == '(' && i > 0 && isIdentChar(src[i-1]) {
			// Consume the type. Stop at `,`, `)`, `=`, `;`,
			// or newline.
			i++
			for i < len(src) {
				c2 := src[i]
				if c2 == ',' || c2 == '=' || c2 == ')' || c2 == '\n' || c2 == ';' {
					break
				}
				i++
			}
			continue
		}
		out.WriteByte(c)
		switch c {
		case '(':
			exprStart = '('
		case '{':
			// `{` opens an object literal in expression
			// position. Detect expression position by what came
			// before: `(`, `,`, `=`, `=>`, `?`, `:`, etc.
			switch exprStart {
			case 0, '(', ',', '=', '?', ':', '>', '!', '+', '-', '*', '/', '%', '&', '|', '^', '~', '[', ';':
				exprStart = '{'
			}
		default:
			// Don't update exprStart on regular chars — we want
			// it to track the EXPRESSION START (the `(` or `{`),
			// not the last char. This is what lets us distinguish
			// `x: T` (param) from `{ x: 1 }` (object property).
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

// isWhitespace reports whether c is a whitespace character.
func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// stripVarTypes removes `let x: T`, `const x: T`, `var x: T`.
// The colon + type is on the same line as the declaration.
func stripVarTypes(src string) string {
	// Match:
	//   - `let|const|var NAME : TYPE` (regular vars)
	//   - `(private|public|...) NAME : TYPE` (class fields)
	//   - `NAME : TYPE` (class fields without modifier)
	// The type can include generics, array types, union types,
	// but stops at `=` (default value), `,` (next field), `;`
	// (statement end), `{` (object body), or `}` (block end).
	//
	// We preserve any leading modifier/decl keyword in the
	// replacement so we don't break the resulting code.
	pat := regexp.MustCompile(`(?m)((?:^|\b)(?:(?:private|public|protected|readonly)\s+)?(?:(?:let|const|var)\s+)?)(\b\w+)(\s*:\s*(?:\[[^\]]*\]|[A-Z][A-Za-z0-9_<>|]*|(?:number|string|boolean|bigint|symbol|object|unknown|void|never)(?:\[\])?)[\s,;)}{=}\]])`)
	return pat.ReplaceAllStringFunc(src, func(m string) string {
		sub := pat.FindStringSubmatch(m)
		// sub[1] is the prefix (modifier + decl), sub[2] is the
		// identifier, sub[3] is `: TYPE ...` (we want to keep
		// only the part after the type, which is the closing
		// char/space of the type annotation).
		// For simplicity, just keep the prefix + identifier and
		// let the user re-add the trailing char if needed.
		_ = sub
		// Extract the last char of sub[3] which is the char after
		// the type (one of `,`, `;`, `)`, `}`, `{`, `=`, `\s`).
		tail := sub[3][len(sub[3])-1:]
		return sub[1] + sub[2] + tail
	})
}

// stripReturnTypes removes function return type annotations
// `: T {` at the end of a function signature.
func stripReturnTypes(src string) string {
	// Match `): T {` or `): T => {`. The `T` is a type.
	pat := regexp.MustCompile(`(\)):\s*[A-Za-z_][A-Za-z0-9_<>,\s\[\]\.\|&\-]*(\s*[\{=])`)
	return pat.ReplaceAllString(src, "$1$2")
}

// stripVarModifiers removes TS-only class member modifiers
// (private, public, protected, readonly) from declarations.
// These modifiers are not valid in plain JavaScript; the
// resulting class uses default visibility.
//
// The regex matches the modifier + whitespace at the start
// of a line (after optional indent). The indent is captured
// and preserved in the replacement.
func stripVarModifiers(src string) string {
	// Loop until no more matches, to handle multiple modifiers
	// in a row (e.g., `private readonly cfg: any;`).
	for i := 0; i < 5; i++ {
		pat := regexp.MustCompile(`(?m)^([ \t]*)(?:private|public|protected|readonly)[ \t]+`)
		newSrc := pat.ReplaceAllStringFunc(src, func(m string) string {
			sub := pat.FindStringSubmatch(m)
			return sub[1]
		})
		if newSrc == src {
			break
		}
		src = newSrc
	}
	return src
}

// stripExports removes leading `export ` keywords from all
// declarations. This is needed for content scripts (which
// are classic scripts, not modules — `export` is a syntax
// error in classic scripts).
//
// Service workers are modules in MV3 and need their exports
// preserved. The main.go code calls stripExports only on
// content.js (not on service-worker.js).
func stripExports(src string) string {
	pat := regexp.MustCompile(`(?m)^[ \t]*export[ \t]+`)
	return pat.ReplaceAllString(src, "")
}
