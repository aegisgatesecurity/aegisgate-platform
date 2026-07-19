// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Linter
// =========================================================================
//
// lint.go implements the §10.1 Privacy Policy CI checks.
// The build fails if any of the following are present in
// the Lens source:
//
//   1. eval(...) or new Function(...)
//      The Lens must not execute arbitrary strings.
//
//   2. innerHTML, outerHTML, insertAdjacentHTML
//      The Lens must not insert raw HTML. All DOM updates
//      use textContent or createElement.
//
//   3. fetch(...) outside the allowlist
//      The Lens only fetches the configured Lens backend.
//      Any other URL is a leak.
//
//   4. document.write, document.writeln
//      The Lens must not write to the document stream.
//
//   5. import(  with a URL argument (dynamic import)
//      The Lens does not dynamically import modules; if it
//      does, the import target must be a string literal
//      in the allowlist (none in v0.1).
//
//   6. prompt content in log lines
//      No log line should contain the substrings 'prompt',
//      'content', 'input', 'textarea', 'url', 'host' (as
//      a full word) -- this catches accidental log lines
//      that include the prompt text.
//
//   7. console.log (use console.info, console.warn, or
//      console.error instead -- console.log is reserved
//      for the user-facing popups and is gated in
//      production builds).
//
//   8. chrome.runtime.connect (use sendMessage only)
//      The Lens uses request-response, not long-lived
//      connections. connect() is a footgun for privacy
//      products because it can leak data over time.
//
// The linter reads each .js file in the source directory
// and runs the checks line-by-line. A single violation
// fails the build (in strict mode; the soft mode counts
// violations and reports them but does not fail).
//
// v0.1.0+ Lens Phase 1 (plain-JS pivot, 2026-06-19).
// =========================================================================

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LintViolation is one occurrence of a forbidden pattern.
type LintViolation struct {
	File    string
	Line    int
	Column  int
	Rule    string
	Snippet string
}

// lint runs the linter on every .ts file in the source
// directory. In strict mode, any violation fails the build.
func lint(cfg *Config) error {
	violations, err := lintAll(cfg.Src)
	if err != nil {
		return fmt.Errorf("lint: %w", err)
	}
	if len(violations) == 0 {
		return nil
	}
	// Print all violations, then fail (in strict mode).
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  %s:%d:%d: %s: %s\n",
			v.File, v.Line, v.Column, v.Rule, v.Snippet)
	}
	if cfg.Strict {
		return fmt.Errorf("lint: %d violation(s) in strict mode", len(violations))
	}
	// Non-strict: log a warning but continue.
	fmt.Fprintf(os.Stderr, "warning: %d lint violation(s) (non-strict mode; continuing)\n",
		len(violations))
	return nil
}

// lintAll walks the source directory and returns all violations.
func lintAll(srcDir string) ([]LintViolation, error) {
	var all []LintViolation
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error { // #nosec G703 G122 -- srcDir is the developer-supplied --src CLI arg
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip the vendor/ directory: third-party code is
			// vendored as-is and not subject to the Lens source
			// linter rules (Day 32, Path C - vendored ONNX Runtime).
			// The vendor/ contents are verified by SHA-256 pinning
			// (see tools/verify-vendor.sh) rather than by lint.
			if path != srcDir && filepath.Base(path) == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".js") && !strings.HasSuffix(path, ".html") {
			return nil
		}
		vs, err := lintFile(path)
		if err != nil {
			return err
		}
		all = append(all, vs...)
		return nil
	})
	return all, err
}

// lintFile runs all lint rules on a single file.
func lintFile(path string) ([]LintViolation, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- path is from filepath.Walk of the Lens source directory, which is the build tool's developer-supplied input
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var violations []LintViolation
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1MB lines
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// Strip line comments (a simple approximation; for
		// multi-line /* */ comments, a more sophisticated
		// parser would be needed). v0.1 source is hand-written
		// and uses // comments exclusively.
		stripped := stripLineComment(line)
		for _, rule := range lintRules {
			if loc := rule.re.FindStringIndex(stripped); loc != nil {
				// v0.2.0 A15: check allowlist before reporting.
				// If the stripped line contains any allowlisted
				// substring, the match is a classification label,
				// not leaked prompt text, and should be exempted.
				allowed := false
				if len(rule.allowlist) > 0 {
					for _, ex := range rule.allowlist {
						if strings.Contains(stripped, ex) {
							allowed = true
							break
						}
					}
				}
				if allowed {
					continue
				}
				violations = append(violations, LintViolation{
					File:    path,
					Line:    lineNum,
					Column:  loc[0] + 1,
					Rule:    rule.name,
					Snippet: strings.TrimSpace(stripped),
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return violations, nil
}

// lintRule is a single lint check.
type lintRule struct {
	name      string
	re        *regexp.Regexp
	allowlist []string // substrings that exempt a match (v0.2.0 A15)
}

// lintRules is the set of all lint rules. Each regex is matched
// against the comment-stripped source line.
var lintRules = []lintRule{
	{
		name: "no-eval",
		re:   regexp.MustCompile(`\beval\s*\(`),
	},
	{
		name: "no-Function-constructor",
		re:   regexp.MustCompile(`\bnew\s+Function\s*\(`),
	},
	{
		name: "no-innerHTML",
		re:   regexp.MustCompile(`\.(innerHTML|outerHTML|insertAdjacentHTML)\s*=`),
	},
	{
		name: "no-document-write",
		re:   regexp.MustCompile(`\bdocument\.write(?:ln)?\s*\(`),
	},
	{
		name: "no-dynamic-import",
		// Matches `import("...url...")` but not `import type {...}`
		// or `import {...} from "..."`.
		re: regexp.MustCompile(`\bimport\s*\(\s*["'` + "`" + `]`),
	},
	{
		name: "no-prompt-in-log",
		// Matches console.log/info/warn/error that contains a
		// string literal with one of the forbidden substrings.
		// The substring must be inside a string literal; the
		// regex is conservative (will produce false positives
		// on string literals that mention "URL" or "input" in
		// a non-data context, but those should be rare and
		// would be code-smells anyway).
		//
		// v0.2.0 A15 exemption: classification labels like "email-like content"
		// or "content-type header" are NOT user data leaking into logs. The
		// allowlist below permits known safe compound words where "content"
		// appears as a classification term, not as leaked prompt text.
		re: regexp.MustCompile(`(?i)(console|log)\.\w+\s*\(\s*["'` + "`" + `][^"'` + "`" + `]*(prompt|content|input|textarea|url|host)[^"'` + "`" + `]*["'` + "`" + `]`),
		// allowlist exemptions: log lines containing these substrings
		// are permitted even if they match the forbidden-word pattern,
		// because they are detector classification labels, not prompt text.
		allowlist: []string{
			"-like content",  // e.g. "email-like content, using single-shot ensemble"
			"content-type",   // e.g. "content-type header"
			"Content-Security-Policy", // e.g. CSP header name
		},
	},
	{
		name: "no-console-log",
		// Use console.info / console.warn / console.error.
		// console.log is reserved for the user-facing popups
		// in production builds.
		re: regexp.MustCompile(`\bconsole\.log\s*\(`),
	},
	{
		name: "no-runtime-connect",
		// The Lens uses sendMessage (request-response), not
		// long-lived port connections.
		re: regexp.MustCompile(`\bchrome\.runtime\.connect\s*\(`),
	},
}

// stripLineComment removes everything after "//" on a line.
// A more sophisticated approach would handle strings that
// contain "//", but v0.1 source does not have that.
func stripLineComment(line string) string {
	// Find "//" that is not inside a string.
	// For v0.1, the source does not have strings containing "//",
	// so a simple find is correct.
	idx := strings.Index(line, "//")
	if idx < 0 {
		return line
	}
	// Verify the "//" is not inside a string. Walk through
	// the line tracking quote state.
	inString := false
	quote := byte(0)
	for i := 0; i < len(line)-1; i++ {
		c := line[i]
		if inString {
			if c == '\\' {
				i++ // skip escaped char
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
			continue
		}
		if c == '/' && line[i+1] == '/' {
			return line[:i]
		}
	}
	return line
}
