// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - Port Detections (Platform → Lens)
// =========================================================================
//
// This tool reads the Platform's Go detection files (pkg/response/
// {pii_scanner,secret_detector,toxicity_filter}.go), extracts the
// regex patterns, and emits a JavaScript file at lens-repo-bootstrap/
// src/detectors/from_platform.js that the Lens loads at runtime.
//
// Why this tool exists: the Platform has 40+ detection categories
// battle-tested with 6,400 lines of tests. Manually porting each
// pattern is brittle and error-prone. This tool makes the port
// deterministic — single source of truth (the Go files), single
// conversion (this program), single output (the JS file).
//
// The generated file is checked into the lens-repo-bootstrap repo
// as a vendored artifact. The build tool can verify it's up-to-date
// (rejects CI if drift detected).
//
// Plain Go, no third-party deps. stdlib only.
//
// Usage:
//   go build -o /tmp/port-detections ./tools/port-detections/
//   /tmp/port-detections \
//     --platform-root . \
//     --out lens-repo-bootstrap/src/detectors/from_platform.js
//
// v0.1 pre-release.
// =========================================================================

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// patternExtraction represents a single extracted pattern.
type patternExtraction struct {
	// Source: "pii_scanner", "secret_detector", "toxicity_filter",
	//         "owasp", "atlas_compliance", "eu_ai_act"
	Source string
	// The Go-side constant name (e.g., "PII_SSN", "SECRET_API_KEY",
	// "LLM01-001"). Empty for masked patterns.
	GoKey string
	// The category string from the Go types file (e.g., "ssn",
	// "api_key", "PromptInjection"). For new shapes, derived from
	// the Category field or the slice name.
	Category string
	// The original Go regex source (inside the backticks of MustCompile).
	GoRegex string
	// Whether the pattern has the (?i) inline case-insensitive flag.
	HasCaseInsensitive bool
	// Severity 1-5 from the metadata maps; 0 if unknown.
	Severity int
	// Human description from the metadata maps.
	Description string
	// Compliance tags from the metadata maps.
	Compliance []string
	// Provider list from the metadata maps (secrets only).
	Providers []string
	// Is this a "named" pattern (in the patterns map) or a "masked" pattern?
	IsNamed bool
	// Compliance framework identifier (e.g., "OWASP-LLM01", "MITRE-ATLAS-T1535",
	// "EU-AI-Act-Art5"). Empty for original Platform detectors.
	FrameworkID string
	// Compliance framework name (e.g., "OWASP LLM Top 10",
	// "MITRE ATLAS", "EU AI Act").
	Framework string
}

// compile extracts patterns from the Platform's Go detection files.
func compile(platformRoot string) ([]patternExtraction, error) {
	var out []patternExtraction

	// PII patterns
	piiPatterns, err := extractFromFile(
		filepath.Join(platformRoot, "pkg/response/pii_scanner.go"),
		"pii_scanner",
	)
	if err != nil {
		return nil, fmt.Errorf("pii_scanner: %w", err)
	}
	out = append(out, piiPatterns...)

	// Secret patterns
	secretPatterns, err := extractFromFile(
		filepath.Join(platformRoot, "pkg/response/secret_detector.go"),
		"secret_detector",
	)
	if err != nil {
		return nil, fmt.Errorf("secret_detector: %w", err)
	}
	out = append(out, secretPatterns...)

	// Toxicity patterns
	toxicityPatterns, err := extractFromFile(
		filepath.Join(platformRoot, "pkg/response/toxicity_filter.go"),
		"toxicity_filter",
	)
	if err != nil {
		return nil, fmt.Errorf("toxicity_filter: %w", err)
	}
	out = append(out, toxicityPatterns...)

	// OWASP LLM Top 10 patterns (append-to-slice with struct literal)
	owaspPatterns, err := extractOwaspFile(
		filepath.Join(platformRoot, "pkg/compliance/owasp.go"),
	)
	if err != nil {
		return nil, fmt.Errorf("owasp: %w", err)
	}
	out = append(out, owaspPatterns...)

	// MITRE ATLAS compliance patterns (append-to-slice with struct literal)
	atlasPatterns, err := extractAtlasFile(
		filepath.Join(platformRoot, "pkg/compliance/atlas.go"),
	)
	if err != nil {
		return nil, fmt.Errorf("atlas: %w", err)
	}
	out = append(out, atlasPatterns...)

	// EU AI Act patterns (named slice of regexps)
	euPatterns, err := extractNamedSliceFile(
		filepath.Join(platformRoot, "pkg/compliance/eu-ai-act/eu_ai_act.go"),
		"eu_ai_act",
		"EU AI Act",
		"EU-AI-Act",
	)
	if err != nil {
		return nil, fmt.Errorf("eu_ai_act: %w", err)
	}
	out = append(out, euPatterns...)

	// ANP guard patterns
	anpPatterns, err := extractNamedSliceFile(
		filepath.Join(platformRoot, "pkg/anp/guard.go"),
		"anp_guard",
		"ANP Guard",
		"ANP",
	)
	if err != nil {
		return nil, fmt.Errorf("anp_guard: %w", err)
	}
	out = append(out, anpPatterns...)

	// Computer Use (Anthropic API) guard patterns
	cuPatterns, err := extractNamedSliceFile(
		filepath.Join(platformRoot, "pkg/computeruse/guard.go"),
		"computeruse_guard",
		"Computer Use Guard",
		"Computer_Use",
	)
	if err != nil {
		return nil, fmt.Errorf("computeruse_guard: %w", err)
	}
	out = append(out, cuPatterns...)

	// Load metadata from types.go (only for legacy files)
	typesPath := filepath.Join(platformRoot, "pkg/response/types.go")
	md, err := parseTypesMetadata(typesPath)
	if err != nil {
		return nil, fmt.Errorf("types: %w", err)
	}

	// Merge metadata into each pattern (only for legacy pii/secret/toxicity)
	for i := range out {
		p := &out[i]
		if p.Source != "pii_scanner" && p.Source != "secret_detector" && p.Source != "toxicity_filter" {
			continue
		}
		if m, ok := md[p.GoKey]; ok {
			p.Category = m.Category
			p.Severity = m.Severity
			p.Description = m.Description
			p.Compliance = m.Compliance
			p.Providers = m.Providers
		}
	}

	return out, nil
}

// extractFromFile finds all regexp.MustCompile(...) calls in the given
// source file, along with the variable name on the LHS of the assignment
// (which tells us the Go key, e.g., "PII_SSN").
func extractFromFile(path, source string) ([]patternExtraction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []patternExtraction

	// Match lines like:
	//   ps.patterns[PII_SSN] = regexp.MustCompile(`...`)
	//   sd.maskedPatterns = append(sd.maskedPatterns, regexp.MustCompile(`...`))
	//   tf.categories[TOXICITY_VIOLENCE] = regexp.MustCompile(`...`)
	//
	// We split on `\n` and process each line. The patterns we care
	// about are always on a single line in the Platform's code
	// (the original developers kept them readable).

	// Regex: extract (lhs) and (regex-string). Two flavors:
	//   1) `<map>[<KEY>] = regexp.MustCompile(`<PATTERN>`)`
	//   2) `regexp.MustCompile(`<PATTERN>`)` (in append or alone)
	lhsRe := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\[([A-Z_][A-Z0-9_]*)\]\s*=\s*regexp\.MustCompile\(\s*` + "`([^`]*)`" + `\s*\)`)
	plainRe := regexp.MustCompile(`regexp\.MustCompile\(\s*` + "`([^`]*)`" + `\s*\)`)

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "regexp.MustCompile") {
			continue
		}
		if strings.HasPrefix(line, "//") {
			continue
		}

		// Try named pattern first
		if m := lhsRe.FindStringSubmatch(line); m != nil {
			// m[1] is the map name (ps.patterns, sd.patterns, tf.categories)
			// m[2] is the constant (PII_SSN, SECRET_API_KEY, TOXICITY_VIOLENCE)
			// m[3] is the regex pattern
			goRegex := m[3]
			out = append(out, patternExtraction{
				Source:             source,
				GoKey:              m[2],
				GoRegex:            goRegex,
				HasCaseInsensitive: hasInlineFlag(goRegex, "i"),
				IsNamed:            true,
			})
		} else if m := plainRe.FindStringSubmatch(line); m != nil {
			// Masked/anonymous pattern. Categorize as the parent source's
			// generic category.
			goRegex := m[1]
			out = append(out, patternExtraction{
				Source:             source,
				GoKey:              sourceToGenericKey(source),
				GoRegex:            goRegex,
				HasCaseInsensitive: hasInlineFlag(goRegex, "i"),
				IsNamed:            false,
			})
		}
	}
	return out, nil
}

// extractOwaspFile extracts patterns from OWASP LLM Top 10.
//
// Shape:
//   return []OwaspPattern{
//       {ID: "LLM01-001", Category: "LLM01", Name: "...", Regex: regexp.MustCompile(`...`)},
//       ...
//   }
func extractOwaspFile(path string) ([]patternExtraction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []patternExtraction

	// Match blocks of the form:
	//   {
	//       ID: "...",
	//       Category: "...",
	//       Name: "...",
	//       (optional Description: "...", Severity: "...")
	//       Regex: regexp.MustCompile(`...`)
	//   }
	//
	// We process line by line. When we see "ID:" we start capturing
	// the struct; when we see "Regex:" we capture the regex; when we
	// see "}" at end of line we commit.

	type pending struct {
		id, category, name, description, severity, regex string
	}
	var cur pending
	inBlock := false

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)

		// Skip comments and non-struct lines.
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}

		// Detect start of a block.
		if strings.HasPrefix(trimmed, "{") && !inBlock {
			inBlock = true
			cur = pending{}
			continue
		}

		if !inBlock {
			continue
		}

		// Detect end of block.
		if strings.HasPrefix(trimmed, "}") {
			if cur.id != "" && cur.regex != "" {
				out = append(out, patternExtraction{
					Source:             "owasp",
					GoKey:              cur.id,
					GoRegex:            cur.regex,
					HasCaseInsensitive: hasInlineFlag(cur.regex, "i"),
					IsNamed:            true,
					Category:           deriveOwaspCategory(cur.id, cur.category),
					Severity:           severityFromString(cur.severity),
					Description:        cur.description,
					Compliance:         []string{deriveOwaspFramework(cur.id)},
					FrameworkID:        cur.id,
					Framework:          "OWASP LLM Top 10",
				})
			}
			inBlock = false
			continue
		}

		// Field capture.
		switch {
		case strings.HasPrefix(trimmed, "ID:"):
			cur.id = trimFieldValue(strings.TrimPrefix(trimmed, "ID:"))
		case strings.HasPrefix(trimmed, "Category:"):
			cur.category = trimFieldValue(strings.TrimPrefix(trimmed, "Category:"))
		case strings.HasPrefix(trimmed, "Name:"):
			cur.name = trimFieldValue(strings.TrimPrefix(trimmed, "Name:"))
		case strings.HasPrefix(trimmed, "Description:"):
			cur.description = trimFieldValue(strings.TrimPrefix(trimmed, "Description:"))
		case strings.HasPrefix(trimmed, "Severity:"):
			cur.severity = trimFieldValue(strings.TrimPrefix(trimmed, "Severity:"))
		case strings.HasPrefix(trimmed, "Regex:"):
			cur.regex = extractRegexFromMustCompile(trimmed)
		}
	}
	return out, nil
}

// trimFieldValue trims whitespace, optional leading quote, optional
// trailing quote and trailing comma from a field value. The trailing
// comma is common in Go struct literals (e.g., `Description: "..."`).
func trimFieldValue(s string) string {
	s = strings.TrimSpace(s)
	// Strip trailing comma (Go struct literal style).
	s = strings.TrimSuffix(s, ",")
	s = strings.TrimSpace(s)
	// Strip matching leading and trailing quotes/backticks.
	if len(s) >= 2 {
		first := s[0]
		last := s[len(s)-1]
		if (first == '"' && last == '"') || (first == '`' && last == '`') || (first == '\'' && last == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	return s
}

// extractRegexFromMustCompile extracts the regex string from a line
// containing `regexp.MustCompile(...). The regex may be in backticks,
// single quotes, or double quotes, and may span multiple lines (rare
// but possible). Returns "" if the pattern is too complex to extract
// reliably (e.g., uses string concatenation with strings.Repeat).
func extractRegexFromMustCompile(line string) string {
	// Detect concatenation patterns (which we can't reliably resolve
	// to a single regex string). Bail out.
	if strings.Contains(line, "+") {
		// Could be string concatenation; check if it's outside a quoted context.
		// For simplicity, if there's a + outside of backticks/quotes, skip.
		if hasUnquotedPlus(line) {
			return ""
		}
	}

	// Find `regexp.MustCompile(` then read until the matching close.
	idx := strings.Index(line, "regexp.MustCompile(")
	if idx == -1 {
		return ""
	}
	rest := line[idx+len("regexp.MustCompile("):]
	// Trim leading whitespace.
	rest = strings.TrimSpace(rest)

	// Find opening quote/backslash-backtick.
	if len(rest) == 0 {
		return ""
	}

	var quote byte
	switch rest[0] {
	case '`', '"', '\'':
		quote = rest[0]
	case ')':
		// Empty MustCompile().
		return ""
	default:
		// Could be a string-concatenated regex. Walk until '`'.
		quote = '`'
	}

	// Find matching close quote. For backticks, read until next backtick.
	// For double quotes, read until matching close (handle escapes).
	bodyStart := 1
	body := rest[bodyStart:]
	bodyEnd := -1
	if quote == '`' {
		bodyEnd = strings.Index(body, "`")
	} else {
		// Walk double-quoted string handling escapes.
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				i++ // skip escaped char
				continue
			}
			if body[i] == quote {
				bodyEnd = i
				break
			}
		}
	}
	if bodyEnd == -1 {
		return body
	}
	return body[:bodyEnd]
}

// deriveOwaspCategory converts an OWASP category (LLM01..LLM10) to a
// human-readable Lens category.
func deriveOwaspCategory(id, category string) string {
	cat := map[string]string{
		"LLM01": "owasp_prompt_injection",
		"LLM02": "owasp_insecure_output",
		"LLM03": "owasp_training_poisoning",
		"LLM04": "owasp_model_dos",
		"LLM05": "owasp_supply_chain",
		"LLM06": "owasp_sensitive_disclosure",
		"LLM07": "owasp_insecure_plugin",
		"LLM08": "owasp_excessive_agency",
		"LLM09": "owasp_overreliance",
		"LLM10": "owasp_model_theft",
	}
	if c, ok := cat[category]; ok {
		return c
	}
	return "owasp_" + strings.ToLower(category)
}

// deriveOwaspFramework returns a framework tag for OWASP patterns.
func deriveOwaspFramework(id string) string {
	return "OWASP-LLM"
}

// extractAtlasFile extracts patterns from MITRE ATLAS compliance file.
//
// Shape (similar to OWASP):
//   f.patterns = append(f.patterns, &Pattern{
//       ID: "T1535.001",
//       Technique: "T1535",
//       Severity: SeverityHigh,
//       Category: "PromptInjection",
//       Description: "...",
//       Regex: regexp.MustCompile(`...`),
//   })
func extractAtlasFile(path string) ([]patternExtraction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []patternExtraction

	type pending struct {
		id, technique, severity, category, description, regex string
	}
	var cur pending
	inBlock := false
	inAppend := false

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}

		// Detect the append() call that opens a block.
		if strings.Contains(trimmed, "append") && strings.Contains(trimmed, "&Pattern{") {
			inAppend = true
			inBlock = true
			cur = pending{}
			continue
		}
		if !inAppend {
			continue
		}
		if !inBlock {
			continue
		}

		if strings.HasPrefix(trimmed, "}") {
			if cur.id != "" && cur.regex != "" {
				out = append(out, patternExtraction{
					Source:             "atlas_compliance",
					GoKey:              cur.id,
					GoRegex:            cur.regex,
					HasCaseInsensitive: hasInlineFlag(cur.regex, "i"),
					IsNamed:            true,
					Category:           "atlas_" + strings.ToLower(cur.category),
					Severity:           severityFromString(cur.severity),
					Description:        cur.description,
					Compliance:         []string{"MITRE-ATLAS"},
					FrameworkID:        cur.id,
					Framework:          "MITRE ATLAS",
				})
			}
			inBlock = false
			inAppend = false
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "ID:"):
			cur.id = trimFieldValue(strings.TrimPrefix(trimmed, "ID:"))
		case strings.HasPrefix(trimmed, "Technique:"):
			cur.technique = trimFieldValue(strings.TrimPrefix(trimmed, "Technique:"))
		case strings.HasPrefix(trimmed, "Severity:"):
			cur.severity = trimFieldValue(strings.TrimPrefix(trimmed, "Severity:"))
		case strings.HasPrefix(trimmed, "Category:"):
			cur.category = trimFieldValue(strings.TrimPrefix(trimmed, "Category:"))
		case strings.HasPrefix(trimmed, "Description:"):
			cur.description = trimFieldValue(strings.TrimPrefix(trimmed, "Description:"))
		case strings.HasPrefix(trimmed, "Regex:"):
			cur.regex = extractRegexFromMustCompile(trimmed)
		}
	}
	return out, nil
}

// extractNamedSliceFile extracts patterns from a file with named regexp slices.
//
// Shape:
//   m.subliminalPatterns = []*regexp.Regexp{
//       regexp.MustCompile(`(?i)...`),
//       regexp.MustCompile(`(?i)...`),
//   }
//
// The slice name becomes the Lens-side category hint.
func extractNamedSliceFile(path, source, frameworkName, frameworkID string) ([]patternExtraction, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []patternExtraction

	// Match:
	//   varName = []*regexp.Regexp{
	//       regexp.MustCompile(`...`),
	//       ...
	//   }
	// Capture the varName and every regex in the block.

	// First, find all variable assignments.
	assignRe := regexp.MustCompile(`(\w+(?:Patterns|Regexp|Regex))\s*=\s*\[\]\*regexp\.Regexp\{`)
	patternRe := regexp.MustCompile("regexp\\.MustCompile\\(\\s*`([^`]*)`\\s*\\)")

	for _, m := range assignRe.FindAllStringSubmatch(text, -1) {
		varName := m[1]
		// Find the block start.
		blockStart := strings.Index(text, m[0])
		if blockStart == -1 {
			continue
		}
		// Find the matching closing brace.
		blockEnd := findClosingBrace(text, blockStart+len(m[0])-1)
		if blockEnd == -1 {
			continue
		}
		block := text[blockStart:blockEnd]

		idx := 0
		for _, p := range patternRe.FindAllStringSubmatch(block, -1) {
			idx++
			// Derive category from var name (e.g., "subliminalPatterns" -> "subliminal").
			catName := strings.TrimSuffix(varName, "Patterns")
			catName = strings.TrimSuffix(catName, "Regexp")
			catName = strings.TrimSuffix(catName, "Regex")
			catName = strings.ToLower(catName)

			out = append(out, patternExtraction{
				Source:             source,
				GoKey:              varName + "_" + strconv.Itoa(idx),
				GoRegex:            p[1],
				HasCaseInsensitive: hasInlineFlag(p[1], "i"),
				IsNamed:            true,
				Category:           source + "_" + catName,
				Severity:           3, // default medium; compliance frameworks
				Description:        fmt.Sprintf("%s pattern (%s)", catName, frameworkName),
				Compliance:         []string{frameworkID},
				FrameworkID:        frameworkID,
				Framework:          frameworkName,
			})
		}
	}
	return out, nil
}

// findClosingBrace finds the matching `}` for an opening `{` at position `start`.
// Handles nested braces.
func findClosingBrace(s string, start int) int {
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// severityFromString maps a Go severity string to an int 1-5.
func severityFromString(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	// Handle Go-style "SeverityHigh", "SeverityMedium", etc.
	switch {
	case strings.Contains(s, "Critical"):
		return 5
	case strings.Contains(s, "High"):
		return 4
	case strings.Contains(s, "Medium"):
		return 3
	case strings.Contains(s, "Low"):
		return 2
	}
	return 3
}

// hasUnquotedPlus returns true if the line contains a `+` outside of
// any quoted string. Used to detect Go string-concatenated regex patterns
// which we can't reliably extract.
func hasUnquotedPlus(line string) bool {
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && (inSingle || inDouble) && i+1 < len(line) {
			i++ // skip escaped char
			continue
		}
		switch c {
		case '\'':
			if !inDouble && !inBacktick {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inBacktick {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inBacktick = !inBacktick
			}
		case '+':
			if !inSingle && !inDouble && !inBacktick {
				return true
			}
		}
	}
	return false
}

// hasInlineFlag checks if the Go regex has an inline flag like (?i)...
// at the start of the pattern.
func hasInlineFlag(goRegex, flag string) bool {
	// The flag can be at the very start (after `(?`) or in a group
	// anywhere in the pattern. We strip it from the head for purposes
	// of "is there a flag".
	return strings.Contains(goRegex, "(?"+flag)
}

// sourceToGenericKey returns the generic Go key for a masked pattern
// from a given source.
func sourceToGenericKey(source string) string {
	switch source {
	case "pii_scanner":
		return "PII_CUSTOM"
	case "secret_detector":
		return "SECRET_API_KEY" // masked patterns are typically API keys
	case "toxicity_filter":
		return "TOXICITY_CUSTOM"
	}
	return "UNKNOWN"
}

// metadata is the parsed contents of types.go's metadata maps.
type metadata struct {
	Category    string
	Severity    int
	Description string
	Compliance  []string
	Providers   []string
}

// parseTypesMetadata extracts per-category metadata from types.go.
//
// The Platform's types.go contains three metadata maps:
//
//	var PIICategoryMetadata = map[PIICategory]struct {
//	    Description  string
//	    Compliance   []string
//	    Severity     int
//	    RedactPrefix string
//	}{ PII_SSN: {...}, ... }
//
//	var SecretMetadata = map[SecretCategory]struct {...}{...}
//
// Toxicity doesn't have a metadata map; we use the literal category
// strings and severity=5 (matches Platform's behavior).
func parseTypesMetadata(typesPath string) (map[string]metadata, error) {
	data, err := os.ReadFile(typesPath)
	if err != nil {
		return nil, err
	}
	text := string(data)

	out := make(map[string]metadata)

	// PII metadata: PII_SSN: {"US Social Security Number", []string{"SOC2", "HIPAA", "PCI-DSS"}, 5, "XXX-XX-"}
	piiRe := regexp.MustCompile(`(PII_[A-Z_]+):\s*\{("[^"]+")\s*,\s*\[\]string\{([^}]+)\}\s*,\s*(\d+)`)
	for _, m := range piiRe.FindAllStringSubmatch(text, -1) {
		key := m[1]
		desc := strings.Trim(m[2], `"`)
		compliance := parseStringArray(m[3])
		sev, _ := strconv.Atoi(m[4])
		out[key] = metadata{
			Category:    keyToCategory(key),
			Severity:    sev,
			Description: desc,
			Compliance:  compliance,
		}
	}

	// Secret metadata: SECRET_API_KEY: {"API Key for various services", []string{"SOC2"}, 4, []string{"Stripe", ...}}
	secretRe := regexp.MustCompile(`(SECRET_[A-Z_]+):\s*\{("[^"]+")\s*,\s*\[\]string\{([^}]+)\}\s*,\s*(\d+)\s*,\s*\[\]string\{([^}]+)\}\}`)
	for _, m := range secretRe.FindAllStringSubmatch(text, -1) {
		key := m[1]
		desc := strings.Trim(m[2], `"`)
		compliance := parseStringArray(m[3])
		sev, _ := strconv.Atoi(m[4])
		providers := parseStringArray(m[5])
		out[key] = metadata{
			Category:    keyToCategory(key),
			Severity:    sev,
			Description: desc,
			Compliance:  compliance,
			Providers:   providers,
		}
	}

	// Toxicity: no metadata map. Use the literal category name (lowercase)
	// and severity 5.
	for _, key := range []string{
		"TOXICITY_HATE_SPEECH",
		"TOXICITY_VIOLENCE",
		"TOXICITY_SEXUAL",
		"TOXICITY_SELF_HARM",
		"TOXICITY_HARASSMENT",
		"TOXICITY_WEAPONS",
		"TOXICITY_ILLEGAL",
	} {
		out[key] = metadata{
			Category:    strings.ToLower(strings.TrimPrefix(key, "TOXICITY_")),
			Severity:    5,
			Description: "Toxic content: " + strings.ToLower(strings.TrimPrefix(key, "TOXICITY_")),
		}
	}

	return out, nil
}

// parseStringArray parses ` "x", "y", "z"` into []string{"x", "y", "z"}.
func parseStringArray(s string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// keyToCategory converts a Go const like "PII_SSN" or "SECRET_API_KEY"
// to the Lens-side category string (e.g., "pii_ssn", "secret_api_key").
//
// The convention in the Platform is the lowercase string with underscores.
func keyToCategory(goKey string) string {
	// Strip the prefix and lowercase.
	prefixes := []string{"PII_", "SECRET_", "TOXICITY_", "HALLUCINATION_"}
	for _, p := range prefixes {
		if strings.HasPrefix(goKey, p) {
			return strings.ToLower(p + strings.TrimPrefix(goKey, p))
		}
	}
	return strings.ToLower(goKey)
}

// convertGoRegexToJS converts a Go regex string to a JS regex.
//
// Go uses (?i) for inline case-insensitive; JS uses the trailing /i flag.
// Go uses backtick raw strings; we don't need to worry about that since
// the regex string we extracted already has the backticks stripped.
//
// We return (jsPattern, hasIFlag).
func convertGoRegexToJS(goRegex string) (string, bool) {
	hasI := false
	// Strip the (?i) at the start of the pattern (or anywhere it appears).
	// JavaScript doesn't have inline flags; we move (?i) to the trailing
	// /i flag.
	//
	// Note: we only strip (?i). Go's regex also supports (?s) for
	// single-line mode and (?m) for multi-line, but the Platform's
	// patterns don't use them — they're using (?i) only.
	cleaned := goRegex
	for {
		idx := strings.Index(cleaned, "(?i)")
		if idx == -1 {
			break
		}
		hasI = true
		cleaned = cleaned[:idx] + cleaned[idx+4:]
	}
	return cleaned, hasI
}

// severityToLens maps Platform's 1-5 integer severity to the Lens's
// "low"/"medium"/"high"/"critical" string.
func severityToLens(sev int) string {
	switch {
	case sev >= 5:
		return "critical"
	case sev >= 4:
		return "high"
	case sev >= 3:
		return "medium"
	default:
		return "low"
	}
}

// escapeJSString escapes a string for use inside a JS single-quoted
// string literal.
func escapeJSString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

// render produces the JavaScript module from the extracted patterns.
func render(patterns []patternExtraction) string {
	var sb strings.Builder

	sb.WriteString(`/* SPDX-License-Identifier: Apache-2.0
   =========================================================================
   AegisGate Lens - Platform-Ported Detections
   =========================================================================

   *** THIS FILE IS GENERATED. DO NOT EDIT BY HAND. ***

   This file is generated by tools/port-detections in the Platform
   monorepo. The source is the Platform's Go detection files in
   pkg/response/{pii_scanner,secret_detector,toxicity_filter}.go.

   The Platform has 40+ detection categories battle-tested with
   6,400 lines of tests. This file ports the regex patterns to
   JavaScript so the Lens can run them in the browser with zero
   dependencies.

   To regenerate:
     cd consolidated/aegisgate-platform
     go build -o /tmp/port-detections ./tools/port-detections/
     /tmp/port-detections --platform-root . --out lens-repo-bootstrap/src/detectors/from_platform.js

   CI verification:
     The Platform's build tool can verify this file matches what
     the Go source produces (deterministic, byte-identical).
     Drift detected -> build fails.

   Privacy: this file contains ONLY regex pattern strings and
   metadata (category, severity, name, description). It does NOT
   contain any prompt content, URLs, or page content. See
   legal/AEGISGATE-LENS-LEGAL-DEVELOPER-CONSTRAINTS.md,
   non-negotiable #1.

   Plain JavaScript, no transpilation, no dependencies.
   The bytes in this file are the bytes that run in the browser.

   v0.1 pre-release.
   ========================================================================= */

'use strict';

(function () {
  const NS = (typeof window !== 'undefined' ? window : self).AegisGateLens =
    (typeof window !== 'undefined' ? window : self).AegisGateLens || {};

  /**
   * @typedef {Object} PortedPattern
   * @property {string} source       'pii_scanner' | 'secret_detector' | 'toxicity_filter'
   * @property {string} category     Lowercase category identifier
   *   (e.g., "pii_ssn", "secret_api_key").
   * @property {string} name         Stable identifier for this pattern.
   *   Format: "<source>_<category>_v1". Used by telemetry and tests.
   * @property {'low'|'medium'|'high'|'critical'} severity
   *   How bad it is if this data leaks. Mapped from the Platform's
   *   1-5 severity (5 -> critical, 4 -> high, 3 -> medium, 1-2 -> low).
   * @property {RegExp} regex        Compiled at module load. ES2020-compliant
   *   pattern; no lookbehind, no backreferences.
   * @property {string} description  One-line human-readable description.
   * @property {ReadonlyArray<string>} compliance  Tags like "GDPR", "HIPAA",
   *   "SOC2", "PCI-DSS".
   */

  /**
   * The patterns array. Ordered by source then category for stable output.
   * @type {ReadonlyArray<PortedPattern>}
   */
  const PATTERNS = Object.freeze([
`)

	// Sort: by source, then by GoKey
	sort.SliceStable(patterns, func(i, j int) bool {
		if patterns[i].Source != patterns[j].Source {
			return patterns[i].Source < patterns[j].Source
		}
		return patterns[i].GoKey < patterns[j].GoKey
	})

	for i, p := range patterns {
		jsPattern, hasInlineI := convertGoRegexToJS(p.GoRegex)
		hasI := p.HasCaseInsensitive || hasInlineI
		jsFlags := ""
		if hasI {
			jsFlags = "i"
		}

		// Skip patterns we know are too noisy for the Lens context.
		// The Platform's server-side context tolerates false positives;
		// the Lens's user-facing UI does not.
		skipReasons := []string{}
		category := p.Category
		if category == "" {
			category = strings.ToLower(p.GoKey)
		}
		// PII_NAME matches "Dr. Smith" etc. — common in chat. Skip.
		if category == "pii_name" {
			skipReasons = append(skipReasons, "high false positive rate in chat context")
		}
		// PII_PASSPORT matches any 9-char alphanumeric token. Too broad.
		if category == "pii_passport" {
			skipReasons = append(skipReasons, "9-char alphanumeric is too broad")
		}
		// HALLUCINATION_* is for AI output, not user input.
		if strings.HasPrefix(category, "hallucination") {
			skipReasons = append(skipReasons, "hallucination detection is for AI output, not user input")
		}
		// OWASP/ATLAS "ask for SSN/credit card" patterns are server-side
		// intent classifiers (e.g., "user asked for an SSN"). They match
		// the WORD "SSN" anywhere, which fires on every security article.
		if strings.Contains(category, "sensitive_disclosure") {
			skipReasons = append(skipReasons, "matches standalone 'SSN'/'credit card' words; too noisy for chat")
		}
		// EU AI Act biometric patterns match "facial recognition" etc. —
		// legitimate security topics, not attacks.
		if strings.HasPrefix(category, "eu_ai_act_biometric") {
			skipReasons = append(skipReasons, "biometric-pattern detection is for AI compliance, not user prompts")
		}
		// Generic cardinality / URL reducers are server-side ops, not detection.
		if strings.Contains(p.GoRegex, "cardinality") || strings.Contains(p.GoRegex, "^/v\\d+") {
			skipReasons = append(skipReasons, "URL cardinality reducer, not detection")
		}
		if len(skipReasons) > 0 {
			sb.WriteString(fmt.Sprintf("    // SKIPPED: %s — %s\n", p.GoKey, strings.Join(skipReasons, "; ")))
			continue
		}

		// If the pattern had a generic key (e.g., PII_CUSTOM for masked
		// patterns), derive a more descriptive category from the source.
		if p.GoKey == "PII_CUSTOM" || p.GoKey == "SECRET_API_KEY" && !p.IsNamed {
			// Masked PII pattern → treat as generic_email or similar.
			// Most masked patterns in pii_scanner are user-provided;
			// in secret_detector they're provider-specific (sk-, sk-ant-,
			// AIza, SK..., SG.). Use a category derived from the regex
			// prefix when possible.
			category = deriveMaskedCategory(jsPattern, category)
		}

		severityStr := severityToLens(p.Severity)

		complianceJSON := "[]"
		if len(p.Compliance) > 0 {
			var items []string
			for _, c := range p.Compliance {
				items = append(items, fmt.Sprintf("'%s'", escapeJSString(c)))
			}
			complianceJSON = "[" + strings.Join(items, ", ") + "]"
		}

		// Build the stable name. For compliance patterns, use the framework ID
		// (e.g., "LLM01-001" or "T1535.001") so the name is unique across
		// categories. For legacy patterns, use source_category_v1.
		var name string
		if p.FrameworkID != "" {
			name = p.Source + "_" + p.FrameworkID
		} else {
			name = p.Source + "_" + category + "_v1"
		}
		desc := p.Description
		if desc == "" {
			desc = fmt.Sprintf("%s from %s", p.GoKey, p.Source)
		}

		// Truncate description if very long
		if len(desc) > 100 {
			desc = desc[:97] + "..."
		}

		comma := ","
		if i == len(patterns)-1 {
			comma = ""
		}

		sb.WriteString(fmt.Sprintf("    Object.freeze({\n"))
		sb.WriteString(fmt.Sprintf("      source: '%s',\n", escapeJSString(p.Source)))
		sb.WriteString(fmt.Sprintf("      category: '%s',\n", escapeJSString(category)))
		sb.WriteString(fmt.Sprintf("      name: '%s',\n", escapeJSString(name)))
		sb.WriteString(fmt.Sprintf("      severity: '%s',\n", severityStr))
		sb.WriteString(fmt.Sprintf("      regex: new RegExp('%s'%s),\n", escapeJSString(jsPattern), flagArg(jsFlags)))
		sb.WriteString(fmt.Sprintf("      description: '%s',\n", escapeJSString(desc)))
		sb.WriteString(fmt.Sprintf("      compliance: Object.freeze(%s),\n", complianceJSON))
		sb.WriteString(fmt.Sprintf("    })%s\n", comma))
	}

	sb.WriteString(`  ]);

  NS.detectors = NS.detectors || {};
  NS.detectors.fromPlatform = Object.freeze({
    PATTERNS,
    /** The number of patterns in this module. */
    get count() { return PATTERNS.length; },
  });
})();
`)
	return sb.String()
}

// flagArg formats the JS RegExp flags argument.
// We always emit the 'g' flag so text.matchAll(regex) works.
// We append 'i' if the Go pattern had (?i).
func flagArg(flags string) string {
	all := "g"
	if flags != "" {
		all = "g" + flags
	}
	return ", '" + all + "'"
}

// deriveMaskedCategory gives a meaningful category to a "masked" pattern
// (one that didn't have a Go-side constant key).
func deriveMaskedCategory(jsPattern, fallback string) string {
	// Common prefixes we can identify.
	prefixes := map[string]string{
		`sk-[a-zA-Z0-9]{48}`:           "secret_openai_key",
		`sk-proj-`:                     "secret_openai_key",
		`sk-ant-`:                      "secret_anthropic_key",
		`AIza`:                         "secret_google_api_key",
		`SK[0-9a-fA-F]{32}`:            "secret_twilio_key",
		`SG\.[a-zA-Z0-9_-]{22}\.`:      "secret_sendgrid_key",
		`api[_-]?key|apikey`:           "secret_generic_api_key",
		`token|auth`:                   "secret_generic_token",
	}
	for prefix, cat := range prefixes {
		if strings.Contains(jsPattern, prefix) {
			return cat
		}
	}
	return fallback
}

func main() {
	platformRoot := flag.String("platform-root", ".", "path to aegisgate-platform repo root")
	outPath := flag.String("out", "", "output JS file path")
	flag.Parse()

	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "--out is required")
		os.Exit(2)
	}

	patterns, err := compile(*platformRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compile:", err)
		os.Exit(3)
	}

	rendered := render(patterns)

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(4)
	}
	if err := os.WriteFile(*outPath, []byte(rendered), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(5)
	}

	// Report skipped patterns.
	skipped := 0
	for _, p := range patterns {
		c := p.Category
		if c == "" {
			c = strings.ToLower(p.GoKey)
		}
		if c == "pii_name" || c == "pii_passport" || strings.HasPrefix(c, "hallucination") {
			skipped++
		}
	}
	fmt.Fprintf(os.Stderr, "port-detections: %d patterns ported, %d skipped, %d total\n",
		len(patterns)-skipped, skipped, len(patterns))
}