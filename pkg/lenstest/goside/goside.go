// SPDX-License-Identifier: Apache-2.0
// Go-side detector for cross-validation with the JS detector.
//
// This package reads the SAME Go source files that the
// port-detections tool reads (pkg/response/*.go, pkg/compliance/*.go,
// pkg/anp/guard.go, pkg/computeruse/guard.go), extracts the regex
// patterns via the same parser logic, and exposes a unified
// Detect() method that mirrors the JS detector's API.
//
// Purpose: cross-validation. The Lens JS detector is ported from
// the Platform Go detectors via the codegen tool. This package
// lets us run the SAME prompts through both the Go and JS detectors
// and assert that they agree on what was detected (drift detection).
//
// Approach: we parse the Go source files ourselves, rather than
// calling the high-level Go detector APIs (which have evolved
// independently of the JS detector's interface). This makes the
// cross-validation test directly comparable to what the codegen
// tool produced.
package goside

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// GosideDetection is one match returned by the Go-side detector.
type GosideDetection struct {
	Category string
	Severity string
	Match    string
	Index    int
	Length   int
	Name     string
}

// Detector wraps a list of compiled regex patterns extracted from
// the Platform's Go source files.
type Detector struct {
	Patterns []PatternDef
}

// PatternDef is one pattern extracted from a Go source file.
type PatternDef struct {
	Source   string
	Category string
	Name     string
	Severity string
	Regex    *regexp.Regexp
}

// New constructs a Detector by reading the Platform Go source files.
// platformRoot is the path to the aegisgate-platform directory
// (the directory containing pkg/).
//
// Reads from the SAME files as the port-detections codegen tool:
//   - pkg/response/pii_scanner.go (extractFromFile)
//   - pkg/response/secret_detector.go (extractFromFile)
//   - pkg/response/toxicity_filter.go (extractFromFile)
//   - pkg/compliance/owasp.go (extractOwaspFile)
//   - pkg/compliance/atlas.go (extractAtlasFile)
//   - pkg/compliance/eu-ai-act/eu_ai_act.go (extractNamedSliceFile)
//   - pkg/anp/guard.go (extractNamedSliceFile)
//   - pkg/computeruse/guard.go (extractNamedSliceFile)
func New(platformRoot string) (*Detector, error) {
	d := &Detector{}

	// 1-3: extractFromFile (PII, secrets, toxicity)
	fileSources := []struct {
		path   string
		source string
	}{
		{filepath.Join(platformRoot, "pkg/response/pii_scanner.go"), "pii_scanner"},
		{filepath.Join(platformRoot, "pkg/response/secret_detector.go"), "secret_detector"},
		{filepath.Join(platformRoot, "pkg/response/toxicity_filter.go"), "toxicity_filter"},
	}
	for _, s := range fileSources {
		patterns, err := extractFromFile(s.path, s.source)
		if err != nil {
			return nil, fmt.Errorf("goside: extract %s: %w", s.path, err)
		}
		d.Patterns = append(d.Patterns, patterns...)
	}

	// 4: OWASP (extractOwaspFile)
	owasp, err := extractOwaspFile(filepath.Join(platformRoot, "pkg/compliance/owasp.go"))
	if err != nil {
		return nil, fmt.Errorf("goside: extract owasp: %w", err)
	}
	d.Patterns = append(d.Patterns, owasp...)

	// 5: ATLAS (extractAtlasFile)
	atlas, err := extractAtlasFile(filepath.Join(platformRoot, "pkg/compliance/atlas.go"))
	if err != nil {
		return nil, fmt.Errorf("goside: extract atlas: %w", err)
	}
	d.Patterns = append(d.Patterns, atlas...)

	// 6-8: extractNamedSliceFile (EU AI Act, ANP, Computer Use)
	namedSources := []struct {
		path          string
		source        string
		frameworkName string
	}{
		{filepath.Join(platformRoot, "pkg/compliance/eu-ai-act/eu_ai_act.go"), "eu_ai_act", "EU AI Act"},
		{filepath.Join(platformRoot, "pkg/anp/guard.go"), "anp_guard", "ANP"},
		{filepath.Join(platformRoot, "pkg/computeruse/guard.go"), "computeruse_guard", "Computer_Use"},
	}
	for _, s := range namedSources {
		patterns, err := extractNamedSliceFile(s.path, s.source, s.frameworkName)
		if err != nil {
			return nil, fmt.Errorf("goside: extract %s: %w", s.source, err)
		}
		d.Patterns = append(d.Patterns, patterns...)
	}

	return d, nil
}

// extractOwaspFile extracts patterns from OWASP LLM Top 10.
// Shape: struct literals with ID, Category, Name, Description, Severity, Regex.
//
// Categories come from the Go struct's Category field (e.g., "LLM01"),
// which the codegen tool maps to "owasp_prompt_injection" etc. via
// the deriveOwaspCategory function. We replicate the same mapping
// here so that Go-side category names match JS detector names.
func extractOwaspFile(path string) ([]PatternDef, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from filepath.WalkDir on the test corpus directory; not user input
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []PatternDef
	type pending struct {
		id, category, name, severity, regex string
	}
	var cur pending
	inBlock := false

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "{") && !inBlock {
			inBlock = true
			cur = pending{}
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(trimmed, "}") {
			if cur.id != "" && cur.regex != "" {
				patStr := cur.regex
				re, err := regexp.Compile(patStr)
				if err != nil {
					inBlock = false
					continue
				}
				// Match the codegen tool's deriveOwaspCategory:
				cat := owaspCategoryMap(cur.category)
				out = append(out, PatternDef{
					Source:   "owasp",
					Category: cat,
					Name:     fmt.Sprintf("owasp_%s", cur.id),
					Severity: cur.severity,
					Regex:    re,
				})
			}
			inBlock = false
			continue
		}
		// Capture fields. Trim quotes and trailing comma.
		if id := strings.TrimPrefix(trimmed, "ID:"); strings.HasPrefix(trimmed, "ID:") && !strings.HasPrefix(trimmed, "IDentifier") {
			cur.id = strings.Trim(strings.TrimSpace(id), `",`)
		}
		if cat := strings.TrimPrefix(trimmed, "Category:"); strings.HasPrefix(trimmed, "Category:") {
			cur.category = strings.Trim(strings.TrimSpace(cat), `",`)
		}
		if sev := strings.TrimPrefix(trimmed, "Severity:"); strings.HasPrefix(trimmed, "Severity:") {
			cur.severity = strings.Trim(strings.TrimSpace(sev), `",`)
		}
		// Regex: regexp.MustCompile(`...`)
		if strings.HasPrefix(trimmed, "Regex:") {
			m := regexp.MustCompile("regexp\\.MustCompile\\(`([^`]*)`").FindStringSubmatch(trimmed)
			if m != nil {
				cur.regex = m[1]
			}
		}
	}
	return out, nil
}

// owaspCategoryMap mirrors deriveOwaspCategory in the codegen tool:
// maps Go's "LLM01"-"LLM10" categories to JS-style "owasp_*" names.
func owaspCategoryMap(category string) string {
	mapping := map[string]string{
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
	if c, ok := mapping[category]; ok {
		return c
	}
	return "owasp_" + strings.ToLower(category)
}

// extractAtlasFile extracts patterns from MITRE ATLAS compliance file.
// Shape: similar to OWASP but uses "ID" like "T1484.001" and "Technique" field.
// The block opener is `f.patterns = append(f.patterns, &Pattern{` rather
// than just `{`.
//
// Categories come from the Go struct's Category field (e.g.,
// "PromptInjection"), which the codegen tool lowercases and prefixes
// with "atlas_" (e.g., "atlas_promptinjection"). This matches the
// JS detector's category names.
func extractAtlasFile(path string) ([]PatternDef, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from filepath.WalkDir on the test corpus directory; not user input
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []PatternDef
	type pending struct {
		id, technique, category, severity, regex string
	}
	var cur pending
	inBlock := false

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}
		// Detect start of a block: either `{` alone or `f.patterns = append(f.patterns, &Pattern{`
		if !inBlock {
			if strings.HasPrefix(trimmed, "{") || strings.Contains(trimmed, "= append(") {
				inBlock = true
				cur = pending{}
				continue
			}
			continue
		}
		if strings.HasPrefix(trimmed, "}") {
			if cur.id != "" && cur.regex != "" {
				patStr := cur.regex
				re, err := regexp.Compile(patStr)
				if err != nil {
					inBlock = false
					continue
				}
				// Match the codegen tool's category naming:
				//   "atlas_" + strings.ToLower(cur.category)
				cat := "atlas_" + strings.ToLower(cur.category)
				out = append(out, PatternDef{
					Source:   "atlas_compliance",
					Category: cat,
					Name:     fmt.Sprintf("atlas_compliance_%s", cur.id),
					Severity: cur.severity,
					Regex:    re,
				})
			}
			inBlock = false
			continue
		}
		// Capture fields. Trim quotes and trailing comma.
		if id := strings.TrimPrefix(trimmed, "ID:"); strings.HasPrefix(trimmed, "ID:") {
			cur.id = strings.Trim(strings.TrimSpace(id), `",`)
		}
		if tech := strings.TrimPrefix(trimmed, "Technique:"); strings.HasPrefix(trimmed, "Technique:") {
			cur.technique = strings.Trim(strings.TrimSpace(tech), `",`)
		}
		if cat := strings.TrimPrefix(trimmed, "Category:"); strings.HasPrefix(trimmed, "Category:") {
			cur.category = strings.Trim(strings.TrimSpace(cat), `",`)
		}
		if sev := strings.TrimPrefix(trimmed, "Severity:"); strings.HasPrefix(trimmed, "Severity:") {
			cur.severity = strings.Trim(strings.TrimSpace(sev), `",`)
		}
		if strings.HasPrefix(trimmed, "Regex:") {
			m := regexp.MustCompile("regexp\\.MustCompile\\(`([^`]*)`").FindStringSubmatch(trimmed)
			if m != nil {
				cur.regex = m[1]
			}
		}
	}
	return out, nil
}

// extractNamedSliceFile extracts regex patterns from a file with
// named regexp slices. Used for EU AI Act, ANP, Computer Use.
//
// Shape: varName = []*regexp.Regexp{ regexp.MustCompile(`...`), ... }
// All regexes in a slice get the same source category.
func extractNamedSliceFile(path, source, frameworkName string) ([]PatternDef, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from filepath.WalkDir on the test corpus directory; not user input
	if err != nil {
		return nil, err
	}
	text := string(data)

	var out []PatternDef
	assignRe := regexp.MustCompile(`(\w+(?:Patterns|Regexp|Regex))\s*=\s*\[\]\*regexp\.Regexp\{`)
	patternRe := regexp.MustCompile("regexp\\.MustCompile\\(\\s*`([^`]*)`\\s*\\)")

	seen := make(map[string]bool)
	for _, m := range assignRe.FindAllStringSubmatch(text, -1) {
		// Find the matching closing brace.
		blockStart := strings.Index(text, m[0])
		if blockStart == -1 {
			continue
		}
		blockEnd := blockStart
		depth := 0
		for i := blockStart; i < len(text); i++ {
			if text[i] == '{' {
				depth++
			} else if text[i] == '}' {
				depth--
				if depth == 0 {
					blockEnd = i
					break
				}
			}
		}
		block := text[blockStart : blockEnd+1]
		varName := m[1]
		// Map varName to category. e.g., "injectionPatterns" -> "injection".
		// Match the codegen tool: strip Patterns/Regexp/Regex suffix
		// then lowercase. This matches JS detector categories.
		catName := strings.TrimSuffix(varName, "Patterns")
		catName = strings.TrimSuffix(catName, "Regexp")
		catName = strings.TrimSuffix(catName, "Regex")
		catName = strings.ToLower(catName)
		sliceCategory := source + "_" + catName

		for _, pm := range patternRe.FindAllStringSubmatch(block, -1) {
			patStr := pm[1]
			if seen[patStr] {
				continue
			}
			seen[patStr] = true
			re, err := regexp.Compile(patStr)
			if err != nil {
				continue
			}
			out = append(out, PatternDef{
				Source:   source,
				Category: sliceCategory,
				Name:     fmt.Sprintf("%s_%s_%d", source, varName, len(out)),
				Severity: "medium",
				Regex:    re,
			})
		}
	}
	_ = frameworkName // unused for now
	return out, nil
}

// extractFromFile finds all regexp.MustCompile(`<PATTERN>`) calls
// in the given Go source file and extracts them as PatternDefs.
//
// This is intentionally simpler than the full codegen tool — we
// just need regex strings and the surrounding variable name.
// Output is suitable for direct comparison to the JS patterns.
func extractFromFile(path, source string) ([]PatternDef, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from filepath.WalkDir on the test corpus directory; not user input
	if err != nil {
		return nil, err
	}

	// Match: <var>[<KEY>] = regexp.MustCompile(`<PATTERN>`)
	//   or: regexp.MustCompile(`<PATTERN>`) alone
	assignedRe := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\[\s*([A-Z_][A-Z0-9_]*)\s*\]\s*=\s*regexp\.MustCompile\(\s*` + "`([^`]*)`" + `\s*\)`)
	plainRe := regexp.MustCompile(`regexp\.MustCompile\(\s*` + "`([^`]*)`" + `\s*\)`)

	// Map Go key constants to category strings. This is a simplified
	// mapping; the full codegen tool has more.
	// For PII: PII_SSN -> pii_ssn, etc.
	// For Secret: SECRET_API_KEY -> secret_api_key
	// For Toxicity: TOXICITY_VIOLENCE -> violence
	keyToCategory := func(key string) string {
		// Convert e.g., PII_SSN -> pii_ssn, SECRET_API_KEY -> secret_api_key.
		// The Go key already encodes the category prefix in a way that
		// matches the JS detector's category strings.
		raw := strings.ToLower(key)
		// Strip the source prefix and re-prepend it lowercased.
		switch source {
		case "pii_scanner":
			// PII_SSN -> pii_ssn
			if strings.HasPrefix(raw, "pii_") {
				return raw
			}
			return "pii_" + raw
		case "secret_detector":
			if strings.HasPrefix(raw, "secret_") {
				return raw
			}
			return "secret_" + raw
		case "toxicity_filter":
			// TOXICITY_VIOLENCE -> violence (no prefix)
			return strings.TrimPrefix(raw, "toxicity_")
		default:
			return raw
		}
	}

	// Severity: PII/secret defaults to "high" or "critical",
	// toxicity defaults to "critical". The codegen tool reads severity
	// from the source; we use simple defaults.
	defaultSeverity := func(key string) string {
		switch source {
		case "pii_scanner":
			if key == "PII_SSN" || key == "PII_CREDIT_CARD" {
				return "critical"
			}
			return "high"
		case "secret_detector":
			return "high"
		case "toxicity_filter":
			return "critical"
		default:
			return "medium"
		}
	}

	var out []PatternDef
	lines := strings.Split(string(data), "\n")
	// Track seen patterns to avoid duplicates from across the file
	seen := make(map[string]bool)
	for _, line := range lines {
		if !strings.Contains(line, "regexp.MustCompile") {
			continue
		}
		// Skip comments
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Try assigned form first
		if m := assignedRe.FindStringSubmatch(line); m != nil {
			key := m[2]
			patStr := m[3]
			if seen[patStr] {
				continue
			}
			seen[patStr] = true
			re, err := regexp.Compile(patStr)
			if err != nil {
				// Skip patterns that don't compile (e.g., lookaheads not supported)
				continue
			}
			out = append(out, PatternDef{
				Source:   source,
				Category: keyToCategory(key),
				Name:     fmt.Sprintf("%s_%s_v1", source, strings.ToLower(key)),
				Severity: defaultSeverity(key),
				Regex:    re,
			})
		} else if m := plainRe.FindStringSubmatch(line); m != nil {
			patStr := m[1]
			if seen[patStr] {
				continue
			}
			seen[patStr] = true
			re, err := regexp.Compile(patStr)
			if err != nil {
				continue
			}
			// Plain-form patterns get a generic category based on the source.
			genericCategory := source
			if source == "secret_detector" {
				genericCategory = "secret_api_key" // default
			} else if source == "toxicity_filter" {
				genericCategory = "toxicity_custom"
			}
			out = append(out, PatternDef{
				Source:   source,
				Category: genericCategory,
				Name:     fmt.Sprintf("%s_anon_%d", source, len(out)),
				Severity: "medium",
				Regex:    re,
			})
		}
	}
	return out, nil
}

// Detect runs all patterns against the text and returns matches.
func (d *Detector) Detect(text string) []GosideDetection {
	var out []GosideDetection
	for _, p := range d.Patterns {
		matches := p.Regex.FindAllStringIndex(text, -1)
		for _, m := range matches {
			out = append(out, GosideDetection{
				Category: p.Category,
				Severity: p.Severity,
				Match:    text[m[0]:m[1]],
				Index:    m[0],
				Length:   m[1] - m[0],
				Name:     p.Name,
			})
		}
	}
	return out
}

// Count returns the number of patterns loaded.
func (d *Detector) Count() int {
	return len(d.Patterns)
}
