// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - XSS Detection Patterns
// =========================================================================
//
// Port of aegisgate-lens/src/detectors/regex/source_xss.js (12 patterns).
// Regex strings are adapted from JavaScript /g flag syntax to Go regexp.
// =========================================================================

package detectors

// XSSPatterns defines all XSS and source code injection detection patterns.
// Lens parity: source_xss.js v0.2.0 (12 patterns).
var XSSPatterns = []PatternDef{
	{
		Name:        "xss_script_tag",
		Severity:    SeverityCritical,
		Regex:       `(?i)<\s*script\b[^>]*>(?:[\s\S]*?<\s*/\s*script\s*>)?`,
		Description: "Script tag (opening or closing)",
	},
	{
		Name:        "xss_event_handler",
		Severity:    SeverityHigh,
		Regex:       `(?i)\s(?:on(?:click|error|load|mouseover|mouseout|focus|blur|submit|change|keydown|keyup|keypress|input|abort|resize|scroll|unload|drag|drop))\s*=\s*["'][^"']*["']`,
		Description: "HTML event handler attribute",
	},
	{
		Name:        "xss_javascript_url",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:href|src|action|formaction)\s*=\s*["']?\s*javascript:`,
		Description: "JavaScript URL in href/src/action",
	},
	{
		Name:        "xss_data_url",
		Severity:    SeverityHigh,
		Regex:       `(?i)(?:href|src|action|formaction)\s*=\s*["']?\s*data:text/html`,
		Description: "data:text/html URL (XSS vector)",
	},
	{
		Name:        "xss_svg_script",
		Severity:    SeverityCritical,
		Regex:       `(?i)<\s*svg\b[^>]*(?:on\w+\s*=|<\s*script)`,
		Description: "SVG with script or event handler",
	},
	{
		Name:        "xss_dom_clobbering",
		Severity:    SeverityMedium,
		Regex:       `(?i)<\s*(?:a|form|img|iframe|input|embed|object)\b[^>]*\s(?:id|name)\s*=\s*["'](?:getElementById|cookie|write|forms|length|parent|top|name)\b`,
		Description: "DOM clobbering via named elements",
	},
	{
		Name:        "xss_svg_namespace_abuse",
		Severity:    SeverityCritical,
		Regex:       `(?i)<\s*svg\b[^>]*\s+(?:xmlns|xmlns:[a-z]+)\s*=\s*["'][^"']*["'][^>]*<\s*(?:foreignObject|animation|set|animate|use|script)\b`,
		Description: "SVG namespace abuse for XSS",
	},
	{
		Name:        "xss_mutation_xss",
		Severity:    SeverityHigh,
		Regex:       `(?i)<\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\b[^>]*>(?:[^<]|<[^/]){0,500}?(?:on\w+\s*=|javascript:)[^<]{0,500}?<\s*/\s*(?:noembed|noscript|title|xmp|iframe|noframes|plaintext|listing)\s*>`,
		Description: "Mutation XSS (mXSS) pattern",
	},
	{
		Name:        "xss_polyglot",
		Severity:    SeverityHigh,
		Regex:       `(?:alert|eval|prompt|confirm|document\.write)\s*\(\s*[` + "`" + `'"'][^` + "`" + `'"']{0,200}?\$\{[^}]{0,100}?\}[^` + "`" + `'"']*[` + "`" + `'"']\s*\)`,
		Description: "Polyglot XSS (multi-context payload)",
	},
	{
		Name:        "xss_svg_use_external",
		Severity:    SeverityCritical,
		Regex:       `(?i)<\s*use\b[^>]*\s(?:xlink:)?href\s*=\s*["']\s*(?:https?:|data:|file:|//)`,
		Description: "SVG use element with external href",
	},
	{
		Name:        "xss_javascript_data_url",
		Severity:    SeverityCritical,
		Regex:       `(?i)(?:href|src|action|formaction|xlink:href|background|poster|cite|usemap|data)\s*=\s*["']?\s*javascript:`,
		Description: "JavaScript scheme in any URL context",
	},
	{
		Name:        "xss_meta_refresh",
		Severity:    SeverityMedium,
		Regex:       `(?i)<\s*meta\b[^>]*\shttp-equiv\s*=\s*["']\s*refresh\s*["'][^>]*\scontent\s*=\s*["'][^"']*javascript:`,
		Description: "Meta refresh with JavaScript URL",
	},
}

// CompiledXSSPatterns holds pre-compiled XSS regex patterns.
var CompiledXSSPatterns []compiledPattern

func init() {
	CompiledXSSPatterns = compilePatterns(XSSPatterns)
}

// DetectXSS scans text for all XSS patterns and returns matches.
func DetectXSS(text string) []Match {
	return detectWithPatterns(text, CompiledXSSPatterns, string(CategoryXSS))
}
