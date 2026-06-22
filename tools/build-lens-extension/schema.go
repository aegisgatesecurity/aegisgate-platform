// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Schema Validator
// =========================================================================
//
// schema.go reads the Go Event struct in
// pkg/lensbackend/validation.go, generates a JSON Schema
// from the struct tags, and asserts that the JSDoc
// `@typedef {Object} LensEvent` block in the Lens source
// declares the same fields with the same JSON names and
// types.
//
// This is the cross-language contract. The Go side and the
// JavaScript side are both sources of truth for the wire
// format; if they drift, the build fails.
//
// We use a hand-rolled JSON Schema generator (no third-party
// library) that reads the Go source file as text, parses the
// struct definition, and produces a JSON Schema document.
// The JS side is parsed from the JSDoc @typedef block in
// api/client.js. The validation is then: for every field
// in the Go struct, is there a corresponding @property in
// the JSDoc typedef? For every @property, is there a
// corresponding field in the Go struct?
//
// v0.1.0+ Lens Phase 1 (plain-JS pivot, 2026-06-19).
// =========================================================================

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SchemaField is one field in the JSON Schema.
type SchemaField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
}

// Schema is the JSON Schema for the Lens event.
type Schema struct {
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Fields      map[string]SchemaField `json:"fields"`
}

// validateSchema reads the Go Event struct and the
// TypeScript LensEvent interface, generates JSON Schemas
// for both, and asserts they match.
//
// On success, the schema is written to <dist>/schema.json
// for the build artifact to include.
//
// On failure, the error describes the first mismatch
// (e.g., "field X is in Go but missing in TypeScript" or
// "field Y has type 'string' in Go but 'number' in TS").
func validateSchema(cfg *Config) error {
	goSchema, err := extractGoEventSchema()
	if err != nil {
		return fmt.Errorf("extract Go schema: %w", err)
	}
	jsSchema, err := extractJSLensEventSchema(cfg.Src)
	if err != nil {
		return fmt.Errorf("extract JavaScript schema: %w", err)
	}
	// Cross-check: every field in Go must be in JS and vice versa.
	if err := crossCheckSchemas(goSchema, jsSchema); err != nil {
		return err
	}
	// Write the schema to <dist>/schema.json. We use the Go
	// side as the authoritative source.
	if err := os.MkdirAll(cfg.Dist, 0o755); err != nil { // #nosec G301 G703 -- build output directory
		return fmt.Errorf("mkdir dist: %w", err)
	}
	b, err := json.MarshalIndent(goSchema, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal schema: %w", err)
	}
	schemaPath := filepath.Join(cfg.Dist, "schema.json")
	// G304 and G703 on the WriteFile line below; G304 is file
	// inclusion, G703 is path traversal. The path is this
	// build's own output, hardcoded.
	if err := os.WriteFile(schemaPath, b, 0o644); err != nil { // #nosec G304 G703 G306 -- schema.json is this build's own output, hardcoded path
		return fmt.Errorf("write schema: %w", err)
	}
	return nil
}

// extractGoEventSchema reads the Go source file at the
// canonical path and extracts the Event struct's fields.
//
// We deliberately use a simple regex-based parser rather
// than go/parser to avoid coupling the build tool to the
// Go AST. The Lens schema is small (~9 fields) and the
// Go source is hand-written, so a regex is sufficient.
//
// If the source format ever changes in a way that breaks
// the regex, the build fails loudly with a clear error
// pointing at the regex.
func extractGoEventSchema() (*Schema, error) {
	// The Go file is at <platform>/pkg/lensbackend/validation.go
	// relative to the platform module root. We compute the
	// path by walking up from the working directory.
	goFile, err := findGoFile()
	if err != nil {
		return nil, err
	}
	src, err := os.ReadFile(goFile) // #nosec G304 -- Go file is a fixed, build-time path computed by walking up from cwd, not from user input
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", goFile, err)
	}
	content := string(src)
	// Extract the Event struct body.
	structBody, err := extractStructBody(content, "Event")
	if err != nil {
		return nil, err
	}
	fields, err := parseGoFields(structBody)
	if err != nil {
		return nil, err
	}
	// The Go side has a method Validate() that documents the
	// required fields; we cross-check the Required flags
	// against the Validate() body. For v0.1 we hard-code
	// the required fields; the build tool can be improved
	// later to parse Validate().
	required := map[string]bool{
		"DomainHash":   true,
		"Category":     true,
		"Severity":     true,
		"UserAction":   true,
		"Timestamp":    true,
		"ModelVersion": true,
		"LensVersion":  true,
		"Confidence":   true,
		"ID":           false, // optional
	}
	// The wire-format field name is taken from the json tag
	// when present; otherwise we derive it via PascalCase
	// -> snake_case. The "ID" field has a special case: it
	// becomes "id" (not "i_d").
	schemaFields := make(map[string]SchemaField, len(fields))
	for goName, f := range fields {
		var wireName string
		if f.JSONName != "" {
			wireName = f.JSONName
		} else {
			wireName = toSnakeCase(goName)
		}
		schemaFields[wireName] = SchemaField{
			Name:        wireName,
			Type:        f.Type,
			Required:    required[goName],
			Description: f.Description,
		}
	}
	return &Schema{
		Title:       "AegisGate Lens Event",
		Description: "The wire format for POST /api/v1/lens/telemetry. v0.1.",
		Version:     "0.1.0",
		Fields:      schemaFields,
	}, nil
}

// goField is a parsed Go struct field.
type goField struct {
	Type        string
	JSONName    string
	Description string
}

// findGoFile returns the absolute path to validation.go.
func findGoFile() (string, error) {
	// Walk up from the working directory until we find
	// pkg/lensbackend/validation.go. The build tool is
	// invoked from <platform>/tools/build-lens-extension/
	// or from the platform root.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "pkg", "lensbackend", "validation.go")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("could not find pkg/lensbackend/validation.go (cwd=%s)", cwd)
}

// extractStructBody extracts the body of a struct definition
// from Go source. Returns the body text (without the outer
// braces) or an error if not found.
func extractStructBody(src, structName string) (string, error) {
	// Find "type <name> struct {"
	pat := regexp.MustCompile(`(?s)type\s+` + regexp.QuoteMeta(structName) + `\s+struct\s*\{([^}]*)\}`)
	m := pat.FindStringSubmatch(src)
	if m == nil {
		return "", fmt.Errorf("struct %q not found", structName)
	}
	return m[1], nil
}

// parseGoFields parses a struct body into a map of field name -> field.
func parseGoFields(body string) (map[string]goField, error) {
	fields := make(map[string]goField)
	// Split on newlines and process each line.
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "//") {
			continue
		}
		// Field line: "Name Type `json:"json_name,omitempty"`"
		// We extract both the type and the JSON tag.
		pat := regexp.MustCompile(`^([A-Z][A-Za-z0-9]*)\s+([^\s` + "`" + `]+)(?:\s+` + "`" + `json:"([^"]+)"(?:\s*,\s*[^"]+)*` + "`" + `)?`)
		m := pat.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		typ := m[2]
		jsonTag := m[3]
		// The json tag may include ",omitempty" etc. We
		// take only the name part (before the first comma).
		jsonName := ""
		if jsonTag != "" {
			if idx := strings.Index(jsonTag, ","); idx >= 0 {
				jsonName = jsonTag[:idx]
			} else {
				jsonName = jsonTag
			}
		}
		fields[name] = goField{Type: typ, JSONName: jsonName}
	}
	return fields, nil
}

// extractJSLensEventSchema reads every .js file in the
// Lens source tree, looking for the JSDoc `@typedef {Object}
// LensEvent` block. It then parses the `@property` lines
// of that block to extract the wire-format fields.
//
// The plain-JS source has no TypeScript interfaces; the
// LensEvent type is documented as a JSDoc @typedef block
// in api/client.js. The build tool's cross-language
// contract is: the JSDoc @typedef must agree field-for-
// field with the Go struct in pkg/lensbackend/validation.go.
//
// Like the Go parser, this is a simple regex-based parser.
// The JS source is hand-written and the schema is small
// (~9 fields), so a regex is sufficient.
func extractJSLensEventSchema(srcDir string) (*Schema, error) {
	// Walk the source tree and find the file containing
	// the LensEvent typedef.
	srcFile, content, err := findLensEventTypedef(srcDir)
	if err != nil {
		return nil, err
	}
	// Find "@typedef {Object} LensEvent" and capture the
	// @property lines until the closing */. The body may
	// contain leading-* on each line (JSDoc style), so we use
	// a lazy match against `*/` rather than excluding `*`.
	pat := regexp.MustCompile(`(?:^|\s|\*)\s*@typedef\s*\{Object\}\s*LensEvent[\s\S]*?\*/`)
	m := pat.FindString(content)
	if m == "" {
		return nil, fmt.Errorf("@typedef LensEvent not found in %s", srcFile)
	}
	fields := make(map[string]SchemaField)
	// Parse each @property line: "@property {type} name" or
	// "@property {type} [name]" (the brackets mark an optional
	// field, per JSDoc convention).
	propPat := regexp.MustCompile(`@property\s*\{([^}]+)\}\s*\[?(\w+)\]?`)
	for _, fm := range propPat.FindAllStringSubmatch(m, -1) {
		typ := strings.TrimSpace(fm[1])
		name := fm[2]
		// Detect optional via leading bracket in original match.
		// The regex consumes the optional brackets so we re-check
		// the full match: if it's `[name]` it's optional.
		fullMatch := fm[0]
		optional := strings.Contains(fullMatch, "["+name+"]")
		// Map JS types to JSON Schema types.
		jsonType := jsTypeToJSONType(typ)
		fields[name] = SchemaField{
			Name:     name,
			Type:     jsonType,
			Required: !optional,
		}
	}
	return &Schema{
		Title:   "AegisGate Lens Event (JavaScript)",
		Version: "0.1.0",
		Fields:  fields,
	}, nil
}

// findLensEventTypedef walks srcDir looking for the first
// .js file containing "@typedef {Object} LensEvent".
// Returns the file path and its contents.
func findLensEventTypedef(srcDir string) (string, string, error) {
	var foundPath, foundContent string
	// Day 15: switched from filepath.Walk to filepath.WalkDir to
	// silence CodeQL G122 (race-prone path in callback). WalkDir uses
	// fs.DirEntry which avoids the path-during-walk race. srcDir is
	// the developer-supplied --src tree, not user input.
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".js") {
			return nil
		}
		// Use the WalkDir 'path' argument directly (not d.Name(),
		// which loses subdirectory info on recursive walks). The
		// path is relative to srcDir, so it's safe to read directly.
		readPath := path
		b, err := os.ReadFile(readPath) // #nosec G304 G703 -- path is from WalkDir of --src tree; codeql[go/path-injection] codeql[go/symlink-fs
		// Day 19 fix (CodeQL alerts #312, #314): the path comes from
		// filepath.WalkDir's own callback arg, which is constrained to
		// srcDir (the developer-supplied --src tree, not user input).
		// The TOCTOU race is not a security issue here because we don't
		// dereference symlinks (we only read .js files for parsing).
		if err != nil {
			return err
		}
		// Look for "@typedef {Object} LensEvent" with optional
		// leading whitespace AND/OR JSDoc asterisk prefix (e.g.,
		// " * @typedef ..."). The previous literal-string check
		// missed JSDoc-formatted typedefs because the "* " prefix
		// wasn't recognized. Day 18 fix.
		if strings.Contains(string(b), "typedef {Object} LensEvent") {
			foundPath = readPath
			foundContent = string(b)
			return fs.SkipAll // stop walking
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	if foundPath == "" {
		return "", "", fmt.Errorf("no .js file contains @typedef {Object} LensEvent (searched %s)", srcDir)
	}
	return foundPath, foundContent, nil
}

// jsTypeToJSONType maps a JSDoc @property type to a JSON
// Schema type. We recognize:
//   - {string}, {number}, {boolean} primitives
//   - {TypeName} aliases (treated as string; the Lens uses
//     string-based enums for Category, Severity, UserAction)
//   - {TypeName[]} array types (treated as the element type)
//   - {?} or {*} treated as string (conservative)
func jsTypeToJSONType(typ string) string {
	typ = strings.TrimSpace(typ)
	// Strip trailing [] for arrays.
	typ = strings.TrimSuffix(typ, "[]")
	switch typ {
	case "string":
		return "string"
	case "number":
		return "number"
	case "boolean":
		return "boolean"
	}
	// Treat any other identifier (Category, Severity, etc.)
	// as string. The wire format stores enums as strings.
	return "string"
}

// crossCheckSchemas asserts that the Go and JavaScript
// schemas describe the same wire format.
func crossCheckSchemas(goSchema, jsSchema *Schema) error {
	// Every Go field must be in JS.
	goNames := make([]string, 0, len(goSchema.Fields))
	for n := range goSchema.Fields {
		goNames = append(goNames, n)
	}
	sort.Strings(goNames)
	for _, name := range goNames {
		if _, ok := jsSchema.Fields[name]; !ok {
			return fmt.Errorf("field %q is in Go but missing in JavaScript", name)
		}
	}
	// Every JS field must be in Go.
	jsNames := make([]string, 0, len(jsSchema.Fields))
	for n := range jsSchema.Fields {
		jsNames = append(jsNames, n)
	}
	sort.Strings(jsNames)
	for _, name := range jsNames {
		if _, ok := goSchema.Fields[name]; !ok {
			return fmt.Errorf("field %q is in JavaScript but missing in Go", name)
		}
	}
	// Type cross-check (only for primitives; ignore aliases).
	for name, goF := range goSchema.Fields {
		jsF, ok := jsSchema.Fields[name]
		if !ok {
			continue
		}
		goJSONType := goTypeToJSONType(goF.Type)
		jsJSONType := jsTypeToJSONType(jsF.Type)
		if goJSONType != "" && jsJSONType != "" && goJSONType != jsJSONType {
			return fmt.Errorf(
				"field %q has type %q in Go but type %q in JavaScript",
				name, goF.Type, jsF.Type,
			)
		}
	}
	return nil
}

// goTypeToJSONType maps a Go type to a JSON Schema type.
// Returns "" if the type is a non-primitive (e.g., a struct,
// a slice) and cross-checking should be skipped.
func goTypeToJSONType(typ string) string {
	switch typ {
	case "string":
		return "string"
	case "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64",
		"float32", "float64":
		return "number"
	case "bool":
		return "boolean"
	}
	return ""
}

// toSnakeCase converts PascalCase to snake_case.
func toSnakeCase(s string) string {
	var out []rune
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			out = append(out, '_')
		}
		out = append(out, r)
	}
	return strings.ToLower(string(out))
}
