// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Report Renderer — structured report builder (TODO-501)
//
// report.go adapts the upstream `reporting.Report` /
// `reporting.ReportRequest` shape to the v0.1 PDF
// renderer. The platform's `pkg/reporting.Reporter`
// (also part of TODO-501) calls `BuildReportFromData`
// to convert a generic report's `Data` field into a
// list of PDF sections, then passes those sections to
// `pdf.RenderReport`.
//
// The data shapes supported in v0.1:
//
//   - map[string]interface{} with a "title" key: rendered
//     as a heading + key-value pairs as paragraphs.
//   - []map[string]interface{}: rendered as a table where
//     the keys are the column headers and each map is a
//     row.
//   - [][]string: rendered as a table (first row is
//     header).
//   - string: rendered as a paragraph.
//   - everything else: rendered as a "data dump"
//     paragraph.

package pdf

import (
	"encoding/json"
	"fmt"
)

// BuildReportFromData converts a generic report's
// `Data` field into a list of PDF sections. The
// sections are then passed to RenderReport.
//
// The `title` parameter is the document title (set by
// the caller; e.g., "Report {id} -- Type: {type}").
//
// `subtitle` is optional and is rendered as a heading
// below the title (usually the report type).
func BuildReportFromData(title, subtitle string, data interface{}) []Section {
	var sections []Section
	if subtitle != "" {
		sections = append(sections, Section{
			Kind: SectionHeading,
			Text: subtitle,
		})
	}
	switch v := data.(type) {
	case [][]string:
		// Table data: first row is header.
		sections = append(sections, Section{
			Kind:  SectionTable,
			Table: Table{Rows: v},
		})
	case []map[string]interface{}:
		// List-of-records data: derive columns from
		// the keys of the first record (sorted for
		// determinism).
		if len(v) == 0 {
			sections = append(sections, Section{
				Kind: SectionParagraph,
				Text: "(no data)",
			})
			break
		}
		keys := sortedKeys(v[0])
		header := make([]string, len(keys))
		copy(header, keys)
		rows := [][]string{header}
		for _, record := range v {
			row := make([]string, len(keys))
			for i, k := range keys {
				row[i] = fmt.Sprintf("%v", record[k])
			}
			rows = append(rows, row)
		}
		sections = append(sections, Section{
			Kind:  SectionTable,
			Table: Table{Rows: rows},
		})
	case map[string]interface{}:
		// Map data: render as key-value pairs.
		keys := sortedKeys(v)
		for _, k := range keys {
			sections = append(sections, Section{
				Kind: SectionParagraph,
				Text: fmt.Sprintf("%s: %v", k, v[k]),
			})
		}
	case string:
		sections = append(sections, Section{
			Kind: SectionParagraph,
			Text: v,
		})
	default:
		// Fallback: JSON-encode the data and render
		// as a paragraph.
		js, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			sections = append(sections, Section{
				Kind: SectionParagraph,
				Text: fmt.Sprintf("%v", v),
			})
		} else {
			sections = append(sections, Section{
				Kind: SectionParagraph,
				Text: string(js),
			})
		}
	}
	return sections
}

// sortedKeys returns the keys of m in sorted order
// (for deterministic column ordering in the PDF
// table). The keys are converted to strings.
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple insertion sort (the map is small; no
	// need for sort.Strings here to keep imports
	// minimal).
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
