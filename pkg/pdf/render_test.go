// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Report Renderer tests (TODO-501)
//
// render_test.go covers the v0.1 PDF renderer:
//   - RenderRequest validation
//   - Title / heading / paragraph / table / page break
//   - PDF magic bytes and trailer markers (valid PDF)
//   - pdfEscape and BuildReportFromData helpers
//   - Edge cases: empty data, special characters, large tables

package pdf

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// =====================================================================
// Test helpers
// =====================================================================

// makeSimpleRequest returns a minimal valid RenderRequest.
func makeSimpleRequest() *RenderRequest {
	return &RenderRequest{
		Title: "Test Report",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Hello, world."},
		},
	}
}

// containsPDFMagic returns true if data starts with the
// PDF magic header.
func containsPDFMagic(data []byte) bool {
	return bytes.HasPrefix(data, []byte("%PDF-1.4"))
}

// containsPDFEOF returns true if data ends with the PDF
// end-of-file marker.
func containsPDFEOF(data []byte) bool {
	return bytes.HasSuffix(data, []byte("%%EOF\n"))
}

// countPageObjects returns the number of "/Type /Page"
// occurrences in the data. (Each page has one such
// object.)
func countPageObjects(data []byte) int {
	return bytes.Count(data, []byte("/Type /Page "))
}

// countPagesTree returns 1 if the data has a Pages tree,
// 0 otherwise.
func countPagesTree(data []byte) int {
	if bytes.Contains(data, []byte("/Type /Pages")) {
		return 1
	}
	return 0
}

// =====================================================================
// RenderReport validation
// =====================================================================

func TestRenderReport_NilRequest(t *testing.T) {
	if _, err := RenderReport(nil); err == nil {
		t.Errorf("RenderReport(nil) should fail")
	}
}

func TestRenderReport_EmptyTitle(t *testing.T) {
	req := makeSimpleRequest()
	req.Title = ""
	if _, err := RenderReport(req); err == nil {
		t.Errorf("RenderReport with empty title should fail")
	}
}

func TestRenderReport_NoSections(t *testing.T) {
	req := makeSimpleRequest()
	req.Sections = nil
	if _, err := RenderReport(req); err == nil {
		t.Errorf("RenderReport with no sections should fail")
	}
}

func TestRenderReport_UnknownSectionKind(t *testing.T) {
	req := makeSimpleRequest()
	req.Sections = []Section{
		{Kind: SectionKind("unknown"), Text: "test"},
	}
	if _, err := RenderReport(req); err == nil {
		t.Errorf("RenderReport with unknown section kind should fail")
	}
}

func TestRenderReport_TableInconsistentRows(t *testing.T) {
	req := makeSimpleRequest()
	req.Sections = []Section{
		{Kind: SectionTable, Table: Table{Rows: [][]string{
			{"a", "b", "c"},
			{"1", "2"}, // 2 cells, should be 3
		}}},
	}
	if _, err := RenderReport(req); err == nil {
		t.Errorf("RenderReport with inconsistent table rows should fail")
	}
}

func TestRenderReport_EmptyTable(t *testing.T) {
	req := makeSimpleRequest()
	req.Sections = []Section{
		{Kind: SectionTable, Table: Table{Rows: nil}},
	}
	if _, err := RenderReport(req); err == nil {
		t.Errorf("RenderReport with empty table should fail")
	}
}

func TestRenderReport_HappyPath(t *testing.T) {
	req := makeSimpleRequest()
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !containsPDFMagic(data) {
		t.Errorf("Output does not start with PDF magic")
	}
	if !containsPDFEOF(data) {
		t.Errorf("Output does not end with PDF EOF marker")
	}
	if countPageObjects(data) != 1 {
		t.Errorf("Expected 1 page object, got %d", countPageObjects(data))
	}
	if countPagesTree(data) != 1 {
		t.Errorf("Expected Pages tree, got 0")
	}
}

// =====================================================================
// Page breaks
// =====================================================================

func TestRenderReport_PageBreak(t *testing.T) {
	req := &RenderRequest{
		Title: "Page Break Test",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Page 1 content"},
			{Kind: SectionPageBreak},
			{Kind: SectionParagraph, Text: "Page 2 content"},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if countPageObjects(data) != 2 {
		t.Errorf("Expected 2 page objects, got %d", countPageObjects(data))
	}
}

func TestRenderReport_AutomaticPageBreak(t *testing.T) {
	// Create a request with many sections that will
	// overflow the page; the renderer should
	// automatically break to a new page.
	req := &RenderRequest{
		Title: "Auto Page Break",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Start"},
		},
	}
	// Add 200 paragraph sections to force overflow.
	for i := 0; i < 200; i++ {
		req.Sections = append(req.Sections, Section{
			Kind: SectionParagraph,
			Text: "Filler paragraph for overflow test",
		})
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if countPageObjects(data) < 2 {
		t.Errorf("Expected multiple page objects (auto page break), got %d", countPageObjects(data))
	}
}

// =====================================================================
// Section types
// =====================================================================

func TestRenderReport_Heading(t *testing.T) {
	req := &RenderRequest{
		Title: "Heading Test",
		Sections: []Section{
			{Kind: SectionHeading, Text: "My Heading"},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !containsPDFMagic(data) {
		t.Errorf("Output is not a valid PDF")
	}
}

func TestRenderReport_Table(t *testing.T) {
	req := &RenderRequest{
		Title: "Table Test",
		Sections: []Section{
			{Kind: SectionTable, Table: Table{Rows: [][]string{
				{"A", "B", "C"},
				{"1", "2", "3"},
				{"4", "5", "6"},
			}}},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !containsPDFMagic(data) {
		t.Errorf("Output is not a valid PDF")
	}
}

func TestRenderReport_TableWithCustomColumns(t *testing.T) {
	req := &RenderRequest{
		Title: "Table with Custom Columns",
		Sections: []Section{
			{Kind: SectionTable, Table: Table{Rows: [][]string{
				{"A", "B"},
				{"1", "2"},
			}}, Columns: []float64{200, 300}},
		},
	}
	if _, err := RenderReport(req); err != nil {
		t.Errorf("RenderReport with custom columns: %v", err)
	}
}

// =====================================================================
// Page sizes
// =====================================================================

func TestRenderReport_PageLetter(t *testing.T) {
	req := makeSimpleRequest()
	req.PageSize = PageLetter
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !bytes.Contains(data, []byte("612 792")) {
		t.Errorf("Output does not contain Letter page dimensions (612 792)")
	}
}

func TestRenderReport_PageA4(t *testing.T) {
	req := makeSimpleRequest()
	req.PageSize = PageA4
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !bytes.Contains(data, []byte("595 842")) {
		t.Errorf("Output does not contain A4 page dimensions (595 842)")
	}
}

func TestRenderReport_DefaultPageSize(t *testing.T) {
	req := makeSimpleRequest()
	req.PageSize = PageSize{} // zero value
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	// Default should be Letter.
	if !bytes.Contains(data, []byte("612 792")) {
		t.Errorf("Default page size is not Letter")
	}
}

// =====================================================================
// Metadata
// =====================================================================

func TestRenderReport_GeneratedAt(t *testing.T) {
	req := makeSimpleRequest()
	req.GeneratedAt = time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	// GeneratedAt is a metadata field that v0.1 doesn't
	// embed in the body, but the request should still
	// validate and render.
	if _, err := RenderReport(req); err != nil {
		t.Errorf("RenderReport: %v", err)
	}
}

func TestRenderReport_Footer(t *testing.T) {
	req := makeSimpleRequest()
	req.Footer = "Custom Footer"
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !bytes.Contains(data, []byte("Custom Footer")) {
		t.Errorf("Custom footer not in output")
	}
}

func TestRenderReport_DefaultFooter(t *testing.T) {
	req := makeSimpleRequest()
	req.Footer = ""
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !bytes.Contains(data, []byte("AegisGate Platform")) {
		t.Errorf("Default footer not in output")
	}
}

// =====================================================================
// Special characters (pdfEscape)
// =====================================================================

func TestPdfEscape_BasicASCII(t *testing.T) {
	got := pdfEscape("Hello, world!")
	if got != "Hello, world!" {
		t.Errorf("pdfEscape basic ASCII = %q, want %q", got, "Hello, world!")
	}
}

func TestPdfEscape_Parentheses(t *testing.T) {
	got := pdfEscape("(parens)")
	if got != "\\(parens\\)" {
		t.Errorf("pdfEscape parens = %q, want %q", got, "\\(parens\\)")
	}
}

func TestPdfEscape_Backslash(t *testing.T) {
	got := pdfEscape(`back\slash`)
	if got != `back\\slash` {
		t.Errorf("pdfEscape backslash = %q, want %q", got, `back\\slash`)
	}
}

func TestPdfEscape_NonASCII(t *testing.T) {
	// v0.2 behavior: WinAnsi-encodable characters
	// (like é) are preserved as their WinAnsi bytes;
	// non-WinAnsi characters are replaced with '?'.
	got := pdfEscape("héllo")
	// é is 0xE9 in WinAnsi. The other characters
	// are ASCII.
	if !strings.Contains(got, "\xE9") {
		t.Errorf("pdfEscape 'héllo' = %q, expected to contain 0xE9 (é)", got)
	}
	// The original é (Unicode 0x00E9) is now
	// represented as the WinAnsi byte 0xE9, not as
	// the original Unicode code point.
	if strings.ContainsRune(got, 'é') {
		t.Errorf("pdfEscape 'héllo' = %q, should contain WinAnsi byte 0xE9, not Unicode é", got)
	}
}

func TestPdfEscape_NonWinAnsi(t *testing.T) {
	// Non-WinAnsi characters (e.g., Chinese) are
	// replaced with '?'.
	got := pdfEscape("你好")
	if !strings.Contains(got, "?") {
		t.Errorf("pdfEscape '你好' = %q, expected '?' replacement", got)
	}
}

func TestPdfEscape_Empty(t *testing.T) {
	if got := pdfEscape(""); got != "" {
		t.Errorf("pdfEscape empty = %q, want empty", got)
	}
}

// =====================================================================
// BuildReportFromData
// =====================================================================

func TestBuildReportFromData_StringSlice(t *testing.T) {
	data := [][]string{
		{"A", "B"},
		{"1", "2"},
	}
	sections := BuildReportFromData("Title", "Subtitle", data)
	if len(sections) != 2 {
		t.Errorf("Expected 2 sections (subtitle + table), got %d", len(sections))
	}
	if sections[0].Kind != SectionHeading {
		t.Errorf("First section kind = %q, want heading", sections[0].Kind)
	}
	if sections[1].Kind != SectionTable {
		t.Errorf("Second section kind = %q, want table", sections[1].Kind)
	}
}

func TestBuildReportFromData_ListOfMaps(t *testing.T) {
	data := []map[string]interface{}{
		{"a": "1", "b": "2"},
		{"a": "3", "b": "4"},
	}
	sections := BuildReportFromData("Title", "", data)
	if len(sections) != 1 {
		t.Fatalf("Expected 1 section, got %d", len(sections))
	}
	if sections[0].Kind != SectionTable {
		t.Errorf("Section kind = %q, want table", sections[0].Kind)
	}
	// 3 rows: header + 2 data.
	if len(sections[0].Table.Rows) != 3 {
		t.Errorf("Table rows = %d, want 3", len(sections[0].Table.Rows))
	}
}

func TestBuildReportFromData_EmptyListOfMaps(t *testing.T) {
	data := []map[string]interface{}{}
	sections := BuildReportFromData("Title", "", data)
	if len(sections) != 1 {
		t.Errorf("Expected 1 section for empty list, got %d", len(sections))
	}
	if sections[0].Kind != SectionParagraph {
		t.Errorf("Section kind = %q, want paragraph", sections[0].Kind)
	}
}

func TestBuildReportFromData_Map(t *testing.T) {
	data := map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	}
	sections := BuildReportFromData("Title", "", data)
	// 3 key-value pairs as 3 paragraphs.
	if len(sections) != 3 {
		t.Errorf("Expected 3 sections, got %d", len(sections))
	}
	for i, s := range sections {
		if s.Kind != SectionParagraph {
			t.Errorf("Section[%d] kind = %q, want paragraph", i, s.Kind)
		}
	}
}

func TestBuildReportFromData_String(t *testing.T) {
	sections := BuildReportFromData("Title", "", "just a string")
	if len(sections) != 1 {
		t.Errorf("Expected 1 section, got %d", len(sections))
	}
	if sections[0].Kind != SectionParagraph {
		t.Errorf("Section kind = %q, want paragraph", sections[0].Kind)
	}
	if sections[0].Text != "just a string" {
		t.Errorf("Section text = %q, want %q", sections[0].Text, "just a string")
	}
}

func TestBuildReportFromData_UnknownType(t *testing.T) {
	// An int is unknown, should fall through to JSON dump.
	sections := BuildReportFromData("Title", "", 42)
	if len(sections) != 1 {
		t.Errorf("Expected 1 section, got %d", len(sections))
	}
	if sections[0].Kind != SectionParagraph {
		t.Errorf("Section kind = %q, want paragraph", sections[0].Kind)
	}
	// The text should be a JSON representation of 42.
	if !strings.Contains(sections[0].Text, "42") {
		t.Errorf("Section text = %q, expected to contain '42'", sections[0].Text)
	}
}

func TestBuildReportFromData_NoSubtitle(t *testing.T) {
	sections := BuildReportFromData("Title", "", [][]string{{"a"}})
	if len(sections) != 1 {
		t.Errorf("Expected 1 section (no subtitle), got %d", len(sections))
	}
}

// =====================================================================
// sortedKeys
// =====================================================================

func TestSortedKeys(t *testing.T) {
	m := map[string]interface{}{
		"banana": 1,
		"apple":  2,
		"cherry": 3,
	}
	keys := sortedKeys(m)
	if len(keys) != 3 {
		t.Fatalf("Expected 3 keys, got %d", len(keys))
	}
	want := []string{"apple", "banana", "cherry"}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("sortedKeys[%d] = %q, want %q", i, k, want[i])
		}
	}
}

func TestSortedKeys_Empty(t *testing.T) {
	keys := sortedKeys(map[string]interface{}{})
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}
}

// =====================================================================
// formatTime
// =====================================================================

func TestFormatTime(t *testing.T) {
	t1 := time.Date(2026, 6, 18, 12, 30, 45, 0, time.UTC)
	got := formatTime(t1)
	want := "2026-06-18 12:30:45 UTC"
	if got != want {
		t.Errorf("formatTime = %q, want %q", got, want)
	}
}

// =====================================================================
// PDF structure integrity
// =====================================================================

func TestRenderReport_ValidPDFStructure(t *testing.T) {
	req := &RenderRequest{
		Title:    "Structure Test",
		Author:   "Test Author",
		Subject:  "Test Subject",
		Keywords: "test, pdf",
		Footer:   "Test Footer",
		Sections: []Section{
			{Kind: SectionHeading, Text: "Heading 1"},
			{Kind: SectionParagraph, Text: "Paragraph 1"},
			{Kind: SectionTable, Table: Table{Rows: [][]string{
				{"Col 1", "Col 2"},
				{"val 1", "val 2"},
			}}},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	// Magic header.
	if !bytes.HasPrefix(data, []byte("%PDF-1.4")) {
		t.Errorf("Missing PDF magic header")
	}
	// Binary comment.
	if !bytes.Contains(data, []byte{0xe2, 0xe3, 0xcf, 0xd3}) {
		t.Errorf("Missing binary comment")
	}
	// Catalog object.
	if !bytes.Contains(data, []byte("/Type /Catalog")) {
		t.Errorf("Missing catalog object")
	}
	// Pages tree.
	if !bytes.Contains(data, []byte("/Type /Pages")) {
		t.Errorf("Missing pages tree")
	}
	// Page object.
	if !bytes.Contains(data, []byte("/Type /Page ")) {
		t.Errorf("Missing page object")
	}
	// Helvetica font (built-in).
	if !bytes.Contains(data, []byte("/Helvetica")) {
		t.Errorf("Missing Helvetica font")
	}
	// xref.
	if !bytes.Contains(data, []byte("xref")) {
		t.Errorf("Missing xref table")
	}
	// trailer.
	if !bytes.Contains(data, []byte("trailer")) {
		t.Errorf("Missing trailer")
	}
	// EOF.
	if !bytes.HasSuffix(data, []byte("%%EOF\n")) {
		t.Errorf("Missing EOF marker")
	}
}

func TestRenderReport_EmptyTableRendersOK(t *testing.T) {
	// A table with a single row is valid; it should
	// render without error.
	req := &RenderRequest{
		Title: "Single Row Table",
		Sections: []Section{
			{Kind: SectionTable, Table: Table{Rows: [][]string{{"only one row"}}}},
		},
	}
	if _, err := RenderReport(req); err != nil {
		t.Errorf("RenderReport: %v", err)
	}
}

// =====================================================================
// Sanitize
// =====================================================================

// bytesContainsBytes returns true if data contains
// substr (raw bytes). Defined here because the
// alternative (importing bytes) would require a
// runtime import; this keeps the test file
// self-contained.
func bytesContainsBytes(data, substr []byte) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(data) {
		return false
	}
	for i := 0; i <= len(data)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if data[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestSanitizeASCII(t *testing.T) {
	got := sanitizeASCII("hello (world)")
	if got != "hello \\(world\\)" {
		t.Errorf("sanitizeASCII = %q, want %q", got, "hello \\(world\\)")
	}
}

// =====================================================================
// v0.2 branding
// =====================================================================

func TestRenderReport_WithHeader(t *testing.T) {
	// v0.2: when Header is set, the page 1 should
	// contain the header text (left-aligned) + the
	// subtitle (right-aligned) + the title
	// (centered, below the header).
	req := &RenderRequest{
		Title:           "Test Document",
		Author:          "Test Author",
		Header:          "AegisGate Posture Digest",
		HeaderSubtitle:  "weekly | test-1",
		Footer:          "Generated 2026-06-18 UTC",
		FooterURL:       "https://aegisgatesecurity.io",
		FooterIncludeID: "test-1",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Body content."},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !bytesHasPrefix(data, "%PDF-1.4") {
		t.Errorf("Output is not a valid PDF")
	}
	// The header should appear in the output.
	if !bytesContainsBytes(data, []byte("AegisGate Posture Digest")) {
		t.Errorf("Output does not contain the header")
	}
	// The subtitle should appear in the output.
	if !bytesContainsBytes(data, []byte("weekly | test-1")) {
		t.Errorf("Output does not contain the subtitle")
	}
	// The footer URL should appear in the output.
	if !bytesContainsBytes(data, []byte("https://aegisgatesecurity.io")) {
		t.Errorf("Output does not contain the footer URL")
	}
	// The footer ID should appear in the output.
	if !bytesContainsBytes(data, []byte("ID: test-1")) {
		t.Errorf("Output does not contain the footer ID")
	}
}

func TestRenderReport_WithoutHeader(t *testing.T) {
	// v0.1 behavior: when Header is empty, the
	// page 1 should have the centered title only
	// (no header text).
	req := &RenderRequest{
		Title: "Test Document",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Body content."},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if !bytesHasPrefix(data, "%PDF-1.4") {
		t.Errorf("Output is not a valid PDF")
	}
	// No "AegisGate" branding in the body (the
	// footer defaults to "AegisGate Platform" which
	// is the v0.1 default).
	if !bytesContainsBytes(data, []byte("AegisGate Platform")) {
		t.Errorf("v0.1 default footer not present")
	}
}
