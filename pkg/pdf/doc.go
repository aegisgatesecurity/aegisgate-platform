// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Report Renderer (TODO-501)
//
// Package pdf is a from-scratch PDF 1.4 generator
// that renders AegisGate reports to PDF bytes. It is
// deliberately minimal: text, tables, page breaks, and
// basic metadata. No external font dependencies; uses
// the standard PDF Helvetica-family fonts (which are
// guaranteed to be available in every PDF reader).
//
// v0.1 supports:
//   - Title (centered, large font)
//   - Author / Subject / Keywords metadata
//   - Multi-paragraph body text (left-aligned, with
//     real word-wrap so long lines don't overflow)
//   - Section headings (bold, larger font)
//   - Tables (header row in bold, body rows in regular)
//   - Page breaks (manual via NewPage, automatic on
//     overflow)
//   - Footer with page number
//   - Unicode text (most Western European characters
//     via WinAnsiEncoding; non-Latin scripts replaced
//     with '?')
//
// v0.1 does NOT support:
//   - Images / charts
//   - Non-Western-European Unicode (replaced with '?')
//   - Custom fonts (standard Helvetica family only;
//     word-wrap tables cover F1-F4)
//   - Hyphenation (long words that exceed the line
//     width overflow rather than break)
//
// Design notes:
//
//   - The PDF is generated entirely in memory; no disk
//     I/O. The caller decides where to write the bytes.
//   - The implementation is ~400 LOC, all in this
//     package. Zero external dependencies.
//   - The output is a single self-contained PDF 1.4
//     document.
//
// Wire target: the upstream `pkg/reporting` has
// `ReportFormatPDF = "pdf"` as a placeholder. The
// platform's `pkg/reporting` wrapper (also part of
// TODO-501) routes the `ReportFormatPDF` case to
// `pdf.RenderReport(req, data)`.
package pdf

import (
	"fmt"
	"time"
)

// PageSize defines the dimensions of a page in points
// (1 point = 1/72 inch). Standard sizes: Letter, A4.
type PageSize struct {
	Width  float64
	Height float64
}

// Predefined page sizes.
var (
	// PageLetter is US Letter (8.5" x 11" = 612 x 792 pt).
	PageLetter = PageSize{Width: 612, Height: 792}
	// PageA4 is A4 (210mm x 297mm = 595 x 842 pt).
	PageA4 = PageSize{Width: 595, Height: 842}
)

// Standard font sizes in points.
const (
	FontTitle    = 20.0
	FontHeading  = 14.0
	FontBody     = 10.0
	FontFooter   = 8.0
	FontTableHdr = 10.0
	// FontHeader (v0.2) is the top-of-page header
	// font. Smaller than FontTitle (so the header is
	// visually distinct from the title on page 1) but
	// larger than FontFooter (so it reads as a
	// "header" not a "footer"). v0.1 doesn't have a
	// header; v0.2 introduces one.
	FontHeader = 12.0
)

// Standard PDF font (Helvetica family; built into every
// PDF reader, no font file needed).
const (
	fontHelvetica   = "F1" // Helvetica regular
	fontHelveticaB  = "F2" // Helvetica bold
	fontHelveticaBI = "F3" // Helvetica bold italic
	fontHelveticaI  = "F4" // Helvetica italic
)

// =====================================================================
// RenderRequest
// =====================================================================

// RenderRequest is the input to RenderReport. It is
// the v0.1 analog of `reporting.Report` (upstream
// `pkg/reporting.Report`) but simplified to only the
// fields the PDF renderer needs.
//
// v0.2 adds:
//   - Header (top-of-page banner; replaces the
//     centered title on page 1 if non-empty)
//   - FooterURL (appended to the footer text;
//     defaults to "https://aegisgatesecurity.io")
//   - FooterIncludeID (appends the digest ID to the
//     footer; useful for audit traceability)
type RenderRequest struct {
	// Title is the document title. REQUIRED.
	Title string
	// Author is the document author (e.g., "AegisGate
	// Platform"). OPTIONAL.
	Author string
	// Subject is the document subject (e.g., "Posture
	// Digest Week of 2026-06-09"). OPTIONAL.
	Subject string
	// Keywords is a comma-separated list of keywords.
	// OPTIONAL.
	Keywords string
	// PageSize is the page size. Default: PageLetter.
	PageSize PageSize
	// Sections is the list of body sections in the
	// document. Each section is rendered in order.
	// REQUIRED (at least one section).
	Sections []Section
	// Footer is the footer text. OPTIONAL. The page
	// number is appended automatically.
	Footer string
	// Header (v0.2) is the top-of-page banner. If
	// non-empty, it replaces the centered title on
	// page 1 with a left-aligned "AegisGate" wordmark
	// + a right-aligned period string. If empty, the
	// v0.1 behavior is used (centered title only).
	Header string
	// HeaderSubtitle (v0.2) is the right-aligned
	// subtitle of the header (e.g., the digest
	// period). Only used if Header is non-empty.
	HeaderSubtitle string
	// FooterURL (v0.2) is the URL appended to the
	// footer text. Default: "https://aegisgatesecurity.io".
	FooterURL string
	// FooterIncludeID (v0.2) is the digest ID
	// appended to the footer text. Set by the digest
	// renderer; the report renderer can also set it
	// for the c3 manifest.
	FooterIncludeID string
	// GeneratedAt is the document creation time. Set by
	// RenderReport if zero.
	GeneratedAt time.Time
}

// Section is a single section of the document body.
// A section is either a heading, a paragraph, a table,
// or a page break.
type Section struct {
	// Kind is the section type. REQUIRED.
	Kind SectionKind
	// Text is the section text (for Heading and
	// Paragraph).
	Text string
	// Table is the section table (for Table).
	Table Table
	// Columns is the column widths in points (for
	// Table). If empty, columns are auto-sized.
	Columns []float64
}

// SectionKind is the type discriminator for Section.
type SectionKind string

const (
	// SectionHeading is a section heading (bold, large
	// font). Text field is the heading text.
	SectionHeading SectionKind = "heading"
	// SectionParagraph is a body paragraph. Text field
	// is the paragraph text.
	SectionParagraph SectionKind = "paragraph"
	// SectionTable is a data table. Table field is the
	// table data.
	SectionTable SectionKind = "table"
	// SectionPageBreak is a manual page break.
	SectionPageBreak SectionKind = "pagebreak"
)

// Table is a 2D data table. The first row is the
// header (rendered in bold). Subsequent rows are the
// body (rendered in regular font).
type Table struct {
	// Rows is the table data. REQUIRED. Each row is a
	// slice of cell strings. All rows must have the
	// same number of cells.
	Rows [][]string
}

// =====================================================================
// RenderReport (the public API)
// =====================================================================

// RenderReport generates a PDF document from the
// request. Returns the PDF bytes.
//
// The output is a self-contained PDF 1.4 document.
// The bytes can be written to a file, sent over HTTP,
// or embedded in a signed envelope (TODO-601).
//
// Errors:
//   - req is nil
//   - req.Title is empty
//   - req.Sections is empty
//   - A Section has an unknown Kind
//   - A Table has inconsistent row lengths
func RenderReport(req *RenderRequest) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("pdf: RenderRequest is nil")
	}
	if req.Title == "" {
		return nil, fmt.Errorf("pdf: Title is required")
	}
	if len(req.Sections) == 0 {
		return nil, fmt.Errorf("pdf: at least one Section is required")
	}
	// Apply defaults.
	r := *req
	if r.PageSize.Width == 0 || r.PageSize.Height == 0 {
		r.PageSize = PageLetter
	}
	if r.GeneratedAt.IsZero() {
		r.GeneratedAt = time.Now().UTC()
	}
	// Validate sections.
	for i, s := range r.Sections {
		switch s.Kind {
		case SectionHeading, SectionParagraph, SectionPageBreak:
			// OK
		case SectionTable:
			if len(s.Table.Rows) == 0 {
				return nil, fmt.Errorf("pdf: section[%d] is a table with no rows", i)
			}
			colCount := len(s.Table.Rows[0])
			for j, row := range s.Table.Rows {
				if len(row) != colCount {
					return nil, fmt.Errorf("pdf: section[%d] table row %d has %d cells, expected %d", i, j, len(row), colCount)
				}
			}
		default:
			return nil, fmt.Errorf("pdf: section[%d] has unknown Kind %q", i, s.Kind)
		}
	}
	// Generate.
	return generatePDF(&r)
}

// =====================================================================
// Internal: PDF generation
// =====================================================================

// generatePDF is the internal PDF generator. The
// algorithm is straightforward:
//
//  1. Build a list of "draw commands" (one per
//     section), with the cursor position tracked.
//  2. As commands are emitted, detect when the cursor
//     would overflow the page bottom margin; if so,
//     emit a "new page" and reset the cursor.
//  3. Translate the draw commands into PDF content
//     streams (one stream per page).
//  4. Assemble the document objects (catalog, pages,
//     page, font, content streams).
//  5. Write the cross-reference table and trailer.
func generatePDF(req *RenderRequest) ([]byte, error) {
	doc := newDocument(req)

	// Emit draw commands.
	for _, section := range req.Sections {
		if err := doc.emitSection(section); err != nil {
			return nil, err
		}
	}
	doc.flushPage() // ensure the last page is closed

	// Assemble the document bytes.
	return doc.assemble()
}
