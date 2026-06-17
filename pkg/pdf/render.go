// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Report Renderer implementation (TODO-501)
//
// render.go contains the core PDF generation logic.
// The implementation is a from-scratch PDF 1.4
// generator using only the Go standard library.
//
// Algorithm overview:
//
//   - The document is built as a list of objects
//     (catalog, pages tree, page, font, content
//     stream). Each object is numbered.
//   - As sections are emitted, content stream
//     commands are appended to the current page's
//     content stream. When the cursor overflows the
//     bottom margin, a new page is started.
//   - The cross-reference table maps object numbers
//     to byte offsets (for the PDF reader to seek).
//   - The trailer points to the catalog and the
//     xref offset.
//
// PDF 1.4 is the lowest version that supports the
// features we need (text, basic tables, page breaks).
// Every modern PDF reader supports 1.4 or higher.

package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// document is the internal mutable state used during
// PDF generation. The zero value is NOT usable;
// construct via newDocument.
type document struct {
	req *RenderRequest

	// Object bookkeeping. Each object is a raw byte
	// slice; the assemble step wraps each in the
	// "N 0 obj ... endobj" envelope.
	objects [][]byte

	// Content stream for the current page
	currentPageContent bytes.Buffer
	currentPageY       float64 // current cursor Y (from top, in points)

	// Track all the page object numbers so we can
	// build the Pages tree (object 2) at assemble time.
	pageObjectNums []int

	// Track the current page's CONTENT STREAM object
	// number. Set by addPage, used by flushPage. We
	// track this separately because the content stream
	// is added before the page object.
	currentPageContentObjNum int

	// 1-indexed page number of the page currently
	// being built. 0 means "no page is active".
	currentPageIndex int
}

// newDocument creates a new document and seeds the
// fixed objects (catalog, pages, fonts).
func newDocument(req *RenderRequest) *document {
	d := &document{
		req: req,
	}
	// Object 1: Catalog (placeholder, real ref added later)
	d.addObject([]byte("<< /Type /Catalog /Pages 2 0 R >>"))
	// Object 2: Pages tree (placeholder, real ref added later)
	d.addObject([]byte("<< /Type /Pages /Kids [] /Count 0 >>"))
	// Objects 3-6: Built-in fonts (Helvetica family)
	d.addObject([]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))             // F1
	d.addObject([]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"))        // F2
	d.addObject([]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-BoldOblique >>")) // F3
	d.addObject([]byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>"))     // F4
	return d
}

// addObject appends a pre-built object to the
// document. Returns the object number (1-indexed).
// The byte slice should be the FULL object content
// WITHOUT the "N 0 obj ... endobj" wrapper; that is
// added during assemble.
func (d *document) addObject(content []byte) int {
	d.objects = append(d.objects, content)
	return len(d.objects) // 1-indexed
}

// addPage starts a new page. Returns the 1-indexed
// page number. Adds the content stream object (empty
// at this point; the caller appends to it) and
// schedules the page object for flushPage.
//
// v0.2 branding: if d.req.Header is non-empty, render
// a left-aligned "AegisGate" wordmark in bold + a
// right-aligned HeaderSubtitle (the period string) on
// the top of every page, instead of the centered title
// on page 1. If d.req.Header is empty, the v0.1
// behavior is used (centered title only on page 1).
func (d *document) addPage() int {
	// Increment the page index BEFORE emitting the
	// content, so the footer shows the correct page
	// number.
	d.currentPageIndex++

	// The content stream is a separate object; we
	// allocate its object number now (the bytes are
	// written later, at flushPage time). addObject
	// returns the new object's 1-indexed number.
	d.currentPageContentObjNum = d.addObject(nil) // placeholder; bytes written in flushPage

	// Reset the cursor to the top of the new page
	// (with some top margin).
	d.currentPageY = d.req.PageSize.Height - 50
	d.currentPageContent.Reset()

	// Emit the title (v0.1 behavior) OR the branded
	// header (v0.2 behavior).
	if d.req.Header != "" {
		// v0.2 branded header: left-aligned wordmark +
		// right-aligned subtitle. The wordmark uses
		// the bold font; the subtitle uses regular.
		// We emit the wordmark on the left, then
		// measure its width and emit the subtitle on
		// the right.
		d.emitText(d.req.Header, fontHelveticaB, FontHeader, 50, d.currentPageY, false)
		if d.req.HeaderSubtitle != "" {
			// Measure the wordmark width so the
			// subtitle is right-aligned to the page
			// edge (with a 50pt margin).
			wordmarkWidth := textWidth(d.req.Header, fontHelveticaB, FontHeader)
			subtitleX := d.req.PageSize.Width - 50 - textWidth(d.req.HeaderSubtitle, fontHelvetica, FontHeader)
			// If the wordmark would overlap the
			// subtitle, fall back to left-aligned
			// subtitle on the next line.
			if subtitleX < wordmarkWidth+10 {
				// Fall back: wordmark only.
				d.emitText(d.req.Header, fontHelveticaB, FontHeader, 50, d.currentPageY, false)
			} else {
				d.emitText(d.req.HeaderSubtitle, fontHelvetica, FontHeader, subtitleX, d.currentPageY, false)
			}
		}
		// After the header, add a thin separator line
		// (a horizontal rule made of 4 short lines)
		// for visual separation from the body.
		// The separator is at currentPageY - 3 (just
		// below the header text).
		sepY := d.currentPageY - 3
		pageWidth := d.req.PageSize.Width - 100 // 50pt margins
		// The separator is rendered as 4 short
		// underscore characters evenly spaced across
		// the page width.
		for i := 0; i < 4; i++ {
			x := 50.0 + float64(i)*(pageWidth/4) + pageWidth/8
			d.emitText("_", fontHelvetica, FontHeader-2, x, sepY, false)
		}
		d.currentPageY -= FontHeader + 10
		// On page 1, ALSO render the title centered
		// below the header (so the document still has
		// a clear "title page" feel).
		if d.currentPageIndex == 1 {
			d.emitText(d.req.Title, fontHelveticaB, FontTitle, 50, d.currentPageY, true)
			d.currentPageY -= FontTitle + 20
		}
	} else {
		// v0.1 behavior: centered title on page 1.
		if d.currentPageIndex == 1 {
			d.emitText(d.req.Title, fontHelveticaB, FontTitle, 50, d.currentPageY, true)
			d.currentPageY -= FontTitle + 20
		}
	}

	// Emit the footer on every page. The page
	// separator is ASCII-only (the em-dash is not in
	// Latin-1 and would be replaced with '?' by
	// pdfEscape).
	footerText := d.req.Footer
	if footerText == "" {
		footerText = "AegisGate Platform"
	}
	footerParts := []string{footerText}
	if d.req.FooterIncludeID != "" {
		footerParts = append(footerParts, "ID: "+d.req.FooterIncludeID)
	}
	if d.req.FooterURL != "" {
		footerParts = append(footerParts, d.req.FooterURL)
	}
	footerParts = append(footerParts, fmt.Sprintf("Page %d", d.currentPageIndex))
	footerWithPage := strings.Join(footerParts, " -- ")
	footerY := 30.0
	d.emitText(footerWithPage, fontHelvetica, FontFooter, 50, footerY, false)

	// Return the page index (NOT the object number)
	// so the caller can use it for "Page N" display.
	return d.currentPageIndex
}

// emitSection emits a single section, handling page
// breaks as needed.
func (d *document) emitSection(s Section) error {
	// If we haven't started a page yet (currentPageIndex
	// is 0 means no page is active), start one.
	if d.currentPageIndex == 0 {
		d.addPage()
	}
	switch s.Kind {
	case SectionHeading:
		return d.emitHeading(s.Text)
	case SectionParagraph:
		return d.emitParagraph(s.Text)
	case SectionTable:
		return d.emitTable(s.Table, s.Columns)
	case SectionPageBreak:
		d.flushPage()
		d.addPage()
		return nil
	default:
		return fmt.Errorf("pdf: unknown section kind %q", string(s.Kind))
	}
}

// emitHeading writes a heading line. If the cursor is
// near the top of a page (after the title), it adds
// extra space.
func (d *document) emitHeading(text string) error {
	if !d.hasRoom(30) {
		d.flushPage()
		d.addPage()
	}
	d.currentPageY -= 10 // spacing
	d.emitText(text, fontHelveticaB, FontHeading, 50, d.currentPageY-FontHeading, false)
	d.currentPageY -= FontHeading + 5
	return nil
}

// emitParagraph writes a paragraph of text with
// word-wrap. v0.1 rendered text verbatim; v0.2 uses
// WrapText to break long lines at word boundaries
// so they fit within the page width. The cursor
// advances by FontBody+2 per line.
//
// Multi-line paragraphs (text with embedded \n) are
// supported: each line is wrapped independently.
func (d *document) emitParagraph(text string) error {
	maxWidth := MaxTextWidth(d.req.PageSize)
	lines := WrapText(text, fontHelvetica, FontBody, maxWidth)
	for _, line := range lines {
		if !d.hasRoom(FontBody + 4) {
			d.flushPage()
			d.addPage()
		}
		d.currentPageY -= FontBody + 2
		d.emitText(line, fontHelvetica, FontBody, 50, d.currentPageY, false)
	}
	d.currentPageY -= 5
	return nil
}

// emitTable writes a table. The first row is the
// header (bold). Subsequent rows are the body. v0.1
// does NOT auto-size columns; the caller must supply
// `columns` (in points) OR pass nil/empty to use
// equal column widths.
func (d *document) emitTable(t Table, columns []float64) error {
	if len(t.Rows) == 0 {
		return nil
	}
	colCount := len(t.Rows[0])
	// Apply column defaults: equal widths.
	if len(columns) == 0 {
		usable := d.req.PageSize.Width - 100 // 50pt margins on each side
		colWidth := usable / float64(colCount)
		columns = make([]float64, colCount)
		for i := range columns {
			columns[i] = colWidth
		}
	}
	rowHeight := FontTableHdr + 6

	for i, row := range t.Rows {
		if !d.hasRoom(rowHeight) {
			d.flushPage()
			d.addPage()
		}
		// Determine font (header = bold, body = regular).
		font := fontHelvetica
		if i == 0 {
			font = fontHelveticaB
		}
		// Emit each cell.
		x := 50.0
		for j, cell := range row {
			d.emitText(sanitizeASCII(cell), font, FontTableHdr, x, d.currentPageY-rowHeight, false)
			x += columns[j]
		}
		d.currentPageY -= rowHeight
	}
	d.currentPageY -= 5
	return nil
}

// hasRoom returns true if the current page has at
// least `height` points of vertical space left below
// the cursor.
func (d *document) hasRoom(height float64) bool {
	return d.currentPageY-height >= 50 // leave 50pt bottom margin
}

// flushPage finalizes the current page: writes the
// content stream to its reserved object slot, adds
// the page object (with a reference to the content
// stream), and records the page object's number for
// the Pages tree.
func (d *document) flushPage() {
	if d.currentPageIndex == 0 {
		// No page was started.
		return
	}
	// Wrap the content stream bytes in a stream
	// object: "<< /Length N >>\nstream\n...bytes...
	// \nendstream". The N is the byte length of the
	// stream content.
	contentBytes := d.currentPageContent.Bytes()
	streamObj := []byte(fmt.Sprintf("<< /Length %d >>\nstream\n", len(contentBytes)))
	streamObj = append(streamObj, contentBytes...)
	streamObj = append(streamObj, []byte("\nendstream")...)
	// Overwrite the placeholder object we reserved
	// in addPage.
	d.objects[d.currentPageContentObjNum-1] = streamObj
	// Add the page object. The page references the
	// content stream by object number.
	pageObjNum := d.addObject([]byte(fmt.Sprintf(
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] "+
			"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> "+
			"/Contents %d 0 R >>",
		d.req.PageSize.Width, d.req.PageSize.Height, d.currentPageContentObjNum,
	)))
	d.pageObjectNums = append(d.pageObjectNums, pageObjNum)
	// Reset.
	d.currentPageIndex = 0
	d.currentPageContentObjNum = 0
}

// emitText writes a text string at (x, y) using the
// given font. The y coordinate is the BASELINE of the
// text (PDF convention).
//
// The text is wrapped in a BT/ET block (PDF text
// object). The font and size are set inline. The
// string is escaped (parentheses and backslashes are
// escaped per PDF 1.4 spec, then converted from
// UTF-8 to WinAnsiEncoding by pdfEscape).
//
// `center` is a hint: if true, the text is rendered
// centered horizontally relative to the page width.
// v0.2 uses the real word widths (textWidth); v0.1
// used the approximation 0.5*size per char.
func (d *document) emitText(s, font string, size, x, y float64, center bool) {
	if center {
		// Use the real word widths (from the
		// charWidthTable) to center accurately.
		textW := textWidth(s, font, size)
		x = (d.req.PageSize.Width - textW) / 2
	}
	escaped := pdfEscape(s)
	fmt.Fprintf(&d.currentPageContent, "BT /%s %.1f Tf %.0f %.0f Td (%s) Tj ET\n",
		font, size, x, y, escaped)
}

// assemble writes the complete PDF: header, objects,
// xref, trailer.
func (d *document) assemble() ([]byte, error) {
	// First, update the Pages tree (object 2) to
	// reference all the page objects we created. The
	// Pages tree was created with placeholder values
	// in newDocument; we now fill in the real values.
	pagesKids := make([]string, len(d.pageObjectNums))
	for i, n := range d.pageObjectNums {
		pagesKids[i] = fmt.Sprintf("%d 0 R", n)
	}
	pagesObj := fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>",
		strings.Join(pagesKids, " "), len(d.pageObjectNums))
	d.objects[1] = []byte(pagesObj) // object 2 is index 1

	var buf bytes.Buffer

	// PDF header
	buf.WriteString("%PDF-1.4\n")
	// Binary comment to mark this as a binary file
	// (PDF readers check for this).
	buf.WriteString("%\xe2\xe3\xcf\xd3\n")

	// Track the byte offset of each object. We'll
	// overwrite the xref offsets in a second pass.
	// (For simplicity, we build the xref as we go.)

	// Reserve a placeholder for the xref offset.
	// We'll fill it in after we know the byte count
	// of the object section.
	offsets := make([]int, len(d.objects))

	// Write each object.
	for i, content := range d.objects {
		if content == nil {
			return nil, fmt.Errorf("pdf: object %d is nil (internal bug)", i+1)
		}
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n", i+1)
		buf.Write(content)
		buf.WriteString("\nendobj\n")
	}

	// Cross-reference table.
	xrefOffset := buf.Len()
	buf.WriteString("xref\n")
	fmt.Fprintf(&buf, "0 %d\n", len(d.objects)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}

	// Trailer.
	buf.WriteString("trailer\n")
	fmt.Fprintf(&buf, "<< /Size %d /Root 1 0 R >>\n", len(d.objects)+1)
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOffset)

	return buf.Bytes(), nil
}

// =====================================================================
// Helpers
// =====================================================================

// pdfEscape converts a string for use in a PDF text
// object. The string is first converted from UTF-8
// to WinAnsiEncoding (so non-ASCII characters like
// é, ñ, ü are preserved as their WinAnsi byte
// equivalents), then the WinAnsi bytes are escaped
// per PDF 1.4 spec (parentheses and backslashes
// are escaped).
//
// IMPORTANT: After utf8ToWinAnsi, the result is a
// Go string containing WinAnsi bytes, which is NOT
// valid UTF-8 (bytes 0x80-0xFF are not valid
// UTF-8 sequences by themselves). We MUST iterate
// over the raw bytes, not the runes, because
// `for _, c := range` would decode as UTF-8 and
// turn the WinAnsi bytes into U+FFFD (replacement
// character).
//
// Characters not in WinAnsi (e.g., non-Latin
// scripts) are replaced with '?' (the v0.1
// behavior, retained for compatibility). v0.2 could
// add a "embed Unicode font" path.
func pdfEscape(s string) string {
	// First, convert UTF-8 to WinAnsi. The result is
	// a Go string where each byte is a WinAnsi byte.
	winAnsi := utf8ToWinAnsi(s)
	// Iterate over the raw bytes (NOT runes).
	var b strings.Builder
	b.Grow(len(winAnsi))
	for i := 0; i < len(winAnsi); i++ {
		c := winAnsi[i]
		switch {
		case c == '(' || c == ')' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 128:
			b.WriteByte(c)
		default:
			// Latin-1 supplement (0x80-0xFF): emit
			// as-is. PDF text objects can hold
			// any Latin-1 character directly.
			b.WriteByte(c)
		}
	}
	return b.String()
}

// sanitizeASCII is a convenience wrapper around
// pdfEscape for cell text. (Same logic; the
// separation is for clarity in the table renderer.)
func sanitizeASCII(s string) string {
	return pdfEscape(s)
}

// =====================================================================
// Time formatting helper
// =====================================================================

// formatTime is a tiny helper for embedding
// timestamps in PDF metadata. Used by RenderReport
// callers that want to include a "Generated at" line
// in the body.
//
// (This is exported but not used by the generator
// itself; it's a convenience for callers.)
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}
