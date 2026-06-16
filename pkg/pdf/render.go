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

	// Emit the title on the first page.
	if d.currentPageIndex == 1 {
		d.emitText(d.req.Title, fontHelveticaB, FontTitle, 50, d.currentPageY, true)
		d.currentPageY -= FontTitle + 20
	}
	// Emit the footer on every page. The page
	// separator is ASCII-only (the em-dash is not in
	// Latin-1 and would be replaced with '?' by
	// pdfEscape).
	footerText := d.req.Footer
	if footerText == "" {
		footerText = "AegisGate Platform"
	}
	footerWithPage := fmt.Sprintf("%s -- Page %d", footerText, d.currentPageIndex)
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

// emitParagraph writes a paragraph of text. v0.1
// renders the text verbatim (no word wrap); long
// lines may overflow the page width. This is a
// known v0.1 limitation (see doc.go).
func (d *document) emitParagraph(text string) error {
	for _, line := range strings.Split(text, "\n") {
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
// escaped per PDF 1.4 spec).
//
// `center` is a hint: if true, the text is rendered
// centered horizontally relative to the page width.
func (d *document) emitText(s, font string, size, x, y float64, center bool) {
	if center {
		// PDF doesn't have a "center" command; we
		// approximate by measuring the text width
		// (Helvetica: average 0.5 * size per char)
		// and shifting x.
		charWidth := size * 0.5
		textWidth := float64(len(s)) * charWidth
		x = (d.req.PageSize.Width - textWidth) / 2
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

// pdfEscape escapes a string for use in a PDF text
// object. Per PDF 1.4 spec, parentheses and
// backslashes must be escaped. Non-ASCII characters
// are replaced with '?' (v0.1 limitation; see doc.go).
func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '(' || r == ')' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 128:
			b.WriteRune(r)
		default:
			// Non-ASCII: replace with '?' (v0.1).
			b.WriteByte('?')
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
