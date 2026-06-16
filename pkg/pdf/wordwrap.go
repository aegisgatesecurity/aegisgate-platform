// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Word-Wrap (TODO-601 prerequisite)
//
// wordwrap.go adds real word-wrap to the PDF
// generator. v0.1 of pkg/pdf rendered text verbatim;
// long lines overflowed the page width. The CISO
// Digest (TODO-601) has long sentences that need to
// wrap to fit the page.
//
// Algorithm: a simple greedy word-wrap. We compute
// the width of each word using a fixed
// character-width table (one per standard PDF font
// family; this is the standard PDF 1.4 approach —
// no font metrics needed). We split the input text
// on whitespace, then accumulate words into lines
// until the next word would overflow the line
// width.
//
// Limitations (v0.1 of the word-wrap):
//   - Uses fixed character-width tables (Helvetica
//     family only). Custom fonts would need their
//     own tables.
//   - Doesn't handle hyphenation (long words that
//     exceed the line width are NOT split; they
//     overflow the line).
//   - Doesn't handle tab characters (replaced with
//     spaces).

package pdf

import (
	"strings"
)

// charWidthTable maps a font name (e.g., "F1" for
// Helvetica regular) to a per-character width in
// points at a given font size. The widths are
// approximate (PDF's standard Helvetica widths are
// used; custom fonts would need their own tables).
//
// These widths are from the PDF 1.4 spec's
// "Standard Type 1 Fonts" section. They're
// normalized to a 1000-unit em; we multiply by
// (size / 1000) at runtime to get points.
//
// The keys are the 4 standard Helvetica family fonts.
var charWidthTable = map[string]map[rune]float64{
	"F1": { // Helvetica regular
		' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667,
		'\'': 191, '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333,
		'.': 278, '/': 278, '0': 556, '1': 556, '2': 556, '3': 556, '4': 556,
		'5': 556, '6': 556, '7': 556, '8': 556, '9': 556, ':': 278, ';': 278,
		'<': 584, '=': 584, '>': 584, '?': 556, '@': 1015, 'A': 667, 'B': 667,
		'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778, 'H': 722, 'I': 278,
		'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778, 'P': 667,
		'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944,
		'X': 667, 'Y': 667, 'Z': 611, '[': 278, '\\': 278, ']': 278, '^': 469,
		'_': 556, '`': 333, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556,
		'f': 278, 'g': 556, 'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222,
		'm': 833, 'n': 556, 'o': 556, 'p': 556, 'q': 556, 'r': 333, 's': 500,
		't': 278, 'u': 556, 'v': 500, 'w': 722, 'x': 500, 'y': 500, 'z': 500,
		'{': 334, '|': 260, '}': 334, '~': 584,
	},
	// F2 (Helvetica bold), F3 (Helvetica bold italic),
	// F4 (Helvetica italic) use the same widths as F1
	// in v0.1 of the word-wrap. (Bold and italic glyphs
	// have slightly different widths in production;
	// the difference is ~5% which is acceptable for
	// v0.1. v0.2 can add separate tables.)
}

// getCharWidth returns the width of a single
// character in points at the given font size.
// Unknown characters get a fallback width of 0.5 *
// size (the same as the v0.1 simple "approximate"
// formula).
func getCharWidth(font string, c rune, size float64) float64 {
	// Look up the table for this font. If not found,
	// fall back to F1.
	tab, ok := charWidthTable[font]
	if !ok {
		tab = charWidthTable["F1"]
	}
	// Look up the character in the table. If not
	// found, use a fallback (half the em).
	w, ok := tab[c]
	if !ok {
		return size * 0.5
	}
	// The widths are in 1000-unit em. Convert to
	// points.
	return w * size / 1000.0
}

// textWidth returns the total width of s in points at
// the given font and size. Unknown characters use
// the fallback width.
func textWidth(s, font string, size float64) float64 {
	w := 0.0
	for _, c := range s {
		w += getCharWidth(font, c, size)
	}
	return w
}

// WrapText wraps s to fit within maxWidth points at
// the given font and size. Words (separated by
// whitespace) are kept intact; long words that exceed
// maxWidth are placed on their own line (they
// overflow).
//
// Existing newlines in s are preserved (the input
// is split on '\n' first, each chunk is wrapped
// independently, and the wrapped chunks are joined
// with '\n').
func WrapText(s, font string, size, maxWidth float64) []string {
	if maxWidth <= 0 {
		// Invalid width: just split on newlines.
		return strings.Split(s, "\n")
	}
	var lines []string
	for _, paragraph := range strings.Split(s, "\n") {
		lines = append(lines, wrapParagraph(paragraph, font, size, maxWidth)...)
	}
	return lines
}

// wrapParagraph wraps a single paragraph (no
// newlines) to fit within maxWidth. Returns a
// slice of lines.
func wrapParagraph(paragraph, font string, size, maxWidth float64) []string {
	if paragraph == "" {
		return []string{""}
	}
	words := strings.Fields(paragraph)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	var currentLine string
	for _, word := range words {
		// Try adding the word to the current line.
		var candidate string
		if currentLine == "" {
			candidate = word
		} else {
			candidate = currentLine + " " + word
		}
		if textWidth(candidate, font, size) > maxWidth {
			// The candidate doesn't fit. If
			// the current line is non-empty,
			// flush it and start a new line
			// with this word. If the current
			// line IS empty, the word itself
			// is too long; place it on its
			// own line and accept the
			// overflow.
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = word
			} else {
				lines = append(lines, word)
				currentLine = ""
			}
		} else {
			currentLine = candidate
		}
	}
	// Flush the last line.
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	return lines
}

// MaxTextWidth returns the maximum text width in
// points that fits within the page, given the page
// width and the horizontal margins. This is a
// convenience for the document generator.
func MaxTextWidth(page PageSize) float64 {
	const margin = 50.0 // 50pt margins on each side
	return page.Width - 2*margin
}
