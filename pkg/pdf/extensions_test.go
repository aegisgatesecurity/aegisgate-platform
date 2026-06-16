// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Word-Wrap + Unicode tests (TODO-601 prerequisite)
//
// extensions_test.go covers the v0.2 extensions to
// pkg/pdf: real word-wrap and basic Unicode support.

package pdf

import (
	"strings"
	"testing"
)

// =====================================================================
// WrapText
// =====================================================================

func TestWrapText_Empty(t *testing.T) {
	got := WrapText("", fontHelvetica, FontBody, 500)
	if len(got) != 1 {
		t.Errorf("Expected 1 line for empty input, got %d", len(got))
	}
}

func TestWrapText_ShortLine(t *testing.T) {
	got := WrapText("Hello, world.", fontHelvetica, FontBody, 500)
	if len(got) != 1 {
		t.Errorf("Expected 1 line, got %d: %v", len(got), got)
	}
	if got[0] != "Hello, world." {
		t.Errorf("Line[0] = %q, want %q", got[0], "Hello, world.")
	}
}

func TestWrapText_LongLine(t *testing.T) {
	// A long line that needs to wrap.
	got := WrapText("The quick brown fox jumps over the lazy dog", fontHelvetica, FontBody, 100)
	if len(got) < 2 {
		t.Errorf("Expected at least 2 lines, got %d: %v", len(got), got)
	}
	// Verify no line exceeds the width.
	for i, line := range got {
		w := textWidth(line, fontHelvetica, FontBody)
		// Allow a small tolerance (within 1 char's width).
		if w > 100+textWidth("M", fontHelvetica, FontBody) {
			t.Errorf("Line %d exceeds width: %q (width=%v)", i, line, w)
		}
	}
}

func TestWrapText_PreservesNewlines(t *testing.T) {
	got := WrapText("Line 1\nLine 2", fontHelvetica, FontBody, 500)
	if len(got) != 2 {
		t.Errorf("Expected 2 lines, got %d: %v", len(got), got)
	}
	if got[0] != "Line 1" {
		t.Errorf("Line[0] = %q, want %q", got[0], "Line 1")
	}
	if got[1] != "Line 2" {
		t.Errorf("Line[1] = %q, want %q", got[1], "Line 2")
	}
}

func TestWrapText_ZeroWidth(t *testing.T) {
	// Zero width: just split on newlines.
	got := WrapText("a\nb", fontHelvetica, FontBody, 0)
	if len(got) != 2 {
		t.Errorf("Expected 2 lines, got %d: %v", len(got), got)
	}
}

func TestWrapText_LongWordOverflow(t *testing.T) {
	// A single word longer than the line width is
	// placed on its own line and overflows.
	longWord := strings.Repeat("x", 100)
	got := WrapText(longWord, fontHelvetica, FontBody, 50)
	if len(got) != 1 {
		t.Errorf("Expected 1 line for long single word, got %d", len(got))
	}
	if got[0] != longWord {
		t.Errorf("Line[0] = %q, want %q", got[0], longWord)
	}
}

func TestWrapText_MultipleParagraphs(t *testing.T) {
	got := WrapText("Para 1 line 1\nPara 1 line 2\n\nPara 2", fontHelvetica, FontBody, 500)
	if len(got) < 2 {
		t.Errorf("Expected multiple lines, got %d: %v", len(got), got)
	}
}

// =====================================================================
// textWidth
// =====================================================================

func TestTextWidth_Empty(t *testing.T) {
	if w := textWidth("", fontHelvetica, FontBody); w != 0 {
		t.Errorf("textWidth(\"\") = %v, want 0", w)
	}
}

func TestTextWidth_SingleChar(t *testing.T) {
	// 'M' has the widest width in Helvetica (833 per 1000 em).
	w := textWidth("M", fontHelvetica, 10.0)
	expected := 833.0 * 10.0 / 1000.0
	if w != expected {
		t.Errorf("textWidth('M') = %v, want %v", w, expected)
	}
}

func TestTextWidth_UnknownChar(t *testing.T) {
	// Unknown characters use the fallback (0.5 * size).
	w := textWidth("\u2603", fontHelvetica, 10.0) // snowman
	if w != 5.0 {
		t.Errorf("textWidth(unknown) = %v, want 5.0 (fallback)", w)
	}
}

// =====================================================================
// utf8ToWinAnsi
// =====================================================================

func TestUtf8ToWinAnsi_ASCII(t *testing.T) {
	got := utf8ToWinAnsi("Hello, world!")
	if got != "Hello, world!" {
		t.Errorf("utf8ToWinAnsi(ASCII) = %q, want %q", got, "Hello, world!")
	}
}

func TestUtf8ToWinAnsi_AccentedLatin(t *testing.T) {
	// Accented Latin characters should be preserved
	// as their WinAnsi byte equivalents.
	tests := []struct {
		in   string
		want string
	}{
		{"café", "caf\xE9"},   // é = 0xE9 in WinAnsi
		{"naïve", "na\xEFve"}, // ï = 0xEF
		{"résumé", "r\xE9sum\xE9"},
		{"Zürich", "Z\xFCrich"}, // ü = 0xFC (not 0xF6 which is ö)
		{"Über", "\xDCber"},     // Ü = 0xDC
		{"señor", "se\xF1or"},   // ñ = 0xF1
	}
	for _, tc := range tests {
		got := utf8ToWinAnsi(tc.in)
		if got != tc.want {
			t.Errorf("utf8ToWinAnsi(%q) = %q (bytes: %v), want %q (bytes: %v)",
				tc.in, got, []byte(got), tc.want, []byte(tc.want))
		}
	}
}

func TestUtf8ToWinAnsi_Typographic(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"—", "\x97"}, // em-dash
		{"–", "\x96"}, // en-dash
		{"€", "\x80"}, // euro
		{"©", "\xA9"}, // copyright
		{"®", "\xAE"}, // registered
		{"™", "\x99"}, // trademark
		{"•", "\x95"}, // bullet
		{"…", "\x85"}, // ellipsis
	}
	for _, tc := range tests {
		got := utf8ToWinAnsi(tc.in)
		if got != tc.want {
			t.Errorf("utf8ToWinAnsi(%q) = %q, want %q",
				tc.in, got, tc.want)
		}
	}
}

func TestUtf8ToWinAnsi_NonLatin(t *testing.T) {
	// Non-Latin characters should be replaced with '?'.
	tests := []string{
		"你好",     // Chinese
		"こんにちは",  // Japanese
		"Привет", // Cyrillic
		"مرحبا",  // Arabic
		"שלום",   // Hebrew
		"😀",      // emoji
	}
	for _, s := range tests {
		got := utf8ToWinAnsi(s)
		if !strings.Contains(got, "?") {
			t.Errorf("utf8ToWinAnsi(%q) = %q, expected '?' replacement", s, got)
		}
	}
}

func TestUtf8ToWinAnsi_Empty(t *testing.T) {
	if got := utf8ToWinAnsi(""); got != "" {
		t.Errorf("utf8ToWinAnsi(\"\") = %q, want empty", got)
	}
}

func TestUtf8ToWinAnsi_Mixed(t *testing.T) {
	// Mixed ASCII and Unicode.
	got := utf8ToWinAnsi("Café Ω")
	// 'C', 'a', 'f' are ASCII; 'é' = 0xE9; ' ' is ASCII;
	// 'Ω' is not in WinAnsi → '?'.
	want := "Caf\xE9 ?"
	if got != want {
		t.Errorf("utf8ToWinAnsi(mixed) = %q, want %q", got, want)
	}
}

// =====================================================================
// Integration: RenderReport with word-wrap and Unicode
// =====================================================================

func TestRenderReport_WordWrappedParagraph(t *testing.T) {
	// A long paragraph that should wrap to multiple
	// lines.
	longText := "This is a very long paragraph that should definitely wrap to multiple lines because it exceeds the page width significantly. " +
		"The word-wrap algorithm should split it at word boundaries so each line fits within the page."
	req := &RenderRequest{
		Title: "Word-Wrap Test",
		Sections: []Section{
			{Kind: SectionParagraph, Text: longText},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	// The output should be a valid PDF.
	if !bytesHasPrefix(data, "%PDF-1.4") {
		t.Errorf("Output is not a valid PDF")
	}
	// Should have at least 1 page.
	if countPageObjects(data) < 1 {
		t.Errorf("Expected at least 1 page")
	}
}

func TestRenderReport_UnicodeCharacters(t *testing.T) {
	// A paragraph with Unicode characters.
	req := &RenderRequest{
		Title: "Café Über",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Café naïve résumé Zürich"},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	// The PDF should contain the WinAnsi-encoded
	// versions of the Unicode characters.
	// é = 0xE9 in WinAnsi.
	if !bytesContains(data, "\xE9") {
		t.Errorf("Output does not contain WinAnsi-encoded é (0xE9)")
	}
	// Ü = 0xDC in WinAnsi.
	if !bytesContains(data, "\xDC") {
		t.Errorf("Output does not contain WinAnsi-encoded Ü (0xDC)")
	}
}

func TestRenderReport_NonLatinReplacedWithQuestionMark(t *testing.T) {
	// Non-Latin characters should be replaced with '?'.
	req := &RenderRequest{
		Title: "Test",
		Sections: []Section{
			{Kind: SectionParagraph, Text: "Chinese: 你好, Japanese: こんにちは"},
		},
	}
	data, err := RenderReport(req)
	if err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	// The output should contain '?' for the
	// non-Latin characters.
	// We don't check for specific '?' count because
	// other text might also contain '?'.
	if !bytesContains(data, "?") {
		t.Errorf("Output does not contain '?' replacement")
	}
}

// =====================================================================
// MaxTextWidth
// =====================================================================

func TestMaxTextWidth_Letter(t *testing.T) {
	w := MaxTextWidth(PageLetter)
	if w != 612-100 {
		t.Errorf("MaxTextWidth(Letter) = %v, want %v", w, 612-100)
	}
}

func TestMaxTextWidth_A4(t *testing.T) {
	w := MaxTextWidth(PageA4)
	if w != 595-100 {
		t.Errorf("MaxTextWidth(A4) = %v, want %v", w, 595-100)
	}
}

// =====================================================================
// Test helpers
// =====================================================================

// bytesContains returns true if data contains substr
// (treated as raw bytes). We use this to check for
// PDF-specific bytes (WinAnsi, etc.) in the output.
func bytesContains(data []byte, substr string) bool {
	// The substr may contain bytes that aren't
	// valid in a Go string literal, so we use
	// bytes.Contains with a []byte conversion.
	return containsBytes(data, []byte(substr))
}

// containsBytes is a re-export of bytes.Contains to
// avoid importing bytes just for this.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
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

// bytesHasPrefix is a re-export of bytes.HasPrefix
// to avoid importing bytes just for this.
func bytesHasPrefix(haystack []byte, prefix string) bool {
	if len(prefix) > len(haystack) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if haystack[i] != prefix[i] {
			return false
		}
	}
	return true
}
