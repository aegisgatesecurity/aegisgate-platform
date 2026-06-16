// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - PDF Unicode-to-WinAnsi converter (TODO-601 prerequisite)
//
// unicode.go adds basic Unicode support to the PDF
// generator. v0.1 of pkg/pdf replaced every
// non-ASCII character with '?' via pdfEscape. The
// CISO Digest (TODO-601) may have non-ASCII content
// (EU AI Act articles, customer names with
// diacritics). This file implements a WinAnsi
// encoder so the standard PDF Helvetica family can
// display most Western European characters.
//
// WinAnsiEncoding is PDF 1.4's "Windows ANSI"
// encoding (essentially Windows code page 1252).
// It supports most Western European characters,
// including:
//   - accented Latin letters (à, é, ñ, ü, etc.)
//   - German ß, French œ, Turkish ş/ı
//   - common typographic characters (— " ' © ®)
//
// It does NOT support:
//   - non-Latin scripts (Cyrillic, Greek, CJK,
//     Arabic, Hebrew, etc.)
//   - emojis
//   - many specialized typographic characters
//
// For v0.1 of the Unicode support, characters not
// in WinAnsi are replaced with '?' (matching the
// v0.1 behavior). v0.2 could add a "embed Unicode
// font" path for full Unicode support.

package pdf

import (
	"strings"
)

// winAnsiTable maps Unicode code points (above
// ASCII) to their WinAnsi byte value. Characters
// not in this table are replaced with '?' by the
// utf8ToWinAnsi function.
//
// The table is the standard PDF 1.4 WinAnsiEncoding
// mapping. Code points 0x00-0x7F are passed through
// as-is (ASCII is a subset of WinAnsi).
//
// This is a partial table (the most common Western
// European characters). v0.2 can expand it.
var winAnsiTable = map[rune]byte{
	// Latin-1 supplement (0xA0-0xFF)
	0xA0: 0xA0,                                                 // NBSP
	0xA1: 0xA1,                                                 // ¡
	0xA2: 0xA2,                                                 // ¢
	0xA3: 0xA3,                                                 // £
	0xA4: 0xA4,                                                 // ¤
	0xA5: 0xA5,                                                 // ¥
	0xA6: 0xA6,                                                 // ¦
	0xA7: 0xA7,                                                 // §
	0xA8: 0xA8,                                                 // ¨
	0xA9: 0xA9,                                                 // ©
	0xAA: 0xAA,                                                 // ª
	0xAB: 0xAB,                                                 // «
	0xAC: 0xAC,                                                 // ¬
	0xAD: 0xAD,                                                 // soft hyphen
	0xAE: 0xAE,                                                 // ®
	0xAF: 0xAF,                                                 // ¯
	0xB0: 0xB0,                                                 // °
	0xB1: 0xB1,                                                 // ±
	0xB2: 0xB2,                                                 // ²
	0xB3: 0xB3,                                                 // ³
	0xB4: 0xB4,                                                 // ´
	0xB5: 0xB5,                                                 // µ
	0xB6: 0xB6,                                                 // ¶
	0xB7: 0xB7,                                                 // ·
	0xB8: 0xB8,                                                 // ¸
	0xB9: 0xB9,                                                 // ¹
	0xBA: 0xBA,                                                 // º
	0xBB: 0xBB,                                                 // »
	0xBC: 0xBC,                                                 // ¼
	0xBD: 0xBD,                                                 // ½
	0xBE: 0xBE,                                                 // ¾
	0xBF: 0xBF,                                                 // ¿
	0xC0: 0xC0, 0xC1: 0xC1, 0xC2: 0xC2, 0xC3: 0xC3, 0xC4: 0xC4, // À Á Â Ã Ä
	0xC5: 0xC5, 0xC6: 0xC6, 0xC7: 0xC7, 0xC8: 0xC8, 0xC9: 0xC9, // Å Æ Ç È É
	0xCA: 0xCA, 0xCB: 0xCB, 0xCC: 0xCC, 0xCD: 0xCD, 0xCE: 0xCE, // Ê Ë Ì Í Î
	0xCF: 0xCF, 0xD0: 0xD0, 0xD1: 0xD1, 0xD2: 0xD2, 0xD3: 0xD3, // Ï Ð Ñ Ò Ó
	0xD4: 0xD4, 0xD5: 0xD5, 0xD6: 0xD6, 0xD7: 0xD7, 0xD8: 0xD8, // Ô Õ Ö × Ø
	0xD9: 0xD9, 0xDA: 0xDA, 0xDB: 0xDB, 0xDC: 0xDC, 0xDD: 0xDD, // Ù Ú Û Ü Ý
	0xDE: 0xDE, 0xDF: 0xDF, // Þ ß
	0xE0: 0xE0, 0xE1: 0xE1, 0xE2: 0xE2, 0xE3: 0xE3, 0xE4: 0xE4, // à á â ã ä
	0xE5: 0xE5, 0xE6: 0xE6, 0xE7: 0xE7, 0xE8: 0xE8, 0xE9: 0xE9, // å æ ç è é
	0xEA: 0xEA, 0xEB: 0xEB, 0xEC: 0xEC, 0xED: 0xED, 0xEE: 0xEE, // ê ë ì í î
	0xEF: 0xEF, 0xF0: 0xF0, 0xF1: 0xF1, 0xF2: 0xF2, 0xF3: 0xF3, // ï ð ñ ò ó
	0xF4: 0xF4, 0xF5: 0xF5, 0xF6: 0xF6, 0xF7: 0xF7, 0xF8: 0xF8, // ô õ ö ÷ ø
	0xF9: 0xF9, 0xFA: 0xFA, 0xFB: 0xFB, 0xFC: 0xFC, 0xFD: 0xFD, // ù ú û ü ý
	0xFE: 0xFE, 0xFF: 0xFF, // þ ÿ
	// Typographic characters in WinAnsi 0x80-0x9F range
	0x20AC: 0x80, // €
	0x201A: 0x82, // ‚
	0x0192: 0x83, // ƒ
	0x201E: 0x84, // „
	0x2026: 0x85, // …
	0x2020: 0x86, // †
	0x2021: 0x87, // ‡
	0x02C6: 0x88, // ˆ
	0x2030: 0x89, // ‰
	0x0160: 0x8A, // Š
	0x2039: 0x8B, // ‹
	0x0152: 0x8C, // Œ
	0x017D: 0x8E, // Ž
	0x2018: 0x91, // ‘
	0x2019: 0x92, // ’
	0x201C: 0x93, // “
	0x201D: 0x94, // ”
	0x2022: 0x95, // •
	0x2013: 0x96, // –
	0x2014: 0x97, // —
	0x02DC: 0x98, // ˜
	0x2122: 0x99, // ™
	0x0161: 0x9A, // š
	0x203A: 0x9B, // ›
	0x0153: 0x9C, // œ
	0x017E: 0x9E, // ž
	0x0178: 0x9F, // Ÿ
}

// utf8ToWinAnsi converts a UTF-8 string to a
// WinAnsi-encoded string. Characters not in the
// WinAnsi table are replaced with '?' (matching
// the v0.1 behavior). The output is a regular
// Go string (not a byte slice); the bytes are the
// WinAnsi bytes interpreted as Latin-1.
func utf8ToWinAnsi(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 {
			// ASCII: pass through.
			b.WriteByte(byte(r))
		} else if v, ok := winAnsiTable[r]; ok {
			// In WinAnsi: emit the WinAnsi byte.
			b.WriteByte(v)
		} else {
			// Not in WinAnsi: replace with '?'.
			b.WriteByte('?')
		}
	}
	return b.String()
}
