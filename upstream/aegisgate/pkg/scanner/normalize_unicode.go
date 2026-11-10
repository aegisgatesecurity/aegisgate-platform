// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform - Unicode Mathematical Alphanumeric Symbol Normalization
//
// Converts Unicode mathematical alphanumeric symbols (bold, italic, sans-serif,
// circled, regional indicators) back to their ASCII letter equivalents.
// These Unicode ranges are used for evasion attacks where attackers encode
// "ignore" as "𝗶𝗴𝗻𝗼𝗿𝗲" (mathematical sans-serif bold) or "ⓘⓖⓝⓞⓡⓔ" (circled)
// to bypass regex pattern matching.
//
// Each function is DESTRUCTIVE on legitimate mathematical text, so they are
// provided as separate normalization variants scanned alongside the original.
//
// Ported from Rampart internal/detectors/unicode_normalize.go.

package scanner

import "strings"

// NormalizeMathBold converts mathematical bold letters (U+1D400–U+1D433) to ASCII.
// Catches: 𝐢𝐠𝐧𝐨𝐫𝐞 → ignore
func NormalizeMathBold(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 0x1D41A && r <= 0x1D433: // Mathematical Bold Small a-z
			b.WriteRune(rune(r - 0x1D41A + 'a'))
		case r >= 0x1D400 && r <= 0x1D419: // Mathematical Bold Capital A-Z
			b.WriteRune(rune(r - 0x1D400 + 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeMathSansSerifBold converts mathematical sans-serif bold letters to ASCII.
// Catches: 𝗶𝗴𝗻𝗼𝗿𝗲 → ignore
// Small letters: U+1D5EE–U+1D607, Capital letters: U+1D5D8–U+1D5F1
func NormalizeMathSansSerifBold(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 0x1D5EE && r <= 0x1D607: // Mathematical Sans-Serif Bold Small a-z
			b.WriteRune(rune(r - 0x1D5EE + 'a'))
		case r >= 0x1D5D8 && r <= 0x1D5F1: // Mathematical Sans-Serif Bold Capital A-Z
			b.WriteRune(rune(r - 0x1D5D8 + 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeMathItalic converts mathematical italic letters to ASCII.
// Small letters: U+1D44E–U+1D467, Capital letters: U+1D434–U+1D44D
func NormalizeMathItalic(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 0x1D44E && r <= 0x1D467: // Mathematical Italic Small a-z
			b.WriteRune(rune(r - 0x1D44E + 'a'))
		case r >= 0x1D434 && r <= 0x1D44D: // Mathematical Italic Capital A-Z
			b.WriteRune(rune(r - 0x1D434 + 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeMathBoldItalic converts mathematical bold italic letters to ASCII.
// Small letters: U+1D482–U+1D49B, Capital letters: U+1D468–U+1D481
func NormalizeMathBoldItalic(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 0x1D482 && r <= 0x1D49B: // Mathematical Bold Italic Small a-z
			b.WriteRune(rune(r - 0x1D482 + 'a'))
		case r >= 0x1D468 && r <= 0x1D481: // Mathematical Bold Italic Capital A-Z
			b.WriteRune(rune(r - 0x1D468 + 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeMathSansSerif converts mathematical sans-serif (non-bold) letters to ASCII.
// Small letters: U+1D5BA–U+1D5D3, Capital letters: U+1D5A4–U+1D5BD
func NormalizeMathSansSerif(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 0x1D5BA && r <= 0x1D5D3: // Mathematical Sans-Serif Small a-z
			b.WriteRune(rune(r - 0x1D5BA + 'a'))
		case r >= 0x1D5A4 && r <= 0x1D5BD: // Mathematical Sans-Serif Capital A-Z
			b.WriteRune(rune(r - 0x1D5A4 + 'A'))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeCircled converts circled Latin letters to ASCII.
// Small letters: U+24D0–U+24E9 (ⓐ–ⓩ), Capital letters: U+24B6–U+24CF (Ⓐ–Ⓩ)
// Also handles circled digits: U+2460–U+2473 (①–⑳) → 1-20
func NormalizeCircled(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		case r >= 0x24D0 && r <= 0x24E9: // Circled Small a-z
			b.WriteRune(rune(r - 0x24D0 + 'a'))
		case r >= 0x24B6 && r <= 0x24CF: // Circled Capital A-Z
			b.WriteRune(rune(r - 0x24B6 + 'A'))
		case r >= 0x2460 && r <= 0x2473: // Circled digits 1-20
			b.WriteRune(rune(r - 0x2460 + '1'))
		case r == 0x24EA: // Circled digit zero ⓪
			b.WriteRune('0')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeRegionalIndicators converts regional indicator symbols to ASCII letters.
// Regional indicators: U+1F1E6–U+1F1FF (🇦–🇿) → A-Z
// Catches: 🇮🇬🇳🇴🇷🇪 → IGNORe
func NormalizeRegionalIndicators(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			b.WriteRune(rune(r - 0x1F1E6 + 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeAllUnicodeMath applies all Unicode mathematical/alphabetic normalizations
// in sequence. This is a convenience function for creating a single variant that
// handles all Unicode math symbol evasions at once.
func NormalizeAllUnicodeMath(input string) string {
	result := NormalizeMathBold(input)
	result = NormalizeMathSansSerifBold(result)
	result = NormalizeMathItalic(result)
	result = NormalizeMathBoldItalic(result)
	result = NormalizeMathSansSerif(result)
	result = NormalizeCircled(result)
	result = NormalizeRegionalIndicators(result)
	result = NormalizeFullwidth(result)
	return result
}

// NormalizeFullwidth converts fullwidth Latin characters (U+FF01–U+FF5E)
// to their ASCII equivalents. Catches: Ｉｇｎｏｒｅ → Ignore
func NormalizeFullwidth(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch {
		// Fullwidth Capital A-Z: U+FF21–U+FF3A
		case r >= 0xFF21 && r <= 0xFF3A:
			b.WriteRune(rune(r - 0xFF21 + 'A'))
		// Fullwidth Small a-z: U+FF41–U+FF5A
		case r >= 0xFF41 && r <= 0xFF5A:
			b.WriteRune(rune(r - 0xFF41 + 'a'))
		// Fullwidth digits 0-9: U+FF10–U+FF19
		case r >= 0xFF10 && r <= 0xFF19:
			b.WriteRune(rune(r - 0xFF10 + '0'))
		// Fullwidth space U+3000
		case r == 0x3000:
			b.WriteRune(' ')
		// Fullwidth punctuation/symbols U+FF01–U+FF0F, U+FF1A–U+FF20, U+FF3B–U+FF40, U+FF5B–U+FF5E
		case r >= 0xFF01 && r <= 0xFF5E:
			b.WriteRune(rune(r - 0xFEE0)) // Offset to ASCII range
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
