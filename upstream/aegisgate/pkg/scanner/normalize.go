// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform - Text Normalization for Evasion Resistance
//
// Provides normalization functions that deobfuscate common evasion techniques
// (l33t speak, keyboard shifts, character insertion, ROT13, zero-width chars)
// so that downstream pattern matching can detect evaded attack payloads.
//
// Design principle: NormalizeText() applies ONLY idempotent transformations
// (l33t deobfuscation, zero-width stripping, insertion removal, whitespace
// collapse). Keyboard-walk reversal and ROT13 decoding are DESTRUCTIVE on
// normal text, so they are provided as separate functions. The caller should
// scan the original text PLUS all normalized variants.

package scanner

import (
	"strings"
	"unicode"
)

// l33tMap maps common l33t-speak substitutions back to their letter equivalents.
var l33tMap = map[rune]rune{
	'4': 'a',
	'@': 'a',
	'3': 'e',
	'1': 'i',
	'!': 'i',
	'0': 'o',
	'5': 's',
	'$': 's',
	'7': 't',
	'+': 't',
	'8': 'b',
	'9': 'g',
	'6': 'g',
}

// keyWalkReverse maps QWERTY right-shifted keys back to their original position.
// Only maps lowercase letters that have an unambiguous left-neighbor on QWERTY.
var keyWalkReverse = map[rune]rune{
	// Home row: s→a, d→s, f→d, g→f, h→g, j→h, k→j, l→k
	's': 'a', 'd': 's', 'f': 'd', 'g': 'f', 'h': 'g', 'j': 'h', 'k': 'j', 'l': 'k',
	// Top row: e→w, r→e, t→r, y→t, u→y, i→u, o→i, p→o
	'e': 'w', 'r': 'e', 't': 'r', 'y': 't', 'u': 'y', 'i': 'u', 'o': 'i', 'p': 'o',
	// Bottom row: c→x, v→c, b→v, n→b, m→n
	'c': 'x', 'v': 'c', 'b': 'v', 'n': 'b', 'm': 'n',
}

// zeroWidthSet is a lookup set for zero-width/invisible Unicode characters.
var zeroWidthSet = func() map[rune]bool {
	runes := []rune{
		'\u200b', '\u200c', '\u200d', '\u200f', // ZW space, ZWNJ, ZWJ, RTL mark
		'\u2028', '\u2029',                      // Line/paragraph separator
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e', // Directional overrides
		'\u00ad', '\ufeff',                      // Soft hyphen, BOM/ZWNBS
		'\u2000', '\u2001', '\u2002', '\u2003',  // En/Em quad, En/Em space
		'\u2004', '\u2005', '\u2006',            // Three/Four/Six-Per-Em
		'\u2007', '\u2008', '\u2009', '\u200a',  // Figure/Punct/Thin/Hair space
		'\u00a0',                                // NBSP
	}
	m := make(map[rune]bool, len(runes))
	for _, r := range runes {
		m[r] = true
	}
	return m
}()

// NormalizeText applies all IDEMPOTENT normalizations to the input text.
// These transformations are safe to apply to any text — they won't corrupt
// normal input because they only strip invisible characters, decode URL encoding,
// replace l33t in word context, remove suspicious insertions, and collapse whitespace.
//
// Returns a normalized version suitable for pattern matching alongside the original.
// For keyboard-walk and ROT13 evasion, use NormalizeKeyboardWalk() and
// NormalizeROT13() separately — those are destructive on normal text.
func NormalizeText(input string) string {
	if len(input) < 4 {
		return input
	}

	// Step 1: Strip zero-width / invisible characters
	result := stripZeroWidth(input)

	// Step 2: Decode URL encoding (%XX sequences and + as space)
	result = decodeURLEncoding(result)

	// Step 3: Remove inter-character insertions (dots, hyphens, underscores in words)
	// This MUST come before l33t deobfuscation so that "1.g.n.0.r.3" becomes
	// "1gn0r3" first, allowing l33t substitution to recognize digit context.
	result = removeInterCharacterInsertions(result)

	// Step 4: L33t speak deobfuscation (context-aware)
	result = deobfuscateL33t(result)

	// Step 5: Collapse multiple whitespace
	result = collapseWhitespace(result)

	return result
}

// NormalizeKeyboardWalk applies keyboard-walk reversal to the result of NormalizeText.
// This is DESTRUCTIVE on normal text (e.g., "system" → "ayatem"), so it must
// only be used as a SEPARATE scanning variant, not as the primary normalization.
//
// Usage: scan the original text + NormalizeText(original) + NormalizeKeyboardWalk(original)
func NormalizeKeyboardWalk(input string) string {
	return reverseKeyboardWalk(input)
}

// NormalizeROT13 applies ROT13 decoding to the input.
// This is DESTRUCTIVE on normal text (e.g., "ignore" → "vtaber"), so it must
// only be used as a SEPARATE scanning variant.
//
// Usage: scan the original text + NormalizeText(original) + NormalizeROT13(original)
func NormalizeROT13(input string) string {
	return decodeROT13(input)
}

// NormalizeForComparison returns a normalized-lowercase version of the text.
// Applies NormalizeText + lowercasing for comparison purposes.
func NormalizeForComparison(input string) string {
	return strings.ToLower(NormalizeText(input))
}

// NormalizeAllVariants returns all normalization variants of the input text.
// The caller should scan each variant independently. Variants are:
//   - Original text (unmodified)
//   - NormalizeText result (l33t, zero-width, insertions, whitespace, URL decode)
//   - Keyboard-walk reversal of the original
//   - ROT13 of the original
//   - Repeating chars collapsed
//   - Backslash escapes removed
//   - Aggressive l33t deobfuscation
//   - Newline collapse (strips \n/\r between alphanumerics)
//   - Multi-pass pipeline (URL decode → backslash strip → zero-width → insertions → aggressive l33t → whitespace)
//
// Deduplication is applied — if a variant equals the original or already in list, it is omitted.
func NormalizeAllVariants(input string) []string {
	normalized := NormalizeText(input)
	keyboardWalk := NormalizeKeyboardWalk(input)
	rot13 := NormalizeROT13(input)
	repeatingChars := NormalizeRepeatingChars(input)
	backslashEscapes := NormalizeBackslashEscapes(input)
	aggressiveL33t := NormalizeAggressiveL33t(input)
	newlineCollapse := NormalizeNewlineCollapse(input)
	multiPass := NormalizeMultiPass(input)

	variants := []string{input}
	for _, v := range []string{normalized, keyboardWalk, rot13, repeatingChars, backslashEscapes, aggressiveL33t, newlineCollapse, multiPass} {
		if v != input && v != "" {
			// Check it's not already in the list
			dup := false
			for _, existing := range variants {
				if existing == v {
					dup = true
					break
				}
			}
			if !dup {
				variants = append(variants, v)
			}
		}
	}
	return variants
}

// NormalizeRepeatingChars collapses 3+ consecutive identical characters down to 2.
// This is SEMI-DESTRUCTIVE on normal text (e.g., "see" → "see" is fine, but
// "woooo" → "woo" changes meaning), so it is a separate variant, not part of
// NormalizeText.
func NormalizeRepeatingChars(input string) string {
	runes := []rune(input)
	if len(runes) == 0 {
		return input
	}

	var b strings.Builder
	b.Grow(len(input))
	prev := runes[0]
	count := 1
	b.WriteRune(prev)

	for i := 1; i < len(runes); i++ {
		if runes[i] == prev {
			count++
			if count <= 2 {
				b.WriteRune(runes[i])
			}
			// If count > 2, skip (collapse)
		} else {
			prev = runes[i]
			count = 1
			b.WriteRune(runes[i])
		}
	}

	return b.String()
}

// NormalizeBackslashEscapes removes ALL backslash characters from the input.
// This is DESTRUCTIVE on normal text (e.g., "C:\Users\file" → "C:Usersfile"),
// so it is a separate variant for attack detection contexts.
func NormalizeBackslashEscapes(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if r != '\\' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeAggressiveL33t replaces ALL l33t-speak characters with their letter
// equivalents, without any context checks. This is DESTRUCTIVE on normal text
// (e.g., "the 42 foxes" → "the 4b foxes"), so it is a separate variant.
func NormalizeAggressiveL33t(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if replacement, ok := l33tMap[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeNewlineCollapse strips \n and \r characters that appear between
// alphanumeric characters. This catches evasion like "ig\nnore" → "ignore".
// This is DESTRUCTIVE on normal text (e.g., "hello\nworld" → "helloworld"),
// so it is a separate variant.
func NormalizeNewlineCollapse(input string) string {
	runes := []rune(input)
	var b strings.Builder
	b.Grow(len(input))

	for i, r := range runes {
		if r == '\n' || r == '\r' {
			// Only remove if between alphanumeric characters
			hasAlnumBefore := i > 0 && (unicode.IsLetter(runes[i-1]) || unicode.IsDigit(runes[i-1]))
			hasAlnumAfter := i < len(runes)-1 && (unicode.IsLetter(runes[i+1]) || unicode.IsDigit(runes[i+1]))
			if hasAlnumBefore && hasAlnumAfter {
				continue // Strip newline between alphanumerics
			}
		}
		b.WriteRune(r)
	}

	return b.String()
}

// NormalizeMultiPass applies a multi-step decoding pipeline:
// URL-decode → strip backslashes → strip zero-width → remove insertions
// → aggressive l33t → collapse whitespace.
// This catches mixed encoding attacks. DESTRUCTIVE on normal text, so it
// is a separate variant.
func NormalizeMultiPass(input string) string {
	result := decodeURLEncoding(input)
	result = NormalizeBackslashEscapes(result)
	result = stripZeroWidth(result)
	result = removeInterCharacterInsertions(result)
	result = NormalizeAggressiveL33t(result)
	result = collapseWhitespace(result)
	return result
}

// --- Internal helpers ---

// stripZeroWidth removes zero-width and invisible Unicode characters.
func stripZeroWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !zeroWidthSet[r] {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// deobfuscateL33t replaces l33t-speak characters with their letter equivalents.
// Context-aware: only replaces digits/symbols that appear between letters
// to avoid corrupting legitimate numbers like "42" or "AWS123".
func deobfuscateL33t(s string) string {
	runes := []rune(s)
	result := make([]rune, len(runes))
	copy(result, runes)

	for i, r := range runes {
		if replacement, ok := l33tMap[r]; ok {
			// Only replace if the character is in a word context:
			// has a letter on at least one side
			hasLetterBefore := i > 0 && unicode.IsLetter(runes[i-1])
			hasLetterAfter := i < len(runes)-1 && unicode.IsLetter(runes[i+1])

			if hasLetterBefore || hasLetterAfter {
				result[i] = replacement
			}
		}
	}

	return string(result)
}

// reverseKeyboardWalk shifts each lowercase letter one position LEFT on QWERTY.
func reverseKeyboardWalk(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if replacement, ok := keyWalkReverse[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// removeInterCharacterInsertions strips dots, hyphens, and underscores that
// appear between alphanumeric characters within words. Also removes insertions
// between letters and digits, since l33t-speak digits (like "1gn0r3") will
// become letters after deobfuscation. Preserves legitimate punctuation at
// word boundaries (e.g., "end." keeps its period).
func removeInterCharacterInsertions(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i, r := range runes {
		if r == '.' || r == '-' || r == '_' {
			// Remove if surrounded by alphanumeric characters (letters or digits)
			hasAlnumBefore := i > 0 && (unicode.IsLetter(runes[i-1]) || unicode.IsDigit(runes[i-1]))
			hasAlnumAfter := i < len(runes)-1 && (unicode.IsLetter(runes[i+1]) || unicode.IsDigit(runes[i+1]))

			if hasAlnumBefore && hasAlnumAfter {
				continue // Skip this insertion character
			}
		}
		b.WriteRune(r)
	}

	return b.String()
}

// decodeROT13 applies ROT13 decoding.
func decodeROT13(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune((r-'a'+13)%26 + 'a')
		case r >= 'A' && r <= 'Z':
			b.WriteRune((r-'A'+13)%26 + 'A')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// decodeURLEncoding decodes URL-encoded sequences in the input string.
// Replaces %XX hex sequences with their decoded character and converts +
// to space when preceded by an alphanumeric character.
func decodeURLEncoding(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			// Try to decode %XX
			hi := hexDigitVal(s[i+1])
			lo := hexDigitVal(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		// Convert '+' to space only when preceded by alphanumeric
		if s[i] == '+' && i > 0 && (unicode.IsLetter(rune(s[i-1])) || unicode.IsDigit(rune(s[i-1]))) {
			b.WriteByte(' ')
			i++
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// hexDigitVal returns the numeric value of a hex digit, or -1 if invalid.
func hexDigitVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// collapseWhitespace collapses runs of whitespace into single spaces.
func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false

	for _, r := range s {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}

	return strings.TrimSpace(b.String())
}