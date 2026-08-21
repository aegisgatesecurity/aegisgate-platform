// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Character-Level Normalizer
// =========================================================================
//
// Preprocesses raw text into character-level input tensors for the
// Char CNN-BiLSTM model. Converts text to a fixed-length integer array
// suitable for ONNX inference.
//
// Input pipeline:
//   raw text → normalize → truncate/pad → char IDs → [1, max_len] int32 tensor
//
// Character vocabulary: 128 ASCII characters (0-127).
// Unknown characters are mapped to a special UNK token (id=1).
// Padding is done with a PAD token (id=0).
//
// =========================================================================

package ml

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const (
	// MaxSeqLen is the maximum sequence length for the model input.
	MaxSeqLen = 128

	// PadID is the padding token ID.
	PadID = 0

	// UnkID is the unknown character token ID.
	UnkID = 1

	// VocabSize is the size of the character vocabulary.
	VocabSize = 128
)

// CharNormalizer preprocesses text into character-level input for the model.
type CharNormalizer struct {
	maxLen int
}

// NewCharNormalizer creates a new character normalizer with default settings.
func NewCharNormalizer() *CharNormalizer {
	return &CharNormalizer{
		maxLen: MaxSeqLen,
	}
}

// Normalize preprocesses text for model input.
// Steps:
//  1. NFKC normalization (Unicode canonical decomposition + composition)
//     — this maps homoglyphs and compatibility characters to their
//     canonical forms, so "ⅴ" (U+2174) → "v" (U+0076) and "ﬁ" (U+FB01)
//     → "fi". Without this, adversarial inputs using Unicode tricks
//     bypass the model's detection.
//  2. Convert to lowercase
//  3. Strip leading/trailing whitespace
//  4. Collapse multiple whitespace
//  5. Truncate to max length
func (cn *CharNormalizer) Normalize(text string) string {
	// NFKC normalization — canonical decomposition + composition.
	// This maps compatibility characters and homoglyphs to their
	// canonical ASCII equivalents where possible.
	text = norm.NFKC.String(text)

	// Lowercase
	text = strings.ToLower(text)

	// Strip leading/trailing whitespace
	text = strings.TrimSpace(text)

	// Collapse multiple whitespace
	var b strings.Builder
	prevSpace := false
	for _, r := range text {
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
	text = b.String()

	// Truncate
	runes := []rune(text)
	if len(runes) > cn.maxLen {
		runes = runes[:cn.maxLen]
	}

	return string(runes)
}

// Encode converts normalized text to a fixed-length integer array for model input.
// Characters are mapped to their ASCII code if in range [32, 126] (printable ASCII),
// otherwise to UNK_ID. Result is padded to maxLen with PAD_ID.
func (cn *CharNormalizer) Encode(text string) []int32 {
	normalized := cn.Normalize(text)
	runes := []rune(normalized)

	result := make([]int32, cn.maxLen)
	for i := range result {
		result[i] = PadID
	}

	for i, r := range runes {
		if i >= cn.maxLen {
			break
		}

		// Map printable ASCII characters directly
		if r >= 32 && r <= 126 {
			result[i] = int32(r)
		} else if r < 128 {
			// Non-printable ASCII → UNK
			result[i] = UnkID
		} else {
			// Non-ASCII → UNK
			result[i] = UnkID
		}
	}

	return result
}

// EncodeBatch encodes multiple texts into a batch tensor [batch_size, max_len].
func (cn *CharNormalizer) EncodeBatch(texts []string) [][]int32 {
	batch := make([][]int32, len(texts))
	for i, text := range texts {
		batch[i] = cn.Encode(text)
	}
	return batch
}

// Decode reverses the encoding (for debugging/verification only).
// Not used in production inference.
func (cn *CharNormalizer) Decode(ids []int32) string {
	var b strings.Builder
	for _, id := range ids {
		if id == PadID {
			continue // Skip padding
		}
		if id == UnkID {
			b.WriteRune('�') // Replacement character
			continue
		}
		if id >= 32 && id <= 126 {
			b.WriteRune(rune(id))
		}
	}
	return b.String()
}
