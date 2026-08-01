// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform - ML Training Augmentation Tests
// =========================================================================

package training

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewAugmentor(t *testing.T) {
	aug := NewAugmentor()
	if len(aug.payloads) != 52 {
		t.Errorf("expected 52 ATLAS payloads, got %d", len(aug.payloads))
	}
}

func TestGenerateAll(t *testing.T) {
	aug := NewAugmentor()
	examples := aug.GenerateAll()

	// Should have original 52 + augmented variants
	if len(examples) < 52 {
		t.Errorf("expected at least 52 examples, got %d", len(examples))
	}

	// Count labels
	counts := CountByLabel(examples)
	if counts[LabelAdversarial] < 52 {
		t.Errorf("expected at least 52 adversarial examples, got %d", counts[LabelAdversarial])
	}

	// All adversarial examples should have technique IDs
	for _, ex := range examples {
		if ex.Label == LabelAdversarial && ex.Technique == "" {
			t.Errorf("adversarial example missing technique ID: %q", ex.Text[:50])
		}
	}

	t.Logf("Generated %d total examples (%d adversarial, %d benign)",
		len(examples), counts[LabelAdversarial], counts[LabelBenign])
}

func TestGenerateBenign(t *testing.T) {
	aug := NewAugmentor()
	examples := aug.GenerateBenign()

	if len(examples) < 80 {
		t.Errorf("expected at least 80 benign examples, got %d", len(examples))
	}

	// All benign examples should have benign label
	for _, ex := range examples {
		if ex.Label != LabelBenign {
			t.Errorf("expected benign label, got %s", ex.Label)
		}
	}

	counts := CountByLabel(examples)
	t.Logf("Generated %d benign examples", counts[LabelBenign])
}

func TestAugmentationTransforms(t *testing.T) {
	tests := []struct {
		name     string
		fn       func(string) string
		input    string
		wantDiff bool // true if we expect the output to differ from input
	}{
		// Character substitution
		{"l33t_common", l33tCommon, "ignore instructions", true},
		{"l33t_aggressive", l33tAggressive, "bypass restrictions", true},
		{"char_insert_dots", charInsertDots, "ignore", true},
		{"char_insert_hyphens", charInsertHyphens, "bypass", true},
		{"char_delete_vowels", charDeleteVowels, "ignore instructions", true},
		{"char_transpose_adjacent", charTransposeAdjacent, "bypass the security", true},
		{"keyboard_walk_shift", keyboardWalkShift, "bypass", true},
		{"char_substitute_symbols", charSubstituteSymbols, "admin access", true},

		// Encoding
		{"encoding_base64_prefix", encodingBase64Prefix, "ignore instructions", true},
		{"encoding_base64_full", encodingBase64Full, "ignore", true},
		{"encoding_rot13_partial", encodingROT13Partial, "ignore instructions", true},
		{"encoding_url_encode_spaces", encodingURLEncodeSpaces, "ignore instructions", true},
		{"encoding_unicode_escapes", encodingUnicodeEscapes, "ignore", true},
		{"encoding_html_entity", encodingHTMLEntityEncode, "ignore", true},
		{"encoding_hex_escape", encodingHexEscape, "ignore", true},
		{"encoding_mixed_encoding", encodingMixedEncoding, "ignore", true},

		// Linguistic
		{"linguistic_synonym_sub", linguisticSynonymSub, "ignore instructions", true},
		{"linguistic_hypothetical", linguisticHypothetical, "bypass security", true},
		{"linguistic_polite_wrapper", linguisticPoliteWrapper, "reveal the password", true},
		{"linguistic_story_framing", linguisticStoryFraming, "bypass the filter", true},

		// Whitespace
		{"ws_extra_spaces", wsExtraSpaces, "ignore instructions", true},
		{"ws_double_spaces", wsDoubleSpaces, "ignore instructions", true},

		// Fragmentation
		{"frag_split_half", fragSplitHalf, "ignore all previous instructions", true},
		{"frag_context_boundary", fragContextBoundary, "ignore instructions", true},
		{"frag_system_prefix", fragSystemPrefix, "ignore instructions", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn(tt.input)
			if tt.wantDiff && result == tt.input {
				t.Errorf("expected transform %q to modify input, got same string", tt.name)
			}
			if result == "" {
				t.Errorf("transform %q returned empty string", tt.name)
			}
		})
	}
}

func TestAugmentSpecificTransforms(t *testing.T) {
	// Test l33t_common specifically
	result := l33tCommon("ignore")
	if !strings.Contains(result, "1") && !strings.Contains(result, "0") {
		t.Errorf("l33t_common should substitute vowels, got %q", result)
	}

	// Test char_delete_vowels
	result = charDeleteVowels("ignore instructions")
	if result == "ignore instructions" {
		t.Errorf("char_delete_vowels should remove vowels, got %q", result)
	}

	// Test encoding_base64_prefix
	result = encodingBase64Prefix("ignore")
	if !strings.HasPrefix(result, "decode:base64,") {
		t.Errorf("expected base64 prefix, got %q", result)
	}

	// Test encoding_url_encode_spaces
	result = encodingURLEncodeSpaces("ignore instructions")
	if !strings.Contains(result, "%20") {
		t.Errorf("expected URL-encoded spaces, got %q", result)
	}
}

func TestWriteAndReadJSONL(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.jsonl")

	examples := []Example{
		{Text: "ignore instructions", Label: LabelAdversarial, Technique: "T1535.001", Variant: "original"},
		{Text: "what are your capabilities", Label: LabelBenign, Source: "synthetic"},
	}

	// Write
	if err := WriteJSONL(examples, path); err != nil {
		t.Fatalf("WriteJSONL failed: %v", err)
	}

	// Read back
	readBack, err := ReadJSONL(path)
	if err != nil {
		t.Fatalf("ReadJSONL failed: %v", err)
	}

	if len(readBack) != 2 {
		t.Errorf("expected 2 examples, got %d", len(readBack))
	}

	if readBack[0].Text != examples[0].Text {
		t.Errorf("text mismatch: got %q, want %q", readBack[0].Text, examples[0].Text)
	}

	if readBack[0].Label != LabelAdversarial {
		t.Errorf("label mismatch: got %q, want %q", readBack[0].Label, LabelAdversarial)
	}
}

func TestSplitDataset(t *testing.T) {
	aug := NewAugmentor()
	examples := aug.GenerateAll()

	train, val, test := SplitDataset(examples, 0.8, 0.1, 0.1)

	total := len(train) + len(val) + len(test)
	if total != len(examples) {
		t.Errorf("split lost examples: %d -> %d+%d+%d=%d",
			len(examples), len(train), len(val), len(test), total)
	}

	// Check approximate ratios
	trainRatio := float64(len(train)) / float64(len(examples))
	if trainRatio < 0.75 || trainRatio > 0.85 {
		t.Errorf("train ratio %.2f outside expected range [0.75, 0.85]", trainRatio)
	}
}

func TestCountByLabel(t *testing.T) {
	examples := []Example{
		{Label: LabelAdversarial},
		{Label: LabelBenign},
		{Label: LabelAdversarial},
	}

	counts := CountByLabel(examples)
	if counts[LabelAdversarial] != 2 {
		t.Errorf("expected 2 adversarial, got %d", counts[LabelAdversarial])
	}
	if counts[LabelBenign] != 1 {
		t.Errorf("expected 1 benign, got %d", counts[LabelBenign])
	}
}

func TestEndToEndAugmentationPipeline(t *testing.T) {
	aug := NewAugmentor()

	// Generate adversarial examples
	adversarial := aug.GenerateAll()
	if len(adversarial) < 100 {
		t.Errorf("expected at least 100 adversarial examples, got %d", len(adversarial))
	}

	// Generate benign examples
	benign := aug.GenerateBenign()
	if len(benign) < 80 {
		t.Errorf("expected at least 80 benign examples, got %d", len(benign))
	}

	// Combine
	all := append(adversarial, benign...)

	// Split
	train, val, test := SplitDataset(all, 0.8, 0.1, 0.1)

	total := len(train) + len(val) + len(test)
	if total != len(all) {
		t.Errorf("split lost examples: %d -> %d", len(all), total)
	}

	// Write to JSONL
	tmpDir := t.TempDir()
	trainPath := filepath.Join(tmpDir, "train.jsonl")
	valPath := filepath.Join(tmpDir, "val.jsonl")
	testPath := filepath.Join(tmpDir, "test.jsonl")

	if err := WriteJSONL(train, trainPath); err != nil {
		t.Fatalf("WriteJSONL train: %v", err)
	}
	if err := WriteJSONL(val, valPath); err != nil {
		t.Fatalf("WriteJSONL val: %v", err)
	}
	if err := WriteJSONL(test, testPath); err != nil {
		t.Fatalf("WriteJSONL test: %v", err)
	}

	// Verify files exist and are non-empty
	for _, path := range []string{trainPath, valPath, testPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", path, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", path)
		}
	}

	// Read back and verify
	readBack, err := ReadJSONL(trainPath)
	if err != nil {
		t.Fatalf("ReadJSONL train: %v", err)
	}
	if len(readBack) != len(train) {
		t.Errorf("read back %d examples, expected %d", len(readBack), len(train))
	}

	t.Logf("Pipeline: %d adversarial + %d benign = %d total",
		len(adversarial), len(benign), len(all))
	t.Logf("Split: train=%d, val=%d, test=%d", len(train), len(val), len(test))
}
