// SPDX-License-Identifier: Apache-2.0

package i18n

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPhase1bArabicPluralRule exercises all branches of arabicPluralRule.
func TestPhase1bArabicPluralRule(t *testing.T) {
	tests := []struct {
		count  int
		expect PluralForm
	}{
		{0, PluralOther},   // zero → other
		{1, PluralOne},     // one
		{2, PluralTwo},     // two
		{3, PluralFew},     // mod100 in 3..10
		{10, PluralFew},    // mod100 in 3..10
		{11, PluralMany},   // mod100 in 11..99
		{99, PluralMany},   // mod100 in 11..99
		{100, PluralOther}, // default
		{103, PluralFew},   // mod100 = 3
		{111, PluralMany},  // mod100 = 11
	}
	for _, tt := range tests {
		got := GetPluralForm(LocaleAr, tt.count)
		if got != tt.expect {
			t.Errorf("arabicPluralRule(%d) = %s, want %s", tt.count, got, tt.expect)
		}
	}
}

// TestPhase1bRussianPluralRule exercises all branches of russianPluralRule.
func TestPhase1bRussianPluralRule(t *testing.T) {
	tests := []struct {
		count  int
		expect PluralForm
	}{
		{1, PluralOne},   // mod10==1 && mod100!=11
		{11, PluralMany}, // mod10==1 but mod100==11 → many
		{2, PluralFew},   // mod10 2..4, mod100 not 12..14
		{3, PluralFew},   // mod10 2..4, mod100 not 12..14
		{4, PluralFew},   // mod10 2..4, mod100 not 12..14
		{12, PluralMany}, // mod10==2 but mod100==12 → many
		{13, PluralMany}, // mod10==3 but mod100==13 → many
		{14, PluralMany}, // mod10==4 but mod100==14 → many
		{22, PluralFew},  // mod10==2, mod100==22 → few
		{25, PluralMany}, // mod10==5 → many
		{0, PluralMany},  // mod10==0 → many
	}
	for _, tt := range tests {
		got := GetPluralForm(LocaleRu, tt.count)
		if got != tt.expect {
			t.Errorf("russianPluralRule(%d) = %s, want %s", tt.count, got, tt.expect)
		}
	}
}

// TestPhase1bHebrewPluralRule exercises all branches of hebrewPluralRule.
func TestPhase1bHebrewPluralRule(t *testing.T) {
	tests := []struct {
		count  int
		expect PluralForm
	}{
		{1, PluralOne},    // n==1
		{2, PluralTwo},    // n==2
		{3, PluralMany},   // 3..10
		{10, PluralMany},  // 3..10
		{11, PluralOther}, // not 1, 2, 3..10, mod10!=0
		{15, PluralOther}, // not 1, 2, 3..10, mod10!=0
		{20, PluralMany},  // mod10==0
		{30, PluralMany},  // mod10==0
	}
	for _, tt := range tests {
		got := GetPluralForm(LocaleHe, tt.count)
		if got != tt.expect {
			t.Errorf("hebrewPluralRule(%d) = %s, want %s", tt.count, got, tt.expect)
		}
	}
}

// TestPhase1bHindiPluralRule exercises all branches of hindiPluralRule.
func TestPhase1bHindiPluralRule(t *testing.T) {
	tests := []struct {
		count  int
		expect PluralForm
	}{
		{0, PluralOne},   // 0 → one
		{1, PluralOne},   // 1 → one
		{2, PluralOther}, // >=2 → other
		{10, PluralOther},
	}
	for _, tt := range tests {
		got := GetPluralForm(LocaleHi, tt.count)
		if got != tt.expect {
			t.Errorf("hindiPluralRule(%d) = %s, want %s", tt.count, got, tt.expect)
		}
	}
}

// TestPhase1bDefaultPluralFormsAll exercises all locale cases in DefaultPluralForms.
func TestPhase1bDefaultPluralFormsAll(t *testing.T) {
	tests := []struct {
		locale Locale
		expect []PluralForm
	}{
		{LocaleAr, []PluralForm{PluralOne, PluralTwo, PluralFew, PluralMany, PluralOther}},
		{LocaleRu, []PluralForm{PluralOne, PluralFew, PluralMany}},
		{LocaleHe, []PluralForm{PluralOne, PluralTwo, PluralMany, PluralOther}},
		{LocaleJa, []PluralForm{PluralOther}},
		{LocaleZh, []PluralForm{PluralOther}},
		{LocaleKo, []PluralForm{PluralOther}},
		{LocaleEn, []PluralForm{PluralOne, PluralOther}},
		{LocaleFr, []PluralForm{PluralOne, PluralOther}},
	}
	for _, tt := range tests {
		got := DefaultPluralForms(tt.locale)
		if len(got) != len(tt.expect) {
			t.Errorf("DefaultPluralForms(%s) returned %d forms, want %d", tt.locale, len(got), len(tt.expect))
			continue
		}
		for i, f := range tt.expect {
			if got[i] != f {
				t.Errorf("DefaultPluralForms(%s)[%d] = %s, want %s", tt.locale, i, got[i], f)
			}
		}
	}
}

// TestPhase1bNewManagerWithEmbeddedFS covers the loadEmbedded path in NewManager.
func TestPhase1bNewManagerWithEmbeddedFS(t *testing.T) {
	mgr, err := NewManager(&ManagerOptions{
		DefaultLocale: DefaultLocale,
		EmbeddedFS:    embeddedLocales,
	})
	if err != nil {
		t.Fatalf("NewManager with EmbeddedFS failed: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
}

// TestPhase1bLoadLocaleFilePathTraversal tests path traversal rejection.
func TestPhase1bLoadLocaleFilePathTraversal(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	err = mgr.LoadLocaleFile(LocaleEn, "../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal")
	}
}

// TestPhase1bLoadLocaleFileNotExist tests file read error path.
func TestPhase1bLoadLocaleFileNotExist(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	err = mgr.LoadLocaleFile(LocaleEn, filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

// TestPhase1bLoadLocaleDataInvalidJSON tests JSON parse error.
func TestPhase1bLoadLocaleDataInvalidJSON(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	err = mgr.LoadLocaleData(LocaleEn, []byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestPhase1bGetTemplateExecutionError tests that Get returns the raw message
// when template execution fails (e.g. nil field access).
func TestPhase1bGetTemplateExecutionError(t *testing.T) {
	b := NewBundle(LocaleEn)
	// Template parses fine but fails on execution: .Foo is nil, .Bar on nil errors.
	b.Add("bad", "{{.Foo.Bar}}")
	msg := b.Get("bad", nil)
	if msg != "{{.Foo.Bar}}" {
		t.Errorf("expected raw message on template error, got %q", msg)
	}
}

// TestPhase1bGetPluralInlineParse tests the inline template parsing path in
// GetPlural (when a plural form has interpolation markers but no pre-parsed template).
func TestPhase1bGetPluralInlineParse(t *testing.T) {
	b := NewBundle(LocaleEn)
	// Directly set plurals without calling AddPlural, so no templates are pre-parsed.
	b.plurals["key"] = PluralForms{
		PluralOne:   "{{.Count}} item",
		PluralOther: "{{.Count}} items",
	}
	msg := b.GetPlural("key", 1, nil)
	if msg != "1 item" {
		t.Errorf("expected '1 item' from inline parse, got %q", msg)
	}
	msg = b.GetPlural("key", 5, nil)
	if msg != "5 items" {
		t.Errorf("expected '5 items' from inline parse, got %q", msg)
	}
}

// TestPhase1bGetPluralTemplateError tests that GetPlural returns the raw
// message when both pre-parsed and inline template execution fail.
func TestPhase1bGetPluralTemplateError(t *testing.T) {
	b := NewBundle(LocaleEn)
	// AddPlural pre-parses the template; execution will fail because .Foo is nil.
	b.AddPlural("bad", PluralForms{
		PluralOne:   "{{.Foo.Bar}}",
		PluralOther: "{{.Count}} items",
	})
	msg := b.GetPlural("bad", 1, nil)
	if msg != "{{.Foo.Bar}}" {
		t.Errorf("expected raw message on template error, got %q", msg)
	}
}

// TestPhase1bCloneWithTemplatesAndPlurals verifies Clone copies templates and plurals.
func TestPhase1bCloneWithTemplatesAndPlurals(t *testing.T) {
	original := NewBundle(LocaleEn)
	original.Add("tpl", "Hello, {{.Name}}!")
	original.AddPlural("items", PluralForms{
		PluralOne:   "{{.Count}} item",
		PluralOther: "{{.Count}} items",
	})
	original.Add("plain", "no vars")

	clone := original.Clone()

	// Template interpolation should work in the clone.
	msg := clone.Get("tpl", map[string]interface{}{"Name": "World"})
	if msg != "Hello, World!" {
		t.Errorf("clone template interpolation failed: %q", msg)
	}

	// Plural lookup should work in the clone.
	msg = clone.GetPlural("items", 1, nil)
	if msg != "1 item" {
		t.Errorf("clone plural failed: %q", msg)
	}

	// Plain message should work.
	msg = clone.Get("plain", nil)
	if msg != "no vars" {
		t.Errorf("clone plain message failed: %q", msg)
	}

	if clone.Count() != 2 {
		t.Errorf("expected count 2, got %d", clone.Count())
	}
}

// TestPhase1bMergeWithTemplatesAndPlurals verifies Merge copies templates and plurals.
func TestPhase1bMergeWithTemplatesAndPlurals(t *testing.T) {
	dst := NewBundle(LocaleEn)
	dst.Add("keep", "original")

	src := NewBundle(LocaleEn)
	src.Add("new", "Hello, {{.Name}}!")
	src.AddPlural("items", PluralForms{
		PluralOne:   "{{.Count}} item",
		PluralOther: "{{.Count}} items",
	})

	dst.Merge(src)

	// Template from src should work in dst.
	msg := dst.Get("new", map[string]interface{}{"Name": "World"})
	if msg != "Hello, World!" {
		t.Errorf("merged template interpolation failed: %q", msg)
	}

	// Plural from src should work in dst.
	msg = dst.GetPlural("items", 1, nil)
	if msg != "1 item" {
		t.Errorf("merged plural failed: %q", msg)
	}

	// Original key should still exist.
	msg = dst.Get("keep", nil)
	if msg != "original" {
		t.Errorf("original key overwritten: %q", msg)
	}
}

// TestPhase1bTLocalePluralMissingKeyEn tests TLocalePlural when the key is
// missing and locale is English (no fallback attempt should occur).
func TestPhase1bTLocalePluralMissingKeyEn(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	msg := mgr.TLocalePlural(LocaleEn, "nonexistent.key", 5, nil)
	if msg != "nonexistent.key" {
		t.Errorf("expected key fallback, got %q", msg)
	}
}

// TestPhase1bLoadFromDirectoryBadJSON tests loadFromDirectory when a valid
// locale filename contains invalid JSON (causes LoadLocaleFile to fail).
func TestPhase1bLoadFromDirectoryBadJSON(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "en.json"), []byte(`{invalid json`), 0644)

	// NewManager should not fail — the error is caught and printed as a warning.
	mgr, err := NewManager(&ManagerOptions{LocaleDir: tmpDir})
	if err != nil {
		t.Fatalf("NewManager should not fail: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
}
