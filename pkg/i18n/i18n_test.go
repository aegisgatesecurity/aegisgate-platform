package i18n

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLocaleParsing tests locale parsing and validation
func TestLocaleParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected Locale
	}{
		{"en", LocaleEn},
		{"EN", LocaleEn},
		{" En ", LocaleEn},
		{"fr", LocaleFr},
		{"de", LocaleDe},
		{"es", LocaleEs},
		{"ja", LocaleJa},
		{"zh", LocaleZh},
		{"invalid", DefaultLocale},
		{"", DefaultLocale},
		{"pt", LocalePt},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			locale := ParseLocale(tt.input)
			if locale != tt.expected {
				t.Errorf("ParseLocale(%q) = %q, want %q", tt.input, locale, tt.expected)
			}
		})
	}
}

func TestSupportedLocales(t *testing.T) {
	locales := SupportedLocales()
	if len(locales) != 12 {
		t.Errorf("Expected 12 supported locales, got %d", len(locales))
	}
}

// TestBundleOperations tests Bundle functionality
func TestBundleOperations(t *testing.T) {
	bundle := NewBundle(LocaleEn)

	// Test Add
	bundle.Add("test.key", "Hello, World!")
	if !bundle.Has("test.key") {
		t.Error("Bundle should have test.key")
	}
	if bundle.Count() != 1 {
		t.Errorf("Expected count 1, got %d", bundle.Count())
	}

	// Test Get
	msg := bundle.Get("test.key", nil)
	if msg != "Hello, World!" {
		t.Errorf("Expected 'Hello, World!', got %q", msg)
	}

	// Test missing key
	msg = bundle.Get("missing.key", nil)
	if msg != "missing.key" {
		t.Errorf("Expected 'missing.key' as fallback, got %q", msg)
	}
}

func TestBundleInterpolation(t *testing.T) {
	bundle := NewBundle(LocaleEn)

	// Test simple interpolation
	bundle.Add("greeting", "Hello, {{.Name}}!")
	msg := bundle.Get("greeting", map[string]interface{}{"Name": "Alice"})
	if msg != "Hello, Alice!" {
		t.Errorf("Expected 'Hello, Alice!', got %q", msg)
	}

	// Test multiple variables
	bundle.Add("error.entry", "Entry {{.ID}} not found in {{.Location}}")
	msg = bundle.Get("error.entry", map[string]interface{}{
		"ID":       "abc123",
		"Location": "database",
	})
	if msg != "Entry abc123 not found in database" {
		t.Errorf("Unexpected interpolation result: %q", msg)
	}

	// Test message without template variables (no interpolation)
	bundle.Add("simple.message", "This is a simple message")
	msg = bundle.Get("simple.message", nil)
	if msg != "This is a simple message" {
		t.Errorf("Expected 'This is a simple message', got %q", msg)
	}
}

func TestBundlePlural(t *testing.T) {
	bundle := NewBundle(LocaleEn)

	// Add plural forms
	bundle.AddPlural("items.count", PluralForms{
		PluralOne:   "{{.Count}} item",
		PluralOther: "{{.Count}} items",
	})

	// Test singular
	msg := bundle.GetPlural("items.count", 1, nil)
	if msg != "1 item" {
		t.Errorf("Expected '1 item', got %q", msg)
	}

	// Test plural
	msg = bundle.GetPlural("items.count", 5, nil)
	if msg != "5 items" {
		t.Errorf("Expected '5 items', got %q", msg)
	}

	// Test zero (uses 'other' for English)
	msg = bundle.GetPlural("items.count", 0, nil)
	if msg != "0 items" {
		t.Errorf("Expected '0 items', got %q", msg)
	}
}

func TestBundleMerge(t *testing.T) {
	bundle1 := NewBundle(LocaleEn)
	bundle1.Add("key1", "value1")
	bundle1.Add("key2", "original")

	bundle2 := NewBundle(LocaleEn)
	bundle2.Add("key2", "overwritten")
	bundle2.Add("key3", "value3")

	bundle1.Merge(bundle2)

	if bundle1.Count() != 3 {
		t.Errorf("Expected count 3, got %d", bundle1.Count())
	}

	msg := bundle1.Get("key2", nil)
	if msg != "overwritten" {
		t.Errorf("Expected 'overwritten', got %q", msg)
	}
}

func TestBundleClone(t *testing.T) {
	original := NewBundle(LocaleEn)
	original.Add("key1", "value1")
	original.Add("key2", "value2")

	clone := original.Clone()

	// Modify original
	original.Add("key1", "changed")

	// Clone should be independent
	msg := clone.Get("key1", nil)
	if msg != "value1" {
		t.Errorf("Clone was not independent: %q", msg)
	}
}

func TestBundleMissingKeys(t *testing.T) {
	reference := NewBundle(LocaleEn)
	reference.Add("key1", "value1")
	reference.Add("key2", "value2")
	reference.Add("key3", "value3")

	bundle := NewBundle(LocaleEn)
	bundle.Add("key1", "value1")

	missing := bundle.MissingKeys(reference)
	if len(missing) != 2 {
		t.Errorf("Expected 2 missing keys, got %d: %v", len(missing), missing)
	}
}

func TestBundleExport(t *testing.T) {
	bundle := NewBundle(LocaleEn)
	bundle.Add("key1", "value1")
	bundle.Add("key2", "value2")
	bundle.AddPlural("items.count", PluralForms{
		PluralOne:   "1 item",
		PluralOther: "{{.Count}} items",
	})

	lf := bundle.Export()
	if lf.Locale != "en" {
		t.Errorf("Expected locale 'en', got %q", lf.Locale)
	}
	if len(lf.Messages) != 2 {
		t.Errorf("Expected 2 messages, got %d", len(lf.Messages))
	}
	if len(lf.Plurals) != 1 {
		t.Errorf("Expected 1 plural, got %d", len(lf.Plurals))
	}
}

// TestManager tests Manager functionality
func TestManagerBasic(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if mgr.GetDefault() != DefaultLocale {
		t.Errorf("Expected default locale %s, got %s", DefaultLocale, mgr.GetDefault())
	}
}

func TestManagerAddTranslation(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgr.AddTranslation(LocaleEn, "test.key", "Test message")
	msg := mgr.T("test.key")
	if msg != "Test message" {
		t.Errorf("Expected 'Test message', got %q", msg)
	}
}

func TestManagerSetLocale(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	err = mgr.SetDefault(LocaleFr)
	if err != nil {
		t.Fatalf("SetDefault failed: %v", err)
	}
	if mgr.GetDefault() != LocaleFr {
		t.Errorf("Expected LocaleFr, got %s", mgr.GetDefault())
	}

	// Test invalid locale
	err = mgr.SetDefault(Locale("invalid"))
	if err == nil {
		t.Error("Expected error for invalid locale")
	}
}

func TestManagerTWith(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgr.AddTranslation(LocaleEn, "greeting", "Hello, {{.Name}}!")
	msg := mgr.TWith("greeting", map[string]interface{}{"Name": "World"})
	if msg != "Hello, World!" {
		t.Errorf("Expected 'Hello, World!', got %q", msg)
	}
}

func TestManagerTLocale(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Add English translation
	mgr.AddTranslation(LocaleEn, "test.key", "English message")

	// Add French translation
	mgr.AddTranslation(LocaleFr, "test.key", "Message français")

	// Test English
	msg := mgr.TLocale(LocaleEn, "test.key")
	if msg != "English message" {
		t.Errorf("Expected 'English message', got %q", msg)
	}

	// Test French
	msg = mgr.TLocale(LocaleFr, "test.key")
	if msg != "Message français" {
		t.Errorf("Expected 'Message français', got %q", msg)
	}
}

func TestManagerTPlural(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	bundle := mgr.GetBundle(LocaleEn)
	bundle.AddPlural("items.count", PluralForms{
		PluralOne:   "{{.Count}} item",
		PluralOther: "{{.Count}} items",
	})

	// Test singular
	msg := mgr.TPlural("items.count", 1, nil)
	if msg != "1 item" {
		t.Errorf("Expected '1 item', got %q", msg)
	}

	// Test plural
	msg = mgr.TPlural("items.count", 5, nil)
	if msg != "5 items" {
		t.Errorf("Expected '5 items', got %q", msg)
	}
}

func TestManagerLoadLocaleData(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	localeData := `{
		"locale": "en",
		"language": "English",
		"messages": {
			"test.key1": "Message 1",
			"test.key2": "Message 2"
		}
	}`

	err = mgr.LoadLocaleData(LocaleEn, []byte(localeData))
	if err != nil {
		t.Fatalf("LoadLocaleData failed: %v", err)
	}

	msg := mgr.T("test.key1")
	if msg != "Message 1" {
		t.Errorf("Expected 'Message 1', got %q", msg)
	}
}

func TestManagerLoadLocaleFile(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.json")

	localeData := LocaleFile{
		Locale:   "en",
		Language: "English",
		Messages: map[string]string{
			"test.key": "Test message",
		},
	}
	data, _ := json.Marshal(localeData)
	err := os.WriteFile(tmpFile, data, 0644)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	err = mgr.LoadLocaleFile(LocaleEn, tmpFile)
	if err != nil {
		t.Fatalf("LoadLocaleFile failed: %v", err)
	}

	msg := mgr.T("test.key")
	if msg != "Test message" {
		t.Errorf("Expected 'Test message', got %q", msg)
	}
}

func TestManagerStats(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgr.AddTranslation(LocaleEn, "key1", "value1")
	mgr.AddTranslation(LocaleEn, "key2", "value2")
	mgr.AddTranslation(LocaleFr, "key1", "valeur1")

	stats := mgr.Stats()

	if stats["default_locale"] != "en" {
		t.Errorf("Expected default_locale 'en', got %v", stats["default_locale"])
	}

	counts, ok := stats["message_counts"].(map[string]int)
	if !ok {
		t.Fatal("message_counts not found or wrong type")
	}

	// English should have 2 translations
	if counts["en"] != 2 {
		t.Errorf("Expected en count 2, got %d", counts["en"])
	}
}

func TestManagerHasLocale(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// English should always exist (fallback)
	if !mgr.HasLocale(LocaleEn) {
		t.Error("Manager should have English locale")
	}

	// Add a French translation
	mgr.AddTranslation(LocaleFr, "test", "test")
	if !mgr.HasLocale(LocaleFr) {
		t.Error("Manager should have French locale after adding translation")
	}
}

// TestPluralRules tests pluralization rules for different languages
func TestPluralRules(t *testing.T) {
	tests := []struct {
		locale Locale
		count  int
		expect PluralForm
	}{
		// English
		{LocaleEn, 0, PluralOther},
		{LocaleEn, 1, PluralOne},
		{LocaleEn, 2, PluralOther},

		// French (0 and 1 are 'one')
		{LocaleFr, 0, PluralOne},
		{LocaleFr, 1, PluralOne},
		{LocaleFr, 2, PluralOther},

		// German (same as English)
		{LocaleDe, 1, PluralOne},
		{LocaleDe, 2, PluralOther},

		// Spanish (same as English)
		{LocaleEs, 1, PluralOne},
		{LocaleEs, 2, PluralOther},

		// Japanese (no plural)
		{LocaleJa, 1, PluralOther},
		{LocaleJa, 2, PluralOther},

		// Chinese (no plural)
		{LocaleZh, 1, PluralOther},
		{LocaleZh, 2, PluralOther},
	}

	for _, tt := range tests {
		t.Run(string(tt.locale)+"_"+string(rune(tt.count+'0')), func(t *testing.T) {
			form := GetPluralForm(tt.locale, tt.count)
			if form != tt.expect {
				t.Errorf("GetPluralForm(%s, %d) = %s, want %s", tt.locale, tt.count, form, tt.expect)
			}
		})
	}
}

func TestPluralFormatHelpers(t *testing.T) {
	// Test FormatPlural
	forms := FormatPlural("1 item", "{{.Count}} items")
	if forms[PluralOne] != "1 item" {
		t.Errorf("FormatPlural one form incorrect")
	}
	if forms[PluralOther] != "{{.Count}} items" {
		t.Errorf("FormatPlural other form incorrect")
	}

	// Test FormatPluralFew
	formsFew := FormatPluralFew("1 item", "few items", "many items")
	if formsFew[PluralFew] != "few items" {
		t.Errorf("FormatPluralFew few form incorrect")
	}

	// Test FormatPluralFull
	formsFull := FormatPluralFull("one", "two", "few", "many", "other")
	if formsFull[PluralTwo] != "two" {
		t.Errorf("FormatPluralFull two form incorrect")
	}
}

func TestRegisterPluralRule(t *testing.T) {
	// Register a custom rule for a new locale
	customRule := func(n int) PluralForm {
		if n == 1 {
			return PluralOne
		}
		return PluralOther
	}

	RegisterPluralRule(Locale("custom"), customRule)

	// Verify it works
	form := GetPluralForm(Locale("custom"), 1)
	if form != PluralOne {
		t.Errorf("Custom plural rule not registered correctly")
	}
}

// TestLocaleFiles tests that the locale JSON files are valid
func TestLocaleFilesExist(t *testing.T) {
	locales := []string{"en", "fr", "de", "es", "ja", "zh"}

	for _, loc := range locales {
		t.Run(loc, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("locales", loc+".json"))
			if err != nil {
				t.Fatalf("Failed to read locale file: %v", err)
			}

			var lf LocaleFile
			if err := json.Unmarshal(data, &lf); err != nil {
				t.Fatalf("Failed to parse locale file: %v", err)
			}

			if lf.Locale != loc {
				t.Errorf("Locale file has wrong locale: %s", lf.Locale)
			}

			if len(lf.Messages) == 0 {
				t.Error("Locale file has no messages")
			}
		})
	}
}

// Benchmark tests
func BenchmarkBundleGet(b *testing.B) {
	bundle := NewBundle(LocaleEn)
	bundle.Add("test.key", "Hello, {{.Name}}!")
	vars := map[string]interface{}{"Name": "World"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bundle.Get("test.key", vars)
	}
}

func BenchmarkManagerT(b *testing.B) {
	mgr, _ := NewManager(nil)
	mgr.AddTranslation(LocaleEn, "test.key", "Hello, {{.Name}}!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mgr.T("test.key")
	}
}

func BenchmarkManagerTWith(b *testing.B) {
	mgr, _ := NewManager(nil)
	mgr.AddTranslation(LocaleEn, "test.key", "Hello, {{.Name}}!")
	vars := map[string]interface{}{"Name": "World"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mgr.TWith("test.key", vars)
	}
}

// =========================================================================
// Additional tests to raise coverage above 80%
// =========================================================================

func TestIsValidLocale(t *testing.T) {
	if !IsValidLocale(LocaleEn) {
		t.Error("en should be a valid locale")
	}
	if !IsValidLocale(LocaleFr) {
		t.Error("fr should be a valid locale")
	}
	if !IsValidLocale(LocaleKo) {
		t.Error("ko should be a valid locale")
	}
	if IsValidLocale(Locale("xx")) {
		t.Error("xx should be invalid")
	}
	if IsValidLocale(Locale("")) {
		t.Error("empty string should be invalid")
	}
}

func TestManagerSetCurrent(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Valid locale
	err = mgr.SetCurrent(LocaleFr)
	if err != nil {
		t.Fatalf("SetCurrent(fr) failed: %v", err)
	}
	if mgr.GetCurrent() != LocaleFr {
		t.Errorf("GetCurrent() = %s, want fr", mgr.GetCurrent())
	}

	// Another valid locale
	err = mgr.SetCurrent(LocaleJa)
	if err != nil {
		t.Fatalf("SetCurrent(ja) failed: %v", err)
	}
	if mgr.GetCurrent() != LocaleJa {
		t.Errorf("GetCurrent() = %s, want ja", mgr.GetCurrent())
	}

	// Invalid locale
	err = mgr.SetCurrent(Locale("invalid"))
	if err == nil {
		t.Error("expected error for invalid locale in SetCurrent")
	}
}

func TestManagerGetCurrent(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	if mgr.GetCurrent() != DefaultLocale {
		t.Errorf("default GetCurrent() = %s, want %s", mgr.GetCurrent(), DefaultLocale)
	}
}

func TestManagerGetLoadedLocales(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgr.AddTranslation(LocaleEn, "k", "v")
	mgr.AddTranslation(LocaleFr, "k", "v")
	mgr.AddTranslation(LocaleDe, "k", "v")

	locales := mgr.GetLoadedLocales()
	if len(locales) < 3 {
		t.Errorf("expected at least 3 loaded locales, got %d: %v", len(locales), locales)
	}

	// Check all expected locales are present
	found := map[Locale]bool{}
	for _, l := range locales {
		found[l] = true
	}
	for _, expected := range []Locale{LocaleEn, LocaleFr, LocaleDe} {
		if !found[expected] {
			t.Errorf("expected locale %s in GetLoadedLocales()", expected)
		}
	}
}

func TestManagerAddTranslationNewLocale(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Add translation for a locale that doesn't have a bundle yet
	mgr.AddTranslation(LocaleDe, "hello", "Hallo")
	if !mgr.HasLocale(LocaleDe) {
		t.Error("expected De locale to exist after AddTranslation")
	}
	if mgr.TLocale(LocaleDe, "hello") != "Hallo" {
		t.Errorf("expected 'Hallo', got %q", mgr.TLocale(LocaleDe, "hello"))
	}
}

func TestManagerTLocaleWithFallback(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Add English-only key
	mgr.AddTranslation(LocaleEn, "only.en", "English only")
	// Add French bundle with different key
	mgr.AddTranslation(LocaleFr, "fr.key", "Message français")

	// Request "only.en" from French — should fall back to English
	msg := mgr.TLocaleWith(LocaleFr, "only.en", nil)
	if msg != "English only" {
		t.Errorf("expected fallback to English 'English only', got %q", msg)
	}
}

func TestManagerTLocaleWithNilBundle(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Request a key from a locale with no bundle at all — should fallback to key
	msg := mgr.TLocaleWith(LocaleKo, "missing.key", nil)
	if msg != "missing.key" {
		t.Errorf("expected key fallback, got %q", msg)
	}
}

func TestManagerTLocaleWithVars(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	mgr.AddTranslation(LocaleEn, "greet", "Hello, {{.Name}}!")
	msg := mgr.TLocaleWith(LocaleEn, "greet", map[string]interface{}{"Name": "Alice"})
	if msg != "Hello, Alice!" {
		t.Errorf("expected 'Hello, Alice!', got %q", msg)
	}
}

func TestManagerTLocalePlural(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	bundle := mgr.GetBundle(LocaleEn)
	bundle.AddPlural("count", PluralForms{
		PluralOne:   "{{.Count}} item",
		PluralOther: "{{.Count}} items",
	})

	msg := mgr.TLocalePlural(LocaleEn, "count", 1, nil)
	if msg != "1 item" {
		t.Errorf("expected '1 item', got %q", msg)
	}
	msg = mgr.TLocalePlural(LocaleEn, "count", 5, nil)
	if msg != "5 items" {
		t.Errorf("expected '5 items', got %q", msg)
	}
}

func TestManagerTLocalePluralFallback(t *testing.T) {
	mgr, err := NewManager(nil)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Only English has the plural
	bundle := mgr.GetBundle(LocaleEn)
	bundle.AddPlural("items", PluralForms{
		PluralOne:   "1 item",
		PluralOther: "{{.Count}} items",
	})

	// Request from Korean (no bundle) — should fallback to English
	msg := mgr.TLocalePlural(LocaleKo, "items", 1, nil)
	if msg != "1 item" {
		t.Errorf("expected English fallback '1 item', got %q", msg)
	}
}

func TestManagerNewManagerWithOptions(t *testing.T) {
	opts := &ManagerOptions{DefaultLocale: LocaleFr}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatalf("NewManager with options failed: %v", err)
	}
	if mgr.GetDefault() != LocaleFr {
		t.Errorf("expected default locale fr, got %s", mgr.GetDefault())
	}
}

func TestManagerLoadFromDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a valid French locale file
	frData := LocaleFile{
		Locale:   "fr",
		Language: "French",
		Messages: map[string]string{"hi": "Bonjour"},
	}
	frBytes, _ := json.Marshal(frData)
	os.WriteFile(filepath.Join(tmpDir, "fr.json"), frBytes, 0644)

	// Write an invalid locale file (should be skipped)
	os.WriteFile(filepath.Join(tmpDir, "xx.json"), []byte(`{}`), 0644)

	// Write a non-JSON file (should be skipped)
	os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("skip me"), 0644)

	// Create a subdirectory (should be skipped)
	os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)

	mgr, err := NewManager(&ManagerOptions{LocaleDir: tmpDir})
	if err != nil {
		t.Fatalf("NewManager with LocaleDir failed: %v", err)
	}

	msg := mgr.TLocale(LocaleFr, "hi")
	if msg != "Bonjour" {
		t.Errorf("expected 'Bonjour', got %q", msg)
	}
}

func TestManagerLoadFromDirectoryNotExist(t *testing.T) {
	// Non-existent directory should not fail (just a warning)
	mgr, err := NewManager(&ManagerOptions{LocaleDir: "/nonexistent/path"})
	if err != nil {
		t.Fatalf("NewManager with nonexistent LocaleDir should not fail: %v", err)
	}
	if mgr == nil {
		t.Error("expected non-nil manager")
	}
}

func TestBundleLocale(t *testing.T) {
	b := NewBundle(LocaleFr)
	if b.Locale() != LocaleFr {
		t.Errorf("expected locale fr, got %s", b.Locale())
	}
}

func TestBundleKeys(t *testing.T) {
	b := NewBundle(LocaleEn)
	b.Add("a", "1")
	b.Add("b", "2")
	keys := b.Keys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d: %v", len(keys), keys)
	}
	// Keys should contain both "a" and "b"
	found := map[string]bool{}
	for _, k := range keys {
		found[k] = true
	}
	if !found["a"] || !found["b"] {
		t.Errorf("expected keys to contain 'a' and 'b', got %v", keys)
	}
}

func TestBundleMergeNil(t *testing.T) {
	b := NewBundle(LocaleEn)
	b.Add("key", "val")
	b.Merge(nil) // should not panic
	if b.Count() != 1 {
		t.Errorf("expected count 1 after Merge(nil), got %d", b.Count())
	}
}

func TestBundleMissingKeysNil(t *testing.T) {
	b := NewBundle(LocaleEn)
	b.Add("key", "val")
	result := b.MissingKeys(nil)
	if result != nil {
		t.Errorf("expected nil for MissingKeys(nil), got %v", result)
	}
}

func TestBundleGetPluralFallbackToRegular(t *testing.T) {
	b := NewBundle(LocaleEn)
	// Add a regular message (no plural forms)
	b.Add("items", "{{.Count}} items total")
	// GetPlural should fall back to the regular message
	msg := b.GetPlural("items", 5, nil)
	if msg != "5 items total" {
		t.Errorf("expected '5 items total' (fallback to regular), got %q", msg)
	}
}

func TestBundleGetPluralWithVars(t *testing.T) {
	b := NewBundle(LocaleEn)
	b.AddPlural("msg", PluralForms{
		PluralOne:   "{{.Name}} has {{.Count}} item",
		PluralOther: "{{.Name}} has {{.Count}} items",
	})

	msg := b.GetPlural("msg", 1, map[string]interface{}{"Name": "Alice"})
	if msg != "Alice has 1 item" {
		t.Errorf("expected 'Alice has 1 item', got %q", msg)
	}

	msg = b.GetPlural("msg", 5, map[string]interface{}{"Name": "Alice"})
	if msg != "Alice has 5 items" {
		t.Errorf("expected 'Alice has 5 items', got %q", msg)
	}
}

func TestBundleGetPluralMissingKey(t *testing.T) {
	b := NewBundle(LocaleEn)
	msg := b.GetPlural("nonexistent", 5, nil)
	if msg != "nonexistent" {
		t.Errorf("expected key fallback, got %q", msg)
	}
}

func TestDefaultPluralForms(t *testing.T) {
	// Japanese: only "other"
	ja := DefaultPluralForms(LocaleJa)
	if len(ja) != 1 || ja[0] != PluralOther {
		t.Errorf("Japanese: expected [other], got %v", ja)
	}

	// Chinese: only "other"
	zh := DefaultPluralForms(LocaleZh)
	if len(zh) != 1 || zh[0] != PluralOther {
		t.Errorf("Chinese: expected [other], got %v", zh)
	}

	// Korean: only "other"
	ko := DefaultPluralForms(LocaleKo)
	if len(ko) != 1 || ko[0] != PluralOther {
		t.Errorf("Korean: expected [other], got %v", ko)
	}

	// English: "one" and "other"
	en := DefaultPluralForms(LocaleEn)
	if len(en) != 2 {
		t.Errorf("English: expected 2 forms, got %d", len(en))
	}

	// French: "one" and "other"
	fr := DefaultPluralForms(LocaleFr)
	if len(fr) != 2 {
		t.Errorf("French: expected 2 forms, got %d", len(fr))
	}
}

func TestGetPluralRule(t *testing.T) {
	rule := GetPluralRule(LocaleEn)
	if rule == nil {
		t.Fatal("expected non-nil rule for en")
	}
	if rule(1) != PluralOne {
		t.Error("expected PluralOne for en n=1")
	}
	if rule(2) != PluralOther {
		t.Error("expected PluralOther for en n=2")
	}

	// Unknown locale should return germanic rule
	unknownRule := GetPluralRule(Locale("xx"))
	if unknownRule == nil {
		t.Fatal("expected fallback rule for unknown locale")
	}
	if unknownRule(1) != PluralOne {
		t.Error("expected PluralOne for unknown locale n=1 (germanic fallback)")
	}
}

func TestGetPluralFormUnknownLocale(t *testing.T) {
	// Unknown locale should default to germanic rule
	form := GetPluralForm(Locale("xx"), 1)
	if form != PluralOne {
		t.Errorf("expected PluralOne for unknown locale with n=1, got %s", form)
	}
	form = GetPluralForm(Locale("xx"), 2)
	if form != PluralOther {
		t.Errorf("expected PluralOther for unknown locale with n=2, got %s", form)
	}
}

func TestRemainingLocalePluralRules(t *testing.T) {
	// Portuguese (Germanic rule)
	if GetPluralForm(LocalePt, 1) != PluralOne {
		t.Error("pt n=1 should be PluralOne")
	}
	if GetPluralForm(LocalePt, 2) != PluralOther {
		t.Error("pt n=2 should be PluralOther")
	}

	// Arabic (Germanic rule per current impl)
	if GetPluralForm(LocaleAr, 1) != PluralOne {
		t.Error("ar n=1 should be PluralOne")
	}

	// Russian (Germanic rule per current impl)
	if GetPluralForm(LocaleRu, 1) != PluralOne {
		t.Error("ru n=1 should be PluralOne")
	}

	// Hebrew (Germanic rule per current impl)
	if GetPluralForm(LocaleHe, 1) != PluralOne {
		t.Error("he n=1 should be PluralOne")
	}

	// Hindi (Germanic rule per current impl)
	if GetPluralForm(LocaleHi, 1) != PluralOne {
		t.Error("hi n=1 should be PluralOne")
	}

	// Korean (no plural)
	if GetPluralForm(LocaleKo, 1) != PluralOther {
		t.Error("ko n=1 should be PluralOther (no plural)")
	}
	if GetPluralForm(LocaleKo, 5) != PluralOther {
		t.Error("ko n=5 should be PluralOther (no plural)")
	}
}

func TestLoadEmbedded(t *testing.T) {
	locales, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded failed: %v", err)
	}
	if len(locales) != 12 {
		t.Errorf("expected 12 locales, got %d", len(locales))
	}
	for _, locale := range SupportedLocales() {
		if _, ok := locales[locale]; !ok {
			t.Errorf("locale %s not loaded by LoadEmbedded", locale)
		}
	}
}

func TestGetEmbeddedManager(t *testing.T) {
	mgr, err := GetEmbeddedManager()
	if err != nil {
		t.Fatalf("GetEmbeddedManager failed: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if !mgr.HasLocale(LocaleEn) {
		t.Error("expected English locale in embedded manager")
	}
	if !mgr.HasLocale(LocaleFr) {
		t.Error("expected French locale in embedded manager")
	}
}

func TestGetEmbeddedLocaleData(t *testing.T) {
	data, err := GetEmbeddedLocaleData(LocaleEn)
	if err != nil {
		t.Fatalf("GetEmbeddedLocaleData(en) failed: %v", err)
	}

	var lf LocaleFile
	if err := json.Unmarshal(data, &lf); err != nil {
		t.Fatalf("invalid JSON from GetEmbeddedLocaleData: %v", err)
	}
	if lf.Locale != "en" {
		t.Errorf("expected locale 'en', got %q", lf.Locale)
	}
	if len(lf.Messages) == 0 {
		t.Error("expected non-empty messages in English locale")
	}

	// Non-existent locale should return error
	_, err = GetEmbeddedLocaleData(Locale("nonexistent"))
	if err == nil {
		t.Error("expected error for nonexistent locale")
	}
}

func TestListEmbeddedLocales(t *testing.T) {
	locales := ListEmbeddedLocales()
	if len(locales) != 12 {
		t.Errorf("expected 12 embedded locales, got %d", len(locales))
	}
	// Should contain en
	found := false
	for _, l := range locales {
		if l == LocaleEn {
			found = true
		}
	}
	if !found {
		t.Error("expected en in ListEmbeddedLocales")
	}
}

func TestManagerLoadLocaleDataWithPlurals(t *testing.T) {
	mgr, _ := NewManager(nil)
	data := `{
		"locale": "en",
		"language": "English",
		"messages": {"hi": "Hello"},
		"plurals": {
			"items": {"one": "{{.Count}} item", "other": "{{.Count}} items"}
		}
	}`
	err := mgr.LoadLocaleData(LocaleEn, []byte(data))
	if err != nil {
		t.Fatalf("LoadLocaleData with plurals failed: %v", err)
	}

	msg := mgr.TPlural("items", 1, nil)
	if msg != "1 item" {
		t.Errorf("expected '1 item', got %q", msg)
	}
	msg = mgr.TPlural("items", 5, nil)
	if msg != "5 items" {
		t.Errorf("expected '5 items', got %q", msg)
	}
}

func TestManagerTLocaleWithMissingKeyInBothLocales(t *testing.T) {
	mgr, _ := NewManager(nil)
	mgr.AddTranslation(LocaleEn, "en.only", "English only")

	// Key exists in English but not in requested locale (which also has a bundle)
	mgr.AddTranslation(LocaleFr, "fr.only", "French only")

	// Should fall back to English
	msg := mgr.TLocaleWith(LocaleFr, "en.only", nil)
	if msg != "English only" {
		t.Errorf("expected fallback to English, got %q", msg)
	}
}

func TestAllLocaleFilesValid(t *testing.T) {
	for _, locale := range SupportedLocales() {
		t.Run(string(locale), func(t *testing.T) {
			data, err := GetEmbeddedLocaleData(locale)
			if err != nil {
				t.Fatalf("GetEmbeddedLocaleData(%s) failed: %v", locale, err)
			}

			var lf LocaleFile
			if err := json.Unmarshal(data, &lf); err != nil {
				t.Fatalf("Failed to parse locale file %s: %v", locale, err)
			}

			if lf.Locale != string(locale) {
				t.Errorf("locale file has wrong locale: got %q, want %q", lf.Locale, locale)
			}

			if len(lf.Messages) == 0 {
				t.Error("locale file has no messages")
			}
		})
	}
}
