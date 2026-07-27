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
