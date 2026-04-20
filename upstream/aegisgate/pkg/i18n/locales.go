// SPDX-License-Identifier: MIT
// =========================================================================
// =========================================================================
//
// =========================================================================

// Package i18n provides internationalization support for AegisGate.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed locales/*.json
var embeddedLocales embed.FS

// LoadEmbedded loads all embedded locale files
func LoadEmbedded() (map[Locale]*LocaleFile, error) {
	locales := make(map[Locale]*LocaleFile)

	localeFiles := []struct {
		locale Locale
		path   string
	}{
		{LocaleEn, "locales/en.json"},
		{LocaleFr, "locales/fr.json"},
		{LocaleDe, "locales/de.json"},
		{LocaleEs, "locales/es.json"},
		{LocaleJa, "locales/ja.json"},
		{LocaleZh, "locales/zh.json"},
	}

	for _, lf := range localeFiles {
		data, err := embeddedLocales.ReadFile(lf.path)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded locale %s: %w", lf.locale, err)
		}

		var localeFile LocaleFile
		if err := json.Unmarshal(data, &localeFile); err != nil {
			return nil, fmt.Errorf("failed to parse embedded locale %s: %w", lf.locale, err)
		}

		locales[lf.locale] = &localeFile
	}

	return locales, nil
}

// GetEmbeddedManager creates a manager pre-loaded with embedded locales
func GetEmbeddedManager() (*Manager, error) {
	mgr, err := NewManager(nil)
	if err != nil {
		return nil, err
	}

	locales, err := LoadEmbedded()
	if err != nil {
		return nil, err
	}

	for locale, localeFile := range locales {
		data, err := json.Marshal(localeFile)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal locale %s: %w", locale, err)
		}
		if err := mgr.LoadLocaleData(locale, data); err != nil {
			return nil, fmt.Errorf("failed to load locale %s: %w", locale, err)
		}
	}

	return mgr, nil
}

// GetEmbeddedLocaleData returns the raw JSON data for a specific locale
func GetEmbeddedLocaleData(locale Locale) ([]byte, error) {
	path := fmt.Sprintf("locales/%s.json", locale)
	data, err := embeddedLocales.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("locale %s not found in embedded data: %w", locale, err)
	}
	return data, nil
}

// ListEmbeddedLocales returns a list of all embedded locales
func ListEmbeddedLocales() []Locale {
	return []Locale{LocaleEn, LocaleFr, LocaleDe, LocaleEs, LocaleJa, LocaleZh, LocaleAr, LocaleRu, LocaleHe, LocaleHi, LocalePt, LocaleKo}
}
