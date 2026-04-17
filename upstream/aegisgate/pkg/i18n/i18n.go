// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package i18n provides internationalization support for AegisGate.
// It implements a zero-dependency localization system with support for
// multiple locales, template interpolation, and plural forms.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Locale represents a language code (e.g., "en", "fr", "de")
type Locale string

// Supported locales
const (
	LocaleEn Locale = "en" // English (base)
	LocaleFr Locale = "fr" // French
	LocaleDe Locale = "de" // German
	LocaleEs Locale = "es" // Spanish
	LocaleJa Locale = "ja" // Japanese
	LocaleZh Locale = "zh" // Chinese (Simplified)
	LocaleAr Locale = "ar" // Arabic
	LocaleRu Locale = "ru" // Russian
	LocaleHe Locale = "he" // Hebrew
	LocaleHi Locale = "hi" // Hindi
	LocalePt Locale = "pt" // Portuguese
	LocaleKo Locale = "ko" // Korean
)

// DefaultLocale is the fallback locale when translations are missing
const DefaultLocale = LocaleEn

// SupportedLocales returns all supported locales
func SupportedLocales() []Locale {
	return []Locale{LocaleEn, LocaleFr, LocaleDe, LocaleEs, LocaleJa, LocaleZh, LocaleAr, LocaleRu, LocaleHe, LocaleHi, LocalePt, LocaleKo}
}

// IsValidLocale checks if a locale is supported
func IsValidLocale(locale Locale) bool {
	for _, l := range SupportedLocales() {
		if l == locale {
			return true
		}
	}
	return false
}

// ParseLocale parses a string into a Locale, returning DefaultLocale if invalid
func ParseLocale(s string) Locale {
	locale := Locale(strings.ToLower(strings.TrimSpace(s)))
	if IsValidLocale(locale) {
		return locale
	}
	return DefaultLocale
}

// MessageKey is a type alias for translation message keys
type MessageKey string

// Common message key prefixes for namespacing
const (
	KeyError  MessageKey = "error."
	KeyHTTP   MessageKey = "http."
	KeyLog    MessageKey = "log."
	KeyHealth MessageKey = "health."
	KeyConfig MessageKey = "config."
)

// Translation represents a single translation entry
type Translation struct {
	Key      string                 `json:"key"`
	Message  string                 `json:"message"`
	Plurals  map[string]string      `json:"plurals,omitempty"` // "one", "other", etc.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// LocaleFile represents the structure of a locale JSON file
type LocaleFile struct {
	Locale    string                 `json:"locale"`
	Language  string                 `json:"language"`
	Messages  map[string]string      `json:"messages"`
	Plurals   map[string]PluralForms `json:"plurals,omitempty"`
	Copyright string                 `json:"copyright,omitempty"`
}

// Manager coordinates multiple locale bundles and provides the main API
type Manager struct {
	mu            sync.RWMutex
	defaultLocale Locale
	currentLocale Locale
	bundles       map[Locale]*Bundle
	embedded      embed.FS
	fallback      *Bundle // English fallback bundle
}

// ManagerOptions configures the i18n manager
type ManagerOptions struct {
	DefaultLocale Locale
	LocaleDir     string // Directory containing locale JSON files
	EmbeddedFS    embed.FS
}

// NewManager creates a new i18n manager
func NewManager(opts *ManagerOptions) (*Manager, error) {
	if opts == nil {
		opts = &ManagerOptions{
			DefaultLocale: DefaultLocale,
		}
	}

	mgr := &Manager{
		defaultLocale: opts.DefaultLocale,
		currentLocale: opts.DefaultLocale,
		bundles:       make(map[Locale]*Bundle),
	}

	// Load embedded locales if provided
	if opts.EmbeddedFS != (embed.FS{}) {
		mgr.embedded = opts.EmbeddedFS
		if err := mgr.loadEmbedded(); err != nil {
			return nil, fmt.Errorf("failed to load embedded locales: %w", err)
		}
	}

	// Load external locales if directory provided
	if opts.LocaleDir != "" {
		if err := mgr.loadFromDirectory(opts.LocaleDir); err != nil {
			// Non-fatal: embedded locales may already be loaded
			fmt.Fprintf(os.Stderr, "Warning: failed to load external locales: %v\n", err)
		}
	}

	// Ensure we have at least the default locale
	if _, exists := mgr.bundles[mgr.defaultLocale]; !exists {
		// Create empty bundle for default locale
		mgr.bundles[mgr.defaultLocale] = NewBundle(mgr.defaultLocale)
	}

	// Set fallback to English
	if bundle, exists := mgr.bundles[LocaleEn]; exists {
		mgr.fallback = bundle
	} else {
		mgr.fallback = NewBundle(LocaleEn)
		mgr.bundles[LocaleEn] = mgr.fallback
	}

	return mgr, nil
}

// loadEmbedded loads locale files from the embedded filesystem
func (m *Manager) loadEmbedded() error {
	// This will be populated by the embed directive in locales.go
	return nil
}

// loadFromDirectory loads locale files from an external directory
func (m *Manager) loadFromDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read locale directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}

		// Extract locale from filename (e.g., "en.json" -> "en")
		localeStr := strings.TrimSuffix(name, ".json")
		locale := ParseLocale(localeStr)
		if !IsValidLocale(locale) {
			continue
		}

		filePath := filepath.Join(dir, name)
		if err := m.LoadLocaleFile(locale, filePath); err != nil {
			return fmt.Errorf("failed to load locale %s: %w", locale, err)
		}
	}

	return nil
}

// LoadLocaleFile loads a locale from a JSON file
func (m *Manager) LoadLocaleFile(locale Locale, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read locale file: %w", err)
	}

	return m.LoadLocaleData(locale, data)
}

// LoadLocaleData loads a locale from JSON data
func (m *Manager) LoadLocaleData(locale Locale, data []byte) error {
	var localeFile LocaleFile
	if err := json.Unmarshal(data, &localeFile); err != nil {
		return fmt.Errorf("failed to parse locale data: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	bundle, exists := m.bundles[locale]
	if !exists {
		bundle = NewBundle(locale)
		m.bundles[locale] = bundle
	}

	// Load messages
	for key, msg := range localeFile.Messages {
		bundle.Add(key, msg)
	}

	// Load plurals
	for key, forms := range localeFile.Plurals {
		bundle.AddPlural(key, forms)
	}

	return nil
}

// SetDefault sets the default locale
func (m *Manager) SetDefault(locale Locale) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !IsValidLocale(locale) {
		return fmt.Errorf("invalid locale: %s", locale)
	}

	m.defaultLocale = locale
	m.currentLocale = locale
	return nil
}

// SetCurrent sets the current locale (can be changed at runtime)
func (m *Manager) SetCurrent(locale Locale) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !IsValidLocale(locale) {
		return fmt.Errorf("invalid locale: %s", locale)
	}

	m.currentLocale = locale
	return nil
}

// GetDefault returns the default locale
func (m *Manager) GetDefault() Locale {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultLocale
}

// GetCurrent returns the current locale
func (m *Manager) GetCurrent() Locale {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentLocale
}

// T translates a message key using the current locale
func (m *Manager) T(key string) string {
	return m.TLocale(m.currentLocale, key)
}

// TWith translates a message key with template variables
func (m *Manager) TWith(key string, vars map[string]interface{}) string {
	return m.TLocaleWith(m.currentLocale, key, vars)
}

// TLocale translates a message key for a specific locale
func (m *Manager) TLocale(locale Locale, key string) string {
	return m.TLocaleWith(locale, key, nil)
}

// TLocaleWith translates a message key for a specific locale with template variables
func (m *Manager) TLocaleWith(locale Locale, key string, vars map[string]interface{}) string {
	m.mu.RLock()
	bundle, exists := m.bundles[locale]
	m.mu.RUnlock()

	if !exists || bundle == nil {
		// Fallback to English
		if m.fallback != nil {
			return m.fallback.Get(key, vars)
		}
		return key
	}

	msg := bundle.Get(key, vars)
	if msg == key && m.fallback != nil && locale != LocaleEn {
		// Try English fallback
		return m.fallback.Get(key, vars)
	}

	return msg
}

// TPlural translates a plural form based on count
func (m *Manager) TPlural(key string, count int, vars map[string]interface{}) string {
	return m.TLocalePlural(m.currentLocale, key, count, vars)
}

// TLocalePlural translates a plural form for a specific locale
func (m *Manager) TLocalePlural(locale Locale, key string, count int, vars map[string]interface{}) string {
	m.mu.RLock()
	bundle, exists := m.bundles[locale]
	m.mu.RUnlock()

	if !exists || bundle == nil {
		if m.fallback != nil {
			return m.fallback.GetPlural(key, count, vars)
		}
		return key
	}

	msg := bundle.GetPlural(key, count, vars)
	if msg == key && m.fallback != nil && locale != LocaleEn {
		return m.fallback.GetPlural(key, count, vars)
	}

	return msg
}

// HasLocale checks if a locale is loaded
func (m *Manager) HasLocale(locale Locale) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.bundles[locale]
	return exists
}

// GetLoadedLocales returns all loaded locales
func (m *Manager) GetLoadedLocales() []Locale {
	m.mu.RLock()
	defer m.mu.RUnlock()

	locales := make([]Locale, 0, len(m.bundles))
	for locale := range m.bundles {
		locales = append(locales, locale)
	}
	return locales
}

// GetBundle returns the bundle for a locale
func (m *Manager) GetBundle(locale Locale) *Bundle {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bundles[locale]
}

// AddTranslation adds a translation at runtime
func (m *Manager) AddTranslation(locale Locale, key, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bundle, exists := m.bundles[locale]
	if !exists {
		bundle = NewBundle(locale)
		m.bundles[locale] = bundle
	}

	bundle.Add(key, message)
}

// Stats returns statistics about loaded translations
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	loadedLocales := make([]string, 0)
	messageCounts := make(map[string]int)

	for locale, bundle := range m.bundles {
		loadedLocales = append(loadedLocales, string(locale))
		messageCounts[string(locale)] = bundle.Count()
	}

	stats := map[string]interface{}{
		"default_locale": string(m.defaultLocale),
		"current_locale": string(m.currentLocale),
		"loaded_locales": loadedLocales,
		"message_counts": messageCounts,
	}

	return stats
}
