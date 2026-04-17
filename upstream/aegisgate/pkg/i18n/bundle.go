// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

package i18n

import (
	"bytes"
	"strings"
	"sync"
	"text/template"
)

// Bundle holds translations for a specific locale
type Bundle struct {
	mu        sync.RWMutex
	locale    Locale
	messages  map[string]string
	templates map[string]*template.Template
	plurals   map[string]PluralForms
}

// NewBundle creates a new translation bundle
func NewBundle(locale Locale) *Bundle {
	return &Bundle{
		locale:    locale,
		messages:  make(map[string]string),
		templates: make(map[string]*template.Template),
		plurals:   make(map[string]PluralForms),
	}
}

// Add adds a translation to the bundle
func (b *Bundle) Add(key, message string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.messages[key] = message

	// Parse template if it contains interpolation markers
	if strings.Contains(message, "{{") {
		tmpl, err := template.New(key).Option("missingkey=zero").Parse(message)
		if err == nil {
			b.templates[key] = tmpl
		}
	}
}

// AddPlural adds plural forms for a key
func (b *Bundle) AddPlural(key string, forms PluralForms) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.plurals[key] = forms

	// Pre-parse templates for each plural form
	for form, msg := range forms {
		if strings.Contains(msg, "{{") {
			tmpl, err := template.New(key + "." + string(form)).Option("missingkey=zero").Parse(msg)
			if err == nil {
				b.templates[key+"."+string(form)] = tmpl
			}
		}
	}
}

// Get retrieves a translation, optionally performing template interpolation
func (b *Bundle) Get(key string, vars map[string]interface{}) string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	msg, exists := b.messages[key]
	if !exists {
		return key // Return key as fallback
	}

	// Check for cached template
	tmpl, hasTemplate := b.templates[key]
	if !hasTemplate {
		return msg
	}

	// Ensure vars is never nil for template execution
	if vars == nil {
		vars = make(map[string]interface{})
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return msg // Return unprocessed message on error
	}

	return buf.String()
}

// GetPlural retrieves the appropriate plural form based on count
func (b *Bundle) GetPlural(key string, count int, vars map[string]interface{}) string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Ensure vars map exists and has count
	if vars == nil {
		vars = make(map[string]interface{})
	} else {
		// Copy vars to avoid modifying the original
		newVars := make(map[string]interface{})
		for k, v := range vars {
			newVars[k] = v
		}
		vars = newVars
	}
	vars["Count"] = count
	vars["count"] = count

	// Try to find plural forms
	forms, hasPlural := b.plurals[key]
	if hasPlural {
		form := GetPluralForm(b.locale, count)
		if msg, exists := forms[form]; exists {
			// Perform interpolation on the plural message
			templateKey := key + "." + string(form)
			if tmpl, hasTemplate := b.templates[templateKey]; hasTemplate {
				var buf bytes.Buffer
				if err := tmpl.Execute(&buf, vars); err == nil {
					return buf.String()
				}
			}
			// Try to parse inline if not pre-parsed
			if strings.Contains(msg, "{{") {
				tmpl, err := template.New(templateKey).Option("missingkey=zero").Parse(msg)
				if err == nil {
					var buf bytes.Buffer
					if err := tmpl.Execute(&buf, vars); err == nil {
						return buf.String()
					}
				}
			}
			return msg
		}
	}

	// Fallback to regular message with interpolation
	msg, exists := b.messages[key]
	if !exists {
		return key
	}

	if tmpl, hasTemplate := b.templates[key]; hasTemplate {
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, vars); err == nil {
			return buf.String()
		}
	}

	return msg
}

// Has checks if a key exists in the bundle
func (b *Bundle) Has(key string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, exists := b.messages[key]
	return exists
}

// Count returns the number of translations in the bundle
func (b *Bundle) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.messages)
}

// Locale returns the bundle's locale
func (b *Bundle) Locale() Locale {
	return b.locale
}

// Keys returns all translation keys in the bundle
func (b *Bundle) Keys() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	keys := make([]string, 0, len(b.messages))
	for key := range b.messages {
		keys = append(keys, key)
	}
	return keys
}

// Merge merges translations from another bundle, overwriting existing keys
func (b *Bundle) Merge(other *Bundle) {
	if other == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	other.mu.RLock()
	defer other.mu.RUnlock()

	for key, msg := range other.messages {
		b.messages[key] = msg
	}

	for key, tmpl := range other.templates {
		b.templates[key] = tmpl
	}

	for key, forms := range other.plurals {
		b.plurals[key] = forms
	}
}

// Clone creates a deep copy of the bundle
func (b *Bundle) Clone() *Bundle {
	b.mu.RLock()
	defer b.mu.RUnlock()

	clone := NewBundle(b.locale)

	for key, msg := range b.messages {
		clone.messages[key] = msg
	}

	for key, tmpl := range b.templates {
		clone.templates[key] = tmpl
	}

	for key, forms := range b.plurals {
		clone.plurals[key] = forms
	}

	return clone
}

// Export exports the bundle to a LocaleFile structure
func (b *Bundle) Export() *LocaleFile {
	b.mu.RLock()
	defer b.mu.RUnlock()

	lf := &LocaleFile{
		Locale:   string(b.locale),
		Messages: make(map[string]string),
		Plurals:  make(map[string]PluralForms),
	}

	for key, msg := range b.messages {
		lf.Messages[key] = msg
	}

	for key, forms := range b.plurals {
		lf.Plurals[key] = forms
	}

	return lf
}

// MissingKeys returns keys that are in the reference bundle but missing from this bundle
func (b *Bundle) MissingKeys(reference *Bundle) []string {
	if reference == nil {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	reference.mu.RLock()
	defer reference.mu.RUnlock()

	var missing []string
	for key := range reference.messages {
		if _, exists := b.messages[key]; !exists {
			missing = append(missing, key)
		}
	}

	return missing
}
