// Package i18n provides internationalization support for AegisGuard.
package i18n

// PluralForm represents a plural category (one, few, many, other)
type PluralForm string

// Standard CLDR plural forms
const (
	PluralOne   PluralForm = "one"
	PluralTwo   PluralForm = "two"
	PluralFew   PluralForm = "few"
	PluralMany  PluralForm = "many"
	PluralOther PluralForm = "other"
)

// PluralForms maps plural categories to their translations
type PluralForms map[PluralForm]string

// pluralRule is a function that determines the plural form for a count
type pluralRule func(n int) PluralForm

// pluralRules maps locales to their plural rules
// Based on CLDR plural rules
var pluralRules = map[Locale]pluralRule{
	// English, German, Spanish, etc. - 2 forms
	LocaleEn: germanicPluralRule,
	LocaleDe: germanicPluralRule,
	LocaleEs: germanicPluralRule,

	// French - 2 forms (slightly different)
	LocaleFr: frenchPluralRule,

	// Japanese, Chinese - 1 form (no plural distinction)
	LocaleJa: noPluralRule,
	LocaleZh: noPluralRule,
	LocalePt: germanicPluralRule,
	LocaleKo: noPluralRule,
	LocaleAr: germanicPluralRule,
	LocaleRu: germanicPluralRule,
	LocaleHe: germanicPluralRule,
	LocaleHi: germanicPluralRule,
}

// germanicPluralRule handles English, German, Spanish plural rules
func germanicPluralRule(n int) PluralForm {
	if n == 1 {
		return PluralOne
	}
	return PluralOther
}

// frenchPluralRule handles French plural rules
func frenchPluralRule(n int) PluralForm {
	if n == 0 || n == 1 {
		return PluralOne
	}
	return PluralOther
}

// noPluralRule handles languages without plural distinction
func noPluralRule(n int) PluralForm {
	return PluralOther
}

// GetPluralForm returns the plural form for a locale and count
func GetPluralForm(locale Locale, count int) PluralForm {
	rule, exists := pluralRules[locale]
	if !exists {
		return germanicPluralRule(count)
	}
	return rule(count)
}

// GetPluralRule returns the plural rule function for a locale
func GetPluralRule(locale Locale) pluralRule {
	rule, exists := pluralRules[locale]
	if !exists {
		return germanicPluralRule
	}
	return rule
}

// RegisterPluralRule allows registering custom plural rules for additional locales
func RegisterPluralRule(locale Locale, rule pluralRule) {
	pluralRules[locale] = rule
}

// DefaultPluralForms returns the default plural forms for a locale
func DefaultPluralForms(locale Locale) []PluralForm {
	switch locale {
	case LocaleJa, LocaleZh, LocaleKo:
		return []PluralForm{PluralOther}
	default:
		return []PluralForm{PluralOne, PluralOther}
	}
}

// FormatPlural creates a PluralForms map from one and other forms
func FormatPlural(one, other string) PluralForms {
	return PluralForms{
		PluralOne:   one,
		PluralOther: other,
	}
}
