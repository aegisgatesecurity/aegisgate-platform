// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// =========================================================================
//
// =========================================================================

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
// Based on CLDR plural rules: https://unicode-org.github.io/cldr-staging/charts/37/supplemental/language_plural_rules.html
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
	LocaleAr: arabicPluralRule,
	LocaleRu: russianPluralRule,
	LocaleHe: hebrewPluralRule,
	LocaleHi: hindiPluralRule,
}

// germanicPluralRule handles English, German, Spanish plural rules
// one: 1
// other: 0, 2, 3, 4, ...
func germanicPluralRule(n int) PluralForm {
	if n == 1 {
		return PluralOne
	}
	return PluralOther
}

// frenchPluralRule handles French plural rules
// one: 0, 1
// other: 2, 3, 4, ...
func frenchPluralRule(n int) PluralForm {
	if n == 0 || n == 1 {
		return PluralOne
	}
	return PluralOther
}

// noPluralRule handles languages without plural distinction (Japanese, Chinese, etc.)
// other: all counts
func noPluralRule(n int) PluralForm {
	return PluralOther
}

// arabicPluralRule handles Arabic plural rules (CLDR).
// Arabic has 6 plural forms: zero, one, two, few, many, other.
//
//	zero: n == 0
//	one:  n == 1
//	two:  n == 2
//	few:  n % 100 in 3..10
//	many: n % 100 in 11..99
//	other: everything else (fractions, etc.)
func arabicPluralRule(n int) PluralForm {
	mod100 := n % 100
	switch {
	case n == 0:
		return PluralOther // Arabic "zero" — we map to other for simplicity
	case n == 1:
		return PluralOne
	case n == 2:
		return PluralTwo
	case mod100 >= 3 && mod100 <= 10:
		return PluralFew
	case mod100 >= 11 && mod100 <= 99:
		return PluralMany
	default:
		return PluralOther
	}
}

// russianPluralRule handles Russian plural rules (CLDR).
// Russian has 3 forms: one, few, many.
//
//	one:  n % 10 == 1 && n % 100 != 11
//	few:  n % 10 in 2..4 && n % 100 not in 12..14
//	many: everything else
func russianPluralRule(n int) PluralForm {
	mod10 := n % 10
	mod100 := n % 100
	switch {
	case mod10 == 1 && mod100 != 11:
		return PluralOne
	case mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14):
		return PluralFew
	default:
		return PluralMany
	}
}

// hebrewPluralRule handles Hebrew plural rules (CLDR).
// Hebrew has 4 forms: one, two, many, other.
//
//	one:   n == 1
//	two:   n == 2
//	many:  n in 3..10 || n % 10 == 0
//	other: everything else
func hebrewPluralRule(n int) PluralForm {
	mod10 := n % 10
	switch {
	case n == 1:
		return PluralOne
	case n == 2:
		return PluralTwo
	case (n >= 3 && n <= 10) || mod10 == 0:
		return PluralMany
	default:
		return PluralOther
	}
}

// hindiPluralRule handles Hindi plural rules (CLDR).
// Hindi has 2 forms: one, other (same as Germanic but with different
// boundary — Hindi uses 0..1 as "one").
//
//	one:   n == 0 || n == 1
//	other: n >= 2
func hindiPluralRule(n int) PluralForm {
	if n == 0 || n == 1 {
		return PluralOne
	}
	return PluralOther
}

// GetPluralForm returns the plural form for a locale and count
func GetPluralForm(locale Locale, count int) PluralForm {
	rule, exists := pluralRules[locale]
	if !exists {
		// Default to Germanic/English rule
		rule = germanicPluralRule
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
	case LocaleAr:
		return []PluralForm{PluralOne, PluralTwo, PluralFew, PluralMany, PluralOther}
	case LocaleRu:
		return []PluralForm{PluralOne, PluralFew, PluralMany}
	case LocaleHe:
		return []PluralForm{PluralOne, PluralTwo, PluralMany, PluralOther}
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

// FormatPluralFew creates a PluralForms map with one, few, and other forms
func FormatPluralFew(one, few, other string) PluralForms {
	return PluralForms{
		PluralOne:   one,
		PluralFew:   few,
		PluralOther: other,
	}
}

// FormatPluralFull creates a PluralForms map with all standard forms
func FormatPluralFull(one, two, few, many, other string) PluralForms {
	return PluralForms{
		PluralOne:   one,
		PluralTwo:   two,
		PluralFew:   few,
		PluralMany:  many,
		PluralOther: other,
	}
}
