// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - i18n (Internationalization)
// =========================================================================
//
// Package i18n provides internationalization support for AegisGate.
// It implements a zero-dependency localization system with support for
// 12 locales, template interpolation, and plural forms.
//
// # Supported Locales
//
// English (en), French (fr), German (de), Spanish (es), Japanese (ja),
// Korean (ko), Portuguese (pt-br), Chinese Simplified (zh-cn),
// Chinese Traditional (zh-tw), Arabic (ar), Hindi (hi), and Hebrew (he).
//
// # Usage
//
// Load a locale and resolve translation keys:
//
//	bundle := i18n.NewBundle()
//	bundle.LoadLocale("en")   // loads embedded locale data
//	msg := bundle.Resolve("en", "compliance.violation", map[string]string{
//	    "framework": "HIPAA",
//	    "control":   "AC-1",
//	})
package i18n
