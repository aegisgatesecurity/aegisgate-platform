// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Manual Test Tool: Provider Map
// =========================================================================
//
// providers.go maps a provider name (--provider=<name>) to
// (URL, CSS selector for the prompt textarea). The map covers
// the v0.1 providers plus Duck.ai as a $0-budget alternative
// for manual testing.
//
// v0.1 NOTE: Duck.ai is added to the manual-test tool ONLY.
// It is NOT yet in the Lens extension's content script
// provider allowlist. To run this test against Duck.ai in a
// real browser, you must also add Duck.ai to the Lens's
// content.ts provider list (a 5-line change). We do that
// change after this manual test confirms the Lens works
// end-to-end on a real page.
// =========================================================================

package main

// providerInfo describes one AI provider for testing purposes.
type providerInfo struct {
	URL             string // page to navigate to
	PromptSelector  string // CSS selector for the prompt input
	RequiresAccount bool   // true for ChatGPT/Claude/Gemini/Copilot
}

// providerMap maps provider names (as passed to --provider)
// to their test info.
//
// v0.1: only "duck" works without an account. The other
// providers are listed for documentation; running them
// requires a login session in Chrome.
var providerMap = map[string]providerInfo{
	"duck": {
		URL:             "https://duckduckgo.com/?q=DuckDuckGo+AI+Chat&ia=chat",
		PromptSelector:  "textarea[id*='user-input'], div[contenteditable='true']",
		RequiresAccount: false,
	},
	"chatgpt": {
		URL:             "https://chat.openai.com/",
		PromptSelector:  "#prompt-textarea",
		RequiresAccount: true,
	},
	"claude": {
		URL:             "https://claude.ai/",
		PromptSelector:  "div[contenteditable='true']",
		RequiresAccount: true,
	},
	"gemini": {
		URL:             "https://gemini.google.com/",
		PromptSelector:  "div[contenteditable='true'], rich-textarea",
		RequiresAccount: true,
	},
	"copilot": {
		URL:             "https://copilot.microsoft.com/",
		PromptSelector:  "#userInput, textarea",
		RequiresAccount: true,
	},
}

// providerURLFor returns the URL for a provider, or an empty
// string if the provider is unknown.
func providerURLFor(name string) string {
	if p, ok := providerMap[name]; ok {
		return p.URL
	}
	return ""
}

// promptSelectorFor returns the CSS selector for a provider,
// or a fallback if unknown.
func promptSelectorFor(name string) string {
	if p, ok := providerMap[name]; ok {
		return p.PromptSelector
	}
	// Fallback: try textarea first, then contenteditable.
	return "textarea, div[contenteditable='true']"
}

// requiresAccountFor returns true if the provider needs
// the user to be logged in.
func requiresAccountFor(name string) bool {
	if p, ok := providerMap[name]; ok {
		return p.RequiresAccount
	}
	return false
}
