// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Extension Loader
// =========================================================================
//
// loadExtension.go loads the extension's content script into
// the page. Because we can't easily run an actual Chrome
// extension in headless mode (the --load-extension flag
// works but the extension's manifest validation can be
// flaky in headless), we use a different approach:
//
//   1. Read the bundled content.js from the dist/ directory.
//   2. Use Page.addScriptToEvaluateOnNewDocument to inject
//      the content script on every navigation.
//   3. The content script exposes its detection state via
//      a window global (window.__lens_detections).
//
// This is a test-only injection mechanism. The production
// extension is loaded by Chrome via the manifest.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// loadExtension reads the content script from the dist/
// directory and registers it for evaluation on every new
// document via Page.addScriptToEvaluateOnNewDocument.
func loadExtension(cdp *devtoolsClient, cfg *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	// Read the content script.
	script, err := os.ReadFile(filepath.Join(cfg.Dist, "content.js")) // #nosec G304 -- dist is a developer CLI arg, content.js is a hardcoded path
	if err != nil {
		return fmt.Errorf("read content.js: %w", err)
	}
	// Wrap the script to expose its detection state. The
	// content script defines detect() and observeDOM(), but
	// the test harness needs a way to read the current
	// detections. We patch the script to write its results
	// to window.__lens_detections.
	wrapped := wrapScriptForTest(string(script))
	// Register the script to be evaluated on every new
	// document.
	if err := cdp.addScriptToEvaluateOnNewDocument(ctx, wrapped); err != nil {
		return fmt.Errorf("addScriptToEvaluateOnNewDocument: %w", err)
	}
	// Enable the Page domain.
	if err := cdp.enable(ctx, "Page"); err != nil {
		return fmt.Errorf("enable Page: %w", err)
	}
	// Enable the Runtime domain.
	if err := cdp.enable(ctx, "Runtime"); err != nil {
		return fmt.Errorf("enable Runtime: %w", err)
	}
	// Navigate to the mock AI provider page.
	htmlPath := filepath.Join(cfg.TestdataDir, cfg.Provider+".html")
	htmlURL, err := fileURL(htmlPath)
	if err != nil {
		return fmt.Errorf("build file URL: %w", err)
	}
	if err := cdp.navigate(ctx, htmlURL); err != nil {
		return fmt.Errorf("navigate: %w", err)
	}
	// Wait for the page to finish loading.
	if _, err := cdp.waitForEvent(ctx, "Page.loadEventFired"); err != nil {
		return fmt.Errorf("wait for Page.loadEventFired: %w", err)
	}
	return nil
}

// wrapScriptForTest takes the bundled content script and
// patches it to expose its detection state. The content
// script is a self-contained IIFE; we wrap it to install a
// getter on window.__lens_detections that returns the
// current detections array.
func wrapScriptForTest(script string) string {
	// The content script stores its detections in
	// `this.currentDetections` (a class field), which is
	// not accessible from the global scope. We work
	// around this by scraping the DOM: the content script
	// adds a banner with <li> elements, each containing
	// text of the form:
	//   "Email address (high) — match: \"john.doe@example.com\""
	//
	// The test wrapper installs a MutationObserver that
	// scrapes the banner and parses the text into a
	// structured detections array.
	//
	// The category-to-slug mapping is also handled here
	// (e.g., "Email address" -> "pii_email") to match the
	// expected JSON values in the test corpus.
	//
	// We also set a __lens_test_pending counter that the
	// harness can poll to detect when the content script
	// has processed the input event. This avoids the
	// 50ms-poll race condition.
	return `
(function() {
  // category-from-display-name lookup. The content
  // script's describeCategory() returns the human-readable
  // names; we map them back to the wire-format slugs.
  const categoryFromDisplay = {
    'Email address': 'pii_email',
    'Phone number': 'pii_phone',
    'Social Security number': 'pii_ssn',
    'Credit card number': 'pii_credit_card',
    'API key or token': 'secret_api_key',
    'Source code (private key)': 'source_code'
  };
  window.__lens_detections = [];
  window.__lens_test_input_count = 0;
  window.__lens_test_scan_count = 0;
  function scan() {
    window.__lens_test_scan_count++;
    const banner = document.getElementById('__aegisgate_lens_banner__');
    if (!banner) {
      window.__lens_detections = [];
      return;
    }
    const items = banner.querySelectorAll('li');
    const dets = [];
    items.forEach(li => {
      const text = li.textContent;
      // Format: "Category (severity) — match: \"MATCH\""
      // Use a regex to parse. The em-dash is U+2014.
      const m = text.match(/^(.+?) \(([^)]+)\) — match: "(.+)"$/);
      if (!m) {
        console.warn('[lens-test] failed to parse banner item:', JSON.stringify(text));
        return;
      }
      const displayCat = m[1];
      const sev = m[2];
      const match = m[3];
      const cat = categoryFromDisplay[displayCat] || 'unknown';
      dets.push({
        category: cat,
        severity: sev,
        match: match,
        start: 0,
        end: 0,
        pattern: 'banner'
      });
    });
    window.__lens_detections = dets;
  }
  // Use a MutationObserver for the banner's children so
  // we react immediately to new detections, not on a
  // 50ms poll. Falls back to setInterval if MutationObserver
  // is unavailable (very old browsers).
  const target = document.body;
  if (typeof MutationObserver !== 'undefined') {
    const obs = new MutationObserver(scan);
    obs.observe(target, { childList: true, subtree: true });
  } else {
    setInterval(scan, 50);
  }
  // Also poll at 50ms for the case where the content
  // script mutates the banner's textContent without
  // adding/removing children.
  setInterval(scan, 50);
  // Hook the input event listener to count input events
  // and trigger a scan after the content script has
  // run. The content script's listener runs synchronously
  // on 'input'; we add our listener with capture phase
  // false (default) so we run AFTER the content script.
  document.addEventListener('input', function(e) {
    window.__lens_test_input_count++;
    // The content script's handler has already run
    // synchronously by the time we get here. Scan
    // immediately to capture the new detections.
    setTimeout(scan, 0);
  }, false);
})();
` + script
}

// fileURL converts a relative file path to a file:// URL.
func fileURL(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	u := &url.URL{Scheme: "file", Path: abs}
	return u.String(), nil
}
