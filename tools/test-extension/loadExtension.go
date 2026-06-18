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
	htmlPath := filepath.Join("testdata", cfg.Provider+".html")
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
	// The simplest approach: prepend a small wrapper that
	// hooks into the detect() function. But the content
	// script is bundled and minified, so we can't easily
	// hook individual functions.
	//
	// Instead, we inject a MutationObserver in the test
	// wrapper that watches the DOM for the warning banner
	// the content script adds. The banner's text content
	// contains the detection descriptions.
	//
	// For now, the test harness uses a simpler approach:
	// the content script is expected to set
	// window.__lens_detections directly. We add a tiny
	// monkey-patch in the wrapper that polls every 50ms
	// and reads the DOM.
	return `
(function() {
  window.__lens_detections = [];
  function scan() {
    const banner = document.getElementById('__aegisgate_lens_banner__');
    if (banner) {
      const items = banner.querySelectorAll('li');
      const dets = [];
      items.forEach(li => {
        const text = li.textContent;
        // Parse the banner's list items. The format is
        // "<category> (<severity>) — match: "<match>""
        // but the actual format depends on the content
        // script. We just record the raw text.
        dets.push({
          category: 'unknown',
          severity: 'unknown',
          match: text,
          start: 0,
          end: 0,
          pattern: 'banner'
        });
      });
      window.__lens_detections = dets;
    } else {
      window.__lens_detections = [];
    }
  }
  setInterval(scan, 50);
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
