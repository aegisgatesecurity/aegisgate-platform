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
	"strings"
)

// loadExtension reads the content script from the dist/
// directory and registers it for evaluation on every new
// document via Page.addScriptToEvaluateOnNewDocument.
//
// v3.5.1+ (Bug C follow-up): also reads util/*.js so that
// the dist's banner-ui, model-loader, bundle-loader etc. are
// loaded in the test page. Without this, the content script's
// NS.util.bannerUI is undefined and the banner never renders,
// leaving the test wrapper's __lens_detections at [] even when
// detections exist.
func loadExtension(cdp *devtoolsClient, cfg *Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	// Read the content script.
	script, err := os.ReadFile(filepath.Join(cfg.Dist, "content.js")) // #nosec G304 G703 -- dist is a developer CLI arg, content.js is a hardcoded path
	if err != nil {
		return fmt.Errorf("read content.js: %w", err)
	}
	// Read util/*.js files. They register IIFEs that attach
	// to window.AegisGateLens (banner-ui, model-loader, etc.).
	// These must run BEFORE content.js so the content script
	// can find NS.util.bannerUI when it tries to showBanner().
	utilScripts, err := readUtilScripts(cfg.Dist)
	if err != nil {
		// Soft-fail: if util dir is missing, run without it.
		// The test will still execute but banner-rendering code
		// paths will be skipped.
		utilScripts = ""
	}
	fullScript := utilScripts + string(script)
	// Wrap the script to expose its detection state. The
	// content script defines detect() and observeDOM(), but
	// the test harness needs a way to read the current
	// detections. We patch the script to write its results
	// to window.__lens_detections.
	wrapped := wrapScriptForTest(fullScript)
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
	htmlPath := filepath.Join(cfg.TestdataDir, cfg.Provider+".html") // #nosec G703 -- testdataDir is a developer CLI arg
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
  window.__lens_test_wrapper_loaded = true;
  // Test-mode flag: disable the dist's input-throttle so back-to-back
  // test events don't get coalesced.
  window.__lens_test_no_throttle = true;
  window.__lens_detections = [];
  function scan() {
    window.__lens_test_scan_count++;
    const banner = document.getElementById('__aegisgate_lens_banner__');
    if (!banner) {
      // No banner: clear stale data so the Go test reads an empty array.
      // The dist's showBanner hook wrote the latest detection data when
      // the banner existed. If it's gone, no current detection.
      window.__lens_detections = [];
      return;
    }
    // Banner exists: the dist's direct hook (set up in content.js)
    // has already written authoritative detection data to
    // window.__lens_detections. Do NOT overwrite with the banner's
    // <li> text — the banner shows masked matches and the timing
    // would race the direct hook.
  }
  // Use a MutationObserver for the banner's children so
  // we react immediately to new detections, not on a
  // 50ms poll. Falls back to setInterval if MutationObserver
  // is unavailable (very old browsers).
  // Use document.documentElement (always exists) instead of
  // document.body (may not exist at script-evaluation time).
  const target = document.documentElement || document.body;
  if (target && typeof MutationObserver !== 'undefined') {
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
    // Don't clear __lens_detections here. The dist's showBanner hook
    // writes the new detections, and the bubble-phase event order
    // (target then bubble) means the dist's listener runs first.
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

// readUtilScripts reads the dist's util/*.js files in dependency order
// and returns them as a single concatenated string. The order matters:
// logger must come first (other files use NS.logger), then opt-in,
// telemetry-queue, webgpu-detect, license-checker, bundle-registry,
// bundle-loader, model-loader, then the detectors, then banner-ui
// (which depends on logger).
//
// v3.5.1+ (Bug C follow-up): without this injection, the content script
// cannot find NS.util.bannerUI and the banner never renders in the test,
// so the test wrapper's __lens_detections stays empty.
func readUtilScripts(dist string) (string, error) {
	// Load order matters. Detectors first (define NS.detectors.detect),
	// then util files (define NS.util.*, depend on logger).
	// If a file doesn't exist, skip it (soft-fail).
	order := []string{
		// Detectors — must run before content.js so NS.detectors exists
		"detectors/regex.js",
		"detectors/regex_v2.js",
		"detectors/luhn.js",
		"detectors/from_platform.js",
		"detectors/index.js",
		// Privacy + storage (loaded by content.js's IIFE)
		"privacy/domain_hash.js",
		"privacy/schema.js",
		"api/client.js",
		"storage.js",
		// Util — must run before content.js so NS.util.* exists
		"util/logger.js",
		"util/license-checker.js",
		"util/webgpu-detect.js",
		"util/opt-in.js",
		"util/telemetry-queue.js",
		"util/bundle-registry.js",
		"util/bundle-loader.js",
		"util/model-loader.js",
		"util/banner-ui.js",
	}
	var sb strings.Builder
	for _, rel := range order {
		path := filepath.Join(dist, rel)
		data, err := os.ReadFile(path) // #nosec G304 G703 -- dist is a developer CLI arg, hardcoded subpaths
		if err != nil {
			continue // soft-skip: missing optional file
		}
		sb.Write(data)
		// DEBUG: sentinel after each file
		safeRel := strings.ReplaceAll(rel, "/", "_")
		safeRel = strings.ReplaceAll(safeRel, "-", "_")
		safeRel = strings.ReplaceAll(safeRel, ".", "_")
		fmt.Fprintf(&sb, "\n;\n")
	}
	return sb.String(), nil
}
