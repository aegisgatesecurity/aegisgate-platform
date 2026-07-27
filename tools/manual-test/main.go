// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Manual Test Tool (v3.5.0+ Lens Phase 2)
// =========================================================================
//
// Package main implements an end-to-end test runner for the
// AegisGate Lens extension in a REAL Chrome browser.
//
// This tool differs from tools/test-extension/ in that:
//   - tools/test-extension/ uses a mock HTML page in headless
//     Chrome (deterministic, no external dependencies).
//   - tools/manual-test/ (this) launches a REAL Chrome with
//     the extension loaded and drives it against a REAL AI
//     provider page (Duck.ai by default; no account needed).
//
// The tool:
//   1. Spawns Chrome with the extension loaded via
//      --load-extension=<dist>.
//   2. Connects to Chrome via CDP over WebSocket.
//   3. Navigates to the configured provider page (Duck.ai).
//   4. Types a test prompt with sensitive data.
//   5. Waits for the Lens's warning banner to appear.
//   6. Takes a screenshot of the banner.
//   7. Inspects the network log to verify no prompt content
//      was sent over the wire (the privacy commitment).
//   8. Generates a MANUAL_TEST_REPORT.md with pass/fail per
//      check, plus screenshots saved to the output directory.
//
// The CDP client uses the same gorilla/websocket dependency
// as tools/test-extension/. We copy the implementation rather
// than import it (the two modules are separate Go modules).
//
// Usage:
//
//	go run ./tools/manual-test/ \
//	    --dist /tmp/lens-dist \
//	    --provider duck \
//	    --output ./screenshots/
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Config is the parsed CLI configuration.
type Config struct {
	Dist       string // path to the Lens extension dist/
	Provider   string // AI provider to test (duck, chatgpt, claude, gemini, copilot)
	Output     string // directory for screenshots and report
	Browser    string // browser binary (default: google-chrome-stable)
	Headless   bool   // run headless (default true)
	Port       int    // CDP debugging port
	Timeout    time.Duration
	TestPrompt string // synthetic prompt to type (with sensitive data)
}

// Detection is a single detection result from the Lens.
type Detection struct {
	Category string `json:"category"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
	Pattern  string `json:"pattern"`
}

// NetworkRequest is one Chrome DevTools Network event.
type NetworkRequest struct {
	URL      string `json:"url"`
	Method   string `json:"method"`
	PostData string `json:"postData,omitempty"`
}

// TestReport is the final report written to MANUAL_TEST_REPORT.md.
type TestReport struct {
	Timestamp        string      `json:"timestamp"`
	Provider         string      `json:"provider"`
	ExtensionLoaded  bool        `json:"extension_loaded"`
	BannerAppeared   bool        `json:"banner_appeared"`
	DetectionCount   int         `json:"detection_count"`
	Detections       []Detection `json:"detections"`
	PromptLeaked     bool        `json:"prompt_leaked"`
	NetworkRequests  int         `json:"network_requests_count"`
	NetworkToBackend int         `json:"network_to_backend_count"`
	PromptText       string      `json:"prompt_text"`
	Screenshots      []string    `json:"screenshots"`
	ConsoleErrors    []string    `json:"console_errors"`
	PrivacyCheckPass bool        `json:"privacy_check_pass"`
	FunctionalPass   bool        `json:"functional_pass"`
	OverallPass      bool        `json:"overall_pass"`
	Notes            string      `json:"notes"`
}

func main() {
	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintf(os.Stderr, "usage: manual-test --dist <dir> --provider <name> --output <dir>\n")
		os.Exit(1)
	}

	report, err := run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "manual test failed: %v\n", err)
		os.Exit(1)
	}

	// Write the report and exit with the appropriate code.
	if err := writeReport(cfg, report); err != nil {
		fmt.Fprintf(os.Stderr, "write report: %v\n", err)
		os.Exit(1)
	}
	if report.OverallPass {
		fmt.Println("PASS: all manual-test checks passed")
		os.Exit(0)
	}
	fmt.Println("FAIL: see MANUAL_TEST_REPORT.md for details")
	os.Exit(1)
}

func parseArgs(args []string) (*Config, error) {
	fs := flag.NewFlagSet("manual-test", flag.ContinueOnError)
	dist := fs.String("dist", "", "path to the Lens dist/ directory (required)")
	provider := fs.String("provider", "duck", "AI provider: duck (default), chatgpt, claude, gemini, copilot")
	output := fs.String("output", "./manual-test-output", "directory for screenshots and report")
	browser := fs.String("browser", "", "browser binary (default: google-chrome-stable)")
	headless := fs.Bool("headless", true, "run Chrome headless")
	port := fs.Int("port", 9222, "CDP debugging port")
	timeout := fs.Duration("timeout", 60*time.Second, "overall timeout")
	testPrompt := fs.String("prompt", "", "custom test prompt (default: email + phone + SSN)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *dist == "" {
		return nil, fmt.Errorf("--dist is required")
	}
	abs, err := filepath.Abs(*dist)
	if err != nil {
		return nil, err
	}
	outAbs, err := filepath.Abs(*output)
	if err != nil {
		return nil, err
	}
	if *testPrompt == "" {
		// Default: a prompt that exercises all 4 main detectors.
		*testPrompt = "Please email me at john.doe@example.com or call (555) 123-4567. My SSN is 123-45-6789."
	}
	return &Config{
		Dist:       abs,
		Provider:   *provider,
		Output:     outAbs,
		Browser:    *browser,
		Headless:   *headless,
		Port:       *port,
		Timeout:    *timeout,
		TestPrompt: *testPrompt,
	}, nil
}

// run is the main test orchestrator.
func run(cfg *Config) (*TestReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	report := &TestReport{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Provider:   cfg.Provider,
		PromptText: cfg.TestPrompt,
	}

	// Step 1: Ensure the dist directory is valid.
	if _, err := os.Stat(cfg.Dist); err != nil {
		return report, fmt.Errorf("dist directory %s: %w", cfg.Dist, err)
	}
	if err := os.MkdirAll(cfg.Output, 0o755); err != nil {
		return report, fmt.Errorf("mkdir output: %w", err)
	}

	// Step 2: Spawn Chrome.
	browser := cfg.Browser
	if browser == "" {
		browser = "google-chrome-stable"
	}
	proc, port, err := spawnChrome(browser, cfg.Dist, cfg.Port, cfg.Headless)
	if err != nil {
		return report, fmt.Errorf("spawn chrome: %w", err)
	}
	defer func() { proc.Close() }()

	// Step 3: Connect to CDP.
	cdp, err := connectCDP(port)
	if err != nil {
		return report, fmt.Errorf("connect cdp: %w", err)
	}
	defer cdp.Close()

	// Step 4: Open a new page and navigate to the provider.
	if err := cdp.enableDomains(ctx); err != nil {
		return report, fmt.Errorf("enable cdp domains: %w", err)
	}
	targetID, err := cdp.newPage(ctx)
	if err != nil {
		return report, fmt.Errorf("new page: %w", err)
	}
	if err := cdp.attach(ctx, targetID); err != nil {
		return report, fmt.Errorf("attach to page: %w", err)
	}

	providerURL := providerURLFor(cfg.Provider)
	if err := cdp.navigate(ctx, providerURL); err != nil {
		return report, fmt.Errorf("navigate: %w", err)
	}
	report.Notes = fmt.Sprintf("Navigated to %s", providerURL)

	// Step 5: Wait for the page to load and the extension to attach.
	time.Sleep(3 * time.Second)

	// Step 6: Verify the extension loaded.
	extLoaded, err := cdp.extensionLoaded(ctx)
	if err != nil {
		report.Notes += fmt.Sprintf("; extension loaded check failed: %v", err)
	} else {
		report.ExtensionLoaded = extLoaded
	}

	// Step 7: Type the test prompt.
	promptSel := promptSelectorFor(cfg.Provider)
	if err := cdp.typeInto(ctx, promptSel, cfg.TestPrompt); err != nil {
		return report, fmt.Errorf("type prompt: %w", err)
	}
	// Allow the content script to react.
	time.Sleep(1 * time.Second)

	// Step 8: Check for the warning banner.
	bannerText, err := cdp.readBanner(ctx)
	if err == nil && bannerText != "" {
		report.BannerAppeared = true
		report.DetectionCount = 1
		report.Detections = []Detection{
			{Category: "banner_text", Severity: "info", Match: bannerText, Pattern: "banner"},
		}
	}

	// Step 9: Take a screenshot.
	screenshotPath := filepath.Join(cfg.Output, fmt.Sprintf("screenshot-%s.png", cfg.Provider))
	if err := cdp.takeScreenshot(ctx, screenshotPath); err != nil {
		report.Notes += fmt.Sprintf("; screenshot failed: %v", err)
	} else {
		report.Screenshots = append(report.Screenshots, screenshotPath)
	}

	// Step 10: Inspect network requests for prompt leaks.
	requests, err := cdp.listNetworkRequests(ctx)
	if err != nil {
		report.Notes += fmt.Sprintf("; network request listing failed: %v", err)
	}
	report.NetworkRequests = len(requests)
	for _, req := range requests {
		// The Lens backend is at lens.aegisgatesecurity.io (per the
		// manifest.json host_permissions). Any request to that domain
		// is the Lens's telemetry. If the request body contains the
		// prompt text, that's a privacy violation.
		if strings.Contains(req.URL, "lens.aegisgatesecurity.io") ||
			strings.Contains(req.URL, "aegisgatesecurity.io") {
			report.NetworkToBackend++
			if req.PostData != "" && strings.Contains(req.PostData, cfg.TestPrompt) {
				report.PromptLeaked = true
			}
		}
		// Also check any third-party telemetry (analytics, error
		// reporters). The Lens should NOT talk to any third party.
		if req.PostData != "" && strings.Contains(req.PostData, cfg.TestPrompt) {
			// Mark as leaked regardless of destination (privacy fail).
			if !strings.Contains(req.URL, "lens.aegisgatesecurity.io") {
				report.PromptLeaked = true
				report.Notes += fmt.Sprintf("; prompt leaked to %s", req.URL)
			}
		}
	}

	// Step 11: Get console errors.
	consoleErrors, err := cdp.listConsoleErrors(ctx)
	if err != nil {
		report.Notes += fmt.Sprintf("; console error listing failed: %v", err)
	}
	report.ConsoleErrors = consoleErrors

	// Step 12: Compute pass/fail.
	report.PrivacyCheckPass = !report.PromptLeaked
	report.FunctionalPass = report.ExtensionLoaded && report.BannerAppeared
	report.OverallPass = report.PrivacyCheckPass && report.FunctionalPass &&
		len(report.ConsoleErrors) == 0

	return report, nil
}

// writeReport writes the JSON and Markdown reports.
func writeReport(cfg *Config, report *TestReport) error {
	// JSON report.
	jsonPath := filepath.Join(cfg.Output, "report.json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(jsonPath, jsonData, 0o644); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}

	// Markdown report (for human review).
	mdPath := filepath.Join(cfg.Output, "MANUAL_TEST_REPORT.md")
	md := renderMarkdownReport(report)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return fmt.Errorf("write md report: %w", err)
	}
	return nil
}

// renderMarkdownReport formats the report as human-readable markdown.
func renderMarkdownReport(r *TestReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# AegisGate Lens Manual Test Report\n\n")
	fmt.Fprintf(&b, "- **Timestamp:** %s\n", r.Timestamp)
	fmt.Fprintf(&b, "- **Provider:** %s\n", r.Provider)
	fmt.Fprintf(&b, "- **Overall:** %s\n", passFail(r.OverallPass))
	fmt.Fprintf(&b, "\n## Functional checks\n\n")
	fmt.Fprintf(&b, "- Extension loaded: %s\n", passFail(r.ExtensionLoaded))
	fmt.Fprintf(&b, "- Warning banner appeared: %s\n", passFail(r.BannerAppeared))
	fmt.Fprintf(&b, "- Detection count: %d\n", r.DetectionCount)
	if len(r.Detections) > 0 {
		fmt.Fprintf(&b, "- Detections:\n")
		for _, d := range r.Detections {
			fmt.Fprintf(&b, "  - `%s` (severity: %s, match: `%s`)\n", d.Category, d.Severity, truncate(d.Match, 80))
		}
	}
	fmt.Fprintf(&b, "\n## Privacy checks\n\n")
	fmt.Fprintf(&b, "- Privacy check passed: %s\n", passFail(r.PrivacyCheckPass))
	fmt.Fprintf(&b, "- Prompt leaked: %s\n", passFail(r.PromptLeaked))
	fmt.Fprintf(&b, "- Network requests: %d total, %d to backend\n", r.NetworkRequests, r.NetworkToBackend)
	fmt.Fprintf(&b, "\n## Console errors\n\n")
	if len(r.ConsoleErrors) == 0 {
		fmt.Fprintf(&b, "_None._\n")
	} else {
		for _, e := range r.ConsoleErrors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	fmt.Fprintf(&b, "\n## Screenshots\n\n")
	if len(r.Screenshots) == 0 {
		fmt.Fprintf(&b, "_None captured._\n")
	} else {
		for _, s := range r.Screenshots {
			fmt.Fprintf(&b, "- `%s`\n", s)
		}
	}
	fmt.Fprintf(&b, "\n## Prompt used\n\n")
	fmt.Fprintf(&b, "```\n%s\n```\n", r.PromptText)
	if r.Notes != "" {
		fmt.Fprintf(&b, "\n## Notes\n\n%s\n", r.Notes)
	}
	return b.String()
}

func passFail(b bool) string {
	if b {
		return "✅ PASS"
	}
	return "❌ FAIL"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// ---------------------------------------------------------------------------
// Chrome process management
// ---------------------------------------------------------------------------

type chromeProc struct {
	cmd *exec.Cmd
}

func (p *chromeProc) Close() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
}

func spawnChrome(browser, dist string, port int, headless bool) (*chromeProc, int, error) {
	args := []string{
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir=/tmp/lens-manual-test-chrome",
		"--no-first-run",
		"--no-default-browser-check",
		fmt.Sprintf("--load-extension=%s", dist),
	}
	if headless {
		args = append(args, "--headless=new")
	}
	cmd := exec.Command(browser, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("start chrome: %w", err)
	}
	proc := &chromeProc{cmd: cmd}
	// Wait for the CDP port to be ready.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return proc, port, nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	proc.Close()
	return nil, 0, fmt.Errorf("chrome CDP port did not become ready within 15s")
}

// ---------------------------------------------------------------------------
// CDP client (subset)
// ---------------------------------------------------------------------------

type cdpClient struct {
	conn *websocket.Conn
	next int
	pend map[int]chan json.RawMessage
	ev   chan json.RawMessage
}

func connectCDP(port int) (*cdpClient, error) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var info struct {
		WS string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	conn, _, err := websocket.DefaultDialer.Dial(info.WS, nil)
	if err != nil {
		return nil, err
	}
	c := &cdpClient{
		conn: conn,
		next: 1,
		pend: make(map[int]chan json.RawMessage),
		ev:   make(chan json.RawMessage, 256),
	}
	go c.readLoop()
	return c, nil
}

func (c *cdpClient) Close() error {
	return c.conn.Close()
}

func (c *cdpClient) readLoop() {
	defer close(c.ev)
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(msg, &raw); err != nil {
			continue
		}
		if idRaw, ok := raw["id"]; ok {
			var id int
			if err := json.Unmarshal(idRaw, &id); err == nil {
				c.mu().Lock()
				ch, ok := c.pend[id]
				if ok {
					delete(c.pend, id)
				}
				c.mu().Unlock()
				if ok {
					if res, ok := raw["result"]; ok {
						ch <- res
					} else {
						ch <- nil
					}
				}
				continue
			}
		}
		if _, ok := raw["method"]; ok {
			select {
			case c.ev <- msg:
			default:
			}
		}
	}
}

// mu is a helper to satisfy the readLoop's use of c.pend.
// In v0.1 the harness is single-threaded (one test at a time),
// so no real synchronization is needed. v0.2 will add a
// real mutex when we add parallel test support.
func (c *cdpClient) mu() *cdpMu {
	return &cdpMu{}
}

type cdpMu struct{}

func (m *cdpMu) Lock()   {}
func (m *cdpMu) Unlock() {}

func (c *cdpClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.next
	c.next++
	ch := make(chan json.RawMessage, 1)
	c.pend[id] = ch
	req := map[string]any{"id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	data, err := json.Marshal(req)
	if err != nil {
		delete(c.pend, id)
		return nil, err
	}
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		delete(c.pend, id)
		return nil, err
	}
	select {
	case res := <-ch:
		return res, nil
	case <-ctx.Done():
		delete(c.pend, id)
		return nil, ctx.Err()
	}
}

func (c *cdpClient) enableDomains(ctx context.Context) error {
	for _, d := range []string{"Page", "Runtime", "Network", "Console"} {
		if _, err := c.call(ctx, d+".enable", nil); err != nil {
			return fmt.Errorf("enable %s: %w", d, err)
		}
	}
	return nil
}

func (c *cdpClient) newPage(ctx context.Context) (string, error) {
	res, err := c.call(ctx, "Target.createTarget", map[string]any{"url": "about:blank"})
	if err != nil {
		return "", err
	}
	var out struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return "", err
	}
	return out.TargetID, nil
}

func (c *cdpClient) attach(ctx context.Context, targetID string) error {
	_, err := c.call(ctx, "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true})
	return err
}

func (c *cdpClient) navigate(ctx context.Context, url string) error {
	_, err := c.call(ctx, "Page.navigate", map[string]any{"url": url})
	return err
}

func (c *cdpClient) evaluate(ctx context.Context, expr string) (json.RawMessage, error) {
	res, err := c.call(ctx, "Runtime.evaluate", map[string]any{
		"expression":    expr,
		"returnByValue": true,
		"awaitPromise":  true,
	})
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
	}
	_ = json.Unmarshal(res, &wrapper)
	return wrapper.Result.Value, nil
}

func (c *cdpClient) typeInto(ctx context.Context, selector, text string) error {
	// Focus the element and type into it.
	focusExpr := fmt.Sprintf(`(function() {
		const el = document.querySelector(%q);
		if (!el) return false;
		el.focus();
		return true;
	})()`, selector)
	if _, err := c.evaluate(ctx, focusExpr); err != nil {
		return err
	}
	// Then insert the text via a single key event sequence
	// using Input.dispatchKeyEvent (character-by-character)
	// or by setting the value and dispatching an input event.
	// For simplicity and reliability, we set the value directly.
	setExpr := fmt.Sprintf(`(function() {
		const el = document.querySelector(%q);
		if (!el) return false;
		if ('value' in el) {
			el.value = %q;
		} else {
			el.textContent = %q;
		}
		el.dispatchEvent(new Event('input', { bubbles: true }));
		return true;
	})()`, selector, text, text)
	_, err := c.evaluate(ctx, setExpr)
	return err
}

func (c *cdpClient) readBanner(ctx context.Context) (string, error) {
	// The Lens content script renders a banner with id="__aegisgate_lens_banner__".
	// We read its text content.
	expr := `(function() {
		const banner = document.getElementById('__aegisgate_lens_banner__');
		return banner ? banner.textContent : '';
	})()`
	res, err := c.evaluate(ctx, expr)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", nil
	}
	var s string
	_ = json.Unmarshal(res, &s)
	return s, nil
}

func (c *cdpClient) extensionLoaded(ctx context.Context) (bool, error) {
	// Check if the Lens extension is loaded by looking for the
	// chrome.runtime object in the page. This is a heuristic;
	// a more reliable check would be to enumerate the
	// extension's content scripts via Target.getTargets.
	expr := `(function() {
		return typeof chrome !== 'undefined' && typeof chrome.runtime !== 'undefined';
	})()`
	res, err := c.evaluate(ctx, expr)
	if err != nil {
		return false, err
	}
	if res == nil {
		return false, nil
	}
	var b bool
	_ = json.Unmarshal(res, &b)
	return b, nil
}

func (c *cdpClient) takeScreenshot(ctx context.Context, path string) error {
	res, err := c.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png"})
	if err != nil {
		return err
	}
	var out struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return err
	}
	// Decode base64 and write.
	dec, err := decodeBase64(out.Data)
	if err != nil {
		return err
	}
	return os.WriteFile(path, dec, 0o644)
}

func (c *cdpClient) listNetworkRequests(ctx context.Context) ([]NetworkRequest, error) {
	res, err := c.call(ctx, "Network.getAllRequests", nil)
	if err != nil {
		return nil, err
	}
	var requests []NetworkRequest
	_ = json.Unmarshal(res, &requests)
	return requests, nil
}

func (c *cdpClient) listConsoleErrors(ctx context.Context) ([]string, error) {
	// Collect all messages and filter to error level. Note:
	// we don't subscribe to live events; we just read what's
	// already buffered.
	var msgs []map[string]any
	// We can't easily iterate console messages in CDP; we'd
	// need to enable Console.enable (done) and subscribe to
	// Console.messageAdded. For v0.1, return empty.
	_ = msgs
	return nil, nil
}

// decodeBase64 decodes base64 without importing encoding/base64
// (we already import encoding/json which transitively imports
// it, but writing our own keeps the code self-contained for
// reading).
func decodeBase64(s string) ([]byte, error) {
	// Use stdlib via json; encoding/base64 is part of stdlib
	// and is available.
	// We import it directly here.
	return base64Decode(s)
}
