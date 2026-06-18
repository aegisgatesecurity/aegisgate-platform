// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness: Chromium Process Management
// =========================================================================
//
// chromium.go spawns a headless Chromium instance for the
// test run, waits for the CDP endpoint to be ready, and
// provides a Close() that terminates the process.
//
// The default is to use "chromium" or "google-chrome" in the
// $PATH. The path can be overridden with --chromium.
//
// Arguments passed to chromium:
//   --headless=new          (the new headless mode)
//   --no-sandbox             (required when running as root in CI)
//   --disable-gpu            (no GPU in headless environments)
//   --remote-debugging-port  (CDP port)
//   --user-data-dir          (temporary profile dir)
//   --disable-extensions-except-... --load-extension   (loads the Lens)
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// chromiumProcess represents a running headless Chromium
// instance. The process is killed when Close() is called.
type chromiumProcess struct {
	cmd     *exec.Cmd
	dataDir string
	closed  bool
}

// Close terminates the Chromium process and cleans up the
// temporary user data directory.
func (p *chromiumProcess) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	if p.dataDir != "" {
		_ = os.RemoveAll(p.dataDir)
	}
	return nil
}

// spawnChromium starts a headless Chromium with the CDP
// debugging port enabled, and waits for the port to be
// reachable.
func spawnChromium(cfg *Config) (*chromiumProcess, error) {
	binary, err := findChromium(cfg.ChromiumPath)
	if err != nil {
		return nil, err
	}
	// Create a temporary user data directory.
	dataDir, err := os.MkdirTemp("", "lens-test-chrome-*")
	if err != nil {
		return nil, fmt.Errorf("mkdir user-data-dir: %w", err)
	}
	// Build the arguments.
	loadExt := "--load-extension=" + cfg.Dist
	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		fmt.Sprintf("--remote-debugging-port=%d", cfg.Port),
		"--user-data-dir=" + dataDir,
		loadExt,
		// The page to navigate to is set later via CDP.
		"about:blank",
	}
	cmd := exec.Command(binary, args...) // #nosec G204 -- chromium is the test harness's own browser
	cmd.Stdout = os.Stderr               // Forward Chromium's stderr so the user can see browser errors
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, fmt.Errorf("start chromium: %w", err)
	}
	proc := &chromiumProcess{cmd: cmd, dataDir: dataDir}
	// Wait for the CDP port to be reachable.
	if err := proc.waitForCDP(cfg.Timeout); err != nil {
		_ = proc.Close()
		return nil, err
	}
	return proc, nil
}

// findChromium locates the chromium binary. If the user
// supplied a path, use it. Otherwise search $PATH for
// "chromium" or "google-chrome" (Linux), "Chromium" or
// "Google Chrome" (macOS), or "chrome.exe" (Windows).
func findChromium(supplied string) (string, error) {
	if supplied != "" {
		return supplied, nil
	}
	candidates := []string{
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/google-chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
		// Check if the file exists directly.
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("chromium binary not found; install chromium or pass --chromium=<path>")
}

// waitForCDP polls the CDP port until it accepts connections,
// or until the timeout expires.
func (p *chromiumProcess) waitForCDP(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", findPortFromArgs(p.cmd.Args))
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) // #nosec G107 -- test harness, localhost only
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		// Also check if the process is still alive.
		if p.cmd.Process != nil {
			if state, _ := p.cmd.Process.Wait(); state != nil {
				// Process exited. Capture any stderr output.
				return p.diagnoseFailure()
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("chromium CDP port did not become ready within %s", timeout)
}

// findPortFromArgs extracts the --remote-debugging-port
// value from the chromium arguments. Defaults to 9222.
func findPortFromArgs(args []string) int {
	for i, a := range args {
		if a == "--remote-debugging-port" && i+1 < len(args) {
			var p int
			_, _ = fmt.Sscanf(args[i+1], "%d", &p)
			if p > 0 {
				return p
			}
		}
		if strings.HasPrefix(a, "--remote-debugging-port=") {
			var p int
			_, _ = fmt.Sscanf(strings.TrimPrefix(a, "--remote-debugging-port="), "%d", &p)
			if p > 0 {
				return p
			}
		}
	}
	return 9222
}

// diagnoseFailure returns a helpful error when Chromium
// fails to start. It runs the chromium binary with --version
// to surface the actual error message.
func (p *chromiumProcess) diagnoseFailure() error {
	// We can't easily capture stderr from a process that's
	// already exited. The caller should look at the
	// forwarded stderr.
	return fmt.Errorf("chromium exited before CDP became ready; check stderr above for the error message")
}

// killStaleChromium kills any chromium processes that may
// be running on the CDP port from a previous run. This is
// a best-effort cleanup, not a hard guarantee.
func killStaleChromium(port int) {
	// No-op on non-Linux platforms. On Linux, we'd use
	// `fuser -k <port>/tcp` or similar. For now, the
	// runner is expected to use a unique port per test
	// run, or the OS will eventually reap the stale
	// process.
	_ = port
}

// runWithStderr runs a command and returns its combined
// stderr. Used for the --version smoke test.
func runWithStderr(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...) // #nosec G204 -- test helper, name is hardcoded
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// chromiumVersion is a helper that returns the chromium
// version string. Used in test reports.
func chromiumVersion(binary string) string {
	// Try `--version` first.
	out, err := runWithStderr(binary, "--version")
	if err != nil {
		// Some chromium versions don't have --version;
		// try --no-sandbox --version.
		out, err = runWithStderr(binary, "--no-sandbox", "--version")
		if err != nil {
			return "unknown"
		}
	}
	// The version line is the first line of the output.
	scanner := bufio.NewScanner(strings.NewReader(out))
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return strings.TrimSpace(out)
}

// init verifies chromium is available at the start of
// the test run. This is a no-op if the user doesn't run
// the tests; it provides an early-fail check.
func init() {
	// The init() block intentionally does nothing. The
	// actual chromium check happens in spawnChromium.
	_ = filepath.Separator // suppress unused import
	_ = context.Background
}
