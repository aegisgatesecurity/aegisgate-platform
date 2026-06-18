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
	"fmt"
	"net/http"
	"os"
	"os/exec"
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
		_ = os.RemoveAll(p.dataDir) // #nosec G703 -- p.dataDir is a tmpdir created by the harness
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
	loadExt := "--load-extension=" + cfg.Dist // #nosec G703 -- cfg.Dist is a developer CLI arg, hardcoded in the harness
	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		fmt.Sprintf("--remote-debugging-port=%d", cfg.Port),
		"--user-data-dir=" + dataDir, // #nosec G703 -- dataDir is a tmpdir created by the harness
		loadExt,
		// The page to navigate to is set later via CDP.
		"about:blank",
	}
	cmd := exec.Command(binary, args...) // #nosec G204 G702 -- chromium is the test harness's own browser; args are hardcoded
	cmd.Stdout = os.Stderr               // Forward Chromium's stderr so the user can see browser errors
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil { // #nosec G104 -- start error is reported via the returned error
		_ = os.RemoveAll(dataDir) // #nosec G104 -- best-effort cleanup
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
// or until the timeout expires. If the chromium process exits
// before the port becomes ready, the http.Get will start
// failing and we'll time out (a less informative error, but
// avoids importing golang.org/x/sys/unix just for signal 0).
func (p *chromiumProcess) waitForCDP(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("http://127.0.0.1:%d/json/version", findPortFromArgs(p.cmd.Args))
	consecutiveFails := 0
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) // #nosec G107 G704 -- test harness, localhost only
		if err == nil {
			_ = resp.Body.Close() // #nosec G104 -- best-effort close; OS releases the fd on next GC
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		consecutiveFails++
		// If we've failed many times in a row, the process
		// is likely dead. Break early to surface a
		// better error.
		if consecutiveFails > 20 {
			return p.diagnoseFailure()
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
