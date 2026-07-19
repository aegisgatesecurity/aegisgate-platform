//go:build manual

// +build manual


// Cross-provider consistency test.
//
// Tests that the Lens banner appears for a sensitive prompt on AI
// provider tabs currently open in Chromium. Runs the Python CDP
// test (/tmp/test_cross_provider.py) and reports per-provider results.
//
// This is a smoke test that complements the deeper cross-provider
// testing done in Phase 3 (4-provider smoke test). The full Phase 3
// test verified all 5 providers end-to-end (login, navigation,
// banner injection, screenshot). This test verifies that whatever
// provider tabs are currently open still work.
//
// Note: For full cross-provider testing, see Phase 3 documentation.
// The test here is a runtime smoke check on currently-open tabs.
package lenstest_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCrossProvider_Consistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-provider consistency test in -short mode")
	}

	// Run the Python test that uses CDP to check currently-open tabs.
	cmd := exec.Command("python3", "/tmp/test_cross_provider.py")
	output, err := cmd.CombinedOutput()
	t.Logf("\n%s", string(output))

	// Parse the output for pass/fail
	if err != nil {
		// Exit code 1 means at least one provider failed.
		// But we don't want to fail the test if NO providers are
		// open (which is a valid scenario if the user closed tabs).
		if strings.Contains(string(output), "No AI provider tabs found") {
			t.Skip("No AI provider tabs open. Open at least one to test.")
			return
		}
		// Otherwise, the test failed.
		t.Errorf("Cross-provider consistency test failed")
	}
}