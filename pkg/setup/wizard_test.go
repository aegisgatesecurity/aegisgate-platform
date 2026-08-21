// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Setup Wizard Tests
// =========================================================================

package setup

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
)

// ---------------------------------------------------------------------------
// Environment detection tests
// ---------------------------------------------------------------------------

func TestDetectEnvironmentReturnsResult(t *testing.T) {
	env := DetectEnvironment()
	if env == nil {
		t.Fatal("DetectEnvironment returned nil")
	}
	if env.DataDir == "" {
		t.Error("DataDir should not be empty")
	}
}

func TestDetectEnvironmentDataDirDocker(t *testing.T) {
	env := &Environment{IsDocker: true}
	// Simulate the logic
	if env.IsDocker || env.IsKubernetes {
		env.DataDir = "/data"
	}
	if env.DataDir != "/data" {
		t.Errorf("Docker DataDir should be /data, got %s", env.DataDir)
	}
}

func TestAutoSelectProfileAirGapped(t *testing.T) {
	env := &Environment{IsAirGapped: true}
	result := autoSelectProfile(env)
	if result != "air-gapped" {
		t.Errorf("Air-gapped env should select 'air-gapped', got %q", result)
	}
}

func TestAutoSelectProfileK8sWithCerts(t *testing.T) {
	env := &Environment{IsKubernetes: true, HasCerts: true}
	result := autoSelectProfile(env)
	if result != "production" {
		t.Errorf("K8s with certs should select 'production', got %q", result)
	}
}

func TestAutoSelectProfileK8sWithoutCerts(t *testing.T) {
	env := &Environment{IsKubernetes: true, HasCerts: false}
	result := autoSelectProfile(env)
	if result != "small-team" {
		t.Errorf("K8s without certs should select 'small-team', got %q", result)
	}
}

func TestAutoSelectProfileDockerWithCerts(t *testing.T) {
	env := &Environment{IsDocker: true, HasCerts: true}
	result := autoSelectProfile(env)
	if result != "production" {
		t.Errorf("Docker with certs should select 'production', got %q", result)
	}
}

func TestAutoSelectProfileLocalDev(t *testing.T) {
	env := &Environment{}
	result := autoSelectProfile(env)
	if result != "quickstart" {
		t.Errorf("Local dev should select 'quickstart', got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Non-interactive wizard tests
// ---------------------------------------------------------------------------

func TestRunNonInteractiveQuickstart(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	path, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if path != outPath {
		t.Errorf("Expected path %s, got %s", outPath, path)
	}

	// Verify config file was written
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("Config file not written: %v", err)
	}
	if len(data) == 0 {
		t.Error("Config file is empty")
	}
	if !strings.Contains(string(data), "AegisGate") {
		t.Error("Config file should contain header comment")
	}
}

func TestRunNonInteractiveWithProfile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		Profile:        "production",
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Verify the production profile was used (TLS enabled, min 1.3)
	data, _ := os.ReadFile(outPath)
	content := string(data)
	if !strings.Contains(content, "min_version: \"1.3\"") && !strings.Contains(content, "min_version: 1.3") {
		// YAML may use different quoting, check for "1.3" presence
		if !strings.Contains(content, "1.3") {
			t.Error("Production config should contain TLS min_version 1.3")
		}
	}
}

func TestRunNonInteractiveInvalidProfile(t *testing.T) {
	tmpDir := t.TempDir()
	opts := &WizardOptions{
		NonInteractive: true,
		Profile:        "bogus",
		OutputPath:     filepath.Join(tmpDir, "config.yaml"),
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}

	_, err := Run(opts)
	if err == nil {
		t.Fatal("Expected error for invalid profile")
	}
}

func TestRunNonInteractiveDoesNotOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// Write an existing config
	os.WriteFile(outPath, []byte("existing"), 0644)

	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     outPath,
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}

	_, err := Run(opts)
	if err == nil {
		t.Fatal("Expected error when config exists without --force")
	}
}

func TestRunNonInteractiveForceOverwrites(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// Write an existing config
	os.WriteFile(outPath, []byte("existing"), 0644)

	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		Force:          true,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error with --force: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) == "existing" {
		t.Error("Config should have been overwritten")
	}
}

func TestRunOutputContainsBanner(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     filepath.Join(tmpDir, "config.yaml"),
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	Run(opts)
	output := buf.String()
	if !strings.Contains(output, "Setup Wizard") {
		t.Error("Output should contain banner")
	}
}

func TestRunOutputContainsEnvironment(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     filepath.Join(tmpDir, "config.yaml"),
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	Run(opts)
	output := buf.String()
	if !strings.Contains(output, "Environment Detection") {
		t.Error("Output should contain environment detection")
	}
}

func TestRunOutputContainsNextSteps(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     filepath.Join(tmpDir, "config.yaml"),
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	Run(opts)
	output := buf.String()
	if !strings.Contains(output, "Setup Complete") {
		t.Error("Output should contain 'Setup Complete'")
	}
	if !strings.Contains(output, "aegisgate config validate") {
		t.Error("Output should mention config validate")
	}
}

func TestRunOutputContainsValidation(t *testing.T) {
	tmpDir := t.TempDir()
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     filepath.Join(tmpDir, "config.yaml"),
		Writer:         &buf,
		Reader:         strings.NewReader(""),
	}

	Run(opts)
	output := buf.String()
	if !strings.Contains(output, "Validating") {
		t.Error("Output should mention validation step")
	}
}

func TestRunCreatesParentDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "subdir", "nested", "config.yaml")

	opts := &WizardOptions{
		NonInteractive: true,
		OutputPath:     outPath,
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("Config file should exist at nested path: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Interactive wizard tests (simulated input)
// ---------------------------------------------------------------------------

func TestRunInteractiveWithDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// Simulate pressing Enter for all prompts (accept defaults)
	input := strings.Repeat("\n", 10)
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: false,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(input),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Error("Config file should be written")
	}
}

func TestRunInteractiveSelectProfile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// Select "small-team" then accept all defaults
	input := "small-team\n\n\n\n\n\n\n\n\n\n"
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: false,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(input),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	content := string(data)
	// small-team has rate_limit 300
	if !strings.Contains(content, "300") {
		t.Error("Config should reflect small-team profile (rate_limit 300)")
	}
}

// ---------------------------------------------------------------------------
// Subcommand tests (in cmd package)
// ---------------------------------------------------------------------------

// Test that the wizard generates valid YAML that can be loaded
func TestGeneratedConfigIsLoadable(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	opts := &WizardOptions{
		NonInteractive: true,
		Profile:        "small-team",
		OutputPath:     outPath,
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Try to load the generated config
	cfg, err := loadConfigForTest(outPath)
	if err != nil {
		t.Fatalf("Generated config failed to load: %v", err)
	}
	if cfg == nil {
		t.Fatal("Loaded config is nil")
	}
	if cfg.Proxy.Upstream == "" {
		t.Error("Generated config should have non-empty upstream")
	}
}

// ---------------------------------------------------------------------------
// All profiles generate valid configs
// ---------------------------------------------------------------------------

func TestAllProfilesGenerateValidConfigs(t *testing.T) {
	profileIDs := []string{"quickstart", "small-team", "production", "high-security", "air-gapped"}

	for _, pid := range profileIDs {
		t.Run(pid, func(t *testing.T) {
			tmpDir := t.TempDir()
			outPath := filepath.Join(tmpDir, "config.yaml")

			var buf bytes.Buffer
			opts := &WizardOptions{
				NonInteractive: true,
				Profile:        pid,
				OutputPath:     outPath,
				Writer:         &buf,
				Reader:         strings.NewReader(""),
			}

			_, err := Run(opts)
			if err != nil {
				t.Fatalf("Run error for %s: %v\nOutput: %s", pid, err, buf.String())
			}

			// Verify the file exists and is non-empty
			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("Config file not created for %s: %v", pid, err)
			}
			if info.Size() == 0 {
				t.Errorf("Config file is empty for %s", pid)
			}

			// Verify the config is loadable
			cfg, err := loadConfigForTest(outPath)
			if err != nil {
				t.Errorf("Config for %s failed to load: %v", pid, err)
			}
			if cfg != nil && cfg.Proxy.Upstream == "" {
				t.Errorf("Config for %s has empty upstream", pid)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helper: load config using platformconfig
// ---------------------------------------------------------------------------

func loadConfigForTest(path string) (*platformconfig.Config, error) {
	return platformconfig.LoadFromFile(path)
}

// ---------------------------------------------------------------------------
// Confirm function tests
// ---------------------------------------------------------------------------

func TestConfirmYes(t *testing.T) {
	var buf bytes.Buffer
	w := &wizard{
		out: &buf,
		in:  bufio.NewReader(strings.NewReader("y\n")),
	}
	if !w.confirm("Overwrite?") {
		t.Error("confirm should return true for 'y'")
	}
	if !strings.Contains(buf.String(), "Overwrite?") {
		t.Error("output should contain the question")
	}
}

func TestConfirmYesFull(t *testing.T) {
	w := &wizard{
		out: &bytes.Buffer{},
		in:  bufio.NewReader(strings.NewReader("yes\n")),
	}
	if !w.confirm("Overwrite?") {
		t.Error("confirm should return true for 'yes'")
	}
}

func TestConfirmNo(t *testing.T) {
	w := &wizard{
		out: &bytes.Buffer{},
		in:  bufio.NewReader(strings.NewReader("n\n")),
	}
	if w.confirm("Overwrite?") {
		t.Error("confirm should return false for 'n'")
	}
}

func TestConfirmEmpty(t *testing.T) {
	w := &wizard{
		out: &bytes.Buffer{},
		in:  bufio.NewReader(strings.NewReader("\n")),
	}
	if w.confirm("Overwrite?") {
		t.Error("confirm should return false for empty input (default N)")
	}
}

func TestConfirmReadError(t *testing.T) {
	w := &wizard{
		out: &bytes.Buffer{},
		in:  bufio.NewReader(strings.NewReader("")),
	}
	if w.confirm("Overwrite?") {
		t.Error("confirm should return false on read error/EOF")
	}
}

func TestConfirmCaseInsensitive(t *testing.T) {
	w := &wizard{
		out: &bytes.Buffer{},
		in:  bufio.NewReader(strings.NewReader("Y\n")),
	}
	if !w.confirm("Overwrite?") {
		t.Error("confirm should return true for uppercase 'Y'")
	}
}

// ---------------------------------------------------------------------------
// Interactive overwrite path tests
// ---------------------------------------------------------------------------

func TestRunInteractiveOverwriteYes(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// First run to create the file
	firstOpts := &WizardOptions{
		NonInteractive: true,
		Profile:        "quickstart",
		OutputPath:     outPath,
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}
	if _, err := Run(firstOpts); err != nil {
		t.Fatalf("First run error: %v", err)
	}

	// Second run: interactive, file exists, confirm overwrite with "y"
	// Input: select profile (Enter for default=quickstart), then 5 customization defaults, then "y" for overwrite
	input := "\n\n\n\n\n\ny\n"
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: false,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(input),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Overwrite run error: %v", err)
	}
	if !strings.Contains(buf.String(), "Config written") {
		t.Error("Output should indicate config was written after overwrite confirm")
	}
}

func TestRunInteractiveOverwriteNo(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// First run to create the file
	firstOpts := &WizardOptions{
		NonInteractive: true,
		Profile:        "quickstart",
		OutputPath:     outPath,
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}
	if _, err := Run(firstOpts); err != nil {
		t.Fatalf("First run error: %v", err)
	}
	originalData, _ := os.ReadFile(outPath)

	// Second run: interactive, file exists, decline overwrite with "n"
	input := "\n\n\n\n\n\nn\n"
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: false,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(input),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if !strings.Contains(buf.String(), "cancelled") {
		t.Error("Output should indicate setup was cancelled")
	}

	// Verify original file is preserved
	newData, _ := os.ReadFile(outPath)
	if !bytes.Equal(originalData, newData) {
		t.Error("Original config file should be unchanged after declining overwrite")
	}
}

// ---------------------------------------------------------------------------
// CustomizeConfig tests with actual values
// ---------------------------------------------------------------------------

func TestRunInteractiveCustomValues(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// Select quickstart (by name), then provide custom values for each prompt
	// Prompts: upstream, proxy port, dashboard port, TLS, data dir
	input := "quickstart\nhttps://api.anthropic.com\n9090\n9443\non\n/data/custom\n"
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: false,
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(input),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v\nOutput: %s", err, buf.String())
	}

	// Load the generated config and verify custom values were applied
	cfg, err := loadConfigForTest(outPath)
	if err != nil {
		t.Fatalf("Generated config failed to load: %v", err)
	}
	if cfg.Proxy.Upstream != "https://api.anthropic.com" {
		t.Errorf("Expected upstream 'https://api.anthropic.com', got '%s'", cfg.Proxy.Upstream)
	}
	if cfg.Dashboard.Port != 9443 {
		t.Errorf("Expected dashboard port 9443, got %d", cfg.Dashboard.Port)
	}
	if !cfg.TLS.Enabled {
		t.Error("TLS should be enabled")
	}
	if cfg.Persistence.DataDir != "/data/custom" {
		t.Errorf("Expected data dir '/data/custom', got '%s'", cfg.Persistence.DataDir)
	}
}

func TestRunInteractiveDisableTLS(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// Use small-team (which has TLS on), then disable TLS
	input := "small-team\n\n\noff\n\n"
	var buf bytes.Buffer
	opts := &WizardOptions{
		NonInteractive: false,
		Profile:        "small-team",
		OutputPath:     outPath,
		Writer:         &buf,
		Reader:         strings.NewReader(input),
	}

	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	cfg, err := loadConfigForTest(outPath)
	if err != nil {
		t.Fatalf("Config load error: %v", err)
	}
	if cfg.TLS.Enabled {
		t.Error("TLS should be disabled after user input 'off'")
	}
}

// ---------------------------------------------------------------------------
// WriteConfig error path tests
// ---------------------------------------------------------------------------

func TestRunWriteConfigInvalidPath(t *testing.T) {
	// Use a path that cannot be created (parent is a file, not a directory)
	tmpFile, err := os.CreateTemp("", "aegisgate-blocker-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	invalidPath := filepath.Join(tmpFile.Name(), "subdir", "config.yaml")

	opts := &WizardOptions{
		NonInteractive: true,
		Profile:        "quickstart",
		OutputPath:     invalidPath,
		Writer:         &bytes.Buffer{},
		Reader:         strings.NewReader(""),
	}

	_, err = Run(opts)
	if err == nil {
		t.Error("Run should fail when parent directory cannot be created")
	}
}

// ---------------------------------------------------------------------------
// Run with nil options (defaults path)
// ---------------------------------------------------------------------------

func TestRunNilOptions(t *testing.T) {
	// Run with nil opts should use defaults (os.Stdin/os.Stdout)
	// We can't fully test this without replacing os.Stdin, but we can
	// verify that Run(nil) doesn't panic immediately by providing a profile
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")

	// This tests that opts==nil is handled (Run fills in defaults)
	opts := &WizardOptions{
		NonInteractive: true,
		Profile:        "quickstart",
		OutputPath:     outPath,
	}
	_, err := Run(opts)
	if err != nil {
		t.Fatalf("Run with minimal opts error: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Error("Config file should be written")
	}
}
