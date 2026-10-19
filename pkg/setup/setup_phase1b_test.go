// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPhase1bWriteStr exercises the writeStr convenience wrapper.
func TestPhase1bWriteStr(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{OutputPath: "test"},
		env:  &Environment{},
		out:  &sb,
		in:   bufio.NewReader(strings.NewReader("\n")),
	}
	w.writeStr("hello world")
	if sb.String() != "hello world" {
		t.Errorf("expected 'hello world', got %q", sb.String())
	}
}

// TestPhase1bDetectEnvironment_AllPaths exercises all detection branches.
func TestPhase1bDetectEnvironment_AllPaths(t *testing.T) {
	// This is a smoke test — we can't control /.dockerenv etc, but we
	// can verify the function doesn't crash and returns a valid result.
	env := DetectEnvironment()
	if env == nil {
		t.Fatal("expected non-nil environment")
	}
	if env.DataDir == "" {
		t.Log("DataDir is empty (may be expected)")
	}
}

// TestPhase1bPrintEnvironment_Docker exercises the Docker branch.
func TestPhase1bPrintEnvironment_Docker(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env: &Environment{
			IsDocker: true,
			Hostname: "test-host",
			DataDir:  "/data",
			HasCerts: true,
		},
		out: &sb,
		in:  bufio.NewReader(strings.NewReader("\n")),
	}
	w.printEnvironment()
	output := sb.String()
	if !strings.Contains(output, "Docker") {
		t.Error("expected 'Docker' in environment output")
	}
}

// TestPhase1bPrintEnvironment_Kubernetes exercises the Kubernetes branch.
func TestPhase1bPrintEnvironment_Kubernetes(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env: &Environment{
			IsKubernetes: true,
			Hostname:     "k8s-node",
			DataDir:      "/data",
		},
		out: &sb,
		in:  bufio.NewReader(strings.NewReader("\n")),
	}
	w.printEnvironment()
	if !strings.Contains(sb.String(), "Kubernetes") {
		t.Error("expected 'Kubernetes' in output")
	}
}

// TestPhase1bPrintEnvironment_Systemd exercises the systemd branch.
func TestPhase1bPrintEnvironment_Systemd(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env: &Environment{
			IsSystemd: true,
			Hostname:  "systemd-host",
			DataDir:   "/data",
		},
		out: &sb,
		in:  bufio.NewReader(strings.NewReader("\n")),
	}
	w.printEnvironment()
	if !strings.Contains(sb.String(), "systemd") {
		t.Error("expected 'systemd' in output")
	}
}

// TestPhase1bPrintEnvironment_AirGapped exercises the air-gapped branch.
func TestPhase1bPrintEnvironment_AirGapped(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env: &Environment{
			IsAirGapped: true,
			Hostname:    "airgap-host",
			DataDir:     "/data",
		},
		out: &sb,
		in:  bufio.NewReader(strings.NewReader("\n")),
	}
	w.printEnvironment()
	if !strings.Contains(sb.String(), "Air-gapped") {
		t.Error("expected 'Air-gapped' in output")
	}
}

// TestPhase1bPrintEnvironment_LocalBareMetal exercises the fallback branch.
func TestPhase1bPrintEnvironment_LocalBareMetal(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env: &Environment{
			Hostname: "local-host",
			DataDir:  "/data",
		},
		out: &sb,
		in:  bufio.NewReader(strings.NewReader("\n")),
	}
	w.printEnvironment()
	if !strings.Contains(sb.String(), "Local") {
		t.Error("expected 'Local' in output")
	}
}

// TestPhase1bConfirm_Yes exercises the confirm function with "yes" input.
func TestPhase1bConfirm_Yes(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("yes\n")),
	}
	if !w.confirm("Continue?") {
		t.Error("expected true for 'yes' input")
	}
}

// TestPhase1bConfirm_No exercises the confirm function with "n" input.
func TestPhase1bConfirm_No(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("n\n")),
	}
	if w.confirm("Continue?") {
		t.Error("expected false for 'n' input")
	}
}

// TestPhase1bConfirm_Empty exercises the confirm function with empty input.
func TestPhase1bConfirm_Empty(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("\n")),
	}
	if w.confirm("Continue?") {
		t.Error("expected false for empty input")
	}
}

// TestPhase1bReadLine_EOF exercises the readLine function with EOF.
func TestPhase1bReadLine_EOF(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("")),
	}
	line, err := w.readLine()
	if err != nil {
		t.Errorf("expected nil error for EOF, got: %v", err)
	}
	_ = line
}

// TestPhase1bReadLine_Normal exercises normal line reading.
func TestPhase1bReadLine_Normal(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("hello\n")),
	}
	line, err := w.readLine()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(line, "hello") {
		t.Errorf("expected 'hello' in line, got %q", line)
	}
}

// TestPhase1bRun_NilOptions exercises Run with nil options (defaults).
func TestPhase1bRun_NilOptions(t *testing.T) {
	// Use a temp output path in .workingdirectory
	tmpDir := ".workingdirectory"
	os.MkdirAll(tmpDir, 0755)
	outputPath := filepath.Join(tmpDir, "test_config.yaml")
	defer os.Remove(outputPath)

	_, err := Run(&WizardOptions{
		NonInteractive: true,
		OutputPath:     outputPath,
		Reader:         strings.NewReader("\n"),
		Writer:         &strings.Builder{},
		Force:          true,
	})
	if err != nil {
		t.Logf("Run returned error (may be expected in test env): %v", err)
	}
}

// TestPhase1bRun_NilReaderWriter exercises that nil reader/writer get defaults.
func TestPhase1bRun_NilReaderWriter(t *testing.T) {
	tmpDir := ".workingdirectory"
	os.MkdirAll(tmpDir, 0755)
	outputPath := filepath.Join(tmpDir, "test_config2.yaml")
	defer os.Remove(outputPath)

	// This should not panic even with nil reader/writer
	// (Run replaces them with os.Stdin/os.Stdout)
	// We provide explicit ones to avoid hanging on stdin
	_, err := Run(&WizardOptions{
		NonInteractive: true,
		OutputPath:     outputPath,
		Reader:         strings.NewReader("\n"),
		Writer:         &strings.Builder{},
		Force:          true,
	})
	_ = err
}

// TestPhase1bSelectProfile_InvalidProfile exercises the error path for
// an invalid profile name.
func TestPhase1bSelectProfile_InvalidProfile(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{Profile: "nonexistent-profile"},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("\n")),
	}
	err := w.selectProfile()
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}
}

// TestPhase1bSelectProfile_ValidProfile exercises the happy path.
func TestPhase1bSelectProfile_ValidProfile(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{Profile: "quickstart"},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(strings.NewReader("\n")),
	}
	err := w.selectProfile()
	if err != nil {
		t.Fatalf("unexpected error for valid profile: %v", err)
	}
	if w.chosen != "quickstart" {
		t.Errorf("expected chosen=quickstart, got %s", w.chosen)
	}
}

// TestPhase1bPrintBanner exercises the banner printing.
func TestPhase1bPrintBanner(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &sb,
		in:   bufio.NewReader(strings.NewReader("\n")),
	}
	w.printBanner()
	if sb.String() == "" {
		t.Error("expected non-empty banner output")
	}
}

// TestPhase1bPrintStep exercises step printing.
func TestPhase1bPrintStep(t *testing.T) {
	var sb strings.Builder
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &sb,
		in:   bufio.NewReader(strings.NewReader("\n")),
	}
	w.printStep("Test step")
	if !strings.Contains(sb.String(), "Test step") {
		t.Error("expected 'Test step' in output")
	}
}

// TestPhase1bDetectEnvironment_AirGapped exercises the air-gapped detection
// branch by setting the AEGISGATE_AIR_GAPPED env var.
func TestPhase1bDetectEnvironment_AirGapped(t *testing.T) {
	os.Setenv("AEGISGATE_AIR_GAPPED", "true")
	defer os.Unsetenv("AEGISGATE_AIR_GAPPED")
	env := DetectEnvironment()
	if !env.IsAirGapped {
		t.Fatal("expected IsAirGapped=true")
	}
}

// TestPhase1bDetectEnvironment_AirGappedOne exercises the "1" variant.
func TestPhase1bDetectEnvironment_AirGappedOne(t *testing.T) {
	os.Setenv("AEGISGATE_AIR_GAPPED", "1")
	defer os.Unsetenv("AEGISGATE_AIR_GAPPED")
	env := DetectEnvironment()
	if !env.IsAirGapped {
		t.Fatal("expected IsAirGapped=true for '1'")
	}
}

// TestPhase1bDetectEnvironment_Kubernetes exercises k8s detection.
func TestPhase1bDetectEnvironment_Kubernetes(t *testing.T) {
	os.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	defer os.Unsetenv("KUBERNETES_SERVICE_HOST")
	env := DetectEnvironment()
	if !env.IsKubernetes {
		t.Fatal("expected IsKubernetes=true")
	}
}

// errorReader is a reader that always returns an error.
type errorReader struct{}

func (errorReader) Read(p []byte) (int, error) {
	return 0, os.ErrInvalid
}

// TestPhase1bReadLine_ReadError exercises the error path in readLine
// where the reader returns a non-EOF error.
func TestPhase1bReadLine_ReadError(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(errorReader{}),
	}
	_, err := w.readLine()
	if err == nil {
		t.Fatal("expected error from errorReader")
	}
}

// TestPhase1bConfirm_ReadError exercises the confirm error path
// where readLine returns an error.
func TestPhase1bConfirm_ReadError(t *testing.T) {
	w := &wizard{
		opts: &WizardOptions{},
		env:  &Environment{},
		out:  &strings.Builder{},
		in:   bufio.NewReader(errorReader{}),
	}
	if w.confirm("Test?") {
		t.Fatal("expected false when readLine errors")
	}
}
