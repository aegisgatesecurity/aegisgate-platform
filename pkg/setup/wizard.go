// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform — Setup Wizard
// =========================================================================
//
// Interactive and non-interactive setup wizard for first-run configuration.
// Detects the environment, recommends a deploy profile, generates a config
// file, validates it, and prints next steps.
//
// Usage:
//   aegisgate setup                           # interactive (prompts)
//   aegisgate setup --non-interactive         # auto-detect, no prompts
//   aegisgate setup --profile quickstart      # skip profile selection
//   aegisgate setup --output my-config.yaml   # custom output path
//
// The wizard does NOT start the platform. It only generates a config file
// and prints instructions for starting the platform with that config.
//
// =========================================================================

package setup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/platformconfig"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/profiles"
	"gopkg.in/yaml.v3"
)

// Environment represents the detected deployment environment.
type Environment struct {
	IsDocker          bool
	IsKubernetes      bool
	IsSystemd         bool
	IsAirGapped       bool
	HasCerts          bool
	HasExistingConfig bool
	Hostname          string
	DataDir           string
	DetectedProfile   string
}

// DetectEnvironment inspects the runtime environment and returns what it finds.
func DetectEnvironment() *Environment {
	env := &Environment{
		DataDir: "/data",
	}

	// Docker detection
	if _, err := os.Stat("/.dockerenv"); err == nil {
		env.IsDocker = true
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" || os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
		env.IsKubernetes = true
	}

	// Systemd detection
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		env.IsSystemd = true
	}

	// Air-gapped detection: check if common external endpoints are unreachable
	// We check for a well-known env var that air-gapped deployments set
	if os.Getenv("AEGISGATE_AIR_GAPPED") == "true" || os.Getenv("AEGISGATE_AIR_GAPPED") == "1" {
		env.IsAirGapped = true
	}

	// Certificate detection
	certPaths := []string{
		"/data/certs/cert.pem",
		"/data/certs/server.crt",
		"./certs/cert.pem",
		"/etc/ssl/certs/aegisgate.pem",
	}
	for _, p := range certPaths {
		if _, err := os.Stat(p); err == nil {
			env.HasCerts = true
			break
		}
	}

	// Existing config detection
	if _, err := os.Stat("aegisgate-platform.yaml"); err == nil {
		env.HasExistingConfig = true
	}

	// Hostname
	if h, err := os.Hostname(); err == nil {
		env.Hostname = h
	}

	// Data directory detection
	if env.IsDocker || env.IsKubernetes {
		env.DataDir = "/data"
	} else {
		// Local dev: use ./data
		env.DataDir = "./data"
	}

	// Auto-select profile based on environment
	env.DetectedProfile = autoSelectProfile(env)

	return env
}

// autoSelectProfile picks the best default profile for the environment.
func autoSelectProfile(env *Environment) string {
	if env.IsAirGapped {
		return "air-gapped"
	}
	if env.IsKubernetes || env.IsDocker {
		if env.HasCerts {
			return "production"
		}
		return "small-team"
	}
	// Local dev or unknown → quickstart
	return "quickstart"
}

// WizardOptions controls the setup wizard behavior.
type WizardOptions struct {
	NonInteractive bool
	Profile        string // override auto-detected profile
	OutputPath     string // where to write the config file
	Force          bool   // overwrite existing config
	Reader         io.Reader
	Writer         io.Writer
}

// Run executes the setup wizard and returns the path to the generated config
// file (or an error).
func Run(opts *WizardOptions) (string, error) {
	if opts == nil {
		opts = &WizardOptions{}
	}
	if opts.OutputPath == "" {
		opts.OutputPath = "aegisgate-platform.yaml"
	}
	if opts.Reader == nil {
		opts.Reader = os.Stdin
	}
	if opts.Writer == nil {
		opts.Writer = os.Stdout
	}

	w := &wizard{
		opts: opts,
		env:  DetectEnvironment(),
		out:  opts.Writer,
		in:   bufio.NewReader(opts.Reader),
	}

	return w.run()
}

// wizard is the internal state machine for the setup wizard.
type wizard struct {
	opts   *WizardOptions
	env    *Environment
	out    io.Writer
	in     *bufio.Reader
	chosen string // chosen profile ID
	cfg    *platformconfig.Config
}

// write is a safe wrapper around w.out.Write that ignores errors.
// Writing to stdout/stderr has no meaningful error recovery in a CLI wizard.
func (w *wizard) write(data []byte) { //nosec G104 -- intentional: stdout write errors are not actionable
	_, _ = w.out.Write(data)
}

// writeStr is a convenience wrapper for writing strings.
func (w *wizard) writeStr(s string) { //nosec G104 -- intentional: stdout write errors are not actionable
	_, _ = w.out.Write([]byte(s))
}

func (w *wizard) run() (string, error) {
	w.printBanner()
	w.printEnvironment()

	// Step 1: Select profile
	if err := w.selectProfile(); err != nil {
		return "", err
	}

	// Step 2: Generate config from profile
	cfg, err := profiles.ConfigFor(w.chosen)
	if err != nil {
		return "", fmt.Errorf("failed to load profile: %w", err)
	}
	w.cfg = cfg

	// Auto-fill cert paths for TLS profiles that expect user-provided certs.
	// The production and high-security profiles set AutoGenerate=false with
	// empty cert paths. The wizard fills in sensible defaults so the generated
	// config is valid — the user replaces these with real cert paths before
	// starting the platform.
	if w.cfg.TLS.Enabled && !w.cfg.TLS.AutoGenerate {
		if w.cfg.TLS.CertFile == "" {
			w.cfg.TLS.CertFile = filepath.Join(w.cfg.Persistence.DataDir, "certs", "cert.pem")
		}
		if w.cfg.TLS.KeyFile == "" {
			w.cfg.TLS.KeyFile = filepath.Join(w.cfg.Persistence.DataDir, "certs", "key.pem")
		}
	}

	// Step 3: Interactive customization (only in interactive mode)
	if !w.opts.NonInteractive {
		if err := w.customizeConfig(); err != nil {
			return "", err
		}
	}

	// Step 4: Validate config
	w.printStep("Validating configuration...")
	result := w.cfg.Validate()
	w.write([]byte(result.Summary()))
	if result.HasErrors() {
		return "", fmt.Errorf("config validation failed with %d error(s)", len(result.Errors()))
	}

	// Step 5: Check for existing config
	if !w.opts.Force {
		if _, err := os.Stat(w.opts.OutputPath); err == nil {
			if !w.opts.NonInteractive {
				if !w.confirm(fmt.Sprintf("Config file %q already exists. Overwrite?", w.opts.OutputPath)) {
					w.write([]byte("Setup cancelled. Existing config preserved.\n"))
					return "", nil
				}
			} else {
				return "", fmt.Errorf("config file %q already exists — use --force to overwrite", w.opts.OutputPath)
			}
		}
	}

	// Step 6: Write config file
	if err := w.writeConfig(); err != nil {
		return "", err
	}

	// Step 7: Print next steps
	w.printNextSteps()

	return w.opts.OutputPath, nil
}

func (w *wizard) printBanner() {
	w.write([]byte(`
╔══════════════════════════════════════════════════════════════╗
║           AegisGate Setup Wizard — v4.2.0                    ║
║                                                              ║
║  This wizard will generate a configuration file tailored     ║
║  to your environment. No services will be started.           ║
╚══════════════════════════════════════════════════════════════╝
`))
}

func (w *wizard) printEnvironment() {
	env := w.env
	w.write([]byte(fmt.Sprintf("Environment Detection:\n")))
	w.write([]byte(fmt.Sprintf("  Platform:     %s", "")))
	if env.IsDocker {
		w.write([]byte("Docker "))
	}
	if env.IsKubernetes {
		w.write([]byte("Kubernetes "))
	}
	if env.IsSystemd && !env.IsDocker && !env.IsKubernetes {
		w.write([]byte("systemd "))
	}
	if !env.IsDocker && !env.IsKubernetes && !env.IsSystemd {
		w.write([]byte("Local/Bare-metal "))
	}
	if env.IsAirGapped {
		w.write([]byte("(Air-gapped) "))
	}
	w.write([]byte("\n"))

	w.write([]byte(fmt.Sprintf("  Hostname:     %s\n", env.Hostname)))
	w.write([]byte(fmt.Sprintf("  Data dir:     %s\n", env.DataDir)))
	w.write([]byte(fmt.Sprintf("  TLS certs:    %v\n", env.HasCerts)))
	w.write([]byte(fmt.Sprintf("  Existing cfg: %v\n", env.HasExistingConfig)))
	w.write([]byte(fmt.Sprintf("  Recommended:  %s\n\n", env.DetectedProfile)))
}

func (w *wizard) printStep(msg string) {
	w.write([]byte(fmt.Sprintf("\n▸ %s\n", msg)))
}

func (w *wizard) selectProfile() error {
	// If profile is specified via opts, use it
	if w.opts.Profile != "" {
		if !profiles.IsValid(w.opts.Profile) {
			return fmt.Errorf("unknown profile %q — run 'aegisgate --profile list' for options", w.opts.Profile)
		}
		w.chosen = w.opts.Profile
		w.write([]byte(fmt.Sprintf("Using profile: %s\n", w.chosen)))
		return nil
	}

	// Non-interactive: use auto-detected profile
	if w.opts.NonInteractive {
		w.chosen = w.env.DetectedProfile
		w.write([]byte(fmt.Sprintf("Auto-selected profile: %s\n", w.chosen)))
		return nil
	}

	// Interactive: show options and prompt
	w.write([]byte("Available profiles:\n\n"))
	for _, p := range profiles.List() {
		marker := ""
		if string(p.ID) == w.env.DetectedProfile {
			marker = " (recommended)"
		}
		w.write([]byte(fmt.Sprintf("  %-15s [tier: %s]%s\n", p.ID, p.Tier, marker)))
		w.write([]byte(fmt.Sprintf("  %-15s %s\n", "", p.Description)))
		w.write([]byte("\n"))
	}

	for {
		w.write([]byte(fmt.Sprintf("Select profile [%s]: ", w.env.DetectedProfile)))
		input, err := w.readLine()
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
		input = strings.TrimSpace(input)
		if input == "" {
			input = w.env.DetectedProfile
		}
		if profiles.IsValid(input) {
			w.chosen = input
			return nil
		}
		w.write([]byte(fmt.Sprintf("Unknown profile %q. Try again or press Enter for default.\n", input)))
	}
}

func (w *wizard) customizeConfig() error {
	w.printStep("Configuration customization")
	w.write([]byte("Press Enter to accept defaults, or type a new value.\n\n"))

	// Upstream URL
	w.write([]byte(fmt.Sprintf("  Upstream LLM URL [%s]: ", w.cfg.Proxy.Upstream)))
	if input, err := w.readLine(); err == nil {
		input = strings.TrimSpace(input)
		if input != "" {
			w.cfg.Proxy.Upstream = input
		}
	}

	// Proxy port
	w.write([]byte(fmt.Sprintf("  Proxy port [%d]: ", w.cfg.ProxyPort())))
	if input, err := w.readLine(); err == nil {
		input = strings.TrimSpace(input)
		if input != "" {
			var port int
			if _, err := fmt.Sscanf(input, "%d", &port); err == nil && port > 0 && port < 65536 {
				w.cfg.Proxy.BindAddress = fmt.Sprintf("0.0.0.0:%d", port)
			}
		}
	}

	// Dashboard port
	w.write([]byte(fmt.Sprintf("  Dashboard port [%d]: ", w.cfg.Dashboard.Port)))
	if input, err := w.readLine(); err == nil {
		input = strings.TrimSpace(input)
		if input != "" {
			var port int
			if _, err := fmt.Sscanf(input, "%d", &port); err == nil && port > 0 && port < 65536 {
				w.cfg.Dashboard.Port = port
			}
		}
	}

	// TLS
	currentTLS := "off"
	if w.cfg.TLS.Enabled {
		currentTLS = "on"
	}
	w.write([]byte(fmt.Sprintf("  Enable TLS [%s] (on/off): ", currentTLS)))
	if input, err := w.readLine(); err == nil {
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "on" || input == "true" || input == "yes" {
			w.cfg.TLS.Enabled = true
		} else if input == "off" || input == "false" || input == "no" {
			w.cfg.TLS.Enabled = false
		}
	}

	// Data directory
	w.write([]byte(fmt.Sprintf("  Data directory [%s]: ", w.cfg.Persistence.DataDir)))
	if input, err := w.readLine(); err == nil {
		input = strings.TrimSpace(input)
		if input != "" {
			w.cfg.Persistence.DataDir = input
			w.cfg.Persistence.AuditDir = filepath.Join(input, "audit")
			w.cfg.TLS.CertDir = filepath.Join(input, "certs")
		}
	}

	return nil
}

func (w *wizard) writeConfig() error {
	w.printStep(fmt.Sprintf("Writing config to %s...", w.opts.OutputPath))

	// Ensure parent directory exists
	dir := filepath.Dir(w.opts.OutputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil { //nosec G301 — config dir for single-user setup wizard
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	data, err := yaml.Marshal(w.cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Add header comment
	header := fmt.Sprintf("# AegisGate Security Platform Configuration\n# Generated by setup wizard on %s\n# Profile: %s\n#\n# This file can be customized further. Run 'aegisgate config validate %s'\n# to check for errors after manual edits.\n\n", time.Now().Format("2006-01-02 15:04:05"), w.chosen, w.opts.OutputPath)

	content := header + string(data)

	if err := os.WriteFile(w.opts.OutputPath, []byte(content), 0600); err != nil { //nosec G306 — config file with sensitive settings, owner-only access
		return fmt.Errorf("failed to write config file: %w", err)
	}

	w.write([]byte(fmt.Sprintf("  ✓ Config written to %s (%d bytes)\n", w.opts.OutputPath, len(content))))
	return nil
}

func (w *wizard) printNextSteps() {
	w.write([]byte(fmt.Sprintf(`
╔══════════════════════════════════════════════════════════════╗
║  Setup Complete!                                             ║
╚══════════════════════════════════════════════════════════════╝

Next steps:

  1. Review the config:
     cat %s

  2. Validate the config:
     aegisgate config validate %s

  3. Start the platform:
     aegisgate --config %s --embedded-mcp

  4. Open the dashboard:
     https://localhost:%d

  5. (Optional) Generate TLS certs (if TLS is enabled with auto-generate):
     aegisgate will auto-generate certs on first start.

Useful commands:
  aegisgate --profile list       List deploy profiles
  aegisgate config show          Show effective config
  aegisgate status               Check platform posture

`, w.opts.OutputPath, w.opts.OutputPath, w.opts.OutputPath, w.cfg.Dashboard.Port)))
}

func (w *wizard) confirm(question string) bool {
	w.write([]byte(fmt.Sprintf("%s [y/N]: ", question)))
	input, err := w.readLine()
	if err != nil {
		return false
	}
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "y" || input == "yes"
}

func (w *wizard) readLine() (string, error) {
	line, err := w.in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return line, nil
}
