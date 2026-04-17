// Package commands provides the CLI command implementations for AegisGuard
package commands

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// Version information (set by linker at build time)
var (
	version = "0.1.0"
	commit  = "dev"
	date    = "development"
	builtBy = "aegisguard"
)

// VersionInfo contains version details
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	BuiltBy   string `json:"built_by"`
}

// GetVersion returns the current version info
func GetVersion() VersionInfo {
	return VersionInfo{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		BuiltBy:   builtBy,
	}
}

// PrintVersion prints version information to stdout
func PrintVersion() {
	v := GetVersion()

	fmt.Printf("AegisGuard - AI Agent Security Platform\n")
	fmt.Printf("======================================\n\n")
	fmt.Printf("Version:    %s\n", v.Version)
	fmt.Printf("Commit:     %s\n", v.Commit)
	fmt.Printf("Build Date: %s\n", v.Date)
	fmt.Printf("Built By:   %s\n", v.BuiltBy)
	fmt.Printf("\n")
	fmt.Printf("Go Version: %s\n", v.GoVersion)
	fmt.Printf("OS/Arch:    %s/%s\n", v.OS, v.Arch)
}

// PrintVersionJSON prints version as JSON
func PrintVersionJSON() {
	v := GetVersion()
	fmt.Printf(`{
  "name": "aegisguard",
  "version": "%s",
  "commit": "%s",
  "date": "%s",
  "go_version": "%s",
  "os": "%s",
  "arch": "%s",
  "built_by": "%s"
}
`, v.Version, v.Commit, v.Date, v.GoVersion, v.OS, v.Arch, v.BuiltBy)
}

// PrintVersionShort prints a one-line version string
func PrintVersionShort() {
	fmt.Printf("aegisguard %s (%s)\n", version, commit)
}

// NewVersionCommand creates the version subcommand
func NewVersionCommand() *cobra.Command {
	var short bool
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Display version and build information for AegisGuard.

Examples:
  aegisguard version          # Full version info
  aegisguard version --short  # One-line version
  aegisguard version --json   # JSON output`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput {
				PrintVersionJSON()
			} else if short {
				PrintVersionShort()
			} else {
				PrintVersion()
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&short, "short", "s", false, "Print just the version string")
	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")

	return cmd
}

// CheckVersion checks if current version is up to date (placeholder)
func CheckVersion() error {
	// In a real implementation, this would check against a version server
	fmt.Printf("Note: Version check is not available in development builds.\n")
	return nil
}

// IsDevBuild returns true if running a development build
func IsDevBuild() bool {
	return strings.Contains(commit, "dev") || commit == ""
}

// BuildInfo returns a formatted build info string
func BuildInfo() string {
	if IsDevBuild() {
		return fmt.Sprintf("Development Build (Go %s, %s/%s)",
			runtime.Version(), runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("Release %s (Commit: %s, Built: %s)", version, commit, date)
}

// LicenseInfo prints license information
func LicenseInfo() {
	fmt.Printf(`AegisGuard License
==================

Copyright (c) 2024 AegisGuard Security
All rights reserved.

This software is provided under a proprietary license.
For license information, visit: https://aegisguard.io/license

Third-party licenses are available in the NOTICES file.
`)
}

// PrintFullInfo prints comprehensive version and system information
func PrintFullInfo() {
	PrintVersion()
	fmt.Println()
	fmt.Println("Build Info: ", BuildInfo())
	fmt.Println()
	LicenseInfo()
}

// VersionMismatchError represents a version compatibility issue
type VersionMismatchError struct {
	Current   string
	Required  string
	Component string
}

func (e *VersionMismatchError) Error() string {
	return fmt.Sprintf("version mismatch for %s: current=%s, required=%s",
		e.Component, e.Current, e.Required)
}

// CheckCompatibility checks if the current version meets requirements
func CheckCompatibility(requiredVersion string) error {
	// Simple version check - in production would use semver
	if version == "0.0.0" || version == "" {
		return nil // Dev builds always allowed
	}
	return nil
}

// ExportVersion returns version info as a map (useful for API responses)
func ExportVersion() map[string]string {
	v := GetVersion()
	return map[string]string{
		"version":    v.Version,
		"commit":     v.Commit,
		"build_date": v.Date,
		"go_version": v.GoVersion,
		"os":         v.OS,
		"arch":       v.Arch,
	}
}
