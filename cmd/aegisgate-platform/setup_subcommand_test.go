// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Platform — Setup Subcommand Tests
// =========================================================================

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetupSubcommandNonInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")
	exit := runSetupSubcommand([]string{"--non-interactive", "--output", outPath})
	if exit != 0 {
		t.Errorf("Expected exit 0, got %d", exit)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("Config file should exist: %v", err)
	}
}

func TestSetupSubcommandWithProfile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")
	exit := runSetupSubcommand([]string{"--non-interactive", "--profile", "quickstart", "--output", outPath})
	if exit != 0 {
		t.Errorf("Expected exit 0, got %d", exit)
	}
}

func TestSetupSubcommandInvalidProfile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")
	exit := runSetupSubcommand([]string{"--non-interactive", "--profile", "bogus", "--output", outPath})
	if exit == 0 {
		t.Error("Expected non-zero exit for invalid profile")
	}
}

func TestSetupSubcommandForce(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")
	// Create existing file
	os.WriteFile(outPath, []byte("existing"), 0644)
	exit := runSetupSubcommand([]string{"--non-interactive", "--force", "--output", outPath})
	if exit != 0 {
		t.Errorf("Expected exit 0 with --force, got %d", exit)
	}
	data, _ := os.ReadFile(outPath)
	if string(data) == "existing" {
		t.Error("File should have been overwritten")
	}
}

func TestSetupSubcommandNoForceFails(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(outPath, []byte("existing"), 0644)
	exit := runSetupSubcommand([]string{"--non-interactive", "--output", outPath})
	if exit == 0 {
		t.Error("Expected non-zero exit without --force when file exists")
	}
}

func TestIsSetupSubcommand(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"aegisgate", "setup"}
	if !isSetupSubcommand() {
		t.Error("isSetupSubcommand should return true for 'setup'")
	}

	os.Args = []string{"aegisgate", "--config", "file.yaml"}
	if isSetupSubcommand() {
		t.Error("isSetupSubcommand should return false for --config flag")
	}
}
