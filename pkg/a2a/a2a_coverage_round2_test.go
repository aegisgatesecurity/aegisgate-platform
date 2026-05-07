// SPDX-License-Identifier: Apache-2.0
//go:build !race

package a2a

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// =============================================================================
// Fill remaining gaps — no duplicates from existing *_test.go files
// =============================================================================

// --- LoadConfig: file read error (93.8% → 95%+) ---
func TestLoadConfig_FileReadError(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configsDir, "config.yaml")
	if err := os.WriteFile(path, []byte(`secret: "test"
rate_limit:
  capacity: 100
  refill: 10
  interval: 1m`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	defer os.Chmod(path, 0644)
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for unreadable config file")
	}
}

// --- LoadFromYAML: LoadCaps error path (75% → 95%+) ---
func TestLoadFromYAML_LoadCapsError(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "caps.json")
	pce, err := NewPersistentCapEnforcer(jsonPath)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}
	// Path not in configs/ directory → LoadCaps returns error
	badYAMLPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAMLPath, []byte(`agents: {}`), 0644); err != nil {
		t.Fatal(err)
	}
	err = pce.LoadFromYAML(badYAMLPath)
	if err == nil {
		t.Error("expected error when YAML path not in configs/ directory")
	}
}

// --- LoadFromYAML: saveLocked error (75% → 95%+) ---
func TestLoadFromYAML_SaveLockedError(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "caps.json")
	// Set up the dir so NewPersistentCapEnforcer works
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(configsDir, "caps.yaml")
	if err := os.WriteFile(yamlPath, []byte(`agents:
  agent-from-yaml:
    - read
    - write
`), 0644); err != nil {
		t.Fatal(err)
	}

	pce, err := NewPersistentCapEnforcer(jsonPath)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}
	// Make the directory read-only so saveLocked fails
	if err := os.Chmod(dir, 0555); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	defer os.Chmod(dir, 0755)
	err = pce.LoadFromYAML(yamlPath)
	if err == nil {
		t.Error("expected error when LoadFromYAML save fails")
	}
}

// --- saveLocked: WriteFile error (83.3% → 95%+) ---
// This is exercised through SetCapabilities when the dir is read-only.
// Already covered by TestPersistentCapEnforcer_SaveLocked_WriteError in
// a2a_coverage_hardening_test.go. Also test it through direct SetCapabilities.
func TestSaveLocked_WriteFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")
	pce, err := NewPersistentCapEnforcer(path)
	if err != nil {
		t.Fatalf("NewPersistentCapEnforcer() error: %v", err)
	}
	if err := pce.SetCapabilities("agent-init", []string{"read"}); err != nil {
		t.Fatalf("SetCapabilities() error: %v", err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	defer os.Chmod(dir, 0755)
	err = pce.SetCapabilities("agent-write-fail", []string{"write"})
	if err == nil {
		t.Error("expected error when saveLocked WriteFile fails")
	}
}

// --- ServeHTTP: next handler panics with license manager active ---
func TestServeHTTP_PanicWithLicenseManager(t *testing.T) {
	lm, err := license.NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	caps := NewInMemoryCapEnforcer()
	caps.SetCapabilities("agent-panic", []string{"echo"})
	m := NewA2AMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("panic-with-license")
		}),
		[]byte("secret"),
		lm,
		caps,
	)
	req := signedRequestWithCert([]byte("secret"), []byte(`{}`), "echo", "agent-panic")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- ServeHTTP: license check passes, mTLS passes, rate passes, then panic ---
func TestServeHTTP_PanicAfterEarlyGuards(t *testing.T) {
	caps := NewInMemoryCapEnforcer()
	caps.SetCapabilities("agent-mid-panic", []string{"echo"})
	m := NewA2AMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic("panic-mid-chain")
		}),
		[]byte("secret"),
		nil, // no license manager
		caps,
	)
	req := signedRequestWithCert([]byte("secret"), []byte(`{}`), "echo", "agent-mid-panic")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("code=%d, want %d", w.Code, http.StatusForbidden)
	}
}

// --- LoadCaps: valid config with agents (78.6% → 95%+) ---
func TestLoadCaps_ValidMultiAgentConfig(t *testing.T) {
	dir := t.TempDir()
	configsDir := filepath.Join(dir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configsDir, "caps.yaml")
	if err := os.WriteFile(path, []byte(`agents:
  agent-a:
    - read
    - write
  agent-b:
    - execute
`), 0644); err != nil {
		t.Fatal(err)
	}
	caps, err := LoadCaps(path)
	if err != nil {
		t.Fatalf("LoadCaps() error: %v", err)
	}
	if len(caps) != 2 {
		t.Errorf("got %d agents, want 2", len(caps))
	}
	if caps["agent-a"] == nil {
		t.Error("agent-a should have capabilities")
	}
}
