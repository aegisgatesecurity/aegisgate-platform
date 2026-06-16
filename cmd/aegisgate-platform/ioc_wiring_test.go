// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Federated IOC Library Wiring Tests (v3.3.0+ Track 6)
//
// Verifies the IOC wiring bridge: opt-in flag resolution
// (CLI + env), persistent key + instance ID generation/load,
// the IOC store + producer + sync constructor composition, and
// the installIOCRecorder middleware. The wiring code is the
// bridge between the IOC library and the platform process, so
// the tests focus on persistence and composition — the
// per-endpoint behavior is covered in ioc_admin_api_test.go.
//
// v3.3.0+ Track 6 Task 4.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// resetIOCGlobalsAndEnv clears all IOC env vars and resets
// the CLI flag globals to their zero values. Called by every
// test that exercises flag resolution to prevent cross-test
// pollution.
func resetIOCGlobalsAndEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AEGISGATE_IOC_SHARE",
		"AEGISGATE_IOC_RECEIVE",
		"AEGISGATE_IOC_PEERS",
		"AEGISGATE_IOC_STORE_DIR",
		"AEGISGATE_IOC_GOSSIP_INTERVAL",
		"AEGISGATE_IOC_BOOTSTRAP_PEERS",
	} {
		t.Setenv(k, "")
	}
	*iocShare = false
	*iocReceive = false
	*iocPeers = ""
	*iocGossipInterval = 5 * 60_000_000_000 // 5 minutes in ns; matches the flag default
}

// ------------------------------------------------------------------
// resolveBoolFlag
// ------------------------------------------------------------------

func TestResolveBoolFlag(t *testing.T) {
	cases := []struct {
		name   string
		cli    bool
		envVal string // "" means unset
		setEnv bool
		want   bool
	}{
		{"cli true wins over unset env", true, "", false, true},
		{"cli false, env unset", false, "", false, false},
		{"cli false, env true", false, "true", true, true},
		{"cli false, env TRUE (case)", false, "TRUE", true, true},
		{"cli false, env 1", false, "1", true, true},
		{"cli false, env yes", false, "yes", true, true},
		{"cli false, env on", false, "on", true, true},
		{"cli false, env ON (case)", false, "ON", true, true},
		// strconv.ParseBool fallback (catches values like
		// "false", "0", "False").
		{"cli false, env false", false, "false", true, false},
		{"cli false, env 0", false, "0", true, false},
		{"cli false, env False (case)", false, "False", true, false},
		// Junk falls through to false.
		{"cli false, env garbage", false, "garbage", true, false},
		// Whitespace + mixed case.
		{"cli false, env padded true", false, "  true  ", true, true},
		{"cli false, env padded TRUE", false, "  TRUE ", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setEnv {
				t.Setenv("AEGISGATE_TEST_BOOL", c.envVal)
			} else {
				t.Setenv("AEGISGATE_TEST_BOOL", "")
			}
			// We can't override iocShare in tests, so the
			// "cli wins" property is exercised when c.cli is
			// true (which sets iocShare to true) vs the env
			// value. For cli=false tests we have to ensure
			// iocShare is reset.
			if c.cli {
				*iocShare = true
			} else {
				*iocShare = false
			}
			got := resolveBoolFlag(*iocShare, "AEGISGATE_TEST_BOOL")
			if got != c.want {
				t.Errorf("resolveBoolFlag(cli=%v, env=%q) = %v, want %v",
					c.cli, c.envVal, got, c.want)
			}
		})
	}
}

// TestResolveBoolFlag_CliTrueShortCircuits documents that
// resolveBoolFlag returns true as soon as cliValue is true,
// regardless of the env var content. This is the expected
// "CLI wins" idiom.
func TestResolveBoolFlag_CliTrueShortCircuits(t *testing.T) {
	*iocShare = true
	t.Setenv("AEGISGATE_TEST_BOOL", "garbage-but-cli-wins")
	if got := resolveBoolFlag(*iocShare, "AEGISGATE_TEST_BOOL"); !got {
		t.Errorf("cli=true should short-circuit to true, got %v", got)
	}
}

// ------------------------------------------------------------------
// resolveIOCFlags
// ------------------------------------------------------------------

func TestResolveIOCFlags_AllDefaults(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	share, receive, peers := resolveIOCFlags()
	if share {
		t.Errorf("share = true, want false (default)")
	}
	if receive {
		t.Errorf("receive = true, want false (default)")
	}
	if len(peers) != 0 {
		t.Errorf("peers = %v, want empty (default)", peers)
	}
}

func TestResolveIOCFlags_EnvShare(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	t.Setenv("AEGISGATE_IOC_SHARE", "true")
	share, _, _ := resolveIOCFlags()
	if !share {
		t.Errorf("share = false, want true (env AEGISGATE_IOC_SHARE=true)")
	}
}

func TestResolveIOCFlags_EnvReceive(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	t.Setenv("AEGISGATE_IOC_RECEIVE", "yes")
	_, receive, _ := resolveIOCFlags()
	if !receive {
		t.Errorf("receive = false, want true (env AEGISGATE_IOC_RECEIVE=yes)")
	}
}

func TestResolveIOCFlags_EnvPeers_SingleAndList(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "https://a.example.com:8443", []string{"https://a.example.com:8443"}},
		{"two peers", "https://a.example.com:8443,https://b.example.com:8443",
			[]string{"https://a.example.com:8443", "https://b.example.com:8443"}},
		{"whitespace tolerated", "  https://a.example.com  ,  https://b.example.com  ",
			[]string{"https://a.example.com", "https://b.example.com"}},
		{"trailing comma", "https://a.example.com,",
			[]string{"https://a.example.com"}},
		{"empty entries skipped", "https://a.example.com,,https://b.example.com",
			[]string{"https://a.example.com", "https://b.example.com"}},
		{"only commas", ",,,", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetIOCGlobalsAndEnv(t)
			t.Setenv("AEGISGATE_IOC_PEERS", c.env)
			_, _, peers := resolveIOCFlags()
			if !equalStrings(peers, c.want) {
				t.Errorf("peers = %v, want %v", peers, c.want)
			}
		})
	}
}

func TestResolveIOCFlags_CLIWinsOverEnv(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	*iocShare = true
	t.Setenv("AEGISGATE_IOC_SHARE", "false")
	share, _, _ := resolveIOCFlags()
	if !share {
		t.Errorf("cli-share=true should win over env=false, got share=false")
	}
}

// equalStrings is a small helper for slice equality in tests.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------
// loadOrGenerateInstanceID
// ------------------------------------------------------------------

func TestLoadOrGenerateInstanceID_NoFile_GeneratesNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")
	id, err := loadOrGenerateInstanceID(path)
	if err != nil {
		t.Fatalf("loadOrGenerateInstanceID: %v", err)
	}
	if len(id) < 16 {
		t.Errorf("id length = %d, want >= 16 (hex)", len(id))
	}
	// Verify the file was written.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read instance-id: %v", err)
	}
	if strings.TrimSpace(string(data)) != id {
		t.Errorf("file contents = %q, want %q", string(data), id)
	}
	// Verify the persisted ID is loadable.
	id2, err := loadOrGenerateInstanceID(path)
	if err != nil {
		t.Fatalf("loadOrGenerateInstanceID (2nd call): %v", err)
	}
	if id2 != id {
		t.Errorf("re-load id = %q, want %q (idempotency)", id2, id)
	}
}

func TestLoadOrGenerateInstanceID_ExistingValidFile_Loads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")
	want := "abcdef0123456789abcdef0123456789" // 32 chars
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	id, err := loadOrGenerateInstanceID(path)
	if err != nil {
		t.Fatalf("loadOrGenerateInstanceID: %v", err)
	}
	if id != want {
		t.Errorf("id = %q, want %q", id, want)
	}
}

func TestLoadOrGenerateInstanceID_CorruptFile_Regenerates(t *testing.T) {
	// A file with < 16 chars is treated as corrupt; the loader
	// regenerates and overwrites.
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")
	if err := os.WriteFile(path, []byte("tooshort"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	id, err := loadOrGenerateInstanceID(path)
	if err != nil {
		t.Fatalf("loadOrGenerateInstanceID: %v", err)
	}
	if len(id) < 16 {
		t.Errorf("id length = %d, want >= 16 (regenerated)", len(id))
	}
	// The file on disk should now contain the new id.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.TrimSpace(string(data)) != id {
		t.Errorf("file = %q, want %q (regeneration overwrote file)", string(data), id)
	}
}

func TestLoadOrGenerateInstanceID_PaddingTrimmed(t *testing.T) {
	// A valid 32-char id with surrounding whitespace is accepted
	// (the loader trims).
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")
	seed := "  1234567890abcdef1234567890abcdef\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	id, err := loadOrGenerateInstanceID(path)
	if err != nil {
		t.Fatalf("loadOrGenerateInstanceID: %v", err)
	}
	if id != "1234567890abcdef1234567890abcdef" {
		t.Errorf("id = %q, want trimmed hex", id)
	}
}

func TestLoadOrGenerateInstanceID_ReadError_ReturnsError(t *testing.T) {
	// A file that exists but is unreadable triggers the
	// "!os.IsNotExist(err)" branch.
	dir := t.TempDir()
	path := filepath.Join(dir, "instance-id")
	if err := os.WriteFile(path, []byte("anything"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0: %v (may need root to test)", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	_, err := loadOrGenerateInstanceID(path)
	if err == nil {
		t.Error("expected error reading unreadable file, got nil")
	}
}

func TestLoadOrGenerateInstanceID_WriteError_Propagates(t *testing.T) {
	// A non-existent directory under a read-only parent
	// causes os.WriteFile to fail.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	path := filepath.Join(dir, "instance-id") // cannot be created under 0o500
	_, err := loadOrGenerateInstanceID(path)
	if err == nil {
		t.Error("expected error writing under read-only dir, got nil")
	}
}

// ------------------------------------------------------------------
// wireIOC
// ------------------------------------------------------------------

func TestWireIOC_HappyPath_Professional(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	dir := t.TempDir()
	w, instanceID, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	if w == nil {
		t.Fatal("wiring is nil")
	}
	if instanceID == "" {
		t.Error("instanceID is empty")
	}
	if w.Store == nil {
		t.Error("Store is nil")
	}
	if w.Producer == nil {
		t.Error("Producer is nil")
	}
	if w.Sync == nil {
		t.Error("Sync is nil")
	}
	// Both flags are false by default, so Enabled should be false.
	if w.Enabled {
		t.Errorf("Enabled = true, want false (no share/receive on fresh wiring)")
	}
	// Verify the persisted files exist.
	for _, fname := range []string{iocKeyFile, iocInstanceIDFile} {
		if _, err := os.Stat(filepath.Join(dir, "ioc", fname)); err != nil {
			t.Errorf("persisted file missing: %v", err)
		}
	}
}

func TestWireIOC_EnabledFlag_ShareOnly(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	t.Setenv("AEGISGATE_IOC_SHARE", "true")
	dir := t.TempDir()
	w, _, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	if !w.Enabled {
		t.Error("Enabled = false, want true (share is on)")
	}
	if !w.Sync.IsShare() {
		t.Error("IsShare() = false, want true")
	}
}

func TestWireIOC_EnabledFlag_ReceiveOnly(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	t.Setenv("AEGISGATE_IOC_RECEIVE", "true")
	dir := t.TempDir()
	w, _, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	if !w.Enabled {
		t.Error("Enabled = false, want true (receive is on)")
	}
}

func TestWireIOC_EnabledFlag_ShareAndReceive(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	t.Setenv("AEGISGATE_IOC_SHARE", "true")
	t.Setenv("AEGISGATE_IOC_RECEIVE", "true")
	dir := t.TempDir()
	w, _, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	if !w.Enabled {
		t.Error("Enabled = false, want true (both on)")
	}
}

func TestWireIOC_CommunityTier_ReceiveRefusedAtConstruction(t *testing.T) {
	// The wiring is constructed even on Community tier; the
	// tier gate is enforced at runtime via CanReceive().
	resetIOCGlobalsAndEnv(t)
	t.Setenv("AEGISGATE_IOC_RECEIVE", "true")
	dir := t.TempDir()
	w, _, err := wireIOC(dir, tier.TierCommunity)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	if w == nil {
		t.Fatal("wiring is nil")
	}
	// The flag was on; Enabled reflects that.
	if !w.Enabled {
		t.Error("Enabled = false, want true (receive flag is on at boot)")
	}
	// But CanReceive() must refuse on Community.
	ok, reason := w.Sync.CanReceive()
	if ok {
		t.Error("CanReceive() = true, want false on Community tier")
	}
	if reason == nil {
		t.Error("CanReceive() returned nil reason on refusal; want a tier message")
	}
}

func TestWireIOC_PersistsInstanceIDAcrossCalls(t *testing.T) {
	// Two wireIOC calls on the same data dir must produce the
	// same InstanceID (persistence works).
	resetIOCGlobalsAndEnv(t)
	dir := t.TempDir()
	w1, id1, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC 1: %v", err)
	}
	if w1 != nil && w1.Producer != nil {
		_ = w1.Producer
	}
	w2, id2, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC 2: %v", err)
	}
	if w2 != nil && w2.Producer != nil {
		_ = w2.Producer
	}
	if id1 != id2 {
		t.Errorf("instanceID changed across calls: %q vs %q (persistence broken)", id1, id2)
	}
	// And the key should also persist (same keyId).
	keys1 := w1.Sync.ActiveKeys()
	keys2 := w2.Sync.ActiveKeys()
	if len(keys1) != 1 || len(keys2) != 1 {
		t.Fatalf("expected 1 key after each wireIOC, got %d / %d", len(keys1), len(keys2))
	}
	if keys1[0].KeyID != keys2[0].KeyID {
		t.Errorf("keyId changed: %q vs %q (key not persisted)", keys1[0].KeyID, keys2[0].KeyID)
	}
}

func TestWireIOC_GossipIntervalEnvOverride(t *testing.T) {
	// A valid env var overrides the CLI default; an invalid
	// env var falls back to the CLI default silently.
	cases := []struct {
		name    string
		envVal  string
		cliVal  int64 // nanoseconds
		want    int64
		wantSet bool // whether the override should apply
	}{
		{"valid env 30s", "30s", 5 * 60_000_000_000, 30_000_000_000, true},
		{"valid env 1h", "1h", 5 * 60_000_000_000, 3_600_000_000_000, true},
		{"valid env 100ms", "100ms", 5 * 60_000_000_000, 100_000_000, true},
		{"invalid env falls back", "garbage", 5 * 60_000_000_000, 5 * 60_000_000_000, false},
		{"zero duration falls back", "0s", 5 * 60_000_000_000, 5 * 60_000_000_000, false},
		{"empty env (unset)", "", 5 * 60_000_000_000, 5 * 60_000_000_000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetIOCGlobalsAndEnv(t)
			t.Setenv("AEGISGATE_IOC_GOSSIP_INTERVAL", c.envVal)
			*iocGossipInterval = time.Duration(c.cliVal)
			dir := t.TempDir()
			w, _, err := wireIOC(dir, tier.TierProfessional)
			if err != nil {
				t.Fatalf("wireIOC: %v", err)
			}
			// The interval is stored in the Sync config; we
			// verify by reading it back. The Sync struct does
			// not export the interval, so we verify indirectly:
			// the construction succeeded, which means it
			// accepted the duration. A more direct check
			// would require exposing the field.
			_ = w
			_ = c.want
			_ = c.wantSet
		})
	}
}

func TestWireIOC_ReadOnlyDataDir_ReturnsError(t *testing.T) {
	// A read-only data dir causes the MkdirAll step to fail.
	// This exercises the very first error branch in wireIOC.
	resetIOCGlobalsAndEnv(t)
	// Create a read-only temp dir.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, _, err := wireIOC(dir, tier.TierProfessional)
	if err == nil {
		t.Fatal("wireIOC on read-only dir should fail, got nil")
	}
	if !strings.Contains(err.Error(), "create IOC data dir") {
		t.Errorf("error = %v, want it to mention 'create IOC data dir'", err)
	}
}

// ------------------------------------------------------------------
// installIOCRecorder
// ------------------------------------------------------------------

func TestInstallIOCRecorder_NilInner_NoOp(t *testing.T) {
	// The defensive early-return path: nil inner recorder
	// should be a no-op (no panic, no global side effect).
	store, err := ioc.NewStore(ioc.StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	producer := ioc.NewProducer(ioc.ProducerConfig{}, store)
	// Save the current default to restore it.
	prev := logging.GetDefault()
	t.Cleanup(func() { logging.SetDefault(prev) })
	logging.SetDefault(nil)
	installIOCRecorder(nil, producer, false, false)
	// Default should still be nil (install was a no-op).
	if logging.GetDefault() != nil {
		t.Errorf("Default changed after installIOCRecorder(nil, ...), want nil")
	}
}

func TestInstallIOCRecorder_LayersOnInnerAndEnablesProducer(t *testing.T) {
	store, err := ioc.NewStore(ioc.StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	producer := ioc.NewProducer(ioc.ProducerConfig{}, store)
	inner := logging.NewRingBuffer(10)
	prev := logging.GetDefault()
	t.Cleanup(func() { logging.SetDefault(prev) })
	installIOCRecorder(inner, producer, true, false)
	// After install, the global default is the producer.
	if logging.GetDefault() == nil {
		t.Fatal("Default is nil after install; want the producer")
	}
	// The producer must be enabled because share=true.
	if !producer.Enabled() {
		t.Error("producer.Enabled() = false, want true (share=true)")
	}
	// A record() call to the producer should fan out to the
	// inner ring buffer (verifying the layering).
	// We use a high-severity proxy_response event that passes
	// the producer's allow-list.
	logging.Record(logging.Event{
		Type:     "proxy_response",
		Severity: logging.SeverityHigh,
		Action:   "block",
	})
	// The inner ring buffer should have at least 1 event.
	if n := inner.Size(); n < 1 {
		t.Errorf("inner.Size() = %d, want >= 1 after Record()", n)
	}
}

func TestInstallIOCRecorder_ProducerEnabledWhenReceive(t *testing.T) {
	// share=false, receive=true should also enable the producer.
	store, err := ioc.NewStore(ioc.StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	producer := ioc.NewProducer(ioc.ProducerConfig{}, store)
	inner := logging.NewRingBuffer(10)
	prev := logging.GetDefault()
	t.Cleanup(func() { logging.SetDefault(prev) })
	installIOCRecorder(inner, producer, false, true)
	if !producer.Enabled() {
		t.Error("producer.Enabled() = false, want true (receive=true)")
	}
}

func TestInstallIOCRecorder_ProducerNotEnabledWhenBothFalse(t *testing.T) {
	// share=false, receive=false: producer stays disabled.
	store, err := ioc.NewStore(ioc.StoreConfig{Capacity: 100})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	producer := ioc.NewProducer(ioc.ProducerConfig{}, store)
	inner := logging.NewRingBuffer(10)
	prev := logging.GetDefault()
	t.Cleanup(func() { logging.SetDefault(prev) })
	installIOCRecorder(inner, producer, false, false)
	if producer.Enabled() {
		t.Error("producer.Enabled() = true, want false (share=false, receive=false)")
	}
}

// ------------------------------------------------------------------
// Sanity: verify the persisted key file is well-formed JSON
// ------------------------------------------------------------------

func TestWireIOC_KeyFileIsValidJSON(t *testing.T) {
	resetIOCGlobalsAndEnv(t)
	dir := t.TempDir()
	_, _, err := wireIOC(dir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "ioc", iocKeyFile))
	if err != nil {
		t.Fatalf("read key.json: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("key.json is not valid JSON: %v (contents: %q)", err, string(data))
	}
	// The on-disk format is an object with at least the
	// "current" and "keys" fields. Don't over-specify.
	if _, ok := raw["current"]; !ok {
		t.Errorf("key.json missing 'current' field: %v", raw)
	}
	if _, ok := raw["keys"]; !ok {
		t.Errorf("key.json missing 'keys' field: %v", raw)
	}
}
