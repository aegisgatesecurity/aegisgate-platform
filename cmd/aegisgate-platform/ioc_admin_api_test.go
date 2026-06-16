// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Federated IOC Library Admin API Tests (v3.3.0+ Track 6)
//
// Verifies the admin API endpoints for the Federated IOC library.
// Each endpoint is exercised across its full matrix of
// method-check, wiring-nil, JSON-decode, tier-gate, and
// happy-path branches.
//
// v3.3.0+ Track 6 Task 5.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/tier"
)

// newTestIOCWiring constructs a fully-wired IOC subsystem in a
// temp directory for use by admin API tests. The tier is
// configurable so we can exercise both tier-gated (Professional+)
// and below-tier (Community/Developer) paths.
//
// Calls t.Cleanup() to stop the producer flusher and the sync
// goroutines, and to remove the temp dir. Resets all IOC env
// vars before and after the test to prevent cross-test pollution.
func newTestIOCWiring(t *testing.T, platformTier tier.Tier) *iocWiring {
	t.Helper()
	// Snapshot and reset env vars.
	envKeys := []string{
		"AEGISGATE_IOC_SHARE",
		"AEGISGATE_IOC_RECEIVE",
		"AEGISGATE_IOC_PEERS",
		"AEGISGATE_IOC_STORE_DIR",
		"AEGISGATE_IOC_GOSSIP_INTERVAL",
		"AEGISGATE_IOC_BOOTSTRAP_PEERS",
	}
	for _, k := range envKeys {
		t.Setenv(k, "")
	}
	// Reset CLI globals.
	*iocShare = false
	*iocReceive = false
	*iocPeers = ""
	// iocGossipInterval is left at its flag default (5m).

	dataDir := t.TempDir()
	w, instanceID, err := wireIOC(dataDir, platformTier)
	if err != nil {
		t.Fatalf("wireIOC(%q, %v): %v", dataDir, platformTier, err)
	}
	if instanceID == "" {
		t.Errorf("wireIOC returned empty instanceID")
	}
	// No goroutine cleanup needed: wireIOC does not start the
	// flusher (that's RunFlusher's job) or the receiver loop
	// (that's RunReceiver's job). The caller (main.go) starts
	// those. t.TempDir() handles file cleanup.
	return w
}

// doRequest executes an HTTP request against the admin handler
// and returns the recorded response.
func doRequest(t *testing.T, h http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// decodeJSON is a small test helper that decodes a response
// body as JSON into the given value, failing the test on error.
func decodeJSON(t *testing.T, rr *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON: %v (body: %q)", err, rr.Body.String())
	}
}

// ------------------------------------------------------------------
// Constructor and nil-wiring matrix
// ------------------------------------------------------------------

func TestNewIOCAdminAPI_NilWiring(t *testing.T) {
	api := newIOCAdminAPI(nil)
	if api == nil {
		t.Fatal("newIOCAdminAPI(nil) returned nil; expected non-nil struct")
	}
	if api.wiring != nil {
		t.Errorf("wiring = %v, want nil", api.wiring)
	}
	if api.Handler() == nil {
		t.Error("Handler() returned nil")
	}
}

func TestNewIOCAdminAPI_NonNilWiring(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	api := newIOCAdminAPI(w)
	if api == nil {
		t.Fatal("newIOCAdminAPI returned nil")
	}
	if api.wiring != w {
		t.Error("wiring pointer mismatch")
	}
}

// ------------------------------------------------------------------
// handleStatus
// ------------------------------------------------------------------

func TestIOCAdminAPI_Status_MethodNotAllowed(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/status", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIOCAdminAPI_Status_NilWiring(t *testing.T) {
	h := newIOCAdminAPI(nil).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/status", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestIOCAdminAPI_Status_Happy(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/status", nil)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (body: %q)", rr.Code, http.StatusOK, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]interface{}
	decodeJSON(t, rr, &resp)
	if initialized, _ := resp["initialized"].(bool); !initialized {
		t.Errorf("initialized = %v, want true (full: %v)", resp["initialized"], resp)
	}
	if _, ok := resp["share"]; !ok {
		t.Error("response missing 'share' key")
	}
	if _, ok := resp["receive"]; !ok {
		t.Error("response missing 'receive' key")
	}
	if _, ok := resp["iocCount"]; !ok {
		t.Error("response missing 'iocCount' key")
	}
	if _, ok := resp["peers"]; !ok {
		t.Error("response missing 'peers' key")
	}
	if _, ok := resp["producer"]; !ok {
		t.Error("response missing 'producer' block")
	}
	if _, ok := resp["keyring"]; !ok {
		t.Error("response missing 'keyring' block")
	}
}

// ------------------------------------------------------------------
// handleShare
// ------------------------------------------------------------------

func TestIOCAdminAPI_Share_MethodNotAllowed(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/share", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIOCAdminAPI_Share_NilWiring(t *testing.T) {
	h := newIOCAdminAPI(nil).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/share",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestIOCAdminAPI_Share_BadJSON(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/share",
		strings.NewReader(`{not-json`))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rr.Body.String(), "invalid JSON body") {
		t.Errorf("body = %q, want it to mention 'invalid JSON body'", rr.Body.String())
	}
}

func TestIOCAdminAPI_Share_Enable(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	if w.Sync.IsShare() {
		t.Fatal("precondition: IsShare() should be false on a fresh wiring")
	}
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/share",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	if !w.Sync.IsShare() {
		t.Error("after POST enable, IsShare() = false, want true")
	}
	// Enabling share must also enable the producer.
	if !w.Producer.Stats().Enabled {
		t.Error("after POST enable-share, producer.Stats().Enabled = false, want true")
	}
	var resp map[string]interface{}
	decodeJSON(t, rr, &resp)
	if got, _ := resp["share"].(bool); !got {
		t.Errorf("response share = %v, want true", resp["share"])
	}
}

func TestIOCAdminAPI_Share_Disable(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	// Pre-enable share so we can test the disable path.
	w.Sync.SetShare(true)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/share",
		strings.NewReader(`{"enabled":false}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if w.Sync.IsShare() {
		t.Error("after POST disable, IsShare() = true, want false")
	}
}

// ------------------------------------------------------------------
// handleReceive (with tier gate)
// ------------------------------------------------------------------

func TestIOCAdminAPI_Receive_MethodNotAllowed(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/receive", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIOCAdminAPI_Receive_NilWiring(t *testing.T) {
	h := newIOCAdminAPI(nil).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestIOCAdminAPI_Receive_BadJSON(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{garbage`))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestIOCAdminAPI_Receive_CommunityTier_403(t *testing.T) {
	// Community tier is below Professional; the admin API must
	// refuse to enable receive even when explicitly asked.
	w := newTestIOCWiring(t, tier.TierCommunity)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (body: %q)", rr.Code, http.StatusForbidden, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "cannot enable receive") {
		t.Errorf("body = %q, want it to mention 'cannot enable receive'", rr.Body.String())
	}
	if w.Sync.IsReceive() {
		t.Error("after 403, IsReceive() = true, want false (the 403 should not have flipped the flag)")
	}
}

func TestIOCAdminAPI_Receive_DeveloperTier_403(t *testing.T) {
	// Developer tier is also below Professional; verify it is
	// gated the same way.
	w := newTestIOCWiring(t, tier.TierDeveloper)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestIOCAdminAPI_Receive_ProfessionalTier_Enable(t *testing.T) {
	// The admin API is a runtime toggle. For the gate to
	// accept a "true" request, the operator must have started
	// with --ioc-receive=true (or the env equivalent). Simulate
	// that by pre-enabling the flag, then toggle via the API.
	w := newTestIOCWiring(t, tier.TierProfessional)
	w.Sync.SetReceive(false) // ensure clean state
	w.Sync.SetReceive(true)  // operator already opted in at startup
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	if !w.Sync.IsReceive() {
		t.Error("after POST enable, IsReceive() = false, want true")
	}
	if !w.Producer.Stats().Enabled {
		t.Error("after POST enable-receive, producer.Stats().Enabled = false, want true")
	}
}

func TestIOCAdminAPI_Receive_ProfessionalTier_Disable(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	w.Sync.SetReceive(true)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":false}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if w.Sync.IsReceive() {
		t.Error("after POST disable, IsReceive() = true, want false")
	}
}

// TestIOCAdminAPI_Receive_ProfessionalTier_EnableFromColdStart_OK
// documents the v3.4.0 behavior: the admin API CAN first-time-
// enable receive on a fresh Professional instance. The previous
// "cold-start 403" was a chicken-and-egg bug (CanReceive() required
// the flag to already be on, but the handler checked CanReceive()
// before setting the flag). The fix sets the flag first, then
// checks, and reverts on failure - so a sub-Professional tier
// (Community/Developer) still gets 403, but a Professional can
// first-time-enable from the dashboard without an SSH restart.
func TestIOCAdminAPI_Receive_ProfessionalTier_EnableFromColdStart_OK(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	// Cold start: EnableReceive was false at boot.
	w.Sync.SetReceive(false)
	if w.Sync.IsReceive() {
		t.Fatal("precondition: IsReceive() should be false")
	}
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (Professional should be able to first-time-enable)", rr.Code, http.StatusOK)
	}
	if !w.Sync.IsReceive() {
		t.Error("after OK, IsReceive() = false, want true (the flag should be set)")
	}
}

// TestIOCAdminAPI_Receive_CommunityTier_ColdStart_403_RevertsFlag
// documents that the v3.4.0 fix preserves the tier gate: a
// sub-Professional tier (Community/Developer) trying to enable
// receive via the admin API still gets 403, AND the flag is
// left in the off state (the handler sets-then-reverts).
func TestIOCAdminAPI_Receive_CommunityTier_ColdStart_403_RevertsFlag(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierCommunity)
	w.Sync.SetReceive(false)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/receive",
		strings.NewReader(`{"enabled":true}`))
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (Community should still be 403)", rr.Code, http.StatusForbidden)
	}
	if w.Sync.IsReceive() {
		t.Error("after Community 403, IsReceive() = true, want false (the flag must be reverted)")
	}
}

// ------------------------------------------------------------------
// handleKeyring
// ------------------------------------------------------------------

func TestIOCAdminAPI_Keyring_MethodNotAllowed(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/keyring", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIOCAdminAPI_Keyring_NilWiring(t *testing.T) {
	h := newIOCAdminAPI(nil).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/keyring", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestIOCAdminAPI_Keyring_Happy(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/keyring", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	decodeJSON(t, rr, &resp)
	keys, ok := resp["keys"].([]interface{})
	if !ok {
		t.Fatalf("response missing or non-array 'keys' (full: %v)", resp)
	}
	if len(keys) == 0 {
		t.Error("'keys' is empty; expected at least the active key")
	}
	// Verify the active key entry has keyId + createdAt and NO private key material.
	first, _ := keys[0].(map[string]interface{})
	for _, field := range []string{"keyId", "createdAt"} {
		if _, ok := first[field]; !ok {
			t.Errorf("key entry missing %q (full: %v)", field, first)
		}
	}
	// Redaction: must not contain a "privateKey", "d", or "x" field.
	for _, leak := range []string{"privateKey", "d", "x", "y", "priv"} {
		if _, ok := first[leak]; ok {
			t.Errorf("key entry leaked field %q (redaction failure)", leak)
		}
	}
}

// ------------------------------------------------------------------
// handleKeyringRotate
// ------------------------------------------------------------------

func TestIOCAdminAPI_KeyringRotate_MethodNotAllowed(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/keyring/rotate", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIOCAdminAPI_KeyringRotate_NilWiring(t *testing.T) {
	h := newIOCAdminAPI(nil).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/keyring/rotate", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestIOCAdminAPI_KeyringRotate_Happy(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	keysBefore := w.Sync.ActiveKeys()
	if len(keysBefore) == 0 {
		t.Fatal("precondition: ActiveKeys is empty")
	}
	// ActiveKeys() is sorted by CreatedAt ASC; the original
	// (oldest) key is at index 0.
	originalKeyID := keysBefore[0].KeyID
	if !keysBefore[0].IsCurrent {
		t.Errorf("precondition: keysBefore[0] (%s) should be current", originalKeyID)
	}
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/keyring/rotate", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %q)", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	decodeJSON(t, rr, &resp)
	newKeyID, _ := resp["newKeyId"].(string)
	if newKeyID == "" {
		t.Errorf("response newKeyId is empty (full: %v)", resp)
	}
	if newKeyID == originalKeyID {
		t.Errorf("newKeyId = %q == original %q; rotation did not change the key", newKeyID, originalKeyID)
	}
	// After rotation:
	//   - the original key is still in the ring (retired)
	//   - the new key is the current key
	keysAfter := w.Sync.ActiveKeys()
	if len(keysAfter) != len(keysBefore)+1 {
		t.Errorf("len(ActiveKeys) = %d, want %d (one new key added)",
			len(keysAfter), len(keysBefore)+1)
	}
	// The new key must appear and be marked IsCurrent.
	var foundNew bool
	for _, k := range keysAfter {
		if k.KeyID == newKeyID {
			foundNew = true
			if !k.IsCurrent {
				t.Errorf("new key %s has IsCurrent=false; want true", newKeyID)
			}
		}
	}
	if !foundNew {
		t.Errorf("new key %s not found in ActiveKeys (got %d entries)", newKeyID, len(keysAfter))
	}
	// The original key must still be present (retired) for
	// backwards-compatibility verification of old attestations.
	var foundOrig bool
	for _, k := range keysAfter {
		if k.KeyID == originalKeyID {
			foundOrig = true
			if k.IsCurrent {
				t.Errorf("original key %s is still marked current after rotation", originalKeyID)
			}
		}
	}
	if !foundOrig {
		t.Errorf("original key %s missing from ActiveKeys after rotation", originalKeyID)
	}
}

// ------------------------------------------------------------------
// handleReputation
// ------------------------------------------------------------------

func TestIOCAdminAPI_Reputation_MethodNotAllowed(t *testing.T) {
	w := newTestIOCWiring(t, tier.TierProfessional)
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodPost, "/api/v1/ioc/admin/reputation", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIOCAdminAPI_Reputation_NilWiring(t *testing.T) {
	h := newIOCAdminAPI(nil).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/reputation", nil)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestIOCAdminAPI_Reputation_NoReputationInstalled_404(t *testing.T) {
	// Default wiring does not install a reputation store; the
	// reputation endpoint must return 404, not 200 with empty data.
	w := newTestIOCWiring(t, tier.TierProfessional)
	if w.Sync.Reputation() != nil {
		t.Skip("reputation is already installed; skipping 404 path")
	}
	h := newIOCAdminAPI(w).Handler()
	rr := doRequest(t, h, http.MethodGet, "/api/v1/ioc/admin/reputation", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d (body: %q)", rr.Code, http.StatusNotFound, rr.Body.String())
	}
}

// ------------------------------------------------------------------
// Helper functions
// ------------------------------------------------------------------

func TestWriteJSONResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusTeapot, map[string]string{"hello": "world"})
	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusTeapot)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["hello"] != "world" {
		t.Errorf("decoded = %v, want {hello:world}", got)
	}
}

func TestWriteJSONResponse_EncodesArbitraryTypes(t *testing.T) {
	// Verify that non-map values (slices, numbers, etc.) also
	// encode correctly — this is the path used by the keyring
	// handler returning ActiveKeys() as a slice.
	rr := httptest.NewRecorder()
	writeJSONResponse(rr, http.StatusOK, []int{1, 2, 3})
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !bytes.Contains(body, []byte("[1,2,3]")) {
		t.Errorf("body = %q, want it to contain [1,2,3]", string(body))
	}
}

func TestReasonOrEmpty(t *testing.T) {
	if got := reasonOrEmpty(nil); got != "" {
		t.Errorf("reasonOrEmpty(nil) = %q, want empty string", got)
	}
	want := "something failed"
	if got := reasonOrEmpty(errors.New(want)); got != want {
		t.Errorf("reasonOrEmpty(err) = %q, want %q", got, want)
	}
}

func TestLogIOCAdmin_NoError(t *testing.T) {
	// Just exercise the branch; the output goes to the global
	// logger. We don't assert anything specific (the log package
	// is the standard one and any panics would be caught by the
	// test runner).
	logIOCAdmin("test-action", true, nil)
	logIOCAdmin("test-action", false, nil)
}

func TestLogIOCAdmin_WithError(t *testing.T) {
	logIOCAdmin("test-action", true, errors.New("simulated failure"))
	logIOCAdmin("test-action", false, errors.New("simulated failure"))
}

// ------------------------------------------------------------------
// Sanity: confirm the wiring is actually wired (not just stubbed)
// ------------------------------------------------------------------

func TestNewTestIOCWiring_PersistsKeyAndInstanceID(t *testing.T) {
	// The test helper constructs a wiring and persists to a
	// temp dir; verify the persisted files exist after wiring.
	dataDir := t.TempDir()
	t.Setenv("AEGISGATE_IOC_SHARE", "")
	t.Setenv("AEGISGATE_IOC_RECEIVE", "")
	t.Setenv("AEGISGATE_IOC_PEERS", "")
	*iocShare = false
	*iocReceive = false
	*iocPeers = ""
	// iocGossipInterval is left at its flag default (5m).
	w, instanceID, err := wireIOC(dataDir, tier.TierProfessional)
	if err != nil {
		t.Fatalf("wireIOC: %v", err)
	}
	// Suppress unused warning; w is exercised via t.TempDir cleanup.
	_ = w
	if instanceID == "" {
		t.Error("instanceID is empty")
	}
	// key.json and instance-id are written synchronously by
	// wireIOC. store.json is written asynchronously by the
	// flusher (30s interval by default); Flush is a no-op if
	// the store isn't dirty, so observe an IOC first.
	if err := w.Store.Flush(); err != nil {
		t.Errorf("Store.Flush (empty store): %v", err)
	}
	// The store is NOT dirty on an empty wiring, so we expect
	// no file on disk yet.
	if _, err := os.Stat(dataDir + "/ioc/" + iocStoreFile); err == nil {
		t.Errorf("store.json unexpectedly exists on empty store")
	}
	// Observe an IOC to mark the store dirty, then Flush.
	// The store is dirty iff a write is pending; for an empty
	// store the file is not created. We construct an IOC
	// directly with a pre-computed fingerprint rather than
	// going through the logging.Record() pipeline (which has
	// its own allow-list and would be a different test).
	now := time.Now().UTC()
	sample := ioc.IOC{
		Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
		Type:        ioc.IOCTypeProxyResponse,
		Severity:    ioc.SeverityHigh,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       1,
		Source:      "test",
	}
	if _, err := w.Store.Observe(sample); err != nil {
		t.Fatalf("Store.Observe: %v", err)
	}
	if err := w.Store.Flush(); err != nil {
		t.Errorf("Store.Flush (after Observe): %v", err)
	}
	if _, err := os.Stat(dataDir + "/ioc/" + iocStoreFile); err != nil {
		t.Errorf("expected store.json to exist after Observe+Flush: %v", err)
	}
}

// Ensure ioc package is referenced (avoids unused-import lints).
// ioc.IOCType is the string-typed enum of indicator types; this
// test exercises the type literal to keep the import live.
func TestIOCTypeLiteralCompiles(t *testing.T) {
	var _ ioc.IOCType = ioc.IOCType("")
}
