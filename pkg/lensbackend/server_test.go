// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Unit Tests
// =========================================================================
//
// server_test.go exercises the Lens backend's core logic in
// isolation: config parsing, event validation, domain-hash
// computation, rate limiting, and the iocWriter aggregator.
// These tests do NOT require a real Postgres, Keycloak, or any
// external service; they use only stdlib + the Platform's
// in-memory ioc.Store.
//
// The integration test (lensbackend_lab_test.go) is gated on
// the `lab` build tag and exercises the full HTTP server
// against a real Postgres + Redis + Mailpit stack in the
// testlab Docker environment.
//
// Run: go test -race -v ./pkg/lensbackend/...
// =========================================================================

package lensbackend

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

func TestComputeDomainHash(t *testing.T) {
	// Known-vector test. The output must be the first 16 hex
	// chars of SHA-256(hostname). Locked to prevent regressions
	// in the extension's matching JS code.
	cases := []struct {
		hostname string
		want     string
	}{
		{"chat.openai.com", "b5d56b87a192a38e"},
		{"claude.ai", "743e483ae01f1fa2"},
		{"gemini.google.com", "f8226d80a7c25a04"},
		{"copilot.microsoft.com", "7cbff059b404bede"},
	}
	for _, c := range cases {
		got := ComputeDomainHash(c.hostname)
		if got != c.want {
			t.Errorf("ComputeDomainHash(%q) = %q, want %q", c.hostname, got, c.want)
		}
		// Must be exactly 16 lowercase hex chars.
		if len(got) != 16 {
			t.Errorf("ComputeDomainHash(%q) length = %d, want 16", c.hostname, len(got))
		}
		for _, ch := range got {
			if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
				t.Errorf("ComputeDomainHash(%q) contains non-lowercase-hex char %q", c.hostname, ch)
			}
		}
	}
}

func TestEventValidate(t *testing.T) {
	good := Event{
		// Day 11 pen-test: LensEventVersion is now required (was missing
		// from the Go struct until cross-repo wire-protocol drift was
		// caught by Attack 04). Test fixture must include it.
		// v0.2: Facet is now required.
		LensEventVersion: 1,
		DomainHash:       "eb3a78617eafc7aa",
		Facet:            "pii",
		Category:         "pii_email",
		Severity:         "high",
		UserAction:       "send_anyway",
		Timestamp:        time.Now().Unix(),
		ModelVersion:     "0.1.0+regex-v1",
		LensVersion:      "0.1.0",
		Confidence:       1.0,
	}
	if err := good.Validate(); err != nil {
		t.Errorf("good event rejected: %v", err)
	}

	bad := []Event{
		// DomainHash too short.
		{LensEventVersion: 1, Facet: "pii", DomainHash: "eb3a78617eafc7a", Category: "pii_email", Severity: "high", UserAction: "send_anyway",
			Timestamp: time.Now().Unix(), ModelVersion: "0.1.0+x", LensVersion: "0.1.0", Confidence: 1.0},
		// LensEventVersion missing (legacy v0 event).
		{Category: "pii_email", Severity: "high", UserAction: "send_anyway",
			Timestamp: time.Now().Unix(), ModelVersion: "0.1.0+x", LensVersion: "0.1.0", Confidence: 1.0},
		// LensEventVersion = 2 (future).
		replaceField(good, "LensEventVersion", 2),
		// Invalid category.
		replaceField(good, "Category", "unknown_cat"),
		// Invalid facet.
		replaceField(good, "Facet", "invalid_facet"),
		// Category/facet mismatch.
		replaceField(good, "Facet", "secrets"), // category is pii_email, not a secrets category
		// Invalid severity.
		replaceField(good, "Severity", "extreme"),
		// Invalid user_action.
		replaceField(good, "UserAction", "delete"),
		// Timestamp too old.
		replaceField(good, "Timestamp", time.Now().Add(-48*time.Hour).Unix()),
		// ModelVersion empty (v0.2 relaxed: no longer requires "+").
		// Still tested: ModelVersion must be non-empty.
		replaceField(good, "ModelVersion", ""),
		// LensVersion empty.
		replaceField(good, "LensVersion", ""),
		// Confidence out of range.
		replaceField(good, "Confidence", 1.5),
		// MLScore out of range.
		replaceField(good, "MLScore", 2.0),
		// MLThreshold out of range.
		replaceField(good, "MLThreshold", -0.5),
	}
	for i, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("bad event %d accepted: %+v", i, b)
		}
	}
}

// replaceField returns a copy of e with one field overridden.
// Helper for the table-driven validation test.
func replaceField(e Event, field, value any) Event {
	out := e
	switch field {
	case "LensEventVersion":
		out.LensEventVersion = value.(int)
	case "Facet":
		out.Facet = value.(string)
	case "Category":
		out.Category = value.(string)
	case "Severity":
		out.Severity = value.(string)
	case "UserAction":
		out.UserAction = value.(string)
	case "Timestamp":
		out.Timestamp = value.(int64)
	case "ModelVersion":
		out.ModelVersion = value.(string)
	case "LensVersion":
		out.LensVersion = value.(string)
	case "Confidence":
		out.Confidence = value.(float64)
	case "MLScore":
		out.MLScore = value.(float64)
	case "MLThreshold":
		out.MLThreshold = value.(float64)
	}
	return out
}

func TestDecodeEventRejectsUnknownFields(t *testing.T) {
	body := []byte(`{
		"lens_event_version": 1,
		"domain_hash": "eb3a78617eafc7aa",
		"category": "pii_email",
		"severity": "high",
		"user_action": "send_anyway",
		"timestamp": ` + itoa(time.Now().Unix()) + `,
		"model_version": "0.1.0+regex-v1",
		"lens_version": "0.1.0",
		"confidence": 1.0,
		"prompt_content": "should not be sent"
	}`)
	_, err := decodeEvent(body)
	if err == nil {
		t.Error("decodeEvent accepted event with unknown field 'prompt_content'")
	}
}

func TestIOCWriter(t *testing.T) {
	dir := t.TempDir()
	store, err := ioc.NewStore(ioc.StoreConfig{
		Capacity:      1000,
		FlushInterval: 1 * time.Hour, // don't auto-flush during test
		DiskPath:      filepath.Join(dir, "ioc.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	w := newIOCWriter(store, 10) // flush every 10 events

	// Send 3 events for the same (category, domain_hash) tuple.
	// They should aggregate into 1 IOC with Count=3.
	ts := time.Now().Unix()
	for i := 0; i < 3; i++ {
		e := Event{
			DomainHash:   ComputeDomainHash("chat.openai.com"),
			Category:     "pii_email",
			Severity:     "high",
			UserAction:   "send_anyway",
			Timestamp:    ts + int64(i),
			ModelVersion: "0.1.0+regex-v1",
			LensVersion:  "0.1.0",
			Confidence:   1.0,
		}
		if err := w.add(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	// Force a flush.
	if err := w.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The store should have exactly 1 IOC.
	if got := store.Size(); got != 1 {
		t.Errorf("store.Size() = %d, want 1", got)
	}
	// The IOC should have Count=3.
	snap := store.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(snap))
	}
	if snap[0].Count != 3 {
		t.Errorf("IOC.Count = %d, want 3", snap[0].Count)
	}
	if snap[0].Category != "pii_email" {
		t.Errorf("IOC.Category = %q, want 'pii_email'", snap[0].Category)
	}
	if snap[0].SourceProvider != "chatgpt" {
		t.Errorf("IOC.SourceProvider = %q, want 'chatgpt'", snap[0].SourceProvider)
	}
}

func TestRateLimiter(t *testing.T) {
	// Per-installation limit: 100/min. We allow 100, reject the 101st.
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)
	rl := NewLensRateLimiter(hmacKey, 10000)

	hash1 := "eb3a78617eafc7aa"
	hash2 := "cd29c3a7a8b58a86"

	// Allow 100 from hash1.
	for i := 0; i < 100; i++ {
		if !rl.AllowInstallation(hash1) {
			t.Errorf("AllowInstallation(hash1) returned false at iteration %d", i)
		}
	}
	// 101st from hash1 should be rejected.
	if rl.AllowInstallation(hash1) {
		t.Error("AllowInstallation(hash1) returned true after 100 requests")
	}
	// hash2 should still be allowed.
	if !rl.AllowInstallation(hash2) {
		t.Error("AllowInstallation(hash2) returned false (per-installation isolation broken)")
	}
}

func TestServerHealthz(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0, // unused
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "test-token",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/lens/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Errorf("healthz status = %q, want 'ok'", body["status"])
	}
	if body["version"] != "test-version" {
		t.Errorf("healthz version = %q, want 'test-version'", body["version"])
	}
}

func TestServerRequiresBearerToken(t *testing.T) {
	dir := t.TempDir()
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "secret-token",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	// /stats without bearer token -> 401.
	resp, err := http.Get(ts.URL + "/api/v1/lens/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /stats status = %d, want 401", resp.StatusCode)
	}

	// /stats with wrong bearer token -> 401.
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/stats", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-token /stats status = %d, want 401", resp.StatusCode)
	}

	// /stats with correct bearer token -> 200.
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/lens/stats", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated /stats status = %d, want 200", resp.StatusCode)
	}
}

func TestServerEmptyTokenReturns503(t *testing.T) {
	dir := t.TempDir()
	// BearerToken deliberately empty.
	srv, err := NewServer(&Config{
		Port:            0,
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     "",
	}, "test-version")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()

	// /stats should return 503 because no token is configured.
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/lens/stats", nil)
	req.Header.Set("Authorization", "Bearer anything")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("no-token /stats status = %d, want 503", resp.StatusCode)
	}
}

// itoa is a small helper to format an int64 for inclusion in a
// JSON literal. Avoids importing strconv in test code.
func itoa(i int64) string {
	return string([]byte{
		byte('0' + (i/1000000000)%10),
		byte('0' + (i/100000000)%10),
		byte('0' + (i/10000000)%10),
		byte('0' + (i/1000000)%10),
		byte('0' + (i/100000)%10),
		byte('0' + (i/10000)%10),
		byte('0' + (i/1000)%10),
		byte('0' + (i/100)%10),
		byte('0' + (i/10)%10),
		byte('0' + i%10),
	})
}

func TestLoadConfigDefaults(t *testing.T) {
	// Clear all relevant env vars.
	for _, k := range []string{
		"LENS_PORT", "LENS_TLS_CERT", "LENS_TLS_KEY", "LENS_BEARER_TOKEN",
		"LENS_EVENT_RETENTION_DAYS", "LENS_IOC_STORE_PATH",
		"LENS_RATE_LIMIT_PER_MIN", "LENS_HMAC_KEY", "LENS_LOG_PATH",
		"LENS_PUBLIC_URL",
	} {
		os.Unsetenv(k)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 9090 {
		t.Errorf("default Port = %d, want 9090", cfg.Port)
	}
	if cfg.EventRetention != 90*24*time.Hour {
		t.Errorf("default EventRetention = %v, want 90d", cfg.EventRetention)
	}
	if cfg.RateLimitPerMin != 10000 {
		t.Errorf("default RateLimitPerMin = %d, want 10000", cfg.RateLimitPerMin)
	}
}

func TestDomainHashRoundTrip(t *testing.T) {
	// The domain_hash in a valid Event must be the SHA-256
	// prefix of an AI provider hostname in the allowlist.
	// Verify by computing for each known provider and checking
	// the round-trip in sourceProviderFromDomainHash.
	for _, hostname := range []string{
		"chat.openai.com",
		"claude.ai",
		"gemini.google.com",
		"copilot.microsoft.com",
	} {
		hash := ComputeDomainHash(hostname)
		provider := sourceProviderFromDomainHash(hash)
		if provider == "unknown" {
			t.Errorf("sourceProviderFromDomainHash(%q) = 'unknown', want a known provider", hash)
		}
	}
}

// _ ensures bytes is referenced (used in TestDecodeEvent if we add it).
var _ = bytes.NewReader

// _ ensures hex is referenced.
var _ = hex.EncodeToString
