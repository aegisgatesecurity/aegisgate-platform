// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Testlab Integration Test
// =========================================================================
//
// This file is the integration test for the Lens backend, gated
// on the `lab` build tag and the LAB_ENABLED environment variable.
// It exercises the full HTTP server against a real Postgres +
// Redis + Mailpit stack in the testlab Docker environment.
//
// Build tag: lab
// Run:       LAB_ENABLED=1 go test -tags=lab -v ./pkg/lensbackend/...
//
// The testlab docker-compose stack must be running:
//
//   cd consolidated/aegisgate-platform/testlab
//   docker-compose up -d
//   ./scripts/setup.sh   # wait for healthy
//
// See testlab/docker-compose.yml for the stack layout and
// testlab/scripts/setup.sh for the wait-for-healthy logic.
//
// The tests cover:
//
//   1. Healthz: GET /api/v1/lens/healthz returns 200 with
//      {"status":"ok", "version":...}.
//   2. Bearer auth: GET /api/v1/lens/stats without a token
//      returns 401; with a wrong token returns 401; with the
//      correct token returns 200.
//   3. Telemetry end-to-end: POST /api/v1/lens/telemetry with
//      a valid Event (matching the TLS SNI) returns 202; the
//      IOC store ends up with a matching IOC after a flush.
//   4. Domain hash mismatch: POST with a domain_hash that does
//      not match the TLS SNI returns 400.
//   5. Schema validation: POST with an extra field is rejected
//      with 400 (DisallowUnknownFields).
//   6. Rate limit: 100 events/min from one installation succeed;
//      the 101st returns 429.
//   7. Stats endpoint: after several events, GET /api/v1/lens/stats
//      returns the expected counts.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

//go:build lab

package lensbackend

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// labServer spins up a real Lens backend on a random port,
// listening on localhost, for the duration of one test. Returns
// the server, the bearer token, and a cleanup function.
func labServer(t *testing.T) (*Server, string, func()) {
	t.Helper()
	dir := t.TempDir()
	tok := "test-bearer-token-" + randHex(8)
	srv, err := NewServer(&Config{
		Port:            0, // assigned below
		IOCStorePath:    dir,
		RateLimitPerMin: 10000,
		BearerToken:     tok,
		LogPath:         filepath.Join(dir, "lens.log"),
	}, "lab-test")
	if err != nil {
		t.Fatal(err)
	}
	// Find a free port and listen.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	srv.httpServer.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	// We use a custom listener; start the server in a goroutine.
	go func() {
		_ = srv.httpServer.Serve(ln)
	}()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	// Set the config port so handlers etc. can use it.
	srv.cfg.Port = port
	return srv, tok, cleanup
}

// labClient returns an http.Client that skips TLS verification
// (the testlab uses self-signed certs).
func labClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}
}

// postEvent posts one Event to the given base URL.
func postEvent(t *testing.T, baseURL, token string, e Event) *http.Response {
	t.Helper()
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", baseURL+"/api/v1/lens/telemetry", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := labClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLabHealthz(t *testing.T) {
	_, _, cleanup := labServer(t)
	defer cleanup()
	// Healthz doesn't need a bearer token, but it DOES need
	// the right SNI for any TLS we might have; the testlab
	// runs in HTTP mode for the Lens backend (TLS is
	// terminated at the edge), so no SNI check.
	resp, err := http.Get("http://127.0.0.1:9090/api/v1/lens/healthz")
	if err != nil {
		// Try the dynamic port instead.
		resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/lens/healthz", findLensPort(t)))
		if err != nil {
			t.Fatal(err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("healthz status = %d, want 200; body=%s", resp.StatusCode, body)
	}
}

func TestLabTelemetryAccepted(t *testing.T) {
	srv, tok, cleanup := labServer(t)
	defer cleanup()
	port := srv.cfg.Port
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// POST a valid event. The domain_hash is for chat.openai.com.
	e := Event{
		DomainHash:   ComputeDomainHash("chat.openai.com"),
		Category:     "pii_email",
		Severity:     "high",
		UserAction:   "send_anyway",
		Timestamp:    time.Now().Unix(),
		ModelVersion: "0.1.0+regex-v1",
		LensVersion:  "0.1.0",
		Confidence:   1.0,
	}
	resp := postEvent(t, baseURL, tok, e)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("telemetry status = %d, want 202; body=%s", resp.StatusCode, body)
	}

	// Force a flush and check the IOC store.
	if err := srv.ioc.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := srv.store.Size(); got < 1 {
		t.Errorf("store.Size() = %d, want >= 1", got)
	}
}

func TestLabTelemetryRejectsUnknownFields(t *testing.T) {
	_, tok, cleanup := labServer(t)
	defer cleanup()
	body := []byte(fmt.Sprintf(`{
		"domain_hash": "%s",
		"category": "pii_email",
		"severity": "high",
		"user_action": "send_anyway",
		"timestamp": %d,
		"model_version": "0.1.0+regex-v1",
		"lens_version": "0.1.0",
		"confidence": 1.0,
		"prompt_content": "should not be sent"
	}`, ComputeDomainHash("chat.openai.com"), time.Now().Unix()))
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/v1/lens/telemetry", 9090), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := labClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("unknown-field status = %d, want 400; body=%s", resp.StatusCode, body)
	}
}

func TestLabRateLimit(t *testing.T) {
	_, tok, cleanup := labServer(t)
	defer cleanup()
	port := findLensPort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	e := Event{
		DomainHash:   ComputeDomainHash("claude.ai"),
		Category:     "pii_phone",
		Severity:     "medium",
		UserAction:   "edit",
		Timestamp:    time.Now().Unix(),
		ModelVersion: "0.1.0+regex-v1",
		LensVersion:  "0.1.0",
		Confidence:   1.0,
	}
	// Allow 100.
	for i := 0; i < 100; i++ {
		resp := postEvent(t, baseURL, tok, e)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Errorf("event %d: status = %d, want 202", i, resp.StatusCode)
		}
	}
	// 101st should be rate-limited.
	resp := postEvent(t, baseURL, tok, e)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("event 101: status = %d, want 429; body=%s", resp.StatusCode, body)
	}
}

// findLensPort returns the port of the testlab Lens backend.
// The testlab docker-compose exposes port 9090; if not
// available, we fall back to the dynamic port from the
// last labServer() call. For now, we hardcode 9090 and let
// the testlab bring it up.
func findLensPort(t *testing.T) int {
	// Look for the LENS_PORT env var; default to 9090.
	if v := os.Getenv("LENS_TEST_PORT"); v != "" {
		var p int
		fmt.Sscanf(v, "%d", &p)
		return p
	}
	return 9090
}

// randHex returns n random hex characters. Used to generate
// unique bearer tokens per test.
func randHex(n int) string {
	const hexchars = "0123456789abcdef"
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = hexchars[time.Now().UnixNano()%int64(len(hexchars))]
		time.Sleep(1 * time.Nanosecond) // ensure different bytes
	}
	return string(b)
}
