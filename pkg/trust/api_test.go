// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust HTTP API tests (v3.2.0 Phase 4.3)
//
// Tests for the /api/v1/trust/{score,sessions,attestations,health}
// HTTP handlers. Uses net/http/httptest.

package trust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/trust/score"
)

// newTestAPI returns an API with a fresh manager and no attestation
// generator (so /attestations returns 501 by default).
func newTestAPI(t *testing.T) *API {
	t.Helper()
	engine := score.NewEngine(nil)
	manager := NewManager(engine, nil)
	return NewAPI(manager, nil)
}

// newTestAPIWithAttest returns an API with an attestation generator.
func newTestAPIWithAttest(t *testing.T) (*API, *attestation.Generator) {
	t.Helper()
	engine := score.NewEngine(nil)
	manager := NewManager(engine, nil)
	gen, err := attestation.NewGenerator()
	if err != nil {
		t.Fatalf("attestation.NewGenerator: %v", err)
	}
	v := attestation.NewValidator()
	return NewAPI(manager, &APIConfig{
		AttestationGenerator: gen,
		AttestationValidator: v,
	}), gen
}

func doRequest(api *API, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	return w
}

func parseJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("parseJSON: %v (body=%s)", err, string(body))
	}
	return m
}

// ---- /health ----

func TestAPI_Health(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/health")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	if body["status"] != "ok" {
		t.Errorf("status field = %v, want ok", body["status"])
	}
	if _, ok := body["activeSessions"]; !ok {
		t.Error("activeSessions missing from health response")
	}
}

func TestAPI_Health_MethodNotAllowed(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "POST", "/api/v1/trust/health")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPI_Health_StripsPrefix(t *testing.T) {
	api := newTestAPI(t)
	// Both with and without the /api/v1/trust prefix should work.
	for _, path := range []string{"/api/v1/trust/health", "/health"} {
		w := doRequest(api, "GET", path)
		if w.Code != http.StatusOK {
			t.Errorf("path %q: status = %d, want 200", path, w.Code)
		}
	}
}

// ---- /score ----

func TestAPI_Score_NoEvents(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/score?agent=alpha")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body.Bytes())
	if body["agentId"] != "alpha" {
		t.Errorf("agentId = %v, want alpha", body["agentId"])
	}
	if score, _ := body["score"].(float64); score != 100.0 {
		t.Errorf("score = %v, want 100.0 (default initial)", score)
	}
}

func TestAPI_Score_WithEvents(t *testing.T) {
	api := newTestAPI(t)
	ctx := context.Background()
	// Record a denied event so the score moves.
	sess, _ := api.Manager().Start(ctx, "alpha")
	_, _ = api.Manager().Record(ctx, sess.ID, score.EventCapabilityDenied, "write", 8, "denied")
	w := doRequest(api, "GET", "/api/v1/trust/score?agent=alpha")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	score, _ := body["score"].(float64)
	if score >= 100.0 {
		t.Errorf("score = %v, want < 100.0 after denied event", score)
	}
}

func TestAPI_Score_MissingAgentParam(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/score")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPI_Score_SessionScoped(t *testing.T) {
	api := newTestAPI(t)
	ctx := context.Background()
	sess, _ := api.Manager().Start(ctx, "alpha")
	// Record a denied event to change the score.
	_, _ = api.Manager().Record(ctx, sess.ID, score.EventCapabilityDenied, "write", 8, "denied")
	w := doRequest(api, "GET", "/api/v1/trust/score?session="+sess.ID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body.Bytes())
	delta, _ := body["scoreDelta"].(float64)
	if delta >= 0 {
		t.Errorf("scoreDelta = %v, want < 0 (denied event)", delta)
	}
	if body["initialScore"] == nil {
		t.Error("initialScore missing from session score response")
	}
}

func TestAPI_Score_UnknownSession(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/score?session=nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---- /sessions ----

func TestAPI_Sessions_ListEmpty(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/sessions")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 0 {
		t.Errorf("count = %v, want 0", count)
	}
}

func TestAPI_Sessions_ListAndFilter(t *testing.T) {
	api := newTestAPI(t)
	ctx := context.Background()
	s1, _ := api.Manager().Start(ctx, "alpha")
	s2, _ := api.Manager().Start(ctx, "beta")
	_, _ = api.Manager().End(ctx, s1.ID)
	// All sessions.
	w := doRequest(api, "GET", "/api/v1/trust/sessions")
	body := parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 2 {
		t.Errorf("all count = %v, want 2", count)
	}
	// Active only.
	w = doRequest(api, "GET", "/api/v1/trust/sessions?active=true")
	body = parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 1 {
		t.Errorf("active count = %v, want 1", count)
	}
	// By agent.
	w = doRequest(api, "GET", "/api/v1/trust/sessions?agent=alpha")
	body = parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 1 {
		t.Errorf("by-agent count = %v, want 1", count)
	}
	_ = s2.ID
}

func TestAPI_Sessions_GetByID(t *testing.T) {
	api := newTestAPI(t)
	sess, _ := api.Manager().Start(context.Background(), "alpha")
	w := doRequest(api, "GET", "/api/v1/trust/sessions?id="+sess.ID)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	if body["id"] != sess.ID {
		t.Errorf("id = %v, want %v", body["id"], sess.ID)
	}
}

func TestAPI_Sessions_UnknownID(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/sessions?id=ghost")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---- /attestations ----

func TestAPI_Attestations_NotImplementedWithoutGenerator(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/attestations")
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", w.Code)
	}
}

func TestAPI_Attestations_Empty(t *testing.T) {
	api, _ := newTestAPIWithAttest(t)
	w := doRequest(api, "GET", "/api/v1/trust/attestations")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 0 {
		t.Errorf("count = %v, want 0", count)
	}
}

func TestAPI_Attestations_RecordAndList(t *testing.T) {
	api, _ := newTestAPIWithAttest(t)
	// Record an attestation directly via RecordAttestation (the
	// flow that Phase 4.4 will use).
	att := &attestation.Attestation{
		AgentID:    "alpha",
		IssuedAt:   time.Now().UTC(),
		ExpiresAt:  time.Now().Add(24 * time.Hour).UTC(),
		Frameworks: []attestation.Framework{attestation.FrameworkHIPAA},
	}
	if err := api.RecordAttestation(context.Background(), att); err != nil {
		t.Fatalf("RecordAttestation: %v", err)
	}
	w := doRequest(api, "GET", "/api/v1/trust/attestations?agent=alpha")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 1 {
		t.Errorf("count = %v, want 1", count)
	}
}

func TestAPI_Attestations_SinceFilter(t *testing.T) {
	api, _ := newTestAPIWithAttest(t)
	now := time.Now().UTC()
	// Old attestation (should be filtered out).
	old := &attestation.Attestation{AgentID: "alpha", IssuedAt: now.Add(-1 * time.Hour), ExpiresAt: now.Add(23 * time.Hour)}
	// Recent attestation (should be included).
	recent := &attestation.Attestation{AgentID: "alpha", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
	_ = api.RecordAttestation(context.Background(), old)
	_ = api.RecordAttestation(context.Background(), recent)
	// since=30m ago.
	since := now.Add(-30 * time.Minute).Format(time.RFC3339)
	w := doRequest(api, "GET", "/api/v1/trust/attestations?since="+since)
	body := parseJSON(t, w.Body.Bytes())
	if count, _ := body["count"].(float64); count != 1 {
		t.Errorf("since-filtered count = %v, want 1", count)
	}
}

func TestAPI_Attestations_Latest(t *testing.T) {
	api, _ := newTestAPIWithAttest(t)
	now := time.Now().UTC()
	_ = api.RecordAttestation(context.Background(), &attestation.Attestation{
		AgentID: "alpha", IssuedAt: now.Add(-1 * time.Hour), ExpiresAt: now.Add(23 * time.Hour),
	})
	_ = api.RecordAttestation(context.Background(), &attestation.Attestation{
		AgentID: "alpha", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	})
	w := doRequest(api, "GET", "/api/v1/trust/attestations/latest?agent=alpha")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	att, ok := body["attestation"].(map[string]any)
	if !ok {
		// Could be the bare attestation if no validator.
		att = body
	}
	issuedAt, _ := att["issuedAt"].(string)
	if issuedAt == "" {
		t.Error("issuedAt missing from latest attestation")
	}
}

func TestAPI_Attestations_LatestNoAgent(t *testing.T) {
	api, _ := newTestAPIWithAttest(t)
	w := doRequest(api, "GET", "/api/v1/trust/attestations/latest")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPI_Attestations_LatestNotFound(t *testing.T) {
	api, _ := newTestAPIWithAttest(t)
	w := doRequest(api, "GET", "/api/v1/trust/attestations/latest?agent=ghost")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---- routing ----

func TestAPI_NotFound(t *testing.T) {
	api := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/trust/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPI_AllRoutesMethodNotAllowed(t *testing.T) {
	api := newTestAPI(t)
	for _, path := range []string{
		"/api/v1/trust/score",
		"/api/v1/trust/sessions",
		"/api/v1/trust/attestations",
		"/api/v1/trust/attestations/latest",
	} {
		w := doRequest(api, "POST", path)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: status = %d, want 405", path, w.Code)
		}
	}
}

// ---- helpers ----

func TestParseSince_RFC3339(t *testing.T) {
	got := parseSince("2026-06-05T12:00:00Z")
	if got.IsZero() {
		t.Error("parseSince returned zero time for RFC3339 input")
	}
}

func TestParseSince_UnixSeconds(t *testing.T) {
	got := parseSince("1749120000")
	if got.IsZero() {
		t.Error("parseSince returned zero time for Unix seconds")
	}
}

func TestParseSince_Duration(t *testing.T) {
	got := parseSince("1h")
	if got.IsZero() {
		t.Error("parseSince returned zero time for duration")
	}
	// Should be roughly 1h before now.
	if d := time.Since(got); d < 50*time.Minute || d > 70*time.Minute {
		t.Errorf("parseSince(1h) = %v ago, want ~1h", d)
	}
}

func TestParseSince_Invalid(t *testing.T) {
	got := parseSince("not-a-date")
	if !got.IsZero() {
		t.Errorf("parseSince(invalid) = %v, want zero time", got)
	}
}

func TestParseSince_Empty(t *testing.T) {
	got := parseSince("")
	if !got.IsZero() {
		t.Errorf("parseSince(empty) = %v, want zero time", got)
	}
}
