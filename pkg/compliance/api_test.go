// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance HTTP API tests (v3.2.0 Phase 3.2)

package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// newTestAPI returns an API with a fresh scanner and a manager
// configured with no license (community default).
func newTestAPI(t *testing.T) (*API, *license.Manager) {
	t.Helper()
	mgr, err := license.NewManager()
	if err != nil {
		t.Fatalf("license.NewManager: %v", err)
	}
	scanner := NewScanner(nil, nil)
	return NewAPI(scanner, mgr), mgr
}

func doRequest(api *API, method, path string) *httptest.ResponseRecorder {
	return doRequestWithContext(context.Background(), api, method, path)
}

func doRequestWithContext(ctx context.Context, api *API, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil).WithContext(ctx)
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

func parseJSONArray(t *testing.T, body []byte) []any {
	t.Helper()
	var arr []any
	if err := json.Unmarshal(body, &arr); err != nil {
		t.Fatalf("parseJSONArray: %v (body=%s)", err, string(body))
	}
	return arr
}

// ---- /health ----

func TestAPI_Health(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/health")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	body := parseJSON(t, w.Body.Bytes())
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["scannerPresent"] != true {
		t.Error("scannerPresent should be true")
	}
}

func TestAPI_Health_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "POST", "/api/v1/compliance/health")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPI_Health_StripsPrefix(t *testing.T) {
	api, _ := newTestAPI(t)
	for _, path := range []string{"/api/v1/compliance/health", "/health"} {
		w := doRequest(api, "GET", path)
		if w.Code != http.StatusOK {
			t.Errorf("path %q: status = %d, want 200", path, w.Code)
		}
	}
}

// ---- /scan ----

func TestAPI_Scan_NoLicense(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/scan")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body.Bytes())
	if body["customerTier"] != "community" {
		t.Errorf("customerTier = %v, want community", body["customerTier"])
	}
	if body["hasLicense"] != false {
		t.Error("hasLicense should be false for no license")
	}
	if body["licenseValid"] != false {
		t.Error("licenseValid should be false for no license")
	}
	frameworks, _ := body["frameworks"].([]any)
	if len(frameworks) == 0 {
		t.Error("frameworks should not be empty")
	}
}

func TestAPI_Scan_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "POST", "/api/v1/compliance/scan")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPI_Scan_FrameworksHaveAllFields(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/scan")
	body := parseJSON(t, w.Body.Bytes())
	frameworks, _ := body["frameworks"].([]any)
	if len(frameworks) == 0 {
		t.Fatal("frameworks is empty")
	}
	for _, f := range frameworks {
		fm, _ := f.(map[string]any)
		if fm["framework"] == nil {
			t.Error("framework field missing")
		}
		if fm["displayName"] == nil {
			t.Error("displayName field missing")
		}
		if fm["enforced"] == nil {
			t.Error("enforced field missing")
		}
		if fm["score"] == nil {
			t.Error("score field missing")
		}
		if fm["implementationReady"] == nil {
			t.Error("implementationReady field missing")
		}
	}
}

func TestAPI_Scan_StripsPrefix(t *testing.T) {
	api, _ := newTestAPI(t)
	for _, path := range []string{"/api/v1/compliance/scan", "/scan"} {
		w := doRequest(api, "GET", path)
		if w.Code != http.StatusOK {
			t.Errorf("path %q: status = %d, want 200", path, w.Code)
		}
	}
}

func TestAPI_Scan_FieldsConsistent(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/scan")
	body := parseJSON(t, w.Body.Bytes())
	if body["scanDurationMs"] == nil {
		t.Error("scanDurationMs missing")
	}
	if body["generatedAt"] == nil {
		t.Error("generatedAt missing")
	}
}

// ---- /report ----

func TestAPI_Report_ValidFramework(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/report?framework=hipaa")
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	body := parseJSON(t, w.Body.Bytes())
	if body["framework"] != "hipaa" {
		t.Errorf("framework = %v, want hipaa", body["framework"])
	}
	if body["enforced"] != false {
		t.Error("enforced should be false for no-license community user")
	}
	if body["reasonNotEnforced"] == nil {
		t.Error("reasonNotEnforced should be present for unenforced framework")
	}
}

func TestAPI_Report_MissingFrameworkParam(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/report")
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPI_Report_UnknownFramework(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/report?framework=nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPI_Report_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "POST", "/api/v1/compliance/report?framework=hipaa")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

// TestAPI_Report_Aliases: most framework name aliases can be
// passed directly. Aliases with spaces (e.g., "nist ai rmf", "soc 2")
// are accepted by normalizeFrameworkName but require URL encoding
// in the actual HTTP request (the test below only covers aliases
// that don't contain spaces).

func TestAPI_Report_Aliases(t *testing.T) {
	api, _ := newTestAPI(t)
	cases := []struct {
		alias    string
		expected string
	}{
		{"nist_ai_rmf", "nist_ai_rmf"},
		{"nist-ai-rmf", "nist_ai_rmf"},

		{"pci-dss", "pci"},
		{"pci_dss", "pci"},
	}
	for _, tc := range cases {
		t.Run(tc.alias, func(t *testing.T) {
			w := doRequest(api, "GET", "/api/v1/compliance/report?framework="+tc.alias)
			if w.Code != http.StatusOK {
				t.Fatalf("alias %q: status = %d (body=%s)", tc.alias, w.Code, w.Body.String())
			}
			body := parseJSON(t, w.Body.Bytes())
			if body["framework"] != tc.expected {
				t.Errorf("alias %q: framework = %v, want %q", tc.alias, body["framework"], tc.expected)
			}
		})
	}
}

func TestAPI_Report_AllEnforcedFrameworks(t *testing.T) {
	api, _ := newTestAPI(t)
	for _, fw := range []string{"hipaa", "pci", "soc2", "iso42001", "fedramp", "fips"} {
		t.Run(fw, func(t *testing.T) {
			w := doRequest(api, "GET", "/api/v1/compliance/report?framework="+fw)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			body := parseJSON(t, w.Body.Bytes())
			if body["framework"] != fw {
				t.Errorf("framework = %v, want %s", body["framework"], fw)
			}
			if body["enforced"] != false {
				t.Errorf("enforced = %v, want false (community, no module)", body["enforced"])
			}
			if body["module"] != fw {
				t.Errorf("module = %v, want %s", body["module"], fw)
			}
		})
	}
}

func TestAPI_Report_FreeFrameworkAlwaysEnforced(t *testing.T) {
	api, _ := newTestAPI(t)
	// Only the core free frameworks (ATLAS, OWASP LLM) are always enforced
	// regardless of license. Other Community-tier frameworks (CIS, NIST CSF,
	// OWASP Web, CSA STAR, NIST AI 600-1, CCPA, GDPR, NIST AI RMF) are
	// $0 modules that still go through the module gating path.
	for _, fw := range []string{"atlas", "owasp"} {
		t.Run(fw, func(t *testing.T) {
			w := doRequest(api, "GET", "/api/v1/compliance/report?framework="+fw)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			body := parseJSON(t, w.Body.Bytes())
			if body["enforced"] != true {
				t.Errorf("free framework %s should be enforced for community", fw)
			}
		})
	}
}

// ---- context license injection ----

func TestAPI_ExtractLicense_NilContext(t *testing.T) {
	api, mgr := newTestAPI(t)
	// Manually extract a license from a context that has nothing
	// injected.
	lic := api.extractLicense(context.Background())
	if lic != nil {
		t.Errorf("expected nil for empty context, got %+v", lic)
	}
	// With a key set on the manager, fall through to it.
	mgr.SetLicenseKey("dummy")
	lic = api.extractLicense(context.Background())
	if lic == nil {
		t.Fatal("expected non-nil with manager-stored key")
	}
	// The dummy key won't validate, so lic is the invalid result.
	if lic.Valid {
		t.Error("dummy key should not be valid")
	}
}

func TestAPI_ExtractLicense_FromContext(t *testing.T) {
	api, mgr := newTestAPI(t)
	ctx := license.ContextWithLicenseKey(context.Background(), "ctx-key")
	lic := api.extractLicense(ctx)
	if lic == nil {
		t.Fatal("expected non-nil with context-injected key")
	}
	_ = mgr
}

// ---- routing ----

func TestAPI_NotFound(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/nonexistent")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPI_AllRoutesMethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	for _, path := range []string{
		"/api/v1/compliance/scan",
		"/api/v1/compliance/report?framework=hipaa",
	} {
		w := doRequest(api, "POST", path)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: status = %d, want 405", path, w.Code)
		}
	}
}

// ---- nil guards ----

func TestAPI_NilScanner(t *testing.T) {
	mgr, _ := license.NewManager()
	api := &API{scanner: nil, mgr: mgr}
	w := doRequest(api, "GET", "/api/v1/compliance/health")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestAPI_NilManager(t *testing.T) {
	scanner := NewScanner(nil, nil)
	api := &API{scanner: scanner, mgr: nil}
	w := doRequest(api, "GET", "/api/v1/compliance/health")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// TestAPI_Report_Aliases_WithSpaces verifies that space-containing
// aliases work when properly URL-encoded in the query string.
func TestAPI_Report_Aliases_WithSpaces(t *testing.T) {
	api, _ := newTestAPI(t)
	cases := []struct {
		alias    string
		expected string
	}{
		{"nist ai rmf", "nist_ai_rmf"},
		{"soc 2", "soc2"},
		{"iso 42001", "iso42001"},
		{"fips 140-2", "fips"},
		{"fips 140-3", "fips"},
		{"owasp llm top 10", "owasp"},
		{"mitre atlas", "atlas"},
	}
	for _, tc := range cases {
		t.Run(tc.alias, func(t *testing.T) {
			// Use url.QueryEscape to encode the space.
			w := doRequest(api, "GET", "/api/v1/compliance/report?framework="+url.QueryEscape(tc.alias))
			if w.Code != http.StatusOK {
				t.Fatalf("alias %q: status = %d (body=%s)", tc.alias, w.Code, w.Body.String())
			}
			body := parseJSON(t, w.Body.Bytes())
			if body["framework"] != tc.expected {
				t.Errorf("alias %q: framework = %v, want %q", tc.alias, body["framework"], tc.expected)
			}
		})
	}
}

// ---- normalizeFrameworkName ----

func TestNormalizeFrameworkName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"hipaa", "hipaa"},
		{"HIPAA", "hipaa"},
		{"pci", "pci"},
		{"pci-dss", "pci"},
		{"pci_dss", "pci"},
		{"PCI-DSS", "pci"},
		{"soc2", "soc2"},

		{"soc-2", "soc2"},
		{"iso42001", "iso42001"},

		{"iso-42001", "iso42001"},
		{"iso27001", "iso27001"},
		{"fedramp", "fedramp"},
		{"fed-ramp", "fedramp"},
		{"fips", "fips"},

		{"fips140-2", "fips"},

		{"nist_ai_rmf", "nist_ai_rmf"},
		{"nist-ai-rmf", "nist_ai_rmf"},
		{"nist_ai_rmf", "nist_ai_rmf"},
		{"atlas", "atlas"},

		{"atlas", "atlas"},
		{"owasp", "owasp"},

		{"owasp", "owasp"},
		{"unknown-thing", "unknown-thing"}, // pass-through
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := normalizeFrameworkName(tc.input); got != tc.want {
				t.Errorf("normalizeFrameworkName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}


// ===== Audit Trail API Tests (v3.6.0) =====

func TestAPI_AuditTrail_NoTrail(t *testing.T) {
	api, _ := newTestAPI(t)
	// No audit trail set → 404
	w := doRequest(api, "GET", "/api/v1/compliance/audit-trail")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAPI_AuditTrail_Empty(t *testing.T) {
	api, _ := newTestAPI(t)
	api.SetAuditTrail(NewAuditTrail())
	w := doRequest(api, "GET", "/api/v1/compliance/audit-trail")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	arr := parseJSONArray(t, w.Body.Bytes())
	if len(arr) != 0 {
		t.Errorf("expected empty array, got %d entries", len(arr))
	}
}

func TestAPI_AuditTrail_WithEntries(t *testing.T) {
	api, _ := newTestAPI(t)
	at := NewAuditTrail()
	api.SetAuditTrail(at)

	// Record a pattern addition
	p := &Pattern{
		ID:          "TEST-001",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptInjection",
		Description: "Test pattern",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)test\s+pattern`),
	}
	at.RecordPatternAddition(p, "admin", "Initial pattern")

	w := doRequest(api, "GET", "/api/v1/compliance/audit-trail")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	arr := parseJSONArray(t, w.Body.Bytes())
	if len(arr) != 1 {
		t.Errorf("expected 1 entry, got %d", len(arr))
	}
}

func TestAPI_AuditTrail_FilterByFramework(t *testing.T) {
	api, _ := newTestAPI(t)
	at := NewAuditTrail()
	api.SetAuditTrail(at)

	p := &Pattern{
		ID:          "ATLAS-001",
		Technique:   "T1535",
		Framework:   FrameworkATLAS,
		Severity:    SeverityHigh,
		Category:    "PromptInjection",
		Description: "Test",
		Block:       true,
		Regex:       regexp.MustCompile(`(?i)test`),
	}
	at.RecordPatternAddition(p, "admin", "Added")

	// Filter by ATLAS framework should return 1 entry
	w := doRequest(api, "GET", "/api/v1/compliance/audit-trail?framework=ATLAS")
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	arr := parseJSONArray(t, w.Body.Bytes())
	if len(arr) != 1 {
		t.Errorf("expected 1 entry for ATLAS filter, got %d", len(arr))
	}

	// Filter by non-existent framework should return empty
	w2 := doRequest(api, "GET", "/api/v1/compliance/audit-trail?framework=NONEXISTENT")
	arr2 := parseJSONArray(t, w2.Body.Bytes())
	if len(arr2) != 0 {
		t.Errorf("expected 0 entries for non-existent framework, got %d", len(arr2))
	}
}

func TestAPI_AuditTrail_MethodNotAllowed(t *testing.T) {
	api, _ := newTestAPI(t)
	api.SetAuditTrail(NewAuditTrail())
	w := doRequest(api, "POST", "/api/v1/compliance/audit-trail")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ---- Vendor Risk API tests ----

func TestAPI_VendorRisk_List(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/vendor-risk")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	m := parseJSON(t, w.Body.Bytes())
	if m["count"] == nil {
		t.Error("expected count field")
	}
}

func TestAPI_VendorRisk_Assess(t *testing.T) {
	api, _ := newTestAPI(t)
	body := `{"vendor_name":"TestVendor","category":"llm_provider"}`
	req := httptest.NewRequest("POST", "/api/v1/compliance/vendor-risk/assess", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	m := parseJSON(t, w.Body.Bytes())
	if m["VendorName"] == nil && m["vendor_name"] == nil {
		t.Error("expected vendor_name field")
	}
}

func TestAPI_VendorRisk_Assess_MissingName(t *testing.T) {
	api, _ := newTestAPI(t)
	body := `{"category":"llm_provider"}`
	req := httptest.NewRequest("POST", "/api/v1/compliance/vendor-risk/assess", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ---- Policy Engine API tests ----

func TestAPI_PolicyEngine_List(t *testing.T) {
	api, _ := newTestAPI(t)
	pe := NewPolicyEngine()
	api.SetPolicyEngine(pe)
	w := doRequest(api, "GET", "/api/v1/compliance/policy-engine")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_PolicyEngine_NotConfigured(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/policy-engine")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAPI_PolicyEngine_Evaluate(t *testing.T) {
	api, _ := newTestAPI(t)
	pe := NewPolicyEngine()
	for _, p := range DefaultPolicies() {
		_ = pe.AddPolicy(p)
	}
	api.SetPolicyEngine(pe)
	body := `{"config":{"tier":"community"},"request":{"authenticated":true}}`
	req := httptest.NewRequest("POST", "/api/v1/compliance/policy-engine/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---- Evidence API tests ----

func TestAPI_Evidence_List(t *testing.T) {
	api, _ := newTestAPI(t)
	ec := NewEvidenceCollector()
	api.SetEvidenceCollector(ec)
	w := doRequest(api, "GET", "/api/v1/compliance/evidence")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_Evidence_NotConfigured(t *testing.T) {
	api, _ := newTestAPI(t)
	w := doRequest(api, "GET", "/api/v1/compliance/evidence")
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestAPI_Evidence_Collect(t *testing.T) {
	api, _ := newTestAPI(t)
	ec := NewEvidenceCollector()
	api.SetEvidenceCollector(ec)
	body := `{"framework":"SOC2","control_id":"CC6.1","type":"scan_result"}`
	req := httptest.NewRequest("POST", "/api/v1/compliance/evidence/collect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPI_Evidence_Verify(t *testing.T) {
	api, _ := newTestAPI(t)
	ec := NewEvidenceCollector()
	item := &EvidenceItem{
		ID:        "ev-test-1",
		Type:      EvidenceScanResult,
		Framework: "SOC2",
		ControlID: "CC6.1",
		Content:   []byte("test evidence"),
	}
	_ = ec.AddEvidence(item)
	api.SetEvidenceCollector(ec)
	body := `{"id":"ev-test-1","verified_by":"auditor@example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/compliance/evidence/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
