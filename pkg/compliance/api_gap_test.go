// SPDX-License-Identifier: Apache-2.0
// Compliance API coverage gap tests

package compliance

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/i18n"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

func TestAPI_SetI18N(t *testing.T) {
	api := NewAPI(nil, nil)
	mgr, _ := i18n.NewManager(nil)
	api.SetI18N(mgr)
	if api.i18nMgr == nil {
		t.Error("SetI18N did not set i18nMgr")
	}
}

func TestAPI_localeFromRequest_NoManager(t *testing.T) {
	api := NewAPI(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	locale := api.localeFromRequest(req)
	if locale != i18n.DefaultLocale {
		t.Errorf("locale = %v, want default", locale)
	}
}

func TestAPI_localeFromRequest_WithManager(t *testing.T) {
	api := NewAPI(nil, nil)
	mgr, _ := i18n.NewManager(nil)
	api.SetI18N(mgr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	locale := api.localeFromRequest(req)
	_ = locale // just verify it doesn't panic
}

func TestAPI_localeFromRequest_EmptyHeader(t *testing.T) {
	api := NewAPI(nil, nil)
	mgr, _ := i18n.NewManager(nil)
	api.SetI18N(mgr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	locale := api.localeFromRequest(req)
	if locale != i18n.DefaultLocale {
		t.Errorf("locale = %v, want default", locale)
	}
}

func TestAPI_t_NoManager(t *testing.T) {
	api := NewAPI(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	result := api.t(req, "test.key")
	if result != "test.key" {
		t.Errorf("t() = %q, want test.key (no manager)", result)
	}
}

func TestAPI_t_WithManager(t *testing.T) {
	api := NewAPI(nil, nil)
	mgr, _ := i18n.NewManager(nil)
	api.SetI18N(mgr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	result := api.t(req, "test.key")
	_ = result // just verify it doesn't panic
}

func TestAPI_tWith_NoManager(t *testing.T) {
	api := NewAPI(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	result := api.tWith(req, "test.key", map[string]interface{}{"name": "test"})
	if result != "test.key" {
		t.Errorf("tWith() = %q, want test.key (no manager)", result)
	}
}

func TestAPI_tWith_WithManager(t *testing.T) {
	api := NewAPI(nil, nil)
	mgr, _ := i18n.NewManager(nil)
	api.SetI18N(mgr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	result := api.tWith(req, "test.key", map[string]interface{}{"name": "test"})
	_ = result
}

func TestAPI_serveIntegrity(t *testing.T) {
	api := NewAPI(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/integrity", nil)
	rr := httptest.NewRecorder()
	api.serveIntegrity(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("serveIntegrity status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestAPI_serveIntegrity_MethodNotAllowed(t *testing.T) {
	api := NewAPI(nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/integrity", nil)
	rr := httptest.NewRecorder()
	api.serveIntegrity(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("serveIntegrity POST status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestNormalizeFrameworkName_AllCases(t *testing.T) {
	cases := []struct {
		input  string
		expect string
	}{
		{"nist_ai_rmf", "nist_ai_rmf"},
		{"NIST-AI-RMF", "nist_ai_rmf"},
		{"atlas", "atlas"},
		{"MITRE ATLAS", "atlas"},
		{"owasp", "owasp"},
		{"owasp_llm_top_10", "owasp"},
		{"hipaa", "hipaa"},
		{"pci", "pci"},
		{"pci-dss", "pci"},
		{"soc2", "soc2"},
		{"soc 2", "soc2"},
		{"iso27001", "iso27001"},
		{"iso 27001", "iso27001"},
		{"iso42001", "iso42001"},
		{"fedramp", "fedramp"},
		{"fips", "fips"},
		{"fips 140-2", "fips"},
		{"gdpr", "gdpr"},
		{"cis", "cis"},
		{"cis v8", "cis"},
		{"nist_csf", "nist_csf"},
		{"owasp_web", "owasp_web"},
		{"owasp top 10", "owasp_web"},
		{"csa_star", "csa_star"},
		{"nist_ai_600_1", "nist_ai_600_1"},
		{"ccpa", "ccpa"},
		{"eu_ai_act", "eu_ai_act"},
		{"cmmcl2", "cmmcl2"},
		{"nist800171", "nist800171"},
		{"hitrust", "hitrust"},
		{"tisax", "tisax"},
		{"unknown_framework", "unknown_framework"},
	}
	for _, c := range cases {
		result := normalizeFrameworkName(c.input)
		if result != c.expect {
			t.Errorf("normalizeFrameworkName(%q) = %q, want %q", c.input, result, c.expect)
		}
	}
}

// Ensure license import is used
var _ license.LicenseMiddleware
