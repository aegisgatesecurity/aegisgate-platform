// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Compliance HTTP API (v3.2.0 Phase 3.2)
//
// api.go exposes the compliance scan engine (scanner.go) over HTTP.
// Routes (all under /api/v1/compliance):
//
//   GET /scan                  -> full ScanReport (all 9+ frameworks)
//   GET /report?framework=X    -> single framework detail
//                                  (includes the underlying
//                                  FrameworkAssessment if the
//                                  framework is registered)
//   GET /health                -> liveness (no auth)
//   GET /integrity             -> ATLAS pattern set SHA256 hash for auditors
//   GET /audit-trail            -> rule change audit entries (v3.6.0)
//
// Auth (locked decision Q4): license key via
// pkg/license.LicenseMiddleware. The API itself doesn't enforce
// auth; the caller is expected to wrap with LicenseMiddleware.
//
// Tier gate: the compliance API itself is not tier-gated (it's
// part of the value customers get at any paid tier). The
// underlying SCAN results change with tier/module ownership, so
// the same API serves all tiers — it just returns more
// `enforced: false` entries for lower tiers.
//
// Pattern matches pkg/trust/api.go (raw net/http, per-path switch
// in ServeHTTP, JSON responses). v3.2.0 Phase 3.2.

package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/license"
)

// API serves the compliance HTTP endpoints. Implements http.Handler.
type API struct {
	scanner *Scanner
	// mgr is the license manager. Required to extract the
	// license from the request context and call Validate to
	// produce a ValidationResult for the scanner.
	mgr *license.Manager
	// auditTrail is the rule change audit trail. Optional;
	// if nil, /audit-trail returns 404.
	auditTrail *AuditTrail
	// policyEngine is the OPA/Rego policy engine. Optional.
	policyEngine *PolicyEngine
	// evidenceCollector manages evidence collection. Optional.
	evidenceCollector *EvidenceCollector
}

// NewAPI creates a new compliance HTTP API. Both scanner and mgr
// are required. If either is nil, the API returns 500 for all
// scan requests (fail-closed).
func NewAPI(scanner *Scanner, mgr *license.Manager) *API {
	return &API{scanner: scanner, mgr: mgr}
}

// SetAuditTrail sets the audit trail for the API. If set, the
// /audit-trail endpoint is enabled.
func (a *API) SetAuditTrail(at *AuditTrail) {
	a.auditTrail = at
}

// SetPolicyEngine sets the OPA/Rego policy engine for the API.
func (a *API) SetPolicyEngine(pe *PolicyEngine) {
	a.policyEngine = pe
}

// SetEvidenceCollector sets the evidence collector for the API.
func (a *API) SetEvidenceCollector(ec *EvidenceCollector) {
	a.evidenceCollector = ec
}

// ServeHTTP implements http.Handler. Strips the
// /api/v1/compliance prefix if present and dispatches on the
// suffix.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.scanner == nil || a.mgr == nil {
		writeError(w, http.StatusInternalServerError, "compliance API not configured (scanner or manager nil)")
		return
	}
	path := r.URL.Path
	const prefix = "/api/v1/compliance"
	if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
		path = path[len(prefix):]
	}
	if path == "" || path == "/" {
		path = "/health"
	}
	switch path {
	case "/health":
		a.serveHealth(w, r)
	case "/scan":
		a.serveScan(w, r)
	case "/report":
		a.serveReport(w, r)
	case "/integrity":
		a.serveIntegrity(w, r)
	case "/audit-trail":
		a.serveAuditTrail(w, r)
	case "/vendor-risk":
		a.serveVendorRisk(w, r)
	case "/vendor-risk/assess":
		a.serveVendorRiskAssess(w, r)
	case "/policy-engine":
		a.servePolicyEngine(w, r)
	case "/policy-engine/evaluate":
		a.servePolicyEngineEvaluate(w, r)
	case "/evidence":
		a.serveEvidence(w, r)
	case "/evidence/collect":
		a.serveEvidenceCollect(w, r)
	case "/evidence/verify":
		a.serveEvidenceVerify(w, r)
	default:
		if strings.HasPrefix(path, "/vendor-risk") {
			a.serveVendorRisk(w, r)
		} else if strings.HasPrefix(path, "/policy-engine") {
			a.servePolicyEngine(w, r)
		} else if strings.HasPrefix(path, "/evidence") {
			a.serveEvidence(w, r)
		} else {
			http.NotFound(w, r)
		}
	}
}

// ---- /health ----

func (a *API) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := map[string]any{
		"status":         "ok",
		"scannerPresent": a.scanner != nil,
		"managerPresent": a.mgr != nil,
		"cacheEnabled":   a.scanner.scanCacheTTL > 0,
		"timestamp":      time.Now().UTC(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- /scan ----

func (a *API) serveScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lic := a.extractLicense(r.Context())
	rpt, err := a.scanner.Scan(r.Context(), lic)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}
	// Wrap the response in a top-level "scan" envelope so the
	// roadmap's API contract is preserved.
	//   { "frameworks": [...], "customer_tier": ..., ... }
	resp := map[string]any{
		"customerTier":         rpt.CustomerTier.String(),
		"customerModules":      rpt.CustomerModules,
		"frameworks":           rpt.Frameworks,
		"overallScore":         rpt.OverallScore,
		"overallCompliancePct": rpt.OverallCompliancePct,
		"generatedAt":          rpt.GeneratedAt,
		"scanDurationMs":       rpt.ScanDurationMs,
		"hasLicense":           rpt.HasLicense,
		"licenseValid":         rpt.LicenseValid,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- /report ----

func (a *API) serveReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	framework := r.URL.Query().Get("framework")
	if framework == "" {
		writeError(w, http.StatusBadRequest, "framework query parameter required (e.g., 'hipaa', 'pci', 'soc2', 'iso42001', 'fedramp', 'fips', 'atlas', 'nist_ai_rmf', 'owasp')")
		return
	}
	// Normalize: accept "nist_ai_rmf" as an alias for the NIST.AI
	// framework string.
	framework = normalizeFrameworkName(framework)

	lic := a.extractLicense(r.Context())
	res, assessment, err := a.scanner.ScanFramework(r.Context(), lic, framework)
	if err != nil {
		if errors.Is(err, ErrUnknownFramework) {
			writeError(w, http.StatusNotFound, "unknown framework: "+framework)
			return
		}
		writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}
	resp := map[string]any{
		"framework":   res.Framework,
		"displayName": res.DisplayName,
		"module":      res.Module,
		"enforced":    res.Enforced,
		"score":       res.Score,
		"controls": map[string]any{
			"total":    res.ControlsTotal,
			"enforced": res.ControlsEnforced,
			"pct":      res.CompliancePct,
		},
		"implementationReady": res.ImplementationReady,
		"lastScan":            res.LastScan,
	}
	if res.Enforced {
		if res.ReasonEnforced != "" {
			resp["reasonEnforced"] = res.ReasonEnforced
		}
	} else {
		if res.ReasonNotEnforced != "" {
			resp["reasonNotEnforced"] = res.ReasonNotEnforced
		}
		if res.UpgradeHint != "" {
			resp["upgradeHint"] = res.UpgradeHint
		}
		if len(res.MissingModules) > 0 {
			resp["missingModules"] = res.MissingModules
		}
	}
	// If the framework is registered and we have a real
	// assessment, include it.
	if assessment != nil {
		resp["assessment"] = assessment
	}
	writeJSON(w, http.StatusOK, resp)
}

// extractLicense pulls the validated license from the request
// context. The caller is expected to have wrapped the API with
// LicenseMiddleware.RequireLicense, which injects the manager
// and the license key into the context.
//
// If the LicenseMiddleware wasn't used, the API falls back to
// the manager's stored key (env or config) so the API still
// works in test/development setups. If no key is available
// anywhere, returns a nil license and the Scanner treats the
// customer as Community.
func (a *API) extractLicense(ctx context.Context) *license.ValidationResult {
	// Use the context-stored license key if the LicenseMiddleware
	// has injected one. Fall back to the manager's stored key
	// (env / config) so the API still works in dev/test setups.
	var key string
	if v, ok := ctx.Value(license.CtxKeyLicenseKey).(string); ok {
		key = v
	}
	if key == "" {
		key = a.mgr.GetLicenseKey()
	}
	if key == "" {
		return nil
	}
	result := a.mgr.Validate(key)
	if !result.Valid {
		// Return the invalid result anyway; the scanner will
		// surface LicenseValid=false in the report. Better to
		// show the customer that their license is broken than
		// to silently downgrade.
		return &result
	}
	return &result
}

// normalizeFrameworkName maps user-friendly aliases to the
// canonical framework strings used by the Scanner.
func normalizeFrameworkName(input string) string {
	lower := strings.ToLower(input)
	switch lower {
	case "nist_ai_rmf", "nist-ai-rmf", "nist.ai-1.500", "nist", "nist ai rmf":
		return "nist_ai_rmf"
	case "atlas", "mitre atlas":
		return "atlas"
	case "owasp", "owasp_llm", "owasp llm top 10", "owasp_llm_top_10":
		return "owasp"
	case "hipaa":
		return "hipaa"
	case "pci", "pci-dss", "pci_dss":
		return "pci"
	case "soc2", "soc 2", "soc-2", "soc2_type2":
		return "soc2"
	case "iso27001", "iso 27001", "iso-27001":
		return "iso27001"
	case "iso42001", "iso 42001", "iso-42001", "iso 42001 ai":
		return "iso42001"
	case "fedramp", "fed ramp", "fed-ramp":
		return "fedramp"
	case "fips", "fips 140-2", "fips140-2", "fips_140_2", "fips 140-3", "fips140-3":
		return "fips"
	case "gdpr", "gdpr eu", "eu gdpr":
		return "gdpr"
	case "cis", "cis v8", "cis-v8", "cis_controls", "cis controls":
		return "cis"
	case "nist_csf", "nist csf", "nist-csf", "nist csf 2.0":
		return "nist_csf"
	case "owasp_web", "owasp top 10", "owasp top ten", "owasp-web", "owasp web":
		return "owasp_web"
	case "csa_star", "csa star", "csa-star", "csastar":
		return "csa_star"
	case "nist_ai_600_1", "nist ai 600-1", "nist-ai-600-1", "nist ai 600 1":
		return "nist_ai_600_1"
	case "ccpa", "ccpa/cpra", "ccpa cpra", "california consumer privacy act":
		return "ccpa"
	case "eu_ai_act", "eu ai act", "eu-ai-act", "euaiact", "european ai act":
		return "eu_ai_act"
	case "cmmcl2", "cmmc level 2", "cmmc-l2", "cmmc":
		return "cmmcl2"
	case "nist800171", "nist 800-171", "nist-800-171", "nist 800 171", "nist800-171":
		return "nist800171"
	case "hitrust", "hitrust csf", "hi-trust":
		return "hitrust"
	case "tisax", "tisax enx", "enx tisax":
		return "tisax"
	}
	return input // pass through unchanged; the Scanner will return ErrUnknownFramework
}

// ---- /integrity ----

// serveIntegrity returns the SHA256 hash of the ATLAS pattern set
// for auditors to verify rule integrity. This endpoint allows
// external auditors to compare the deployed pattern set against
// a known-good baseline.
func (a *API) serveIntegrity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get ATLAS pattern integrity directly from a fresh framework instance
	// This ensures deterministic results regardless of registry state.
	f := NewATLASFramework(0)
	result := f.PatternIntegrity()

	resp := map[string]any{
		"integrity": result,
		"framework": "MITRE ATLAS",
	}
	writeJSON(w, http.StatusOK, resp)
}

// serveAuditTrail returns audit trail entries matching the query
// parameters. Supports filtering by pattern_id, framework, change_type,
// since (RFC3339), until (RFC3339), author, and limit.
//
// GET /api/v1/compliance/audit-trail?framework=ATLAS&limit=50
// GET /api/v1/compliance/audit-trail?pattern_id=T1535.001
// GET /api/v1/compliance/audit-trail?change_type=modified&since=2025-01-01T00:00:00Z
func (a *API) serveAuditTrail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.auditTrail == nil {
		writeError(w, http.StatusNotFound, "audit trail not configured")
		return
	}

	q := AuditQuery{
		PatternID:  r.URL.Query().Get("pattern_id"),
		ChangeType: ChangeType(r.URL.Query().Get("change_type")),
		Author:     r.URL.Query().Get("author"),
	}
	if fw := r.URL.Query().Get("framework"); fw != "" {
		q.Framework = Framework(fw)
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			q.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			q.Until = t
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			q.Limit = n
		}
	}

	data, err := a.auditTrail.AuditEntriesAsJSON(q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit trail: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ---- /vendor-risk ----

func (a *API) serveVendorRisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	profiles := PredefinedVendorProfiles()
	vendors := make([]*VendorAssessment, 0, len(profiles))
	for _, v := range profiles {
		vendors = append(vendors, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vendors": vendors,
		"count":   len(vendors),
	})
}

func (a *API) serveVendorRiskAssess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		VendorName string `json:"vendor_name"`
		Category   string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.VendorName == "" {
		writeError(w, http.StatusBadRequest, "vendor_name is required")
		return
	}
	category := VendorCategory(req.Category)
	if category == "" {
		category = VendorOther
	}
	assessment := NewVendorAssessment(req.VendorName, category)
	writeJSON(w, http.StatusOK, assessment)
}

// ---- /policy-engine ----

func (a *API) servePolicyEngine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.policyEngine == nil {
		writeError(w, http.StatusNotFound, "policy engine not configured")
		return
	}
	framework := r.URL.Query().Get("framework")
	policies := a.policyEngine.ListPolicies(PolicyFilter{Framework: framework})
	writeJSON(w, http.StatusOK, map[string]any{
		"policies": policies,
		"count":   len(policies),
	})
}

func (a *API) servePolicyEngineEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.policyEngine == nil {
		writeError(w, http.StatusNotFound, "policy engine not configured")
		return
	}
	var input PolicyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		// Allow empty body
		input = PolicyInput{}
	}
	framework := r.URL.Query().Get("framework")
	var results []*PolicyResult
	var err error
	if framework != "" {
		results, err = a.policyEngine.EvaluateFramework(r.Context(), framework, input)
	} else {
		results, err = a.policyEngine.EvaluateAll(r.Context(), input)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "evaluation failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"count":   len(results),
	})
}

// ---- /evidence ----

func (a *API) serveEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.evidenceCollector == nil {
		writeError(w, http.StatusNotFound, "evidence collector not configured")
		return
	}
	filter := EvidenceFilter{
		Framework: r.URL.Query().Get("framework"),
		ControlID: r.URL.Query().Get("control_id"),
		Type:      EvidenceType(r.URL.Query().Get("type")),
		Status:    EvidenceStatus(r.URL.Query().Get("status")),
	}
	items := a.evidenceCollector.QueryEvidence(filter)
	writeJSON(w, http.StatusOK, map[string]any{
		"evidence": items,
		"count":    len(items),
	})
}

func (a *API) serveEvidenceCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.evidenceCollector == nil {
		writeError(w, http.StatusNotFound, "evidence collector not configured")
		return
	}
	var req struct {
		Framework string `json:"framework"`
		ControlID string `json:"control_id"`
		Type      string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	item, err := a.evidenceCollector.CollectEvidence(r.Context(), req.Framework, req.ControlID, EvidenceType(req.Type))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "collection failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (a *API) serveEvidenceVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.evidenceCollector == nil {
		writeError(w, http.StatusNotFound, "evidence collector not configured")
		return
	}
	var req struct {
		ID         string `json:"id"`
		VerifiedBy string `json:"verified_by"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := a.evidenceCollector.VerifyEvidence(req.ID, req.VerifiedBy); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified", "id": req.ID})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errcheck // Encode errors after headers are typically client disconnects
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":   http.StatusText(status),
		"message": message,
		"status":  status,
	})
}
