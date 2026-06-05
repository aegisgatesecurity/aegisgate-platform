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
}

// NewAPI creates a new compliance HTTP API. Both scanner and mgr
// are required. If either is nil, the API returns 500 for all
// scan requests (fail-closed).
func NewAPI(scanner *Scanner, mgr *license.Manager) *API {
	return &API{scanner: scanner, mgr: mgr}
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
	default:
		http.NotFound(w, r)
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
		return "NIST.AI-1.500"
	case "atlas", "mitre atlas":
		return "ATLAS"
	case "owasp", "owasp_llm", "owasp llm top 10", "owasp_llm_top_10":
		return "OWASP"
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
	}
	return input // pass through unchanged; the Scanner will return ErrUnknownFramework
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
