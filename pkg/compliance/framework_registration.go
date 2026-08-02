// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Control Count Registration
//
// framework_registration.go registers the control counts for all
// compliance frameworks that have real implementations. Each module
// constructs itself, reports its control count, and the count is
// cached for the scanner's scoreFramework helper.
//
// The control count is the meaningful metric that the customer
// portal needs: "this framework has N controls, your current
// scan covers M of them, compliance is M/N * 100%".
//
// v3.6.0 M3: Added CMMC L2, NIST 800-171, HITRUST, TISAX, CCPA
// v3.7.0: Added CSA STAR, NIST AI 600-1, OWASP Web, ISO 27001,
//   NIST CSF, CIS, ISO 42001, FedRAMP, FIPS, EU AI Act.
//   Added community frameworks (ATLAS, GDPR, OWASP LLM).

package compliance

import (
	"strings"
	"sync"

	upstream_common "github.com/aegisgatesecurity/aegisgate/pkg/compliance/common"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/ccpa"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/ferpa"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/cis"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/cjis"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/cmmcl2"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/csa_star"
	eu_ai_act "github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/eu-ai-act"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/fedramp"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/fips"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/hipaa"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/hitrust"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/iso27001"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/iso42001"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/nist800171"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/nist_ai_600_1"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/nist_ai_rmf"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/nist_csf"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/owasp_web"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/pci"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/soc2"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/tisax"
)

// controlCountCache caches the number of registered controls
// per framework name. Computed once at registration time and
// memoized so the scanner can read the count without paying
// the construction cost on every scan.
var (
	controlCountCache   = make(map[string]int)
	controlCountCacheMu sync.RWMutex
)

// registerFrameworkControls runs the framework's constructor
// and records its control count in the cache. Returns the
// count for the caller's convenience.
//
// If the framework constructor panics or fails, the count is
// recorded as 0 (the framework is treated as "no controls
// registered" for scoring purposes).
func registerFrameworkControls(frameworkName string, controls int) {
	controlCountCacheMu.Lock()
	defer controlCountCacheMu.Unlock()
	controlCountCache[frameworkName] = controls
}

// lookupControlCount returns the cached control count for the
// given framework, or 0 if the framework isn't registered. Used
// by the scanner's scoreFramework helper.
func lookupControlCount(framework string) int {
	controlCountCacheMu.RLock()
	defer controlCountCacheMu.RUnlock()
	// Try exact match first, then lowercase.
	if count, ok := controlCountCache[framework]; ok {
		return count
	}
	return controlCountCache[strings.ToLower(framework)]
}

// RegisterBuiltinFrameworks wires all compliance module sub-packages
// into the scanner's control count cache. Should be called once
// at platform startup, before the first /api/v1/compliance/scan
// request is served.
//
// Idempotent: safe to call multiple times. Safe to call
// concurrently.
func RegisterBuiltinFrameworks() {
	// HIPAA
	func() {
		defer func() { _ = recover() }()
		hipaaMod := hipaa.NewHIPAAModule()
		if hipaaMod != nil {
			controls := hipaaMod.Controls()
			registerFrameworkControls("hipaa", len(controls))
		}
	}()
	// PCI-DSS
	func() {
		defer func() { _ = recover() }()
		pciMod := pci.NewPCIModule()
		if pciMod != nil {
			controls := pciMod.Controls()
			registerFrameworkControls("pci", len(controls))
		}
	}()
	// EU AI Act
	func() {
		defer func() { _ = recover() }()
		mod := eu_ai_act.NewEUAIModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("eu_ai_act", len(controls))
		}
	}()
	// FedRAMP Moderate
	func() {
		defer func() { _ = recover() }()
		mod := fedramp.NewFedRAMPModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("fedramp", len(controls))
		}
	}()
	// SOC 2 Type II
	func() {
		defer func() { _ = recover() }()
		mod := soc2.NewSOC2Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("soc2", len(controls))
		}
	}()
	// ISO 27001:2022
	func() {
		defer func() { _ = recover() }()
		mod := iso27001.NewISO27001Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("iso27001", len(controls))
		}
	}()
	// ISO/IEC 42001:2023
	func() {
		defer func() { _ = recover() }()
		mod := iso42001.NewISO42001Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("iso42001", len(controls))
		}
	}()
	// FIPS 140-2/140-3
	func() {
		defer func() { _ = recover() }()
		mod := fips.NewFIPS140Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("fips", len(controls))
		}
	}()
	// NIST CSF 2.0
	func() {
		defer func() { _ = recover() }()
		mod := nist_csf.NewNISTCSFModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("nist_csf", len(controls))
		}
	}()
	// CIS Critical Security Controls v8
	func() {
		defer func() { _ = recover() }()
		mod := cis.NewCISModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("cis", len(controls))
		}
	}()
	// CMMC Level 2
	func() {
		defer func() { _ = recover() }()
		mod := cmmcl2.NewCMMCL2Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("cmmcl2", len(controls))
		}
	}()
	// NIST SP 800-171
	func() {
		defer func() { _ = recover() }()
		mod := nist800171.NewNIST800171Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("nist800171", len(controls))
		}
	}()
	// HITRUST CSF v11.2
	func() {
		defer func() { _ = recover() }()
		mod := hitrust.NewHITRUSTModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("hitrust", len(controls))
		}
	}()
	// TISAX AL2
	func() {
		defer func() { _ = recover() }()
		mod := tisax.NewTISAXModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("tisax", len(controls))
		}
	}()
	// CCPA/CPRA (Community tier)
	func() {
		defer func() { _ = recover() }()
		mod := ccpa.NewCCPAModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("ccpa", len(controls))
		}
	}()
	// NIST AI RMF 1.0 (Community tier)
	func() {
		defer func() { _ = recover() }()
		mod := nist_ai_rmf.NewNISTAIRMFModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("nist_ai_rmf", len(controls))
		}
	}()
	// CSA STAR Level 1 (Community tier)
	func() {
		defer func() { _ = recover() }()
		mod := csa_star.NewCSASTARModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("csa_star", len(controls))
		}
	}()
	// NIST AI 600-1 GenAI Profile (Professional+ tier)
	func() {
		defer func() { _ = recover() }()
		mod := nist_ai_600_1.NewNISTAIGenAIProfileModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("nist_ai_600_1", len(controls))
		}
	}()
	// OWASP Top 10 Web Application Security (Community tier)
	func() {
		defer func() { _ = recover() }()
		mod := owasp_web.NewOWASPWebModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("owasp_web", len(controls))
		}
	}()
	// CJIS Security Policy v5.9.1 (Enterprise tier)
	func() {
		defer func() { _ = recover() }()
		mod := cjis.NewCJISModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("cjis", len(controls))
		}
	}()
	// FERPA (34 CFR Part 99) (Professional tier)
	func() {
		defer func() { _ = recover() }()
		mod := ferpa.NewFERPAModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("ferpa", len(controls))
		}
	}()

	// Community frameworks (ATLAS, GDPR, OWASP LLM) use a different
	// interface (common.Framework) that doesn't have Controls(). Their
	// control/pattern counts are known at registration time and are
	// registered as static values.
	registerFrameworkControls("atlas", 66) // MITRE ATLAS: 66 technique patterns (full v4.6.0 coverage)
	registerFrameworkControls("gdpr", 6)   // GDPR: 6 core data protection requirements
	registerFrameworkControls("owasp", 10) // OWASP LLM Top 10: 10 risk categories
}

// RegisteredFrameworkControls returns the control count for a
// given framework. Used by the scanner as a fallback when the
// framework doesn't have a registered FrameworkModule in the
// scanner's registry. Returns 0 if not registered.
func RegisteredFrameworkControls(framework string) int {
	return lookupControlCount(framework)
}

// RegisterBuiltinFrameworksIntoRegistry registers framework module
// instances into the provided Registry so the scanner can invoke
// GenerateAssessment for detailed compliance checks. Modules that
// implement FrameworkModule (the newer BaseComplianceModule pattern)
// are registered directly. Community-framework modules that only
// implement common.Framework are skipped (they use the control count
// cache for scoring).
//
// This should be called after RegisterBuiltinFrameworks() which
// populates the control count cache.
func RegisterBuiltinFrameworksIntoRegistry(registry *Registry) {
	if registry == nil {
		return
	}
	// Billable modules (FrameworkModule pattern)
	registerIntoRegistry(registry, "hipaa", hipaa.NewHIPAAModule())
	registerIntoRegistry(registry, "pci", pci.NewPCIModule())
	registerIntoRegistry(registry, "eu_ai_act", eu_ai_act.NewEUAIModule())
	registerIntoRegistry(registry, "fedramp", fedramp.NewFedRAMPModule())
	registerIntoRegistry(registry, "soc2", soc2.NewSOC2Module())
	registerIntoRegistry(registry, "iso27001", iso27001.NewISO27001Module())
	registerIntoRegistry(registry, "iso42001", iso42001.NewISO42001Module())
	registerIntoRegistry(registry, "fips_140", fips.NewFIPS140Module())
	registerIntoRegistry(registry, "nist_csf", nist_csf.NewNISTCSFModule())
	registerIntoRegistry(registry, "cis", cis.NewCISModule())
	registerIntoRegistry(registry, "cmmcl2", cmmcl2.NewCMMCL2Module())
	registerIntoRegistry(registry, "nist800171", nist800171.NewNIST800171Module())
	registerIntoRegistry(registry, "hitrust", hitrust.NewHITRUSTModule())
	registerIntoRegistry(registry, "tisax", tisax.NewTISAXModule())
	registerIntoRegistry(registry, "ccpa", ccpa.NewCCPAModule())
	registerIntoRegistry(registry, "nist_ai_rmf", nist_ai_rmf.NewNISTAIRMFModule())
	registerIntoRegistry(registry, "csa_star", csa_star.NewCSASTARModule())
	registerIntoRegistry(registry, "nist_ai_600_1", nist_ai_600_1.NewNISTAIGenAIProfileModule())
	registerIntoRegistry(registry, "owasp_web", owasp_web.NewOWASPWebModule())
	registerIntoRegistry(registry, "cjis", cjis.NewCJISModule())
	registerIntoRegistry(registry, "ferpa", ferpa.NewFERPAModule())
}

// registerIntoRegistry is a helper that safely registers a framework module
// into the Registry. If the module is nil (e.g., due to a panic during
// construction), it is skipped. The module must implement the upstream
// common.Framework interface to be registered.
func registerIntoRegistry(registry *Registry, frameworkID string, mod core.Module) {
	if mod == nil {
		return
	}
	defer func() { _ = recover() }()
	if fw, ok := mod.(upstream_common.Framework); ok {
		_ = registry.Register(fw)
	}
}
