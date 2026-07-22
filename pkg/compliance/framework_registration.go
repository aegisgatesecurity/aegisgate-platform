// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Control Count Registration
//
// framework_registration.go registers the count of compliance
// controls for all frameworks that have real implementations.
// Each module constructs itself, reports its control count, and
// the count is cached for the scanner's scoreFramework helper.
//
// The control count is the meaningful metric that the customer
// portal needs: "this framework has N controls, your current
// scan covers M of them, compliance is M/N * 100%".
//
// v3.5.0: Added FedRAMP (60 controls), SOC 2, ISO 27001, ISO 42001,
// FIPS 140, NIST CSF, and CIS registration alongside HIPAA, PCI,
// and EU AI Act.

package compliance

import (
	"sync"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/cis"
	eu_ai_act "github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/eu-ai-act"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/fedramp"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/fips"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/hipaa"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/iso27001"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/iso42001"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/nist_csf"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/pci"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/soc2"
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
	return controlCountCache[framework]
}

// RegisterBuiltinFrameworks wires the HIPAA and PCI sub-packages
// into the scanner's control count cache. Should be called once
// at platform startup, before the first /api/v1/compliance/scan
// request is served.
//
// Idempotent: safe to call multiple times. Safe to call
// concurrently.
func RegisterBuiltinFrameworks() {
	// HIPAA: construct the module, read its controls, cache the count.
	// We don't keep the module alive because the scanner doesn't
	// run per-request control checks (yet); the count is enough
	// for the customer portal's "this framework has N controls"
	// display.
	func() {
		defer func() {
			// Swallow any panics from the constructor (defensive).
			_ = recover()
		}()
		hipaaMod := hipaa.NewHIPAAModule()
		if hipaaMod != nil {
			// The HIPAAModule embeds *BaseComplianceModule
			// (upstream). Its Controls() method returns the
			// registered control definitions.
			controls := hipaaMod.Controls()
			registerFrameworkControls("hipaa", len(controls))
		}
	}()
	// PCI: same pattern.
	func() {
		defer func() {
			_ = recover()
		}()
		pciMod := pci.NewPCIModule()
		if pciMod != nil {
			controls := pciMod.Controls()
			registerFrameworkControls("pci", len(controls))
		}
	}()
	// EU AI Act (v3.3.0 Phase 1).
	func() {
		defer func() { _ = recover() }()
		mod := eu_ai_act.NewEUAIModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("eu_ai_act", len(controls))
		}
	}()

	// FedRAMP Moderate (v3.5.0 M2 — Path C, 60 controls across 11
	// NIST 800-53 families). This is the module that ships with the
	// Professional+ tier.
	func() {
		defer func() { _ = recover() }()
		mod := fedramp.NewFedRAMPModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("fedramp", len(controls))
		}
	}()

	// SOC 2 Type II.
	func() {
		defer func() { _ = recover() }()
		mod := soc2.NewSOC2Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("soc2", len(controls))
		}
	}()

	// ISO 27001:2022.
	func() {
		defer func() { _ = recover() }()
		mod := iso27001.NewISO27001Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("iso27001", len(controls))
		}
	}()

	// ISO/IEC 42001:2023 (AI Management System).
	func() {
		defer func() { _ = recover() }()
		mod := iso42001.NewISO42001Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("iso42001", len(controls))
		}
	}()

	// FIPS 140-2/140-3.
	func() {
		defer func() { _ = recover() }()
		mod := fips.NewFIPS140Module()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("fips_140", len(controls))
		}
	}()

	// NIST CSF 2.0.
	func() {
		defer func() { _ = recover() }()
		mod := nist_csf.NewNISTCSFModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("nist_csf", len(controls))
		}
	}()

	// CIS Critical Security Controls v8.
	func() {
		defer func() { _ = recover() }()
		mod := cis.NewCISModule()
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("cis", len(controls))
		}
	}()
}

// RegisteredFrameworkControls returns the control count for a
// given framework. Used by the scanner as a fallback when the
// framework doesn't have a registered FrameworkModule in the
// scanner's registry. Returns 0 if not registered.
func RegisteredFrameworkControls(framework string) int {
	return lookupControlCount(framework)
}
