// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Control Count Registration (v3.2.0 Phase 3.4)
//
// framework_registration.go registers the count of compliance
// controls for the frameworks that have real implementations
// (HIPAA and PCI). Other modules (SOC 2, ISO 42001, FedRAMP,
// FIPS) return 0 controls for now (HasImplementation=false in
// the module requirements table).
//
// The control count is the meaningful metric that the customer
// portal needs: "this framework has 54 controls, your current
// scan covers 48 of them, compliance is 88.9%". Per-request
// scoring (which would actually run CheckAll on live request
// data) is a much larger feature for a later release; for v3.2.0,
// the scan API returns the registered control count + a 0 score
// (the "no live scan has been run" indicator).
//
// v3.2.0 Phase 3.4. The HIPAA module is at
// pkg/compliance/hipaa and the PCI module is at pkg/compliance/pci.
// They each register their own controls via the upstream
// BaseComplianceModule.

package compliance

import (
	"sync"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/eu-ai-act"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/hipaa"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance/pci"
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
		mod := eu_ai_act.NewEUAIModule() // keep underscore alias name even though import path uses hyphens
		if mod != nil {
			controls := mod.Controls()
			registerFrameworkControls("eu_ai_act", len(controls))
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
