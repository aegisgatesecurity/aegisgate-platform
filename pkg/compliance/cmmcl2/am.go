// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CMMC L2 AM (Asset Management) Domain
// =========================================================================
//
// CMMC Level 2 — Asset Management domain (AM)
// NIST SP 800-171 Rev. 2 §3.4 practices (partial)
//
// In-scope AM controls (3 of ~5 AM practices are scanner-checkable):
//   AM.1.001  Identify and manage assets               (automated)
//   AM.2.001  Asset inventory                          (automated)
//   AM.2.002  Asset management policy                  (evidence-mapped)
//
// =========================================================================

package cmmcl2

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
)

// registerAMControls wires the AM domain controls into the module.
func (m *CMMCL2Module) registerAMControls() {
	// AM.1.001: Identify and manage assets (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AM-01",
		Name:        "Identify And Manage Assets",
		Description: "CMMC L2 AM.1.001: Identify and manage system assets — inventory, track, and label all hardware/software",
		Category:    "Asset Management",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkIdentifyManageAssets,
		References:  []string{"CMMC L2 AM.1.001", "NIST SP 800-171 §3.4.1"},
	})

	// AM.2.001: Asset inventory (automated)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AM-02",
		Name:        "Asset Inventory",
		Description: "CMMC L2 AM.2.001: Maintain an asset inventory — SBOM, dependency tracking, version management",
		Category:    "Asset Management",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkAssetInventory,
		References:  []string{"CMMC L2 AM.2.001", "NIST SP 800-171 §3.4.2"},
	})

	// AM.2.002: Asset management policy (evidence-mapped)
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CMMCL2-AM-03",
		Name:        "Asset Management Policy",
		Description: "CMMC L2 AM.2.002: Document and disseminate asset management policy. AegisGate generates the asset management evidence for the customer's CMMC assessment.",
		Category:    "Asset Management",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"CMMC L2 AM.2.002", "NIST SP 800-171 §3.4.1"},
	})
}

// checkIdentifyManageAssets verifies that system assets are identified,
// tracked, and labeled. Maps to CMMC L2 AM.1.001.
func (m *CMMCL2Module) checkIdentifyManageAssets(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasInventory := strings.Contains(inputStr, "inventory") || strings.Contains(inputStr, "asset_management")
	hasLabeling := strings.Contains(inputStr, "label") || strings.Contains(inputStr, "classification") || strings.Contains(inputStr, "tags")
	hasTracking := strings.Contains(inputStr, "tracking") || strings.Contains(inputStr, "monitoring")

	if hasInventory && (hasLabeling || hasTracking) {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AM-01",
			ControlName: "Identify And Manage Assets",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Asset management controls verified (inventory + labeling/tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasInventory {
		violations = append(violations, "asset inventory not configured")
	}
	if !hasLabeling && !hasTracking {
		violations = append(violations, "no asset labeling or tracking detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AM-01",
		ControlName: "Identify And Manage Assets",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityHigh,
		Message:     "Asset management gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Configure asset inventory (asset_management=true), enable labeling/classification, and asset tracking",
	}, nil
}

// checkAssetInventory verifies SBOM and dependency tracking is in place.
// Maps to CMMC L2 AM.2.001.
func (m *CMMCL2Module) checkAssetInventory(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSBOM := strings.Contains(inputStr, "sbom") || strings.Contains(inputStr, "cyclonedx")
	hasDeps := strings.Contains(inputStr, "dependencies") || strings.Contains(inputStr, "dependency")
	hasVersion := strings.Contains(inputStr, "version")

	if hasSBOM && hasDeps {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CMMCL2-AM-02",
			ControlName: "Asset Inventory",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Asset inventory verified (SBOM + dependency tracking)",
			Timestamp:   time.Now(),
		}, nil
	}

	violations := []string{}
	if !hasSBOM {
		violations = append(violations, "SBOM not configured")
	}
	if !hasDeps {
		violations = append(violations, "dependency tracking not configured")
	}
	if !hasVersion {
		violations = append(violations, "version tracking not detected")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CMMCL2-AM-02",
		ControlName: "Asset Inventory",
		Status:      compliance.StatusNonCompliant,
		Severity:    compliance.SeverityMedium,
		Message:     "Asset inventory gaps: " + strings.Join(violations, ", "),
		Timestamp:   time.Now(),
		Remediation: "Enable SBOM generation (sbom.enabled=true) and dependency tracking. Ensure all components have version metadata.",
	}, nil
}
