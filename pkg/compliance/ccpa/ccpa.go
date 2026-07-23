// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CCPA/CPRA Compliance Module
// =========================================================================
//
// CCPA/CPRA (California Consumer Privacy Act / California Privacy Rights
// Act) is California's comprehensive consumer privacy law. This module
// implements the in-scope CCPA/CPRA controls as a community-tier (free,
// bundled) compliance module.
//
// Module metadata:
//   - Framework:    "ccpa"
//   - Version:      "1.0"
//   - Required tier: Community (free, bundled)
//   - Dependencies: gdpr, soc2, ioc, trust
//
// IMPORTANT — Self-attested posture:
//   AegisGate is NOT a law firm or regulatory body. The CCPA/CPRA module
//   generates the technical evidence (audit logs, IOC store, trust
//   framework attestations, compliance scan results) that a customer
//   uses in their CCPA/CPRA compliance documentation. Legal review and
//   formal compliance attestation are the customer's responsibility.
//
// Architecture:
//   - ccpa.go:       module wiring, registerControls, Dependencies, pattern caches
//   - ccpa_test.go:  unit tests
//
// Reference:
//   - CCPA: California Civil Code §1798.100–§1798.199
//   - CPRA: Proposition 24 (2020), effective January 1, 2023
//
// =========================================================================

package ccpa

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// CCPAModule implements the CCPA/CPRA (California Consumer Privacy Act /
// California Privacy Rights Act) compliance framework as a community-tier
// (free, bundled) module. It embeds *compliance.BaseComplianceModule which
// provides RegisterControl, Controls, Framework, Version, CheckAll, and
// GenerateAssessment out of the box.
type CCPAModule struct {
	*compliance.BaseComplianceModule

	// Pattern caches for automated controls
	privacyPatterns  []*regexp.Regexp
	consentPatterns  []*regexp.Regexp
	deletionPatterns []*regexp.Regexp
}

// NewCCPAModule creates a new CCPA/CPRA compliance module. It is safe
// to call multiple times; the module is stateless after construction
// aside from its registered controls.
//
// The module is bundled at the Community tier (no separate purchase required).
func NewCCPAModule() *CCPAModule {
	m := &CCPAModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("ccpa", "1.0", core.TierCommunity),
	}
	m.initPatterns()
	m.registerControls()
	return m
}

// initPatterns compiles the regex patterns used by automated controls.
// Called once at construction time.
func (m *CCPAModule) initPatterns() {
	m.privacyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)privacy[_ ]?policy`),
		regexp.MustCompile(`(?i)data[_ ]?collection`),
		regexp.MustCompile(`(?i)personal[_ ]?information`),
		regexp.MustCompile(`(?i)data[_ ]?categories`),
		regexp.MustCompile(`(?i)right[_ ]?to[_ ]?know`),
	}

	m.consentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)opt[_ ]?out`),
		regexp.MustCompile(`(?i)do[_ ]?not[_ ]?sell`),
		regexp.MustCompile(`(?i)consent`),
		regexp.MustCompile(`(?i)preference[_ ]?center`),
		regexp.MustCompile(`(?i)consumer[_ ]?rights`),
	}

	m.deletionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)deletion`),
		regexp.MustCompile(`(?i)data[_ ]?deletion`),
		regexp.MustCompile(`(?i)right[_ ]?to[_ ]?delete`),
		regexp.MustCompile(`(?i)erase`),
	}
}

// registerControls wires all CCPA/CPRA controls into the module.
// Called once from NewCCPAModule.
//
// Controls are organized by CCPA/CPRA category:
//
//	TK = Right to Know (3 controls)
//	DR = Right to Delete (2 controls)
//	OS = Right to Opt-Out/Sell (3 controls)
//	NC = Right to Non-Discrimination (2 controls)
//	PR = Privacy Rights (2 controls, CPRA additions)
func (m *CCPAModule) registerControls() {
	// TK: Right to Know (3 controls)
	m.registerTKControls()

	// DR: Right to Delete (2 controls)
	m.registerDRControls()

	// OS: Right to Opt-Out/Sell (3 controls)
	m.registerOSControls()

	// NC: Right to Non-Discrimination (2 controls)
	m.registerNCControls()

	// PR: Privacy Rights (2 controls, CPRA additions)
	m.registerPRControls()
}

// registerTKControls registers the Right to Know controls (CCPA §1798.100).
func (m *CCPAModule) registerTKControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-TK-01",
		Name:        "Right to Know",
		Description: "CCPA §1798.100: Consumer right to know what personal information is collected",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToKnow,
		References:  []string{"CCPA §1798.100", "CPRA §1798.100"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-TK-02",
		Name:        "Data Categories",
		Description: "CCPA §1798.100(a): Business must disclose categories of personal information collected",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataCategories,
		References:  []string{"CCPA §1798.100(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-TK-03",
		Name:        "Sources of PI",
		Description: "CCPA §1798.110(a)(2): Consumer right to know sources of personal information",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSourcesOfPI,
		References:  []string{"CCPA §1798.110(a)(2)"},
	})
}

// registerDRControls registers the Right to Delete controls (CCPA §1798.105).
func (m *CCPAModule) registerDRControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-DR-01",
		Name:        "Right to Delete",
		Description: "CCPA §1798.105: Consumer right to request deletion of personal information",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToDelete,
		References:  []string{"CCPA §1798.105", "CPRA §1798.105"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-DR-02",
		Name:        "Deletion Exceptions",
		Description: "CCPA §1798.105(d): Exceptions to deletion requirement for specific business purposes",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.105(d)"},
	})
}

// registerOSControls registers the Right to Opt-Out/Sell controls (CCPA §1798.120).
func (m *CCPAModule) registerOSControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-01",
		Name:        "Right to Opt-Out",
		Description: "CCPA §1798.120: Consumer right to opt-out of sale of personal information",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToOptOut,
		References:  []string{"CCPA §1798.120", "CPRA §1798.120"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-02",
		Name:        "Do Not Sell Link",
		Description: "CCPA §1798.135: Business must provide a clear Do Not Sell link on homepage",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDoNotSellLink,
		References:  []string{"CCPA §1798.135"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-03",
		Name:        "Service Provider Contracts",
		Description: "CCPA §1798.140(v): Service provider contracts must include CCPA-compliant data processing terms",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.140(v)", "CPRA §1798.140"},
	})
}

// registerNCControls registers the Right to Non-Discrimination controls (CCPA §1798.125).
func (m *CCPAModule) registerNCControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-NC-01",
		Name:        "Non-Discrimination",
		Description: "CCPA §1798.125(a): Business shall not discriminate against consumers who exercise CCPA rights",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNonDiscrimination,
		References:  []string{"CCPA §1798.125(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-NC-02",
		Name:        "Financial Incentives",
		Description: "CCPA §1798.125(b): Financial incentive programs must disclose material terms and be voluntary",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.125(b)"},
	})
}

// registerPRControls registers the Privacy Rights controls (CPRA additions).
func (m *CCPAModule) registerPRControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-PR-01",
		Name:        "Right to Correct",
		Description: "CPRA §1798.106: Consumer right to request correction of inaccurate personal information",
		Category:    "Privacy Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRightToCorrect,
		References:  []string{"CPRA §1798.106"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-PR-02",
		Name:        "Privacy Policy",
		Description: "CCPA §1798.100(b): Privacy policy must disclose categories of PI collected, purposes, and retention periods",
		Category:    "Privacy Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.100(b)", "CPRA §1798.100(a)"},
	})
}

// Dependencies returns required modules. CCPA/CPRA depends on the
// GDPR module (for shared privacy patterns), SOC 2 module (for
// trust controls), IOC store (for incident data), and Trust Framework
// (for attestations).
func (m *CCPAModule) Dependencies() []string {
	return []string{"gdpr", "soc2", "ioc", "trust"}
}

// --- Automated Check Functions ---

// checkRightToKnow verifies that the business discloses what PI is collected.
func (m *CCPAModule) checkRightToKnow(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasPrivacyPolicy := strings.Contains(inputStr, "privacy_policy") || strings.Contains(inputStr, "privacy_policy_link")
	hasDataCollection := strings.Contains(inputStr, "data_collection") || strings.Contains(inputStr, "personal_information")
	hasRightToKnow := strings.Contains(inputStr, "right_to_know") || strings.Contains(inputStr, "consumer_rights")
	hasDisclosure := strings.Contains(inputStr, "disclosure") || strings.Contains(inputStr, "transparency")

	violations := []string{}
	if !hasPrivacyPolicy {
		violations = append(violations, "privacy policy not detected")
	}
	if !hasDataCollection {
		violations = append(violations, "data collection disclosure not detected")
	}
	if !hasRightToKnow {
		violations = append(violations, "right to know mechanism not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-TK-01",
			ControlName: "Right to Know",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Right to Know: privacy policy, data collection disclosure, and consumer rights mechanism detected",
			Evidence:    []string{"privacy_policy", "data_collection", "right_to_know"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Right to Know gaps: " + strings.Join(violations, ", ")

	if hasPrivacyPolicy || hasDisclosure {
		status = compliance.StatusPartial
		message = "Partial Right to Know compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-TK-01",
		ControlName: "Right to Know",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement privacy policy, data collection disclosure, and right to know mechanism per CCPA §1798.100",
	}, nil
}

// checkDataCategories verifies that categories of PI are disclosed.
func (m *CCPAModule) checkDataCategories(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDataCategories := strings.Contains(inputStr, "data_categories") || strings.Contains(inputStr, "categories")
	hasPIList := strings.Contains(inputStr, "personal_information") || strings.Contains(inputStr, "pi_list")
	hasCollectionPurpose := strings.Contains(inputStr, "collection_purpose") || strings.Contains(inputStr, "purpose")

	violations := []string{}
	if !hasDataCategories {
		violations = append(violations, "data categories not disclosed")
	}
	if !hasPIList {
		violations = append(violations, "personal information list not detected")
	}
	if !hasCollectionPurpose {
		violations = append(violations, "collection purpose not disclosed")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-TK-02",
			ControlName: "Data Categories",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Data Categories: PI categories, personal information, and collection purposes disclosed",
			Evidence:    []string{"data_categories", "personal_information", "collection_purpose"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Data Categories gaps: " + strings.Join(violations, ", ")

	if hasDataCategories || hasPIList {
		status = compliance.StatusPartial
		message = "Partial Data Categories compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-TK-02",
		ControlName: "Data Categories",
		Status:      status,
		Severity:    compliance.SeverityMedium,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Disclose all categories of PI collected, purposes, and sources per CCPA §1798.100(a)",
	}, nil
}

// checkSourcesOfPI verifies that sources of personal information are disclosed.
func (m *CCPAModule) checkSourcesOfPI(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasSources := strings.Contains(inputStr, "data_sources") || strings.Contains(inputStr, "sources")
	hasCollectionMethod := strings.Contains(inputStr, "collection_method") || strings.Contains(inputStr, "data_collection")
	hasTransparency := strings.Contains(inputStr, "transparency") || strings.Contains(inputStr, "consumer_rights")

	violations := []string{}
	if !hasSources {
		violations = append(violations, "data sources not disclosed")
	}
	if !hasCollectionMethod {
		violations = append(violations, "collection method not detected")
	}
	if !hasTransparency {
		violations = append(violations, "transparency mechanism not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-TK-03",
			ControlName: "Sources of PI",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Sources of PI: data sources, collection methods, and transparency detected",
			Evidence:    []string{"data_sources", "collection_method", "transparency"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Sources of PI gaps: " + strings.Join(violations, ", ")

	if hasSources || hasTransparency {
		status = compliance.StatusPartial
		message = "Partial Sources of PI compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-TK-03",
		ControlName: "Sources of PI",
		Status:      status,
		Severity:    compliance.SeverityMedium,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Disclose all sources and collection methods for personal information per CCPA §1798.110(a)(2)",
	}, nil
}

// checkRightToDelete verifies that consumers can request deletion of PI.
func (m *CCPAModule) checkRightToDelete(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDeletion := strings.Contains(inputStr, "deletion") || strings.Contains(inputStr, "data_deletion")
	hasRightToDelete := strings.Contains(inputStr, "right_to_delete") || strings.Contains(inputStr, "right_to_know")
	hasProcess := strings.Contains(inputStr, "deletion_process") || strings.Contains(inputStr, "consumer_rights")

	violations := []string{}
	if !hasDeletion {
		violations = append(violations, "deletion capability not detected")
	}
	if !hasRightToDelete {
		violations = append(violations, "right to delete mechanism not detected")
	}
	if !hasProcess {
		violations = append(violations, "deletion process not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-DR-01",
			ControlName: "Right to Delete",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Right to Delete: deletion capability, mechanism, and process detected",
			Evidence:    []string{"deletion", "right_to_delete", "deletion_process"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Right to Delete gaps: " + strings.Join(violations, ", ")

	if hasDeletion || hasRightToDelete {
		status = compliance.StatusPartial
		message = "Partial Right to Delete compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-DR-01",
		ControlName: "Right to Delete",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement consumer deletion request mechanism and process per CCPA §1798.105",
	}, nil
}

// checkRightToOptOut verifies that consumers can opt-out of PI sale.
func (m *CCPAModule) checkRightToOptOut(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOptOut := strings.Contains(inputStr, "opt_out") || strings.Contains(inputStr, "optout")
	hasConsent := strings.Contains(inputStr, "consent") || strings.Contains(inputStr, "preference_center")
	hasConsumerRights := strings.Contains(inputStr, "consumer_rights") || strings.Contains(inputStr, "do_not_sell")

	violations := []string{}
	if !hasOptOut {
		violations = append(violations, "opt-out mechanism not detected")
	}
	if !hasConsent {
		violations = append(violations, "consent management not detected")
	}
	if !hasConsumerRights {
		violations = append(violations, "consumer rights disclosure not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-OS-01",
			ControlName: "Right to Opt-Out",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Right to Opt-Out: opt-out mechanism, consent management, and consumer rights detected",
			Evidence:    []string{"opt_out", "consent", "consumer_rights"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Right to Opt-Out gaps: " + strings.Join(violations, ", ")

	if hasOptOut || hasConsent {
		status = compliance.StatusPartial
		message = "Partial Right to Opt-Out compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-OS-01",
		ControlName: "Right to Opt-Out",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement opt-out mechanism, consent management, and consumer rights disclosure per CCPA §1798.120",
	}, nil
}

// checkDoNotSellLink verifies that a Do Not Sell link is provided.
func (m *CCPAModule) checkDoNotSellLink(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasDoNotSell := strings.Contains(inputStr, "do_not_sell") || strings.Contains(inputStr, "donotsell")
	hasHomepageLink := strings.Contains(inputStr, "homepage") || strings.Contains(inputStr, "opt_out_link")
	hasPrivacyPolicy := strings.Contains(inputStr, "privacy_policy") || strings.Contains(inputStr, "consumer_rights")

	violations := []string{}
	if !hasDoNotSell {
		violations = append(violations, "Do Not Sell link not detected")
	}
	if !hasHomepageLink {
		violations = append(violations, "homepage opt-out link not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-OS-02",
			ControlName: "Do Not Sell Link",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Do Not Sell Link: homepage link and opt-out mechanism detected",
			Evidence:    []string{"do_not_sell", "homepage"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Do Not Sell Link gaps: " + strings.Join(violations, ", ")

	if hasDoNotSell || hasPrivacyPolicy {
		status = compliance.StatusPartial
		message = "Partial Do Not Sell Link compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-OS-02",
		ControlName: "Do Not Sell Link",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Provide a clear Do Not Sell My Personal Information link on homepage per CCPA §1798.135",
	}, nil
}

// checkNonDiscrimination verifies that consumers are not discriminated against
// for exercising CCPA rights.
func (m *CCPAModule) checkNonDiscrimination(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasNonDiscrimination := strings.Contains(inputStr, "non_discrimination") || strings.Contains(inputStr, "consumer_rights")
	hasEqualService := strings.Contains(inputStr, "equal_service") || strings.Contains(inputStr, "non_discriminatory")
	hasPolicy := strings.Contains(inputStr, "privacy_policy") || strings.Contains(inputStr, "policy")

	violations := []string{}
	if !hasNonDiscrimination {
		violations = append(violations, "non-discrimination policy not detected")
	}
	if !hasEqualService {
		violations = append(violations, "equal service guarantee not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-NC-01",
			ControlName: "Non-Discrimination",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Non-Discrimination: policy and equal service guarantee detected",
			Evidence:    []string{"non_discrimination", "equal_service"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Non-Discrimination gaps: " + strings.Join(violations, ", ")

	if hasNonDiscrimination || hasPolicy {
		status = compliance.StatusPartial
		message = "Partial Non-Discrimination compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-NC-01",
		ControlName: "Non-Discrimination",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement non-discrimination policy and equal service guarantee per CCPA §1798.125(a)",
	}, nil
}

// checkRightToCorrect verifies that consumers can request correction of PI.
func (m *CCPAModule) checkRightToCorrect(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasCorrection := strings.Contains(inputStr, "correction") || strings.Contains(inputStr, "right_to_correct")
	hasConsumerRights := strings.Contains(inputStr, "consumer_rights") || strings.Contains(inputStr, "privacy_policy")
	hasDataAccuracy := strings.Contains(inputStr, "data_accuracy") || strings.Contains(inputStr, "data_correction")

	violations := []string{}
	if !hasCorrection {
		violations = append(violations, "correction mechanism not detected")
	}
	if !hasConsumerRights {
		violations = append(violations, "consumer rights disclosure not detected")
	}
	if !hasDataAccuracy {
		violations = append(violations, "data accuracy process not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-PR-01",
			ControlName: "Right to Correct",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Right to Correct: correction mechanism, consumer rights, and data accuracy process detected",
			Evidence:    []string{"correction", "consumer_rights", "data_accuracy"},
			Timestamp:   time.Now(),
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Right to Correct gaps: " + strings.Join(violations, ", ")

	if hasCorrection || hasConsumerRights {
		status = compliance.StatusPartial
		message = "Partial Right to Correct compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-PR-01",
		ControlName: "Right to Correct",
		Status:      status,
		Severity:    compliance.SeverityMedium,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement correction request mechanism and data accuracy process per CPRA §1798.106",
	}, nil
}
