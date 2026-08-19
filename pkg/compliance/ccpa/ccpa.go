// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - CCPA/CPRA Compliance Module
// =========================================================================
//
// CCPA/CPRA (California Consumer Privacy Act / California Privacy Rights
// Act) is California's comprehensive consumer privacy law. This module
// implements 26 in-scope CCPA/CPRA controls as a developer-tier licensed
// compliance module, organised across five categories:
//
//   - Consumer Rights          (8 controls, 5 automated)
//   - Opt-Out Rights           (6 controls, 4 automated)
//   - Privacy Rights           (4 controls, 2 automated)
//   - Data Handling             (4 controls, 1 automated)
//   - Compliance & Enforcement  (4 controls, 2 automated)
//
// Total: 26 controls — 14 automated, 12 manual.
//
// Module metadata:
//   - Framework:     "ccpa"
//   - Version:       "2.0"
//   - Required tier: Developer (gated via pkg/compliance/gating.go)
//   - Dependencies:  gdpr, soc2, ioc, trust
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
// California Privacy Rights Act) compliance framework as a developer-tier
// licensed module. It embeds *compliance.BaseComplianceModule which
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
// The module is licensed at the Developer tier.
func NewCCPAModule() *CCPAModule {
	m := &CCPAModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("ccpa", "2.0", core.TierDeveloper),
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

// registerControls wires all 26 CCPA/CPRA controls into the module.
// Called once from NewCCPAModule.
//
// Controls are organised by CCPA/CPRA category:
//
//	CR = Consumer Rights          (8 controls)
//	OS = Opt-Out Rights           (6 controls)
//	PR = Privacy Rights           (4 controls)
//	DH = Data Handling             (4 controls)
//	CE = Compliance & Enforcement  (4 controls)
func (m *CCPAModule) registerControls() {
	// CR: Consumer Rights (8 controls)
	m.registerCRControls()

	// OS: Opt-Out Rights (6 controls)
	m.registerOSControls()

	// PR: Privacy Rights (4 controls)
	m.registerPRControls()

	// DH: Data Handling (4 controls)
	m.registerDHControls()

	// CE: Compliance & Enforcement (4 controls)
	m.registerCEControls()
}

// registerCRControls registers the Consumer Rights controls.
func (m *CCPAModule) registerCRControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-01",
		Name:        "Right to Know — Categories of Personal Information Collected",
		Description: "§1798.100(a): Consumers have the right to know the categories of personal information collected",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToKnow,
		References:  []string{"CCPA §1798.100(a)", "CPRA §1798.100(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-02",
		Name:        "Right to Know — Sources of Personal Information",
		Description: "§1798.100(a): Consumers have the right to know the sources of personal information collected",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkSourcesOfPI,
		References:  []string{"CCPA §1798.100(a)", "CCPA §1798.110(a)(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-03",
		Name:        "Right to Know — Purpose of Collection",
		Description: "§1798.100(a): Consumers have the right to know the purpose for collecting personal information",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.100(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-04",
		Name:        "Right to Know — Third Party Sharing",
		Description: "§1798.100(a): Consumers have the right to know categories of third parties with whom data is shared",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkThirdPartySharing,
		References:  []string{"CCPA §1798.100(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-05",
		Name:        "Right to Delete — Submission Process",
		Description: "§1798.105(a): Consumers have the right to request deletion of their personal information",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRightToDelete,
		References:  []string{"CCPA §1798.105(a)", "CPRA §1798.105"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-06",
		Name:        "Right to Delete — Verification Process",
		Description: "§1798.105(a)(5): Business must verify the identity of the consumer making a deletion request",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CCPA §1798.105(a)(5)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-07",
		Name:        "Right to Correct — Personal Information",
		Description: "§1798.106(a): Consumers have the right to correct inaccurate personal information",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToCorrect,
		References:  []string{"CPRA §1798.106(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CR-08",
		Name:        "Right to Data Portability",
		Description: "§1798.100(d): Consumers have the right to receive their personal information in a portable format",
		Category:    "Consumer Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CCPA §1798.100(d)", "CPRA §1798.100(d)"},
	})
}

// registerOSControls registers the Opt-Out Rights controls.
func (m *CCPAModule) registerOSControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-01",
		Name:        "Right to Opt-Out of Sale",
		Description: "§1798.120(a): Consumers have the right to opt-out of the sale of their personal information",
		Category:    "Opt-Out Rights",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRightToOptOut,
		References:  []string{"CCPA §1798.120(a)", "CPRA §1798.120"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-02",
		Name:        "Do Not Sell My Personal Information Link",
		Description: "§1798.135(a)(1): Business must provide a clear and conspicuous 'Do Not Sell My Personal Information' link",
		Category:    "Opt-Out Rights",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkDoNotSellLink,
		References:  []string{"CCPA §1798.135(a)(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-03",
		Name:        "Opt-Out of Sharing",
		Description: "§1798.120(b): Consumers have the right to opt-out of the sharing of personal information for cross-context behavioral advertising",
		Category:    "Opt-Out Rights",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkOptOutSharing,
		References:  []string{"CCPA §1798.120(b)", "CPRA §1798.120(b)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-04",
		Name:        "Opt-Out Preference Signals",
		Description: "§1798.135(b)(1): Business must process opt-out preference signals sent by platforms or technology",
		Category:    "Opt-Out Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkOptOutSignals,
		References:  []string{"CCPA §1798.135(b)(1)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-05",
		Name:        "Right to Limit Use of Sensitive Personal Information",
		Description: "§1798.121(a): Consumers have the right to limit use of sensitive personal information",
		Category:    "Opt-Out Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CPRA §1798.121(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-OS-06",
		Name:        "Minor's Right to Opt-Out",
		Description: "§1798.120(c): Consumers under 16 have additional opt-out protections",
		Category:    "Opt-Out Rights",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"CCPA §1798.120(c)"},
	})
}

// registerPRControls registers the Privacy Rights controls.
func (m *CCPAModule) registerPRControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-PR-01",
		Name:        "Non-Discrimination for Exercising Rights",
		Description: "§1798.125(a): Business shall not discriminate against consumers for exercising their privacy rights",
		Category:    "Privacy Rights",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkNonDiscrimination,
		References:  []string{"CCPA §1798.125(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-PR-02",
		Name:        "Privacy Policy — Content Requirements",
		Description: "§1798.135(c): Business must maintain a privacy policy that describes privacy practices",
		Category:    "Privacy Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.135(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-PR-03",
		Name:        "Privacy Policy — Annual Review",
		Description: "§1798.135(c)(2): Privacy policy must be reviewed and updated at least once every 12 months",
		Category:    "Privacy Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkPrivacyPolicyReview,
		References:  []string{"CCPA §1798.135(c)(2)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-PR-04",
		Name:        "Privacy Policy — Accessibility",
		Description: "§1798.135(c)(3): Privacy policy must be easily accessible to consumers",
		Category:    "Privacy Rights",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.135(c)(3)"},
	})
}

// registerDHControls registers the Data Handling controls.
func (m *CCPAModule) registerDHControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-DH-01",
		Name:        "Data Minimization",
		Description: "§1798.100(c): Business shall only collect personal information that is reasonably necessary for the stated purpose",
		Category:    "Data Handling",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CCPA §1798.100(c)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-DH-02",
		Name:        "Data Retention Limits",
		Description: "§1798.100(a)(3): Business shall not retain personal information for longer than necessary",
		Category:    "Data Handling",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CCPA §1798.100(a)(3)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-DH-03",
		Name:        "Data Categories Disclosure",
		Description: "§1798.100(a): Business must disclose categories of personal information collected",
		Category:    "Data Handling",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataCategories,
		References:  []string{"CCPA §1798.100(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-DH-04",
		Name:        "Sensitive Personal Information Handling",
		Description: "§1798.121: Business must handle sensitive personal information with additional protections",
		Category:    "Data Handling",
		Severity:    compliance.SeverityCritical,
		Automated:   false,
		References:  []string{"CPRA §1798.121"},
	})
}

// registerCEControls registers the Compliance & Enforcement controls.
func (m *CCPAModule) registerCEControls() {
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CE-01",
		Name:        "Data Breach Notification",
		Description: "§1798.150: Consumers must be notified of data breaches affecting their personal information",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachNotification,
		References:  []string{"CCPA §1798.150"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CE-02",
		Name:        "Service Provider Contracts",
		Description: "§1798.140(ag): Service provider contracts must include required privacy provisions",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"CCPA §1798.140(ag)", "CPRA §1798.140"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CE-03",
		Name:        "Consumer Request Response Timeframe",
		Description: "§1798.145(a): Business must respond to consumer requests within 45 days",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRequestTimeframe,
		References:  []string{"CCPA §1798.145(a)"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "CCPA-CE-04",
		Name:        "Record-Keeping for Consumer Requests",
		Description: "§1798.130(a)(5): Business must maintain records of consumer requests for 24 months",
		Category:    "Compliance & Enforcement",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"CCPA §1798.130(a)(5)"},
	})
}

// Dependencies returns required modules. CCPA/CPRA depends on the
// GDPR module (for shared privacy patterns), SOC 2 module (for
// trust controls), IOC store (for incident data), and Trust Framework
// (for attestations).
func (m *CCPAModule) Dependencies() []string {
	return []string{"gdpr", "soc2", "ioc", "trust"}
}

// --- Automated Check Functions (14 total) ---

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
			ControlID:   "CCPA-CR-01",
			ControlName: "Right to Know — Categories of Personal Information Collected",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Right to Know: privacy policy, data collection disclosure, and consumer rights mechanism detected",
			Evidence:    []string{"privacy_policy", "data_collection", "right_to_know"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.100(a)", "CPRA §1798.100(a)"},
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
		ControlID:   "CCPA-CR-01",
		ControlName: "Right to Know — Categories of Personal Information Collected",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement privacy policy, data collection disclosure, and right to know mechanism per CCPA §1798.100(a)",
		References:  []string{"CCPA §1798.100(a)", "CPRA §1798.100(a)"},
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
			ControlID:   "CCPA-CR-02",
			ControlName: "Right to Know — Sources of Personal Information",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Sources of PI: data sources, collection methods, and transparency detected",
			Evidence:    []string{"data_sources", "collection_method", "transparency"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.100(a)", "CCPA §1798.110(a)(2)"},
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
		ControlID:   "CCPA-CR-02",
		ControlName: "Right to Know — Sources of Personal Information",
		Status:      status,
		Severity:    compliance.SeverityMedium,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Disclose all sources and collection methods for personal information per CCPA §1798.100(a)",
		References:  []string{"CCPA §1798.100(a)", "CCPA §1798.110(a)(2)"},
	}, nil
}

// checkThirdPartySharing verifies that third-party sharing of PI is disclosed.
func (m *CCPAModule) checkThirdPartySharing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasThirdParty := strings.Contains(inputStr, "third_party") || strings.Contains(inputStr, "third_party_sharing")
	hasDataSharing := strings.Contains(inputStr, "data_sharing") || strings.Contains(inputStr, "sharing")
	hasDisclosure := strings.Contains(inputStr, "sharing_disclosure") || strings.Contains(inputStr, "disclosure")

	violations := []string{}
	if !hasThirdParty {
		violations = append(violations, "third-party disclosure not detected")
	}
	if !hasDataSharing {
		violations = append(violations, "data sharing disclosure not detected")
	}
	if !hasDisclosure {
		violations = append(violations, "sharing disclosure mechanism not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-CR-04",
			ControlName: "Right to Know — Third Party Sharing",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Third Party Sharing: third-party disclosure, data sharing, and sharing mechanism detected",
			Evidence:    []string{"third_party", "data_sharing", "sharing_disclosure"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.100(a)"},
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Third Party Sharing gaps: " + strings.Join(violations, ", ")

	if hasThirdParty || hasDataSharing {
		status = compliance.StatusPartial
		message = "Partial Third Party Sharing compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-CR-04",
		ControlName: "Right to Know — Third Party Sharing",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Disclose categories of third parties with whom personal information is shared per CCPA §1798.100(a)",
		References:  []string{"CCPA §1798.100(a)"},
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
			ControlID:   "CCPA-CR-05",
			ControlName: "Right to Delete — Submission Process",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Right to Delete: deletion capability, mechanism, and process detected",
			Evidence:    []string{"deletion", "right_to_delete", "deletion_process"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.105(a)", "CPRA §1798.105"},
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
		ControlID:   "CCPA-CR-05",
		ControlName: "Right to Delete — Submission Process",
		Status:      status,
		Severity:    compliance.SeverityCritical,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement consumer deletion request mechanism and process per CCPA §1798.105(a)",
		References:  []string{"CCPA §1798.105(a)", "CPRA §1798.105"},
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
			ControlID:   "CCPA-CR-07",
			ControlName: "Right to Correct — Personal Information",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Right to Correct: correction mechanism, consumer rights, and data accuracy process detected",
			Evidence:    []string{"correction", "consumer_rights", "data_accuracy"},
			Timestamp:   time.Now(),
			References:  []string{"CPRA §1798.106(a)"},
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
		ControlID:   "CCPA-CR-07",
		ControlName: "Right to Correct — Personal Information",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement correction request mechanism and data accuracy process per CPRA §1798.106(a)",
		References:  []string{"CPRA §1798.106(a)"},
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
			ControlName: "Right to Opt-Out of Sale",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Right to Opt-Out: opt-out mechanism, consent management, and consumer rights detected",
			Evidence:    []string{"opt_out", "consent", "consumer_rights"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.120(a)", "CPRA §1798.120"},
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
		ControlName: "Right to Opt-Out of Sale",
		Status:      status,
		Severity:    compliance.SeverityCritical,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement opt-out mechanism, consent management, and consumer rights disclosure per CCPA §1798.120(a)",
		References:  []string{"CCPA §1798.120(a)", "CPRA §1798.120"},
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
			ControlName: "Do Not Sell My Personal Information Link",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Do Not Sell Link: homepage link and opt-out mechanism detected",
			Evidence:    []string{"do_not_sell", "homepage"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.135(a)(1)"},
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
		ControlName: "Do Not Sell My Personal Information Link",
		Status:      status,
		Severity:    compliance.SeverityCritical,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Provide a clear Do Not Sell My Personal Information link on homepage per CCPA §1798.135(a)(1)",
		References:  []string{"CCPA §1798.135(a)(1)"},
	}, nil
}

// checkOptOutSharing verifies that consumers can opt-out of sharing for
// cross-context behavioral advertising.
func (m *CCPAModule) checkOptOutSharing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOptOutSharing := strings.Contains(inputStr, "opt_out_sharing") || strings.Contains(inputStr, "sharing_opt_out")
	hasCrossContext := strings.Contains(inputStr, "cross_context") || strings.Contains(inputStr, "cross_context_advertising")
	hasBehavioral := strings.Contains(inputStr, "behavioral_advertising") || strings.Contains(inputStr, "targeted_advertising")

	violations := []string{}
	if !hasOptOutSharing {
		violations = append(violations, "opt-out of sharing mechanism not detected")
	}
	if !hasCrossContext {
		violations = append(violations, "cross-context disclosure not detected")
	}
	if !hasBehavioral {
		violations = append(violations, "behavioral advertising disclosure not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-OS-03",
			ControlName: "Opt-Out of Sharing",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Opt-Out of Sharing: opt-out mechanism, cross-context disclosure, and behavioral advertising disclosure detected",
			Evidence:    []string{"opt_out_sharing", "cross_context", "behavioral_advertising"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.120(b)", "CPRA §1798.120(b)"},
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Opt-Out of Sharing gaps: " + strings.Join(violations, ", ")

	if hasOptOutSharing || hasCrossContext {
		status = compliance.StatusPartial
		message = "Partial Opt-Out of Sharing compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-OS-03",
		ControlName: "Opt-Out of Sharing",
		Status:      status,
		Severity:    compliance.SeverityCritical,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement opt-out of sharing for cross-context behavioral advertising per CCPA §1798.120(b)",
		References:  []string{"CCPA §1798.120(b)", "CPRA §1798.120(b)"},
	}, nil
}

// checkOptOutSignals verifies that opt-out preference signals (e.g. GPC) are
// processed.
func (m *CCPAModule) checkOptOutSignals(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasOptOutSignal := strings.Contains(inputStr, "opt_out_signal") || strings.Contains(inputStr, "preference_signal")
	hasGPC := strings.Contains(inputStr, "gpc") || strings.Contains(inputStr, "gpc_signal")
	hasGlobalPrivacyControl := strings.Contains(inputStr, "global_privacy_control") || strings.Contains(inputStr, "global_privacy")

	violations := []string{}
	if !hasOptOutSignal {
		violations = append(violations, "opt-out signal processing not detected")
	}
	if !hasGPC {
		violations = append(violations, "GPC support not detected")
	}
	if !hasGlobalPrivacyControl {
		violations = append(violations, "Global Privacy Control support not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-OS-04",
			ControlName: "Opt-Out Preference Signals",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Opt-Out Preference Signals: signal processing, GPC, and Global Privacy Control detected",
			Evidence:    []string{"opt_out_signal", "gpc", "global_privacy_control"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.135(b)(1)"},
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Opt-Out Preference Signals gaps: " + strings.Join(violations, ", ")

	if hasOptOutSignal || hasGPC {
		status = compliance.StatusPartial
		message = "Partial Opt-Out Preference Signals compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-OS-04",
		ControlName: "Opt-Out Preference Signals",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement processing of opt-out preference signals including GPC per CCPA §1798.135(b)(1)",
		References:  []string{"CCPA §1798.135(b)(1)"},
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
			ControlID:   "CCPA-PR-01",
			ControlName: "Non-Discrimination for Exercising Rights",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Non-Discrimination: policy and equal service guarantee detected",
			Evidence:    []string{"non_discrimination", "equal_service"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.125(a)"},
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
		ControlID:   "CCPA-PR-01",
		ControlName: "Non-Discrimination for Exercising Rights",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement non-discrimination policy and equal service guarantee per CCPA §1798.125(a)",
		References:  []string{"CCPA §1798.125(a)"},
	}, nil
}

// checkPrivacyPolicyReview verifies that the privacy policy is reviewed
// at least annually.
func (m *CCPAModule) checkPrivacyPolicyReview(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasReview := strings.Contains(inputStr, "privacy_policy_review") || strings.Contains(inputStr, "policy_review")
	hasAnnualReview := strings.Contains(inputStr, "annual_review") || strings.Contains(inputStr, "12_months")
	hasPolicyUpdate := strings.Contains(inputStr, "policy_update") || strings.Contains(inputStr, "policy_updated")

	violations := []string{}
	if !hasReview {
		violations = append(violations, "privacy policy review process not detected")
	}
	if !hasAnnualReview {
		violations = append(violations, "annual review cadence not detected")
	}
	if !hasPolicyUpdate {
		violations = append(violations, "policy update mechanism not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-PR-03",
			ControlName: "Privacy Policy — Annual Review",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Privacy Policy Annual Review: review process, annual cadence, and update mechanism detected",
			Evidence:    []string{"privacy_policy_review", "annual_review", "policy_update"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.135(c)(2)"},
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Privacy Policy Annual Review gaps: " + strings.Join(violations, ", ")

	if hasReview || hasAnnualReview {
		status = compliance.StatusPartial
		message = "Partial Privacy Policy Annual Review compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-PR-03",
		ControlName: "Privacy Policy — Annual Review",
		Status:      status,
		Severity:    compliance.SeverityMedium,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement annual privacy policy review and update process per CCPA §1798.135(c)(2)",
		References:  []string{"CCPA §1798.135(c)(2)"},
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
			ControlID:   "CCPA-DH-03",
			ControlName: "Data Categories Disclosure",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityMedium,
			Message:     "Data Categories: PI categories, personal information, and collection purposes disclosed",
			Evidence:    []string{"data_categories", "personal_information", "collection_purpose"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.100(a)"},
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
		ControlID:   "CCPA-DH-03",
		ControlName: "Data Categories Disclosure",
		Status:      status,
		Severity:    compliance.SeverityMedium,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Disclose all categories of PI collected, purposes, and sources per CCPA §1798.100(a)",
		References:  []string{"CCPA §1798.100(a)"},
	}, nil
}

// checkBreachNotification verifies that data breach notification procedures
// are in place.
func (m *CCPAModule) checkBreachNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasBreachNotification := strings.Contains(inputStr, "breach_notification") || strings.Contains(inputStr, "notification")
	hasDataBreach := strings.Contains(inputStr, "data_breach") || strings.Contains(inputStr, "breach")
	hasBreachResponse := strings.Contains(inputStr, "breach_response") || strings.Contains(inputStr, "incident_response")

	violations := []string{}
	if !hasBreachNotification {
		violations = append(violations, "breach notification process not detected")
	}
	if !hasDataBreach {
		violations = append(violations, "data breach handling not detected")
	}
	if !hasBreachResponse {
		violations = append(violations, "breach response plan not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-CE-01",
			ControlName: "Data Breach Notification",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityCritical,
			Message:     "Data Breach Notification: notification process, breach handling, and response plan detected",
			Evidence:    []string{"breach_notification", "data_breach", "breach_response"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.150"},
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Data Breach Notification gaps: " + strings.Join(violations, ", ")

	if hasBreachNotification || hasDataBreach {
		status = compliance.StatusPartial
		message = "Partial Data Breach Notification compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-CE-01",
		ControlName: "Data Breach Notification",
		Status:      status,
		Severity:    compliance.SeverityCritical,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement data breach notification procedures and response plan per CCPA §1798.150",
		References:  []string{"CCPA §1798.150"},
	}, nil
}

// checkRequestTimeframe verifies that consumer requests are responded to
// within the 45-day statutory timeframe.
func (m *CCPAModule) checkRequestTimeframe(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	inputStr := string(input)
	hasResponseTime := strings.Contains(inputStr, "request_response_time") || strings.Contains(inputStr, "response_time")
	has45Days := strings.Contains(inputStr, "45_days") || strings.Contains(inputStr, "45-day")
	hasConsumerRequest := strings.Contains(inputStr, "consumer_request") || strings.Contains(inputStr, "request_handling")

	violations := []string{}
	if !hasResponseTime {
		violations = append(violations, "request response timeframe not detected")
	}
	if !has45Days {
		violations = append(violations, "45-day response window not detected")
	}
	if !hasConsumerRequest {
		violations = append(violations, "consumer request handling not detected")
	}

	if len(violations) == 0 {
		return &compliance.ControlCheckResult{
			Framework:   m.Framework(),
			ControlID:   "CCPA-CE-03",
			ControlName: "Consumer Request Response Timeframe",
			Status:      compliance.StatusCompliant,
			Severity:    compliance.SeverityHigh,
			Message:     "Consumer Request Response Timeframe: response time, 45-day window, and request handling detected",
			Evidence:    []string{"request_response_time", "45_days", "consumer_request"},
			Timestamp:   time.Now(),
			References:  []string{"CCPA §1798.145(a)"},
		}, nil
	}

	status := compliance.StatusNonCompliant
	message := "Consumer Request Response Timeframe gaps: " + strings.Join(violations, ", ")

	if hasResponseTime || hasConsumerRequest {
		status = compliance.StatusPartial
		message = "Partial Consumer Request Response Timeframe compliance: " + strings.Join(violations, ", ")
	}

	return &compliance.ControlCheckResult{
		Framework:   m.Framework(),
		ControlID:   "CCPA-CE-03",
		ControlName: "Consumer Request Response Timeframe",
		Status:      status,
		Severity:    compliance.SeverityHigh,
		Message:     message,
		Evidence:    violations,
		Timestamp:   time.Now(),
		Remediation: "Implement consumer request response within 45 days per CCPA §1798.145(a)",
		References:  []string{"CCPA §1798.145(a)"},
	}, nil
}
