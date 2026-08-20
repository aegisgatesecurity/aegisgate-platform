// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security
// =========================================================================
//
// GDPR Compliance Module (Regulation (EU) 2016/679)
//
// Implements all 99 articles across 11 chapters of the General Data
// Protection Regulation using the new-style compliance.BaseComplianceModule
// with RegisterControl pattern. 27 controls are automated (CheckFunc) and
// the remaining 72 are manual (evidence-mapped).
//
// Tier: Developer ($149/mo)
// =========================================================================

// Package gdpr provides GDPR (General Data Protection Regulation) compliance.
package gdpr

import (
	"context"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate/pkg/compliance"
	"github.com/aegisgatesecurity/aegisgate/pkg/core"
)

// GDPRModule implements GDPR compliance controls as a licensed add-on module.
type GDPRModule struct {
	*compliance.BaseComplianceModule
}

// NewGDPRModule creates a new GDPR compliance module.
func NewGDPRModule() *GDPRModule {
	m := &GDPRModule{
		BaseComplianceModule: compliance.NewBaseComplianceModule("gdpr", "Regulation (EU) 2016/679", core.TierDeveloper),
	}
	m.registerControls()
	return m
}

// registerControls registers all 99 GDPR articles as compliance controls.
func (m *GDPRModule) registerControls() {
	// ── Chapter I: General Provisions (Art. 1-4) — all MANUAL ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art1",
		Name:        "Subject matter and objectives",
		Description: "This Regulation lays down rules relating to the protection of natural persons with regard to the processing of personal data and rules relating to the free movement of personal data.",
		Category:    "Chapter I - General Provisions",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 1"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art2",
		Name:        "Material scope",
		Description: "This Regulation applies to the processing of personal data wholly or partly by automated means and to the processing other than by automated means of personal data which form part of a filing system.",
		Category:    "Chapter I - General Provisions",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 2"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art3",
		Name:        "Territorial scope",
		Description: "This Regulation applies to the processing of personal data in the context of the activities of an establishment of a controller or processor in the Union, regardless of whether the processing takes place in the Union or not.",
		Category:    "Chapter I - General Provisions",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 3"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art4",
		Name:        "Definitions",
		Description: "Defines key terms including personal data, processing, controller, processor, consent, and pseudonymisation.",
		Category:    "Chapter I - General Provisions",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 4"},
	})

	// ── Chapter II: Principles (Art. 5-11) ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art5",
		Name:        "Principles relating to processing of personal data",
		Description: "Personal data shall be processed lawfully, fairly and in a transparent manner; collected for specified, explicit and legitimate purposes; adequate, relevant and limited to what is necessary; accurate and kept up to date; kept in a form which permits identification for no longer than necessary.",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkPrinciples,
		References:  []string{"GDPR Art. 5"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art6",
		Name:        "Lawfulness of processing",
		Description: "Processing shall be lawful only if at least one of the legal bases applies: consent, contract, legal obligation, vital interests, public task, or legitimate interests.",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkLawfulness,
		References:  []string{"GDPR Art. 6"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art7",
		Name:        "Conditions for consent",
		Description: "The controller shall be able to demonstrate that the data subject has consented to processing of their personal data. Consent shall be freely given, specific, informed and unambiguous.",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkConsentConditions,
		References:  []string{"GDPR Art. 7"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art8",
		Name:        "Conditions applicable to child's consent",
		Description: "Information society services offered to a child require parental consent for children below the age of 16 (or lower if Member State law provides).",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkChildConsent,
		References:  []string{"GDPR Art. 8"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art9",
		Name:        "Processing of special categories of personal data",
		Description: "Processing of personal data revealing racial or ethnic origin, political opinions, religious or philosophical beliefs, trade union membership, genetic data, biometric data, health data, or sex life/sexual orientation data is prohibited unless an exception applies.",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSpecialCategories,
		References:  []string{"GDPR Art. 9"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art10",
		Name:        "Processing of personal data relating to criminal convictions",
		Description: "Processing of personal data relating to criminal convictions and offences or related security measures shall be carried out only under the control of official authority or when authorised by Union or Member State law.",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkCriminalConvictionData,
		References:  []string{"GDPR Art. 10"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art11",
		Name:        "Processing which does not require identification",
		Description: "If the purposes for which a controller processes personal data do not require identification of a data subject, the controller shall not be obliged to maintain, acquire or process additional information for the sole purpose of complying with this Regulation.",
		Category:    "Chapter II - Principles",
		Severity:    compliance.SeverityLow,
		Automated:   true,
		CheckFunc:   m.checkAnonymization,
		References:  []string{"GDPR Art. 11"},
	})

	// ── Chapter III: Rights of the Data Subject (Art. 12-23) ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art12",
		Name:        "Transparent information, communication and modalities",
		Description: "The controller shall take appropriate measures to provide information referred to in Articles 13 and 14 and any communication under Articles 15-22 in a concise, transparent, intelligible and easily accessible form, using clear and plain language.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkTransparency,
		References:  []string{"GDPR Art. 12"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art13",
		Name:        "Information to be provided where data collected from the data subject",
		Description: "The controller shall provide the data subject with information including identity and contact details of the controller, purposes of processing, legal basis, recipients, retention period, and data subject rights.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataCollectionNotices,
		References:  []string{"GDPR Art. 13"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art14",
		Name:        "Information to be provided where data not obtained from the data subject",
		Description: "Where personal data have not been obtained from the data subject, the controller shall provide the data subject with information regarding the source and categories of data, and the purposes of processing.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkDataSourceNotices,
		References:  []string{"GDPR Art. 14"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art15",
		Name:        "Right of access by the data subject",
		Description: "The data subject shall have the right to obtain from the controller confirmation as to whether or not personal data concerning them are being processed, and, where that is the case, access to the personal data.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightOfAccess,
		References:  []string{"GDPR Art. 15"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art16",
		Name:        "Right to rectification",
		Description: "The data subject shall have the right to obtain from the controller without undue delay the rectification of inaccurate personal data concerning them.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToRectification,
		References:  []string{"GDPR Art. 16"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art17",
		Name:        "Right to erasure (right to be forgotten)",
		Description: "The data subject shall have the right to obtain from the controller the erasure of personal data concerning them without undue delay where the grounds for erasure apply.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkRightToErasure,
		References:  []string{"GDPR Art. 17"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art18",
		Name:        "Right to restriction of processing",
		Description: "The data subject shall have the right to obtain from the controller restriction of processing where one of the conditions applies.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRightToRestriction,
		References:  []string{"GDPR Art. 18"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art19",
		Name:        "Notification obligation regarding rectification or erasure or restriction",
		Description: "The controller shall communicate any rectification or erasure of personal data or restriction of processing to each recipient to whom the personal data have been disclosed.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkRectificationErasureNotification,
		References:  []string{"GDPR Art. 19"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art20",
		Name:        "Right to data portability",
		Description: "The data subject shall have the right to receive the personal data concerning them, which they have provided to a controller, in a structured, commonly used and machine-readable format and have the right to transmit those data to another controller.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataPortability,
		References:  []string{"GDPR Art. 20"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art21",
		Name:        "Right to object",
		Description: "The data subject shall have the right to object, on grounds relating to their particular situation, at any time to processing of personal data concerning them which is based on point (e) of Article 6(1) or point (a) of Article 9(2).",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRightToObject,
		References:  []string{"GDPR Art. 21"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art22",
		Name:        "Automated individual decision-making, including profiling",
		Description: "The data subject shall have the right not to be subject to a decision based solely on automated processing, including profiling, which produces legal effects concerning them or similarly significantly affects them.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkAutomatedDecisionMaking,
		References:  []string{"GDPR Art. 22"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art23",
		Name:        "Restrictions",
		Description: "Union or Member State law may restrict the scope of the obligations and rights provided for in Articles 12 to 22 and Article 34, as well as Article 5, when such restriction respects the essence of the fundamental rights and freedoms.",
		Category:    "Chapter III - Rights of the Data Subject",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 23"},
	})

	// ── Chapter IV: Controller and Processor (Art. 24-43) ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art24",
		Name:        "Responsibility of the controller",
		Description: "The controller shall take appropriate technical and organisational measures to ensure and to be able to demonstrate that processing is performed in accordance with this Regulation.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"GDPR Art. 24"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art25",
		Name:        "Data protection by design and by default",
		Description: "The controller shall, both at the time of the determination of the means for processing and at the time of the processing itself, implement appropriate technical and organisational measures, such as pseudonymisation, which are designed to implement data-protection principles.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDataProtectionByDesign,
		References:  []string{"GDPR Art. 25"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art26",
		Name:        "Joint controllers",
		Description: "Where two or more controllers jointly determine the purposes and means of processing, they shall be joint controllers. They shall in a transparent manner determine their respective responsibilities for compliance with this Regulation.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 26"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art27",
		Name:        "Representatives of controllers or processors not established in the Union",
		Description: "Controllers and processors not established in the Union shall designate a representative in the Union in accordance with the conditions of this Article.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 27"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art28",
		Name:        "Processor",
		Description: "Where processing is to be carried out on behalf of a controller, the controller shall use only processors providing sufficient guarantees to implement appropriate technical and organisational measures.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkProcessor,
		References:  []string{"GDPR Art. 28"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art29",
		Name:        "Processing under the authority of the controller or processor",
		Description: "The processor and any person acting under the authority of the controller or of the processor, who has access to personal data, shall not process those data except on instructions from the controller.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityMedium,
		Automated:   true,
		CheckFunc:   m.checkProcessingUnderAuthority,
		References:  []string{"GDPR Art. 29"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art30",
		Name:        "Records of processing activities",
		Description: "Each controller and, where applicable, the controller's representative, shall maintain a record of processing activities under its responsibility.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkRecordsOfProcessing,
		References:  []string{"GDPR Art. 30"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art31",
		Name:        "Cooperation with the supervisory authority",
		Description: "The controller and the processor and, where applicable, their representatives, shall cooperate, on request, with the supervisory authority in the performance of its tasks.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 31"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art32",
		Name:        "Security of processing",
		Description: "The controller and the processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, including encryption, ongoing confidentiality, integrity, availability and resilience of processing systems.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkSecurityOfProcessing,
		References:  []string{"GDPR Art. 32"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art33",
		Name:        "Notification of a personal data breach to the supervisory authority",
		Description: "In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the personal data breach to the supervisory authority.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityCritical,
		Automated:   true,
		CheckFunc:   m.checkBreachNotification,
		References:  []string{"GDPR Art. 33"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art34",
		Name:        "Communication of a personal data breach to the data subject",
		Description: "When the personal data breach is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall communicate the personal data breach to the data subject without undue delay.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkBreachCommunication,
		References:  []string{"GDPR Art. 34"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art35",
		Name:        "Data protection impact assessment",
		Description: "Where a type of processing in particular using new technologies, and taking into account the nature, scope, context and purposes of the processing, is likely to result in a high risk to the rights and freedoms of natural persons, the controller shall, prior to the processing, carry out an assessment of the impact of the envisaged processing operations on the protection of personal data.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDPIA,
		References:  []string{"GDPR Art. 35"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art36",
		Name:        "Prior consultation",
		Description: "The controller shall consult the supervisory authority prior to processing where a data protection impact assessment indicates that the processing would result in a high risk in the absence of measures taken by the controller to mitigate the risk.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 36"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art37",
		Name:        "Designation of the data protection officer",
		Description: "The controller and the processor shall designate a data protection officer in any case where the conditions of this Article are met.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityHigh,
		Automated:   true,
		CheckFunc:   m.checkDPODesignation,
		References:  []string{"GDPR Art. 37"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art38",
		Name:        "Position of the data protection officer",
		Description: "The data protection officer shall be involved in all issues which relate to the protection of personal data and shall report to the highest level of management of the controller or the processor.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 38"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art39",
		Name:        "Tasks of the data protection officer",
		Description: "The data protection officer shall have at least the following tasks: informing and advising, monitoring compliance, cooperating with the supervisory authority, and acting as contact point.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 39"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art40",
		Name:        "Codes of conduct",
		Description: "Member States, the supervisory authorities, the Board and the Commission shall encourage the drawing up of codes of conduct intended to contribute to the proper application of this Regulation.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 40"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art41",
		Name:        "Monitoring of approved codes of conduct",
		Description: "An accredited body for monitoring compliance with a code of conduct shall monitor compliance with the code by the controllers or processors which make use of it.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 41"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art42",
		Name:        "Certification",
		Description: "Member States, the supervisory authorities, the Board and the Commission shall encourage the establishment of data protection certification mechanisms and of data protection seals and marks.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 42"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art43",
		Name:        "Certification bodies",
		Description: "Without prejudice to the tasks and powers of the competent supervisory authority, a certification body accredited for the purposes of this Article shall be responsible for issuing and renewing certification.",
		Category:    "Chapter IV - Controller and Processor",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 43"},
	})

	// ── Chapter V: Transfer of personal data to third countries (Art. 44-50) — all MANUAL ──

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art44",
		Name:        "General principle for transfers",
		Description: "Any transfer of personal data which are undergoing processing or are intended for processing after transfer to a third country or an international organisation shall take place only if the conditions of this Chapter are complied with.",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"GDPR Art. 44"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art45",
		Name:        "Transfers on the basis of an adequacy decision",
		Description: "A transfer of personal data to a third country or an international organisation may take place where the Commission has decided that the third country or international organisation ensures an adequate level of protection.",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 45"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art46",
		Name:        "Transfers subject to appropriate safeguards",
		Description: "In the absence of a decision pursuant to Article 45, a controller or processor may transfer personal data to a third country only if the controller or processor has provided appropriate safeguards.",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"GDPR Art. 46"},
	})

	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art47",
		Name:        "Binding corporate rules",
		Description: "The controller or processor that is a group undertaking may transfer personal data to a third country under binding corporate rules approved by the supervisory authority.",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityHigh,
		Automated:   false,
		References:  []string{"GDPR Art. 47"},
	})

	// ── Chapter V (cont.): Art. 48-50 ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art48",
		Name:        "Transfers not covered by adequacy decision",
		Description: "Transfers of personal data to a third country not covered by an adequacy decision shall be made only with appropriate safeguards.",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 48"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art49",
		Name:        "Derogations for specific situations",
		Description: "In the absence of an adequacy decision or appropriate safeguards, a transfer may take place only on specific derogations (explicit consent, public interest, etc.).",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityMedium,
		Automated:   false,
		References:  []string{"GDPR Art. 49"},
	})
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art50",
		Name:        "Humanitarian aid transfers",
		Description: "International humanitarian assistance transfers shall be deemed lawful where personal data is processed for humanitarian purposes.",
		Category:    "Chapter V - Transfers of Personal Data",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 50"},
	})

	// ── Chapter VI (Independent Supervisory Authorities): Art. 51-59 ──
	for _, art := range []struct {
		id, name, desc string
		sev            compliance.Severity
	}{
		{"GDPR-Art51", "Supervisory authority", "Each Member State shall provide for one or more independent public authorities responsible for monitoring GDPR application.", compliance.SeverityMedium},
		{"GDPR-Art52", "Independence", "Supervisory authorities shall act with complete independence in performing their tasks.", compliance.SeverityMedium},
		{"GDPR-Art53", "General conditions for members", "Member States shall ensure conditions for members of supervisory authorities prevent conflicts of interest.", compliance.SeverityLow},
		{"GDPR-Art54", "Competence of supervisory authority", "Each supervisory authority shall be competent for the performance of tasks assigned to it under GDPR.", compliance.SeverityLow},
		{"GDPR-Art55", "Competence of the lead supervisory authority", "The lead supervisory authority shall be competent to act as such where a controller or processor carries out cross-border processing.", compliance.SeverityMedium},
		{"GDPR-Art56", "Competence of the lead supervisory authority for cross-border processing", "The lead supervisory authority coordinates the one-stop-shop mechanism.", compliance.SeverityMedium},
		{"GDPR-Art57", "Tasks", "Supervisory authorities shall monitor and enforce GDPR application, advise controllers, and handle complaints.", compliance.SeverityMedium},
		{"GDPR-Art58", "Powers", "Supervisory authorities have investigative, corrective, advisory, and authorisation powers.", compliance.SeverityHigh},
		{"GDPR-Art59", "Activity reports", "Each supervisory authority shall draw up an annual report on its activities.", compliance.SeverityLow},
	} {
		m.RegisterControl(compliance.ControlDefinition{
			ID:          art.id,
			Name:        art.name,
			Description: art.desc,
			Category:    "Chapter VI - Independent Supervisory Authorities",
			Severity:    art.sev,
			Automated:   false,
			References:  []string{"GDPR Art. " + strings.TrimPrefix(art.id, "GDPR-Art")},
		})
	}

	// ── Chapter VII (Cooperation): Art. 60-76 ──
	for _, art := range []struct {
		id, name, desc string
		sev            compliance.Severity
	}{
		{"GDPR-Art60", "Cooperation between lead and concerned supervisory authorities", "The lead supervisory authority shall cooperate with other concerned authorities.", compliance.SeverityLow},
		{"GDPR-Art61", "Mutual assistance", "Supervisory authorities shall provide each other with relevant information and mutual assistance.", compliance.SeverityLow},
		{"GDPR-Art62", "Joint operations of supervisory authorities", "Supervisory authorities may carry out joint operations including investigations.", compliance.SeverityLow},
		{"GDPR-Art63", "Consistency mechanism", "The Board shall contribute to consistent application of GDPR throughout the Union.", compliance.SeverityLow},
		{"GDPR-Art64", "Opinion of the Board", "The Board may issue opinions on matters submitted to it.", compliance.SeverityLow},
		{"GDPR-Art65", "Binding decision of the Board", "The Board shall take binding decisions in disputes between supervatory authorities.", compliance.SeverityMedium},
		{"GDPR-Art66", "Urgency procedure", "A supervisory authority may take urgent measures where there is an imminent risk of infringement.", compliance.SeverityMedium},
		{"GDPR-Art67", "Exchange of information", "The Commission may adopt acts for exchange of information between supervisory authorities.", compliance.SeverityLow},
		{"GDPR-Art68", "European Data Protection Board", "The Board shall be established as a body of the Union with legal personality.", compliance.SeverityLow},
		{"GDPR-Art69", "Independence of the Board", "The Board shall act independently.", compliance.SeverityLow},
		{"GDPR-Art70", "Tasks of the Board", "The Board shall ensure consistent application of GDPR, advise the Commission, and issue guidelines.", compliance.SeverityMedium},
		{"GDPR-Art71", "Reports", "The Board shall draw up an annual report on its activities.", compliance.SeverityLow},
		{"GDPR-Art72", "Procedure", "The Board shall take decisions by a majority of its members.", compliance.SeverityLow},
		{"GDPR-Art73", "Chair", "The Board shall elect a chair from its members.", compliance.SeverityLow},
		{"GDPR-Art74", "Tasks of the Chair", "The Chair shall have external representation, prepare Board meetings, and ensure cooperation.", compliance.SeverityLow},
		{"GDPR-Art75", "Secretariat of the Board", "The EDPS shall provide the Secretariat of the Board.", compliance.SeverityLow},
		{"GDPR-Art76", "Confidentiality", "Members of the Board shall be subject to confidentiality obligations.", compliance.SeverityLow},
	} {
		m.RegisterControl(compliance.ControlDefinition{
			ID:          art.id,
			Name:        art.name,
			Description: art.desc,
			Category:    "Chapter VII - Cooperation and Consistency",
			Severity:    art.sev,
			Automated:   false,
			References:  []string{"GDPR Art. " + strings.TrimPrefix(art.id, "GDPR-Art")},
		})
	}

	// ── Chapter VIII (Remedies, Liability, Penalties): Art. 77-84 ──
	for _, art := range []struct {
		id, name, desc string
		sev            compliance.Severity
	}{
		{"GDPR-Art77", "Right to lodge a complaint with a supervisory authority", "Data subjects have the right to lodge a complaint with a supervisory authority.", compliance.SeverityMedium},
		{"GDPR-Art78", "Right to an effective judicial remedy against a supervisory authority", "Data subjects have the right to an effective judicial remedy against a supervisory authority.", compliance.SeverityMedium},
		{"GDPR-Art79", "Right to an effective judicial remedy against a controller or processor", "Data subjects have the right to a judicial remedy against a controller or processor.", compliance.SeverityHigh},
		{"GDPR-Art80", "Representation of data subjects", "Data subjects may mandate non-profit bodies to lodge complaints on their behalf.", compliance.SeverityLow},
		{"GDPR-Art81", "Suspension of proceedings", "A court may suspend proceedings where a matter is pending before a supervisory authority.", compliance.SeverityLow},
		{"GDPR-Art82", "Right to compensation and liability", "Data subjects who have suffered material or non-material damage have the right to compensation.", compliance.SeverityHigh},
		{"GDPR-Art83", "Conditions for imposing administrative fines", "Administrative fines shall be imposed depending on circumstances (up to 4% of annual turnover).", compliance.SeverityCritical},
		{"GDPR-Art84", "Penalties", "Member States shall lay down rules on penalties applicable to infringements.", compliance.SeverityHigh},
	} {
		m.RegisterControl(compliance.ControlDefinition{
			ID:          art.id,
			Name:        art.name,
			Description: art.desc,
			Category:    "Chapter VIII - Remedies, Liability and Penalties",
			Severity:    art.sev,
			Automated:   false,
			References:  []string{"GDPR Art. " + strings.TrimPrefix(art.id, "GDPR-Art")},
		})
	}

	// ── Chapter IX (Specific Data Processing Situations): Art. 85 ──
	m.RegisterControl(compliance.ControlDefinition{
		ID:          "GDPR-Art85",
		Name:        "Freedom of expression and information",
		Description: "Member States shall reconcile the right to protection of personal data with the right to freedom of expression and information.",
		Category:    "Chapter IX - Specific Data Processing Situations",
		Severity:    compliance.SeverityLow,
		Automated:   false,
		References:  []string{"GDPR Art. 85"},
	})

	// ── Chapter X (Delegated Acts): Art. 86-91 ──
	for _, art := range []struct {
		id, name, desc string
		sev            compliance.Severity
	}{
		{"GDPR-Art86", "Processing of personal data in public registers", "Processing of personal data in official documents shall be governed by Member State law.", compliance.SeverityLow},
		{"GDPR-Art87", "Processing of national identification numbers", "Member States may prescribe conditions for processing national identification numbers.", compliance.SeverityMedium},
		{"GDPR-Art88", "Processing in the employment context", "Member States may provide specific rules for processing in employment contexts.", compliance.SeverityLow},
		{"GDPR-Art89", "Safeguards and derogations for research, statistical and archival purposes", "Processing for research purposes shall be subject to appropriate safeguards.", compliance.SeverityMedium},
		{"GDPR-Art90", "Obligations of secrecy", "Member States may provide exemptions for professional secrecy obligations.", compliance.SeverityLow},
		{"GDPR-Art91", "Existing data protection rules of churches", "Churches and religious associations may continue to apply their own data protection rules.", compliance.SeverityLow},
	} {
		m.RegisterControl(compliance.ControlDefinition{
			ID:          art.id,
			Name:        art.name,
			Description: art.desc,
			Category:    "Chapter X - Delegated Acts and Implementing Acts",
			Severity:    art.sev,
			Automated:   false,
			References:  []string{"GDPR Art. " + strings.TrimPrefix(art.id, "GDPR-Art")},
		})
	}

	// ── Chapter XI (Final Provisions): Art. 92-99 ──
	for _, art := range []struct {
		id, name, desc string
		sev            compliance.Severity
	}{
		{"GDPR-Art92", "Exercise of delegation", "The power to adopt delegated acts is conferred on the Commission subject to conditions.", compliance.SeverityLow},
		{"GDPR-Art93", "Committee procedure", "The Commission shall be assisted by a committee.", compliance.SeverityLow},
		{"GDPR-Art94", "Repeal of Directive 95/46/EC", "Directive 95/46/EC is repealed.", compliance.SeverityLow},
		{"GDPR-Art95", "Relationship with Directive 2002/58/EC", "This Regulation shall not impose additional obligations regarding processing for electronic communications.", compliance.SeverityLow},
		{"GDPR-Art96", "Relationship with previously concluded international agreements", "This Regulation shall not affect the application of international agreements concluded before its entry into force.", compliance.SeverityLow},
		{"GDPR-Art97", "Commission reports", "The Commission shall submit reports on the evaluation and review of this Regulation.", compliance.SeverityLow},
		{"GDPR-Art98", "Review of other legal acts on data protection", "The Commission may review other Union legal acts on data protection.", compliance.SeverityLow},
		{"GDPR-Art99", "Entry into force and application", "This Regulation shall enter into force on 25 May 2018 and shall apply from that date.", compliance.SeverityLow},
	} {
		m.RegisterControl(compliance.ControlDefinition{
			ID:          art.id,
			Name:        art.name,
			Description: art.desc,
			Category:    "Chapter XI - Final Provisions",
			Severity:    art.sev,
			Automated:   false,
			References:  []string{"GDPR Art. " + strings.TrimPrefix(art.id, "GDPR-Art")},
		})
	}
}

// ── CheckFunc implementations for automated controls ──

func (m *GDPRModule) checkPrinciples(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasMinimization := strings.Contains(s, "minimiz") || strings.Contains(s, "minimis") || strings.Contains(s, "purpose_limit")
	hasRetention := strings.Contains(s, "retention") || strings.Contains(s, "data_minimization")
	if hasMinimization || hasRetention {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art5", ControlName: "Principles relating to processing", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data minimization and purpose limitation principles detected", Timestamp: time.Now(), References: []string{"GDPR Art. 5"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art5", ControlName: "Principles relating to processing", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Data minimization and purpose limitation indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 5"}}, nil
}

func (m *GDPRModule) checkLawfulness(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasConsent := strings.Contains(s, "consent") || strings.Contains(s, "legal_basis") || strings.Contains(s, "lawful_basis")
	if hasConsent {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art6", ControlName: "Lawfulness of processing", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Legal basis for processing detected", Timestamp: time.Now(), References: []string{"GDPR Art. 6"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art6", ControlName: "Lawfulness of processing", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Legal basis indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 6"}}, nil
}

func (m *GDPRModule) checkConsentConditions(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasConsent := strings.Contains(s, "opt-in") || strings.Contains(s, "opt-out") || strings.Contains(s, "consent_management") || strings.Contains(s, "withdraw_consent")
	if hasConsent {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art7", ControlName: "Conditions for consent", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Consent management mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 7"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art7", ControlName: "Conditions for consent", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Consent management indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 7"}}, nil
}

func (m *GDPRModule) checkSpecialCategories(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasSensitive := strings.Contains(s, "health") || strings.Contains(s, "biometric") || strings.Contains(s, "genetic") || strings.Contains(s, "racial") || strings.Contains(s, "ethnic") || strings.Contains(s, "religion") || strings.Contains(s, "political")
	if hasSensitive {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art9", ControlName: "Processing of special categories of personal data", Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical, Message: "Special category data handling detected", Timestamp: time.Now(), References: []string{"GDPR Art. 9"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art9", ControlName: "Processing of special categories of personal data", Status: compliance.StatusPartial, Severity: compliance.SeverityCritical, Message: "Special category data handling indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 9"}}, nil
}

func (m *GDPRModule) checkTransparency(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasPolicy := strings.Contains(s, "privacy_policy") || strings.Contains(s, "privacy_notice") || strings.Contains(s, "transparency") || strings.Contains(s, "data_notice")
	if hasPolicy {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art12", ControlName: "Transparent information, communication and modalities", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Privacy policy and transparency indicators detected", Timestamp: time.Now(), References: []string{"GDPR Art. 12"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art12", ControlName: "Transparent information, communication and modalities", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Transparency indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 12"}}, nil
}

func (m *GDPRModule) checkDataCollectionNotices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasNotice := strings.Contains(s, "data_collection") || strings.Contains(s, "information_notice") || strings.Contains(s, "collection_notice")
	if hasNotice {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art13", ControlName: "Information to be provided where data collected from the data subject", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data collection notices detected", Timestamp: time.Now(), References: []string{"GDPR Art. 13"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art13", ControlName: "Information to be provided where data collected from the data subject", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Data collection notice indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 13"}}, nil
}

func (m *GDPRModule) checkAutomatedDecisionMaking(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAutomated := strings.Contains(s, "automated_decision") || strings.Contains(s, "ml_decision") || strings.Contains(s, "ai_decision") || strings.Contains(s, "algorithm") || strings.Contains(s, "profiling")
	if hasAutomated {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art22", ControlName: "Automated individual decision-making, including profiling", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Automated decision-making safeguards detected", Timestamp: time.Now(), References: []string{"GDPR Art. 22"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art22", ControlName: "Automated individual decision-making, including profiling", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Automated decision-making indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 22"}}, nil
}

func (m *GDPRModule) checkDataProtectionByDesign(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasDPbD := strings.Contains(s, "privacy_by_design") || strings.Contains(s, "data_protection_by_design") || strings.Contains(s, "default_privacy") || strings.Contains(s, "privacy_default")
	if hasDPbD {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art25", ControlName: "Data protection by design and by default", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data protection by design principles detected", Timestamp: time.Now(), References: []string{"GDPR Art. 25"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art25", ControlName: "Data protection by design and by default", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Data protection by design indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 25"}}, nil
}

func (m *GDPRModule) checkRecordsOfProcessing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasRecords := strings.Contains(s, "audit_log") || strings.Contains(s, "logging_enabled") || strings.Contains(s, "processing_records") || strings.Contains(s, "ropa")
	if hasRecords {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art30", ControlName: "Records of processing activities", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Records of processing activities detected", Timestamp: time.Now(), References: []string{"GDPR Art. 30"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art30", ControlName: "Records of processing activities", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Records of processing indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 30"}}, nil
}

func (m *GDPRModule) checkSecurityOfProcessing(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasEncryption := strings.Contains(s, "encrypt") || strings.Contains(s, "aes") || strings.Contains(s, "tls")
	hasAccess := strings.Contains(s, "access_control") || strings.Contains(s, "rbac") || strings.Contains(s, "auth")
	if hasEncryption && hasAccess {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art32", ControlName: "Security of processing", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Encryption and access control measures detected", Timestamp: time.Now(), References: []string{"GDPR Art. 32"}}, nil
	}
	if hasEncryption || hasAccess {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art32", ControlName: "Security of processing", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Partial security measures detected", Timestamp: time.Now(), References: []string{"GDPR Art. 32"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art32", ControlName: "Security of processing", Status: compliance.StatusNonCompliant, Severity: compliance.SeverityHigh, Message: "No security measures detected", Timestamp: time.Now(), References: []string{"GDPR Art. 32"}}, nil
}

func (m *GDPRModule) checkBreachNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasBreach := strings.Contains(s, "breach_notification") || strings.Contains(s, "incident_response") || strings.Contains(s, "breach") || strings.Contains(s, "data_breach")
	if hasBreach {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art33", ControlName: "Notification of a personal data breach to the supervisory authority", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Breach notification procedures detected", Timestamp: time.Now(), References: []string{"GDPR Art. 33"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art33", ControlName: "Notification of a personal data breach to the supervisory authority", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Breach notification indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 33"}}, nil
}

func (m *GDPRModule) checkDPIA(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasDPIA := strings.Contains(s, "dpia") || strings.Contains(s, "impact_assessment") || strings.Contains(s, "data_protection_impact")
	if hasDPIA {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art35", ControlName: "Data protection impact assessment", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "DPIA procedures detected", Timestamp: time.Now(), References: []string{"GDPR Art. 35"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art35", ControlName: "Data protection impact assessment", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "DPIA indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 35"}}, nil
}

// ── P1 Compliance Automation Expansion: Additional automated controls ──

func (m *GDPRModule) checkChildConsent(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasChildConsent := strings.Contains(s, "age_verification") || strings.Contains(s, "parental_consent") || strings.Contains(s, "child_consent") || strings.Contains(s, "minor_protection")
	if hasChildConsent {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art8", ControlName: "Conditions applicable to child's consent", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Child consent and age verification mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 8"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art8", ControlName: "Conditions applicable to child's consent", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Child consent and age verification indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 8"}, Remediation: "Implement age verification and parental consent mechanisms for services offered to children"}, nil
}

func (m *GDPRModule) checkCriminalConvictionData(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasCriminalData := strings.Contains(s, "criminal_conviction") || strings.Contains(s, "criminal_data") || strings.Contains(s, "offense_data") || strings.Contains(s, "criminal_record")
	if hasCriminalData {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art10", ControlName: "Processing of personal data relating to criminal convictions", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Criminal conviction data handling controls detected", Timestamp: time.Now(), References: []string{"GDPR Art. 10"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art10", ControlName: "Processing of personal data relating to criminal convictions", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Criminal conviction data handling indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 10"}, Remediation: "Implement controls for processing criminal conviction data under official authority"}, nil
}

func (m *GDPRModule) checkAnonymization(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAnon := strings.Contains(s, "anonymiz") || strings.Contains(s, "pseudonymiz") || strings.Contains(s, "deidentification") || strings.Contains(s, "de-identification")
	if hasAnon {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art11", ControlName: "Processing which does not require identification", Status: compliance.StatusCompliant, Severity: compliance.SeverityLow, Message: "Anonymization or pseudonymization mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 11"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art11", ControlName: "Processing which does not require identification", Status: compliance.StatusPartial, Severity: compliance.SeverityLow, Message: "Anonymization or pseudonymization indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 11"}, Remediation: "Implement anonymization or pseudonymization for processing that does not require identification"}, nil
}

func (m *GDPRModule) checkDataSourceNotices(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasNotice := strings.Contains(s, "data_source") || strings.Contains(s, "source_notice") || strings.Contains(s, "third_party_source") || strings.Contains(s, "data_origin")
	if hasNotice {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art14", ControlName: "Information to be provided where data not obtained from the data subject", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Data source notification mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 14"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art14", ControlName: "Information to be provided where data not obtained from the data subject", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Data source notification indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 14"}, Remediation: "Implement notices for data obtained from sources other than the data subject"}, nil
}

func (m *GDPRModule) checkRightOfAccess(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAccess := strings.Contains(s, "subject_access") || strings.Contains(s, "access_request") || strings.Contains(s, "data_subject_access") || strings.Contains(s, "sar") || strings.Contains(s, "access_api")
	if hasAccess {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art15", ControlName: "Right of access by the data subject", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data subject access mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 15"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art15", ControlName: "Right of access by the data subject", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Data subject access indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 15"}, Remediation: "Implement data subject access request (SAR) handling mechanisms"}, nil
}

func (m *GDPRModule) checkRightToRectification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasRectification := strings.Contains(s, "rectification") || strings.Contains(s, "data_correction") || strings.Contains(s, "data_amendment") || strings.Contains(s, "correction_request")
	if hasRectification {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art16", ControlName: "Right to rectification", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data rectification mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 16"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art16", ControlName: "Right to rectification", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Data rectification indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 16"}, Remediation: "Implement data correction/rectification request handling"}, nil
}

func (m *GDPRModule) checkRightToErasure(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasErasure := strings.Contains(s, "erasure") || strings.Contains(s, "right_to_be_forgotten") || strings.Contains(s, "data_deletion") || strings.Contains(s, "deletion_request")
	if hasErasure {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art17", ControlName: "Right to erasure (right to be forgotten)", Status: compliance.StatusCompliant, Severity: compliance.SeverityCritical, Message: "Data erasure mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 17"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art17", ControlName: "Right to erasure (right to be forgotten)", Status: compliance.StatusPartial, Severity: compliance.SeverityCritical, Message: "Data erasure indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 17"}, Remediation: "Implement data erasure/right to be forgotten request handling"}, nil
}

func (m *GDPRModule) checkRightToRestriction(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasRestriction := strings.Contains(s, "processing_restriction") || strings.Contains(s, "restriction_request") || strings.Contains(s, "block_processing") || strings.Contains(s, "processing_block")
	if hasRestriction {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art18", ControlName: "Right to restriction of processing", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Processing restriction mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 18"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art18", ControlName: "Right to restriction of processing", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Processing restriction indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 18"}, Remediation: "Implement processing restriction request handling"}, nil
}

func (m *GDPRModule) checkRectificationErasureNotification(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasNotification := strings.Contains(s, "rectification_notification") || strings.Contains(s, "erasure_notification") || strings.Contains(s, "restriction_notification") || strings.Contains(s, "recipient_notification")
	if hasNotification {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art19", ControlName: "Notification obligation regarding rectification or erasure or restriction", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Rectification/erasure notification mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 19"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art19", ControlName: "Notification obligation regarding rectification or erasure or restriction", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Rectification/erasure notification indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 19"}, Remediation: "Implement notification to recipients when data is rectified or erased"}, nil
}

func (m *GDPRModule) checkDataPortability(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasPortability := strings.Contains(s, "data_portability") || strings.Contains(s, "data_export") || strings.Contains(s, "portability") || strings.Contains(s, "machine_readable_export")
	if hasPortability {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art20", ControlName: "Right to data portability", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data portability mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 20"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art20", ControlName: "Right to data portability", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Data portability indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 20"}, Remediation: "Implement data export in structured, machine-readable format"}, nil
}

func (m *GDPRModule) checkRightToObject(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasObjection := strings.Contains(s, "objection") || strings.Contains(s, "opt_out") || strings.Contains(s, "right_to_object") || strings.Contains(s, "processing_objection")
	if hasObjection {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art21", ControlName: "Right to object", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Right to object mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 21"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art21", ControlName: "Right to object", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Right to object indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 21"}, Remediation: "Implement processing objection mechanisms"}, nil
}

func (m *GDPRModule) checkProcessor(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasDPA := strings.Contains(s, "dpa") || strings.Contains(s, "data_processing_agreement") || strings.Contains(s, "processor_agreement") || strings.Contains(s, "subprocessor")
	if hasDPA {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art28", ControlName: "Processor", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data processing agreement controls detected", Timestamp: time.Now(), References: []string{"GDPR Art. 28"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art28", ControlName: "Processor", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Data processing agreement indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 28"}, Remediation: "Establish data processing agreements with all processors"}, nil
}

func (m *GDPRModule) checkProcessingUnderAuthority(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasAuthority := strings.Contains(s, "processing_authorization") || strings.Contains(s, "controller_instruction") || strings.Contains(s, "access_restriction") || strings.Contains(s, "authorized_processing")
	if hasAuthority {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art29", ControlName: "Processing under the authority of the controller or processor", Status: compliance.StatusCompliant, Severity: compliance.SeverityMedium, Message: "Processing authority controls detected", Timestamp: time.Now(), References: []string{"GDPR Art. 29"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art29", ControlName: "Processing under the authority of the controller or processor", Status: compliance.StatusPartial, Severity: compliance.SeverityMedium, Message: "Processing authority indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 29"}, Remediation: "Implement access controls ensuring processing only on controller instructions"}, nil
}

func (m *GDPRModule) checkBreachCommunication(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasBreachComm := strings.Contains(s, "breach_communication") || strings.Contains(s, "breach_notification_data_subject") || strings.Contains(s, "data_subject_breach_notice") || strings.Contains(s, "breach_alert")
	if hasBreachComm {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art34", ControlName: "Communication of a personal data breach to the data subject", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Breach communication mechanisms detected", Timestamp: time.Now(), References: []string{"GDPR Art. 34"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art34", ControlName: "Communication of a personal data breach to the data subject", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "Breach communication indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 34"}, Remediation: "Implement mechanisms to communicate breaches to affected data subjects"}, nil
}

func (m *GDPRModule) checkDPODesignation(ctx context.Context, input []byte) (*compliance.ControlCheckResult, error) {
	s := strings.ToLower(string(input))
	hasDPO := strings.Contains(s, "dpo") || strings.Contains(s, "data_protection_officer") || strings.Contains(s, "privacy_officer") || strings.Contains(s, "dpo_designated")
	if hasDPO {
		return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art37", ControlName: "Designation of the data protection officer", Status: compliance.StatusCompliant, Severity: compliance.SeverityHigh, Message: "Data Protection Officer designation detected", Timestamp: time.Now(), References: []string{"GDPR Art. 37"}}, nil
	}
	return &compliance.ControlCheckResult{Framework: m.Framework(), ControlID: "GDPR-Art37", ControlName: "Designation of the data protection officer", Status: compliance.StatusPartial, Severity: compliance.SeverityHigh, Message: "DPO designation indicators not detected", Timestamp: time.Now(), References: []string{"GDPR Art. 37"}, Remediation: "Designate a Data Protection Officer where required by GDPR Article 37"}, nil
}
