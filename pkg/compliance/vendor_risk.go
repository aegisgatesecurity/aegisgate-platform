// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Vendor Risk Assessment
// =========================================================================
//
// vendor_risk.go provides a structured vendor risk assessment for LLM/AI
// providers. It evaluates third-party AI services across multiple risk
// dimensions including data privacy, security posture, compliance,
// availability, transparency, data residency, model integrity, and
// incident response.
//
// The module maps assessment results to compliance framework control
// references (SOC2, ISO 27001, NIST AI RMF, EU AI Act, HIPAA, PCI DSS)
// and supports vendor comparison for procurement decisions.
// =========================================================================

package compliance

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// RiskLevel represents vendor risk severity.
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
	RiskNone     RiskLevel = "none"
)

// VendorCategory categorizes AI vendors.
type VendorCategory string

const (
	VendorLLMProvider    VendorCategory = "llm_provider"
	VendorEmbedding      VendorCategory = "embedding_provider"
	VendorMCPHost        VendorCategory = "mcp_host"
	VendorDataProcessor  VendorCategory = "data_processor"
	VendorInfrastructure VendorCategory = "infrastructure"
	VendorOther          VendorCategory = "other"
)

// AssessmentDimension is a risk dimension.
type AssessmentDimension string

const (
	DimDataPrivacy      AssessmentDimension = "data_privacy"
	DimSecurityPosture  AssessmentDimension = "security_posture"
	DimCompliance       AssessmentDimension = "compliance"
	DimAvailability      AssessmentDimension = "availability"
	DimTransparency     AssessmentDimension = "transparency"
	DimDataResidency    AssessmentDimension = "data_residency"
	DimModelIntegrity   AssessmentDimension = "model_integrity"
	DimIncidentResponse AssessmentDimension = "incident_response"
)

// DimensionScore holds the score and evidence for a single risk dimension.
type DimensionScore struct {
	Score      float64  // 0-100
	Evidence   string
	Weaknesses []string
	Status     string // "met", "partial", "not_met"
}

// Certification represents a vendor certification.
type Certification struct {
	Name      string
	Status    string    // "active", "expired", "pending", "none"
	ValidUntil time.Time
	Scope     string
}

// IncidentRecord represents a security incident involving the vendor.
type IncidentRecord struct {
	Date         time.Time
	Type         string
	Severity     string
	Description  string
	Resolution   string
	AffectedData bool
}

// DataFlowRisk describes how vendor handles data flows.
type DataFlowRisk struct {
	DataInTransit      string // "encrypted", "unencrypted"
	DataAtRest         string // "encrypted", "unencrypted"
	DataRetention      string
	DataResidency      string
	ThirdPartySharing  bool
	TrainingDataUse    bool
}

// Recommendation is an actionable improvement suggestion.
type Recommendation struct {
	Priority     string // "critical", "high", "medium", "low"
	Dimension    AssessmentDimension
	Description  string
	Effort       string
	FrameworkRef string
}

// VendorAssessment is the core struct for a vendor risk assessment.
type VendorAssessment struct {
	ID              string
	VendorName      string
	Category        VendorCategory
	AssessedAt      time.Time
	Assessor        string
	Dimensions      map[AssessmentDimension]DimensionScore
	Certifications  []Certification
	Incidents       []IncidentRecord
	DataFlowRisk    DataFlowRisk
	OverallScore    float64
	RiskLevel       RiskLevel
	Recommendations []Recommendation
	FrameworkRefs   map[string][]string // framework -> control IDs
}

// dimensionWeights defines the weighted contribution of each dimension.
var dimensionWeights = map[AssessmentDimension]float64{
	DimDataPrivacy:      0.20,
	DimSecurityPosture:  0.20,
	DimCompliance:       0.15,
	DimAvailability:     0.10,
	DimTransparency:     0.15,
	DimDataResidency:    0.10,
	DimModelIntegrity:   0.05,
	DimIncidentResponse: 0.05,
}

// allDimensions is the ordered set of assessment dimensions.
var allDimensions = []AssessmentDimension{
	DimDataPrivacy,
	DimSecurityPosture,
	DimCompliance,
	DimAvailability,
	DimTransparency,
	DimDataResidency,
	DimModelIntegrity,
	DimIncidentResponse,
}

// NewVendorAssessment creates a new assessment with default dimensions.
func NewVendorAssessment(vendorName string, category VendorCategory) *VendorAssessment {
	dims := make(map[AssessmentDimension]DimensionScore)
	for _, d := range allDimensions {
		dims[d] = DimensionScore{Score: 0, Status: "not_met"}
	}
	return &VendorAssessment{
		ID:             fmt.Sprintf("VA-%s-%d", sanitizeID(vendorName), time.Now().UnixNano()),
		VendorName:     vendorName,
		Category:       category,
		AssessedAt:     time.Now().UTC(),
		Dimensions:     dims,
		Certifications: []Certification{},
		Incidents:       []IncidentRecord{},
		FrameworkRefs:   make(map[string][]string),
	}
}

// sanitizeID produces a simple alphanumeric ID component.
func sanitizeID(s string) string {
	var out []byte
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			out = append(out, byte(c))
		}
	}
	if len(out) == 0 {
		return "vendor"
	}
	return string(out)
}

// AssessDimension validates and records a dimension score.
func (va *VendorAssessment) AssessDimension(dim AssessmentDimension, score float64, evidence string, weaknesses []string) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("score must be between 0 and 100, got %.2f", score)
	}
	validDim := false
	for _, d := range allDimensions {
		if d == dim {
			validDim = true
			break
		}
	}
	if !validDim {
		return fmt.Errorf("unknown assessment dimension: %s", dim)
	}

	status := "not_met"
	if score >= 80 {
		status = "met"
	} else if score >= 40 {
		status = "partial"
	}

	va.Dimensions[dim] = DimensionScore{
		Score:      score,
		Evidence:   evidence,
		Weaknesses: weaknesses,
		Status:     status,
	}
	return nil
}

// AddCertification adds a certification to the assessment.
func (va *VendorAssessment) AddCertification(cert Certification) {
	va.Certifications = append(va.Certifications, cert)
}

// AddIncident records a security incident.
func (va *VendorAssessment) AddIncident(incident IncidentRecord) {
	va.Incidents = append(va.Incidents, incident)
}

// SetDataFlowRisk sets the data flow risk profile.
func (va *VendorAssessment) SetDataFlowRisk(risk DataFlowRisk) {
	va.DataFlowRisk = risk
}

// CalculateOverallScore returns the weighted average across all dimensions.
func (va *VendorAssessment) CalculateOverallScore() float64 {
	var total float64
	for _, dim := range allDimensions {
		ds, ok := va.Dimensions[dim]
		if !ok {
			continue
		}
		w, wok := dimensionWeights[dim]
		if !wok {
			continue
		}
		total += ds.Score * w
	}
	va.OverallScore = total
	return total
}

// DetermineRiskLevel maps the overall score to a risk level.
func (va *VendorAssessment) DetermineRiskLevel() RiskLevel {
	score := va.OverallScore
	if score >= 80 {
		va.RiskLevel = RiskNone
	} else if score >= 60 {
		va.RiskLevel = RiskLow
	} else if score >= 40 {
		va.RiskLevel = RiskMedium
	} else if score >= 20 {
		va.RiskLevel = RiskHigh
	} else {
		va.RiskLevel = RiskCritical
	}
	return va.RiskLevel
}

// GenerateRecommendations auto-generates recommendations for dimensions scoring below 70.
func (va *VendorAssessment) GenerateRecommendations() []Recommendation {
	var recs []Recommendation

	// Dimension-specific recommendation templates
	recTemplates := map[AssessmentDimension]struct {
		desc       string
		effort     string
		fwRef      string
	}{
		DimDataPrivacy:      {"Implement comprehensive data privacy controls and DLP measures", "medium", "SOC2 CC6.1"},
		DimSecurityPosture:  {"Strengthen security controls and vulnerability management", "high", "ISO 27001 A.13"},
		DimCompliance:       {"Align practices with applicable compliance frameworks", "medium", "SOC2 CC4.1"},
		DimAvailability:     {"Improve SLA guarantees and disaster recovery capabilities", "high", "ISO 27001 A.17"},
		DimTransparency:     {"Enhance model documentation and disclosure practices", "low", "EU AI Act Art.13"},
		DimDataResidency:    {"Ensure data residency controls meet jurisdictional requirements", "medium", "GDPR Art.44"},
		DimModelIntegrity:   {"Implement model provenance and integrity verification", "medium", "NIST AI RMF MV-1"},
		DimIncidentResponse: {"Establish or improve incident response procedures", "high", "ISO 27001 A.16"},
	}

	for _, dim := range allDimensions {
		ds, ok := va.Dimensions[dim]
		if !ok || ds.Score >= 70 {
			continue
		}
		tmpl, tok := recTemplates[dim]
		if !tok {
			continue
		}

		priority := "low"
		if ds.Score < 20 {
			priority = "critical"
		} else if ds.Score < 40 {
			priority = "high"
		} else if ds.Score < 55 {
			priority = "medium"
		}

		recs = append(recs, Recommendation{
			Priority:     priority,
			Dimension:    dim,
			Description:  fmt.Sprintf("%s (current score: %.0f/100)", tmpl.desc, ds.Score),
			Effort:       tmpl.effort,
			FrameworkRef: tmpl.fwRef,
		})
	}

	sort.Slice(recs, func(i, j int) bool {
		prioOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		return prioOrder[recs[i].Priority] < prioOrder[recs[j].Priority]
	})

	va.Recommendations = recs
	return recs
}

// MapToFrameworks maps assessment results to compliance framework control references.
func (va *VendorAssessment) MapToFrameworks() map[string][]string {
	refs := map[string][]string{
		"SOC2":             {},
		"ISO 27001":        {},
		"NIST AI RMF":      {},
		"EU AI Act":        {},
		"HIPAA":            {},
		"PCI DSS":          {},
	}

	// Dimension-to-framework mappings
	dimToSOC2 := map[AssessmentDimension][]string{
		DimDataPrivacy:      {"CC6.1", "CC6.2"},
		DimSecurityPosture:  {"CC6.3", "CC6.6"},
		DimCompliance:       {"CC4.1", "CC4.2"},
		DimAvailability:     {"CC9.1", "A1.2"},
		DimTransparency:     {"CC2.1", "CC2.2"},
		DimDataResidency:    {"CC6.1", "CC6.7"},
		DimModelIntegrity:   {"CC6.1", "CC8.1"},
		DimIncidentResponse: {"CC7.3", "CC7.4"},
	}

	dimToISO := map[AssessmentDimension][]string{
		DimDataPrivacy:      {"A.5.33", "A.5.34"},
		DimSecurityPosture:  {"A.13", "A.14"},
		DimCompliance:       {"A.5.35", "A.5.36"},
		DimAvailability:     {"A.17", "A.12"},
		DimTransparency:     {"A.5.32", "A.5.37"},
		DimDataResidency:    {"A.5.33", "A.18"},
		DimModelIntegrity:   {"A.14", "A.8.9"},
		DimIncidentResponse: {"A.16", "A.5.24"},
	}

	dimToNISTAI := map[AssessmentDimension][]string{
		DimDataPrivacy:      {"PR.AI-1", "PR.AI-2"},
		DimSecurityPosture:  {"PR.AI-3", "PR.DS-1"},
		DimCompliance:       {"GV-1", "GV-2"},
		DimAvailability:     {"PR.DS-4", "RC.RP-1"},
		DimTransparency:     {"MV-1", "MV-2"},
		DimDataResidency:    {"PR.AI-1", "PR.DS-5"},
		DimModelIntegrity:   {"MV-1", "PR.AI-3"},
		DimIncidentResponse: {"RC.RP-1", "RC.CO-2"},
	}

	dimToEUAIAct := map[AssessmentDimension][]string{
		DimDataPrivacy:      {"Art.10", "Art.13"},
		DimSecurityPosture:  {"Art.9", "Art.15"},
		DimCompliance:       {"Art.9", "Art.31"},
		DimAvailability:     {"Art.15"},
		DimTransparency:     {"Art.13", "Art.14"},
		DimDataResidency:    {"Art.10"},
		DimModelIntegrity:   {"Art.15", "Art.53"},
		DimIncidentResponse: {"Art.62", "Art.26"},
	}

	dimToHIPAA := map[AssessmentDimension][]string{
		DimDataPrivacy:      {"§164.502", "§164.504"},
		DimSecurityPosture:  {"§164.308(a)(1)", "§164.312(a)"},
		DimCompliance:       {"§164.530", "§164.534"},
		DimAvailability:     {"§164.308(a)(7)"},
		DimTransparency:     {"§164.520"},
		DimDataResidency:    {"§164.314"},
		DimModelIntegrity:   {"§164.312(c)"},
		DimIncidentResponse: {"§164.308(a)(6)", "§164.308(b)"},
	}

	dimToPCIDSS := map[AssessmentDimension][]string{
		DimDataPrivacy:      {"Req 3", "Req 6.5"},
		DimSecurityPosture:  {"Req 6", "Req 11"},
		DimCompliance:       {"Req 12", "Req 12.8"},
		DimAvailability:     {"Req 12.10"},
		DimTransparency:     {"Req 12.5"},
		DimDataResidency:    {"Req 12.8", "Req 12.9"},
		DimModelIntegrity:   {"Req 6.3", "Req 6.5"},
		DimIncidentResponse: {"Req 12.10", "Req 12.10.4"},
	}

	// Only include controls for dimensions that have been assessed (score > 0)
	for _, dim := range allDimensions {
		ds, ok := va.Dimensions[dim]
		if !ok || ds.Score == 0 {
			continue
		}
		refs["SOC2"] = append(refs["SOC2"], dimToSOC2[dim]...)
		refs["ISO 27001"] = append(refs["ISO 27001"], dimToISO[dim]...)
		refs["NIST AI RMF"] = append(refs["NIST AI RMF"], dimToNISTAI[dim]...)
		refs["EU AI Act"] = append(refs["EU AI Act"], dimToEUAIAct[dim]...)
		refs["HIPAA"] = append(refs["HIPAA"], dimToHIPAA[dim]...)
		refs["PCI DSS"] = append(refs["PCI DSS"], dimToPCIDSS[dim]...)
	}

	// Deduplicate
	for fw := range refs {
		seen := map[string]bool{}
		var deduped []string
		for _, c := range refs[fw] {
			if !seen[c] {
				seen[c] = true
				deduped = append(deduped, c)
			}
		}
		refs[fw] = deduped
	}

	va.FrameworkRefs = refs
	return refs
}

// ExportJSON exports the assessment as JSON.
func (va *VendorAssessment) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(va, "", "  ")
}

// Validate checks the assessment for completeness.
func (va *VendorAssessment) Validate() error {
	var errs []string

	if va.VendorName == "" {
		errs = append(errs, "vendor name is required")
	}

	validCats := map[VendorCategory]bool{
		VendorLLMProvider: true, VendorEmbedding: true, VendorMCPHost: true,
		VendorDataProcessor: true, VendorInfrastructure: true, VendorOther: true,
	}
	if !validCats[va.Category] {
		errs = append(errs, fmt.Sprintf("invalid vendor category: %s", va.Category))
	}

	if va.AssessedAt.IsZero() {
		errs = append(errs, "assessment timestamp is required")
	}

	for _, dim := range allDimensions {
		ds, ok := va.Dimensions[dim]
		if !ok {
			errs = append(errs, fmt.Sprintf("missing dimension: %s", dim))
			continue
		}
		if ds.Score < 0 || ds.Score > 100 {
			errs = append(errs, fmt.Sprintf("dimension %s has invalid score: %.2f", dim, ds.Score))
		}
		if ds.Status != "met" && ds.Status != "partial" && ds.Status != "not_met" {
			errs = append(errs, fmt.Sprintf("dimension %s has invalid status: %s", dim, ds.Status))
		}
	}

	if va.DataFlowRisk.DataInTransit != "" && va.DataFlowRisk.DataInTransit != "encrypted" && va.DataFlowRisk.DataInTransit != "unencrypted" {
		errs = append(errs, "data_in_transit must be 'encrypted' or 'unencrypted'")
	}
	if va.DataFlowRisk.DataAtRest != "" && va.DataFlowRisk.DataAtRest != "encrypted" && va.DataFlowRisk.DataAtRest != "unencrypted" {
		errs = append(errs, "data_at_rest must be 'encrypted' or 'unencrypted'")
	}

	if len(errs) > 0 {
		return fmt.Errorf("validation failed: %s", joinStrings(errs, "; "))
	}
	return nil
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

// ---------------------------------------------------------------------------
// Predefined Vendor Profiles
// ---------------------------------------------------------------------------

// PredefinedVendorProfiles returns pre-populated assessments for common AI vendors.
func PredefinedVendorProfiles() map[string]*VendorAssessment {
	profiles := make(map[string]*VendorAssessment)

	// OpenAI — strong on availability and model integrity, weaker on transparency
	openai := NewVendorAssessment("OpenAI", VendorLLMProvider)
	openai.Assessor = "AegisGate Auto-Assessment"
	_ = openai.AssessDimension(DimDataPrivacy, 68, "SOC2 Type 2 certified; data retention 30 days; opt-out training data use policy", []string{"training data opt-out is opt-in by default", "limited data residency controls"})
	_ = openai.AssessDimension(DimSecurityPosture, 72, "Bug bounty program; SOC2 Type 2; penetration testing", []string{"no end-to-end encryption for API calls"})
	_ = openai.AssessDimension(DimCompliance, 70, "SOC2 Type 2, CCPA compliant", []string{"HIPAA BAA available but limited scope"})
	_ = openai.AssessDimension(DimAvailability, 92, "99.9% SLA; multi-region deployment", []string{})
	_ = openai.AssessDimension(DimTransparency, 55, "Published model cards; safety reports", []string{"limited disclosure of training data composition", "model weights not open"})
	_ = openai.AssessDimension(DimDataResidency, 50, "US-based; EU data processing available", []string{"default US residency", "limited sovereign cloud options"})
	_ = openai.AssessDimension(DimModelIntegrity, 82, "Red teaming program; safety evaluations published", []string{})
	_ = openai.AssessDimension(DimIncidentResponse, 75, "Published incident response process; status page", []string{"historical delays in disclosure"})
	openai.AddCertification(Certification{Name: "SOC2 Type 2", Status: "active", ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Scope: "GPT API and infrastructure"})
	openai.AddCertification(Certification{Name: "CCPA Compliance", Status: "active", ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Scope: "Consumer data handling"})
	openai.AddIncident(IncidentRecord{Date: time.Date(2025, 3, 20, 0, 0, 0, 0, time.UTC), Type: "data_exposure", Severity: "medium", Description: "Chat history titles exposed to other users briefly", Resolution: "Patched within hours; affected users notified", AffectedData: true})
	openai.SetDataFlowRisk(DataFlowRisk{DataInTransit: "encrypted", DataAtRest: "encrypted", DataRetention: "30 days default", DataResidency: "US (EU option)", ThirdPartySharing: true, TrainingDataUse: true})
	openai.CalculateOverallScore()
	openai.DetermineRiskLevel()
	openai.GenerateRecommendations()
	openai.MapToFrameworks()
	profiles["OpenAI"] = openai

	// Anthropic — strong on transparency and safety, weaker on certifications
	anthropic := NewVendorAssessment("Anthropic", VendorLLMProvider)
	anthropic.Assessor = "AegisGate Auto-Assessment"
	_ = anthropic.AssessDimension(DimDataPrivacy, 78, "Strong privacy commitments; no training on API data by default", []string{"SOC2 certification pending"})
	_ = anthropic.AssessDimension(DimSecurityPosture, 70, "Bug bounty program; regular security audits", []string{"SOC2 not yet achieved"})
	_ = anthropic.AssessDimension(DimCompliance, 62, "Commitment to responsible AI; CCPA compliant", []string{"SOC2 certification in progress", "HIPAA BAA not yet available"})
	_ = anthropic.AssessDimension(DimAvailability, 85, "99.9% SLA; multi-region", []string{"occasional rate-limiting during peaks"})
	_ = anthropic.AssessDimension(DimTransparency, 88, "Detailed model cards; Constitutional AI documentation; safety research published", []string{})
	_ = anthropic.AssessDimension(DimDataResidency, 55, "US-based; working on EU options", []string{"limited non-US hosting"})
	_ = anthropic.AssessDimension(DimModelIntegrity, 85, "Constitutional AI approach; extensive red teaming", []string{})
	_ = anthropic.AssessDimension(DimIncidentResponse, 72, "Transparent disclosure practices; status page", []string{"shorter incident history than competitors"})
	anthropic.AddCertification(Certification{Name: "SOC2 Type 2", Status: "pending", ValidUntil: time.Time{}, Scope: "API and infrastructure"})
	anthropic.AddCertification(Certification{Name: "CCPA Compliance", Status: "active", ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Scope: "Consumer data handling"})
	anthropic.SetDataFlowRisk(DataFlowRisk{DataInTransit: "encrypted", DataAtRest: "encrypted", DataRetention: "30 days default", DataResidency: "US only", ThirdPartySharing: false, TrainingDataUse: false})
	anthropic.CalculateOverallScore()
	anthropic.DetermineRiskLevel()
	anthropic.GenerateRecommendations()
	anthropic.MapToFrameworks()
	profiles["Anthropic"] = anthropic

	// Google DeepMind — strong on infrastructure and compliance, weaker on transparency
	gdm := NewVendorAssessment("Google DeepMind", VendorLLMProvider)
	gdm.Assessor = "AegisGate Auto-Assessment"
	_ = gdm.AssessDimension(DimDataPrivacy, 65, "Broad data collection concerns; Google privacy policy applies", []string{"broad data use policy", "training data usage unclear for API customers"})
	_ = gdm.AssessDimension(DimSecurityPosture, 82, "Google Cloud security infrastructure; extensive certifications", []string{})
	_ = gdm.AssessDimension(DimCompliance, 78, "ISO 27001, SOC2, HIPAA compliant", []string{"complex compliance scope across Google ecosystem"})
	_ = gdm.AssessDimension(DimAvailability, 90, "99.95% SLA on Vertex AI; global infrastructure", []string{})
	_ = gdm.AssessDimension(DimTransparency, 48, "Limited model documentation; some research published", []string{"opaque training data disclosure", "limited model weight transparency"})
	_ = gdm.AssessDimension(DimDataResidency, 72, "Multi-region with data residency controls in Vertex AI", []string{})
	_ = gdm.AssessDimension(DimModelIntegrity, 75, "Safety benchmarks published; red teaming", []string{"less public safety methodology than Anthropic"})
	_ = gdm.AssessDimension(DimIncidentResponse, 80, "Mature incident response; Google Security blog", []string{})
	gdm.AddCertification(Certification{Name: "ISO 27001", Status: "active", ValidUntil: time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC), Scope: "Google Cloud / Vertex AI"})
	gdm.AddCertification(Certification{Name: "SOC2 Type 2", Status: "active", ValidUntil: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), Scope: "Google Cloud"})
	gdm.AddCertification(Certification{Name: "HIPAA", Status: "active", ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Scope: "Vertex AI with BAA"})
	gdm.AddIncident(IncidentRecord{Date: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC), Type: "service_degradation", Severity: "low", Description: "Brief API latency increase in EU region", Resolution: "Auto-resolved within 30 minutes", AffectedData: false})
	gdm.SetDataFlowRisk(DataFlowRisk{DataInTransit: "encrypted", DataAtRest: "encrypted", DataRetention: "Configurable 1-400 days", DataResidency: "Multi-region (US, EU, APAC)", ThirdPartySharing: true, TrainingDataUse: true})
	gdm.CalculateOverallScore()
	gdm.DetermineRiskLevel()
	gdm.GenerateRecommendations()
	gdm.MapToFrameworks()
	profiles["Google DeepMind"] = gdm

	// Mistral — strong on transparency (open weights), weaker on enterprise features
	mistral := NewVendorAssessment("Mistral", VendorLLMProvider)
	mistral.Assessor = "AegisGate Auto-Assessment"
	_ = mistral.AssessDimension(DimDataPrivacy, 70, "EU-GDPR aligned; French data sovereignty", []string{"limited enterprise data processing agreements"})
	_ = mistral.AssessDimension(DimSecurityPosture, 60, "Standard security measures; growing security team", []string{"smaller security team than major providers", "no bug bounty program yet"})
	_ = mistral.AssessDimension(DimCompliance, 55, "GDPR compliant; SOC2 in progress", []string{"SOC2 not yet certified", "limited compliance artifacts"})
	_ = mistral.AssessDimension(DimAvailability, 72, "99.9% SLA on La Plateforme; growing infrastructure", []string{"fewer regions than hyperscalers"})
	_ = mistral.AssessDimension(DimTransparency, 82, "Open weights for many models; published technical reports", []string{"some models remain closed"})
	_ = mistral.AssessDimension(DimDataResidency, 80, "EU-hosted by default; strong data sovereignty", []string{})
	_ = mistral.AssessDimension(DimModelIntegrity, 70, "Open model weights allow verification", []string{"limited red teaming documentation"})
	_ = mistral.AssessDimension(DimIncidentResponse, 58, "Developing incident response procedures", []string{"shorter track record", "limited public incident history"})
	mistral.AddCertification(Certification{Name: "GDPR Compliance", Status: "active", ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Scope: "EU data processing"})
	mistral.AddCertification(Certification{Name: "SOC2 Type 2", Status: "pending", ValidUntil: time.Time{}, Scope: "La Plateforme"})
	mistral.SetDataFlowRisk(DataFlowRisk{DataInTransit: "encrypted", DataAtRest: "encrypted", DataRetention: "Configurable", DataResidency: "EU (France) default", ThirdPartySharing: false, TrainingDataUse: false})
	mistral.CalculateOverallScore()
	mistral.DetermineRiskLevel()
	mistral.GenerateRecommendations()
	mistral.MapToFrameworks()
	profiles["Mistral"] = mistral

	// Cohere — strong on embedding/data use cases, weaker on scale
	cohere := NewVendorAssessment("Cohere", VendorEmbedding)
	cohere.Assessor = "AegisGate Auto-Assessment"
	_ = cohere.AssessDimension(DimDataPrivacy, 72, "SOC2 Type 2 achieved; no customer data used for training", []string{"limited HIPAA support"})
	_ = cohere.AssessDimension(DimSecurityPosture, 68, "SOC2 Type 2; VAPT conducted", []string{"smaller security org"})
	_ = cohere.AssessDimension(DimCompliance, 65, "SOC2 Type 2; GDPR compliant", []string{"no HIPAA BAA yet", "no ISO 27001"})
	_ = cohere.AssessDimension(DimAvailability, 75, "99.9% SLA; multi-region", []string{"fewer edge locations"})
	_ = cohere.AssessDimension(DimTransparency, 65, "Documentation for embedding models; some model cards", []string{"limited red teaming disclosures", "no open weights"})
	_ = cohere.AssessDimension(DimDataResidency, 62, "US and EU deployment options", []string{"limited APAC options"})
	_ = cohere.AssessDimension(DimModelIntegrity, 68, "Model evaluations published", []string{"less comprehensive than larger providers"})
	_ = cohere.AssessDimension(DimIncidentResponse, 65, "Incident response policy in place", []string{"shorter track record"})
	cohere.AddCertification(Certification{Name: "SOC2 Type 2", Status: "active", ValidUntil: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), Scope: "Cohere API platform"})
	cohere.AddCertification(Certification{Name: "GDPR Compliance", Status: "active", ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), Scope: "EU data processing"})
	cohere.SetDataFlowRisk(DataFlowRisk{DataInTransit: "encrypted", DataAtRest: "encrypted", DataRetention: "Configurable 0-365 days", DataResidency: "US, EU", ThirdPartySharing: false, TrainingDataUse: false})
	cohere.CalculateOverallScore()
	cohere.DetermineRiskLevel()
	cohere.GenerateRecommendations()
	cohere.MapToFrameworks()
	profiles["Cohere"] = cohere

	return profiles
}

// ---------------------------------------------------------------------------
// Vendor Comparison
// ---------------------------------------------------------------------------

// VendorRanking holds a vendor's rank and score in a comparison.
type VendorRanking struct {
	VendorName string
	Score      float64
	RiskLevel  RiskLevel
	Rank       int
}

// VendorComparison holds the results of comparing multiple vendors.
type VendorComparison struct {
	Rankings        []VendorRanking
	BestInDimension map[AssessmentDimension]string
	OverallBest     string
}

// CompareVendors compares multiple vendor assessments side-by-side.
func CompareVendors(vendors []*VendorAssessment) *VendorComparison {
	if len(vendors) == 0 {
		return &VendorComparison{
			Rankings:        []VendorRanking{},
			BestInDimension: make(map[AssessmentDimension]string),
			OverallBest:     "",
		}
	}

	// Build rankings sorted by overall score descending
	rankings := make([]VendorRanking, len(vendors))
	for i, v := range vendors {
		rankings[i] = VendorRanking{
			VendorName: v.VendorName,
			Score:      v.OverallScore,
			RiskLevel:  v.RiskLevel,
			Rank:       0,
		}
	}
	sort.Slice(rankings, func(i, j int) bool {
		return rankings[i].Score > rankings[j].Score
	})
	for i := range rankings {
		rankings[i].Rank = i + 1
	}

	// Determine best-in-dimension
	bestInDim := make(map[AssessmentDimension]string)
	for _, dim := range allDimensions {
		bestScore := -1.0
		bestVendor := ""
		for _, v := range vendors {
			ds, ok := v.Dimensions[dim]
			if ok && ds.Score > bestScore {
				bestScore = ds.Score
				bestVendor = v.VendorName
			}
		}
		if bestVendor != "" {
			bestInDim[dim] = bestVendor
		}
	}

	overallBest := ""
	if len(rankings) > 0 {
		overallBest = rankings[0].VendorName
	}

	return &VendorComparison{
		Rankings:        rankings,
		BestInDimension: bestInDim,
		OverallBest:     overallBest,
	}
}