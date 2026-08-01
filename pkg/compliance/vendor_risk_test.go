// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Vendor Risk Assessment Tests
// =========================================================================

package compliance_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVendorAssessment(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	assert.NotEmpty(t, va.ID, "assessment ID should be generated")
	assert.Contains(t, va.ID, "VA-", "ID should have VA- prefix")
	assert.Equal(t, "TestVendor", va.VendorName)
	assert.Equal(t, compliance.VendorLLMProvider, va.Category)
	assert.NotZero(t, va.AssessedAt, "assessedAt should be set")
	assert.Len(t, va.Dimensions, 8, "should have all 8 dimensions")

	// Verify all dimensions initialized to zero/not_met
	for _, dim := range []compliance.AssessmentDimension{
		compliance.DimDataPrivacy,
		compliance.DimSecurityPosture,
		compliance.DimCompliance,
		compliance.DimAvailability,
		compliance.DimTransparency,
		compliance.DimDataResidency,
		compliance.DimModelIntegrity,
		compliance.DimIncidentResponse,
	} {
		ds, ok := va.Dimensions[dim]
		require.True(t, ok, "dimension %s should exist", dim)
		assert.Equal(t, float64(0), ds.Score, "dimension %s should start at 0", dim)
		assert.Equal(t, "not_met", ds.Status, "dimension %s should start as not_met", dim)
	}
}

func TestAssessDimension_Valid(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	err := va.AssessDimension(compliance.DimDataPrivacy, 85, "SOC2 certified", []string{"minor gaps"})
	require.NoError(t, err)

	ds := va.Dimensions[compliance.DimDataPrivacy]
	assert.Equal(t, float64(85), ds.Score)
	assert.Equal(t, "met", ds.Status, "score >= 80 should be met")
	assert.Equal(t, "SOC2 certified", ds.Evidence)
	assert.Equal(t, []string{"minor gaps"}, ds.Weaknesses)
}

func TestAssessDimension_StatusLevels(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	cases := []struct {
		score          float64
		expectedStatus string
	}{
		{90, "met"},
		{80, "met"},
		{79, "partial"},
		{60, "partial"},
		{40, "partial"},
		{39, "not_met"},
		{0, "not_met"},
	}

	for _, tc := range cases {
		err := va.AssessDimension(compliance.DimAvailability, tc.score, "", nil)
		require.NoError(t, err)
		ds := va.Dimensions[compliance.DimAvailability]
		assert.Equal(t, tc.expectedStatus, ds.Status, "score %.0f should yield status %s", tc.score, tc.expectedStatus)
	}
}

func TestAssessDimension_InvalidScore(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	err := va.AssessDimension(compliance.DimDataPrivacy, -5, "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "0 and 100")

	err = va.AssessDimension(compliance.DimDataPrivacy, 150, "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "0 and 100")
}

func TestAssessDimension_InvalidDimension(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	err := va.AssessDimension(compliance.AssessmentDimension("unknown_dimension"), 50, "", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown assessment dimension")
}

func TestCalculateOverallScore(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	// Set known scores for all dimensions
	scores := map[compliance.AssessmentDimension]float64{
		compliance.DimDataPrivacy:      100, // weight 0.20
		compliance.DimSecurityPosture:  100, // weight 0.20
		compliance.DimCompliance:       100, // weight 0.15
		compliance.DimAvailability:     100, // weight 0.10
		compliance.DimTransparency:     100, // weight 0.15
		compliance.DimDataResidency:    100, // weight 0.10
		compliance.DimModelIntegrity:   100, // weight 0.05
		compliance.DimIncidentResponse: 100, // weight 0.05
	}

	for dim, score := range scores {
		err := va.AssessDimension(dim, score, "", nil)
		require.NoError(t, err)
	}

	result := va.CalculateOverallScore()
	assert.Equal(t, float64(100), result, "all 100s should give 100")

	// Test partial scores: privacy=80 (0.20), security=60 (0.20), compliance=50 (0.15),
	// availability=90 (0.10), transparency=70 (0.15), residency=40 (0.10),
	// integrity=85 (0.05), incident=65 (0.05)
	va2 := compliance.NewVendorAssessment("TestVendor2", compliance.VendorLLMProvider)
	partialScores := map[compliance.AssessmentDimension]float64{
		compliance.DimDataPrivacy:      80,
		compliance.DimSecurityPosture:  60,
		compliance.DimCompliance:       50,
		compliance.DimAvailability:     90,
		compliance.DimTransparency:     70,
		compliance.DimDataResidency:    40,
		compliance.DimModelIntegrity:   85,
		compliance.DimIncidentResponse: 65,
	}

	for dim, score := range partialScores {
		err := va2.AssessDimension(dim, score, "", nil)
		require.NoError(t, err)
	}

	result2 := va2.CalculateOverallScore()
	expected := 80*0.20 + 60*0.20 + 50*0.15 + 90*0.10 + 70*0.15 + 40*0.10 + 85*0.05 + 65*0.05
	assert.InDelta(t, expected, result2, 0.01, "weighted average should match")
}

func TestDetermineRiskLevel(t *testing.T) {
	cases := []struct {
		score    float64
		expected compliance.RiskLevel
	}{
		{85, compliance.RiskNone},
		{80, compliance.RiskNone},
		{79, compliance.RiskLow},
		{60, compliance.RiskLow},
		{59, compliance.RiskMedium},
		{40, compliance.RiskMedium},
		{39, compliance.RiskHigh},
		{20, compliance.RiskHigh},
		{19, compliance.RiskCritical},
		{0, compliance.RiskCritical},
	}

	for _, tc := range cases {
		va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)
		va.OverallScore = tc.score
		result := va.DetermineRiskLevel()
		assert.Equal(t, tc.expected, result, "score %.0f should be %s risk", tc.score, tc.expected)
	}
}

func TestGenerateRecommendations(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	// Set all dimensions above 70
	_ = va.AssessDimension(compliance.DimDataPrivacy, 85, "", nil)
	_ = va.AssessDimension(compliance.DimSecurityPosture, 75, "", nil)
	_ = va.AssessDimension(compliance.DimCompliance, 80, "", nil)
	_ = va.AssessDimension(compliance.DimAvailability, 90, "", nil)
	_ = va.AssessDimension(compliance.DimTransparency, 65, "", nil) // below threshold
	_ = va.AssessDimension(compliance.DimDataResidency, 50, "", nil) // below threshold
	_ = va.AssessDimension(compliance.DimModelIntegrity, 72, "", nil)
	_ = va.AssessDimension(compliance.DimIncidentResponse, 30, "", nil) // below threshold

	recs := va.GenerateRecommendations()
	assert.Len(t, recs, 3, "should generate recs for 3 dimensions below 70")

	// Verify recs are sorted by priority
	prioOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	for i := 1; i < len(recs); i++ {
		assert.True(t, prioOrder[recs[i-1].Priority] <= prioOrder[recs[i].Priority],
			"recommendations should be sorted by priority")
	}

	// Verify incident response rec (score 30 => high priority)
	var irRec *compliance.Recommendation
	for i := range recs {
		if recs[i].Dimension == compliance.DimIncidentResponse {
			irRec = &recs[i]
			break
		}
	}
	require.NotNil(t, irRec, "should have a recommendation for incident response")
	assert.Equal(t, "high", irRec.Priority)
}

func TestMapToFrameworks(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)
	_ = va.AssessDimension(compliance.DimDataPrivacy, 70, "", nil)
	_ = va.AssessDimension(compliance.DimSecurityPosture, 65, "", nil)

	refs := va.MapToFrameworks()

	// Verify all 6 frameworks present
	frameworks := []string{"SOC2", "ISO 27001", "NIST AI RMF", "EU AI Act", "HIPAA", "PCI DSS"}
	for _, fw := range frameworks {
		controls, ok := refs[fw]
		assert.True(t, ok, "framework %s should be present", fw)
		assert.NotEmpty(t, controls, "framework %s should have controls", fw)
	}

	// Verify specific controls for data privacy
	assert.Contains(t, refs["SOC2"], "CC6.1")
	assert.Contains(t, refs["ISO 27001"], "A.5.33")
	assert.Contains(t, refs["HIPAA"], "§164.502")
}

func TestMapToFrameworks_Deduplication(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)
	_ = va.AssessDimension(compliance.DimDataPrivacy, 70, "", nil)
	_ = va.AssessDimension(compliance.DimDataResidency, 65, "", nil)

	refs := va.MapToFrameworks()
	// Both data_privacy and data_residency map to CC6.1 in SOC2
	// Should appear only once
	soc2Controls := refs["SOC2"]
	count := 0
	for _, c := range soc2Controls {
		if c == "CC6.1" {
			count++
		}
	}
	assert.Equal(t, 1, count, "CC6.1 should appear only once after deduplication")
}

func TestExportJSON(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)
	_ = va.AssessDimension(compliance.DimDataPrivacy, 75, "GDPR compliant", []string{"limited scope"})
	va.CalculateOverallScore()
	va.DetermineRiskLevel()

	data, err := va.ExportJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify it's valid JSON and can be unmarshalled
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "TestVendor", parsed["VendorName"])
}

func TestValidate_Complete(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)
	_ = va.AssessDimension(compliance.DimDataPrivacy, 75, "evidence", nil)
	_ = va.AssessDimension(compliance.DimSecurityPosture, 80, "evidence", nil)
	_ = va.AssessDimension(compliance.DimCompliance, 70, "evidence", nil)
	_ = va.AssessDimension(compliance.DimAvailability, 90, "evidence", nil)
	_ = va.AssessDimension(compliance.DimTransparency, 65, "evidence", nil)
	_ = va.AssessDimension(compliance.DimDataResidency, 55, "evidence", nil)
	_ = va.AssessDimension(compliance.DimModelIntegrity, 80, "evidence", nil)
	_ = va.AssessDimension(compliance.DimIncidentResponse, 70, "evidence", nil)
	va.SetDataFlowRisk(compliance.DataFlowRisk{DataInTransit: "encrypted", DataAtRest: "encrypted"})

	err := va.Validate()
	assert.NoError(t, err, "complete assessment should validate successfully")
}

func TestValidate_Incomplete(t *testing.T) {
	// Empty assessment with no name
	va := &compliance.VendorAssessment{
		Dimensions: make(map[compliance.AssessmentDimension]compliance.DimensionScore),
	}

	err := va.Validate()
	require.Error(t, err, "incomplete assessment should fail validation")
	assert.Contains(t, err.Error(), "vendor name is required")
	assert.Contains(t, err.Error(), "invalid vendor category")
}

func TestValidate_InvalidDataFlowRisk(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)
	_ = va.AssessDimension(compliance.DimDataPrivacy, 50, "evidence", nil)
	va.SetDataFlowRisk(compliance.DataFlowRisk{DataInTransit: "maybe", DataAtRest: "maybe"})

	err := va.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data_in_transit must be")
	assert.Contains(t, err.Error(), "data_at_rest must be")
}

func TestAddCertification(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	cert := compliance.Certification{
		Name:      "SOC2 Type 2",
		Status:    "active",
		ValidUntil: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		Scope:     "Full platform",
	}
	va.AddCertification(cert)

	assert.Len(t, va.Certifications, 1)
	assert.Equal(t, "SOC2 Type 2", va.Certifications[0].Name)
	assert.Equal(t, "active", va.Certifications[0].Status)
}

func TestAddIncident(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	incident := compliance.IncidentRecord{
		Date:         time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
		Type:         "data_breach",
		Severity:     "high",
		Description:  "Unauthorized access to training data",
		Resolution:   "Revoked access; notified affected users",
		AffectedData: true,
	}
	va.AddIncident(incident)

	assert.Len(t, va.Incidents, 1)
	assert.Equal(t, "data_breach", va.Incidents[0].Type)
	assert.True(t, va.Incidents[0].AffectedData)
}

func TestSetDataFlowRisk(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	risk := compliance.DataFlowRisk{
		DataInTransit:     "encrypted",
		DataAtRest:        "encrypted",
		DataRetention:     "30 days",
		DataResidency:      "US",
		ThirdPartySharing: true,
		TrainingDataUse:   true,
	}
	va.SetDataFlowRisk(risk)

	assert.Equal(t, "encrypted", va.DataFlowRisk.DataInTransit)
	assert.Equal(t, "30 days", va.DataFlowRisk.DataRetention)
	assert.True(t, va.DataFlowRisk.ThirdPartySharing)
	assert.True(t, va.DataFlowRisk.TrainingDataUse)
}

func TestPredefinedVendorProfiles(t *testing.T) {
	profiles := compliance.PredefinedVendorProfiles()

	expectedVendors := []string{"OpenAI", "Anthropic", "Google DeepMind", "Mistral", "Cohere"}
	for _, name := range expectedVendors {
		v, ok := profiles[name]
		require.True(t, ok, "vendor %s should exist", name)
		assert.NotEmpty(t, v.ID)
		assert.NotEmpty(t, v.VendorName)
		assert.Len(t, v.Dimensions, 8, "vendor %s should have 8 dimensions", name)
		assert.NotZero(t, v.OverallScore, "vendor %s should have computed overall score", name)
		assert.NotEmpty(t, v.RiskLevel, "vendor %s should have a risk level", name)
	}

	// Verify vendor categories
	assert.Equal(t, compliance.VendorLLMProvider, profiles["OpenAI"].Category)
	assert.Equal(t, compliance.VendorLLMProvider, profiles["Anthropic"].Category)
	assert.Equal(t, compliance.VendorLLMProvider, profiles["Google DeepMind"].Category)
	assert.Equal(t, compliance.VendorLLMProvider, profiles["Mistral"].Category)
	assert.Equal(t, compliance.VendorEmbedding, profiles["Cohere"].Category)

	// Verify each vendor has certifications
	for _, name := range expectedVendors {
		v := profiles[name]
		assert.NotEmpty(t, v.Certifications, "vendor %s should have certifications", name)
	}

	// Verify framework refs are populated
	for _, name := range expectedVendors {
		v := profiles[name]
		assert.NotEmpty(t, v.FrameworkRefs, "vendor %s should have framework refs", name)
		_, hasSOC2 := v.FrameworkRefs["SOC2"]
		assert.True(t, hasSOC2, "vendor %s should have SOC2 framework refs", name)
	}
}

func TestPredefinedVendorProfiles_Variation(t *testing.T) {
	profiles := compliance.PredefinedVendorProfiles()

	// Verify scores are varied across vendors (not all identical)
	scores := make(map[string]float64)
	for _, name := range []string{"OpenAI", "Anthropic", "Google DeepMind", "Mistral", "Cohere"} {
		scores[name] = profiles[name].OverallScore
	}

	// Check that at least 3 unique scores exist
	uniqueScores := make(map[float64]bool)
	for _, s := range scores {
		uniqueScores[s] = true
	}
	assert.GreaterOrEqual(t, len(uniqueScores), 3, "vendors should have varied overall scores")

	// Check Anthropic has higher transparency than OpenAI
	assert.Greater(t,
		profiles["Anthropic"].Dimensions[compliance.DimTransparency].Score,
		profiles["OpenAI"].Dimensions[compliance.DimTransparency].Score,
		"Anthropic should score higher on transparency than OpenAI")

	// Check Google DeepMind has higher availability than Mistral
	assert.Greater(t,
		profiles["Google DeepMind"].Dimensions[compliance.DimAvailability].Score,
		profiles["Mistral"].Dimensions[compliance.DimAvailability].Score,
		"Google DeepMind should score higher on availability than Mistral")

	// Check Mistral has higher data residency than OpenAI
	assert.Greater(t,
		profiles["Mistral"].Dimensions[compliance.DimDataResidency].Score,
		profiles["OpenAI"].Dimensions[compliance.DimDataResidency].Score,
		"Mistral should score higher on data residency than OpenAI")
}

func TestCompareVendors(t *testing.T) {
	va1 := compliance.NewVendorAssessment("VendorA", compliance.VendorLLMProvider)
	_ = va1.AssessDimension(compliance.DimDataPrivacy, 90, "", nil)
	_ = va1.AssessDimension(compliance.DimSecurityPosture, 85, "", nil)
	_ = va1.AssessDimension(compliance.DimCompliance, 80, "", nil)
	_ = va1.AssessDimension(compliance.DimAvailability, 95, "", nil)
	_ = va1.AssessDimension(compliance.DimTransparency, 70, "", nil)
	_ = va1.AssessDimension(compliance.DimDataResidency, 60, "", nil)
	_ = va1.AssessDimension(compliance.DimModelIntegrity, 80, "", nil)
	_ = va1.AssessDimension(compliance.DimIncidentResponse, 75, "", nil)
	va1.CalculateOverallScore()
	va1.DetermineRiskLevel()

	va2 := compliance.NewVendorAssessment("VendorB", compliance.VendorLLMProvider)
	_ = va2.AssessDimension(compliance.DimDataPrivacy, 70, "", nil)
	_ = va2.AssessDimension(compliance.DimSecurityPosture, 75, "", nil)
	_ = va2.AssessDimension(compliance.DimCompliance, 85, "", nil)
	_ = va2.AssessDimension(compliance.DimAvailability, 80, "", nil)
	_ = va2.AssessDimension(compliance.DimTransparency, 90, "", nil)
	_ = va2.AssessDimension(compliance.DimDataResidency, 85, "", nil)
	_ = va2.AssessDimension(compliance.DimModelIntegrity, 70, "", nil)
	_ = va2.AssessDimension(compliance.DimIncidentResponse, 80, "", nil)
	va2.CalculateOverallScore()
	va2.DetermineRiskLevel()

	comparison := compliance.CompareVendors([]*compliance.VendorAssessment{va1, va2})

	// Verify rankings
	require.Len(t, comparison.Rankings, 2)
	assert.Equal(t, 1, comparison.Rankings[0].Rank)
	assert.Equal(t, 2, comparison.Rankings[1].Rank)

	// Overall best should be VendorA (higher weighted score due to strong privacy/security)
	assert.Equal(t, comparison.OverallBest, comparison.Rankings[0].VendorName)

	// Best in dimension checks
	assert.Equal(t, "VendorA", comparison.BestInDimension[compliance.DimDataPrivacy], "VendorA should be best at data privacy (90 > 70)")
	assert.Equal(t, "VendorB", comparison.BestInDimension[compliance.DimTransparency], "VendorB should be best at transparency (90 > 70)")
	assert.Equal(t, "VendorB", comparison.BestInDimension[compliance.DimDataResidency], "VendorB should be best at data residency (85 > 60)")
}

func TestCompareVendors_Empty(t *testing.T) {
	comparison := compliance.CompareVendors([]*compliance.VendorAssessment{})
	assert.Empty(t, comparison.Rankings)
	assert.Empty(t, comparison.BestInDimension)
	assert.Equal(t, "", comparison.OverallBest)
}

func TestDataFlowRiskScoring(t *testing.T) {
	va := compliance.NewVendorAssessment("TestVendor", compliance.VendorLLMProvider)

	// Unencrypted data flows should lower privacy score expectation
	_ = va.AssessDimension(compliance.DimDataPrivacy, 40, "No encryption for data at rest", []string{"unencrypted data at rest"})
	va.SetDataFlowRisk(compliance.DataFlowRisk{
		DataInTransit:     "encrypted",
		DataAtRest:        "unencrypted",
		DataRetention:     "Indefinite",
		DataResidency:      "US",
		ThirdPartySharing: true,
		TrainingDataUse:   true,
	})

	// Verify data flow risk is set
	assert.Equal(t, "unencrypted", va.DataFlowRisk.DataAtRest)
	assert.True(t, va.DataFlowRisk.ThirdPartySharing)
	assert.True(t, va.DataFlowRisk.TrainingDataUse)

	// Validate - should pass since "unencrypted" is valid
	err := va.Validate()
	require.NoError(t, err, "unencrypted is a valid DataFlowRisk value")
}

func TestVendorAssessment_IDGeneration(t *testing.T) {
	va1 := compliance.NewVendorAssessment("My AI Corp", compliance.VendorDataProcessor)
	va2 := compliance.NewVendorAssessment("My AI Corp", compliance.VendorDataProcessor)

	// IDs should be unique (due to timestamp)
	assert.NotEqual(t, va1.ID, va2.ID, "each assessment should get a unique ID")
	assert.Contains(t, va1.ID, "MyAICorp")
}

func TestVendorAssessment_RiskLevelConstants(t *testing.T) {
	assert.Equal(t, compliance.RiskLevel("critical"), compliance.RiskCritical)
	assert.Equal(t, compliance.RiskLevel("high"), compliance.RiskHigh)
	assert.Equal(t, compliance.RiskLevel("medium"), compliance.RiskMedium)
	assert.Equal(t, compliance.RiskLevel("low"), compliance.RiskLow)
	assert.Equal(t, compliance.RiskLevel("none"), compliance.RiskNone)
}

func TestVendorCategoryConstants(t *testing.T) {
	assert.Equal(t, compliance.VendorCategory("llm_provider"), compliance.VendorLLMProvider)
	assert.Equal(t, compliance.VendorCategory("embedding_provider"), compliance.VendorEmbedding)
	assert.Equal(t, compliance.VendorCategory("mcp_host"), compliance.VendorMCPHost)
	assert.Equal(t, compliance.VendorCategory("data_processor"), compliance.VendorDataProcessor)
	assert.Equal(t, compliance.VendorCategory("infrastructure"), compliance.VendorInfrastructure)
	assert.Equal(t, compliance.VendorCategory("other"), compliance.VendorOther)
}

func TestDimensionConstants(t *testing.T) {
	assert.Equal(t, compliance.AssessmentDimension("data_privacy"), compliance.DimDataPrivacy)
	assert.Equal(t, compliance.AssessmentDimension("security_posture"), compliance.DimSecurityPosture)
	assert.Equal(t, compliance.AssessmentDimension("compliance"), compliance.DimCompliance)
	assert.Equal(t, compliance.AssessmentDimension("availability"), compliance.DimAvailability)
	assert.Equal(t, compliance.AssessmentDimension("transparency"), compliance.DimTransparency)
	assert.Equal(t, compliance.AssessmentDimension("data_residency"), compliance.DimDataResidency)
	assert.Equal(t, compliance.AssessmentDimension("model_integrity"), compliance.DimModelIntegrity)
	assert.Equal(t, compliance.AssessmentDimension("incident_response"), compliance.DimIncidentResponse)
}