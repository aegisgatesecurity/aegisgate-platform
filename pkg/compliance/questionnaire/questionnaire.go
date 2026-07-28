// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Vendor Questionnaire Auto-Answer Engine
// =========================================================================
//
// questionnaire.go implements the core questionnaire engine that maps
// AegisGate compliance scan results to SIG and CAIQ questionnaire
// answers. The engine ingests structured scanner output (the same
// ScanReport and FrameworkScanResult types produced by
// pkg/compliance/scanner.go) and produces filled-out questionnaire
// responses with per-answer confidence scores.
//
// Confidence scoring:
//   - 0.8-1.0: answer derived from automated scan evidence
//   - 0.5-0.7: answer derived from policy inference or partial evidence
//   - 0.0-0.4: answer requires manual review (insufficient evidence)
//
// Export formats:
//   - CSV (fully implemented)
//   - PDF (fully implemented via pkg/pdf renderer; produces real PDF 1.4 documents)
//
// Architecture follows the BaseComplianceModule pattern from
// pkg/compliance/module.go so the questionnaire engine can be
// registered as a licensable module.
//
// =========================================================================

package questionnaire

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/pdf"
)

// Question represents a single questionnaire question with its
// auto-generated answer, confidence score, source traceability, and
// supporting evidence.
type Question struct {
	// ID is the questionnaire question identifier (e.g., "SIG-SEC-001").
	ID string `json:"id"`
	// Category is the question category (e.g., "Security", "Cloud Security").
	Category string `json:"category"`
	// Text is the full question text.
	Text string `json:"text"`
	// Answer is the auto-generated answer derived from scan results.
	Answer string `json:"answer"`
	// Confidence is the confidence score from 0.0 to 1.0.
	Confidence float64 `json:"confidence"`
	// Source indicates how the answer was derived:
	//   "automated_scan" — from scanner evidence
	//   "policy_inference" — from policy rule mapping
	//   "manual_review" — insufficient evidence, needs human review
	Source string `json:"source"`
	// Evidence lists the scanner findings that support this answer.
	Evidence []string `json:"evidence,omitempty"`
}

// QuestionnaireResponse is a complete filled-out questionnaire for a
// specific framework version and organization.
type QuestionnaireResponse struct {
	// Framework is "SIG" or "CAIQ".
	Framework string `json:"framework"`
	// Version is the framework version (e.g., "4.0", "4.0.1").
	Version string `json:"version"`
	// Questions is the list of answered questions.
	Questions []Question `json:"questions"`
	// GeneratedAt is the timestamp when the response was generated.
	GeneratedAt time.Time `json:"generated_at"`
	// OrganizationName is the name of the organization.
	OrganizationName string `json:"organization_name"`
}

// QuestionnaireEngine maps AegisGate compliance scan results to
// questionnaire answers. It holds the SIG and CAIQ question banks and
// the keyword-to-answer mapping rules.
type QuestionnaireEngine struct {
	// sigBank is the SIG question bank.
	sigBank []Question
	// caiqBank is the CAIQ question bank.
	caiqBank []Question
	// answerMap maps scanner result keywords to structured answers.
	answerMap map[string]AnswerRule
}

// AnswerRule defines how a scanner keyword maps to a questionnaire
// answer, including the answer text, confidence level, and source.
type AnswerRule struct {
	// Answer is the pre-defined answer text.
	Answer string
	// Confidence is the default confidence for this rule.
	Confidence float64
	// Source is "automated_scan", "policy_inference", or "manual_review".
	Source string
	// Keywords is the list of scanner keywords that trigger this rule.
	Keywords []string
}

// NewQuestionnaireEngine creates a new QuestionnaireEngine with
// fully populated SIG and CAIQ question banks and the default
// keyword-to-answer mapping rules.
func NewQuestionnaireEngine() *QuestionnaireEngine {
	qe := &QuestionnaireEngine{
		answerMap: defaultAnswerMap(),
	}
	qe.sigBank = buildSIGBank()
	qe.caiqBank = buildCAIQBank()
	return qe
}

// AutoAnswer takes compliance scanner output (a map keyed by scanner
// result identifiers) and maps each entry to questionnaire answers.
// The scannerResults map can contain:
//   - string values (simple findings)
//   - map[string]interface{} (structured scan results)
//   - bool values (pass/fail flags)
//   - float64 values (scores)
//
// It returns a QuestionnaireResponse containing all SIG questions with
// answers derived from the scan data.
func (qe *QuestionnaireEngine) AutoAnswer(scannerResults map[string]interface{}) (*QuestionnaireResponse, error) {
	if len(scannerResults) == 0 {
		return nil, fmt.Errorf("scanner results cannot be empty")
	}

	// Flatten scanner results into keyword-indexed findings.
	findings := flattenResults(scannerResults)

	response := &QuestionnaireResponse{
		Framework:        "SIG",
		Version:          "4.0",
		GeneratedAt:      time.Now().UTC(),
		OrganizationName: "Unknown",
	}

	// Resolve each SIG question against the findings.
	questions := make([]Question, len(qe.sigBank))
	for i, q := range qe.sigBank {
		questions[i] = qe.resolveQuestion(q, findings)
	}
	response.Questions = questions

	return response, nil
}

// GenerateSIG generates a SIG (Standardized Information Gathering)
// questionnaire response for the given organization, mapping scanner
// results to the SIG question bank.
func (qe *QuestionnaireEngine) GenerateSIG(organizationName string, scanResults map[string]interface{}) (*QuestionnaireResponse, error) {
	if organizationName == "" {
		return nil, fmt.Errorf("organization name cannot be empty")
	}
	if len(scanResults) == 0 {
		return nil, fmt.Errorf("scan results cannot be empty")
	}

	findings := flattenResults(scanResults)

	response := &QuestionnaireResponse{
		Framework:        "SIG",
		Version:          "4.0",
		GeneratedAt:      time.Now().UTC(),
		OrganizationName: organizationName,
	}

	questions := make([]Question, len(qe.sigBank))
	for i, q := range qe.sigBank {
		questions[i] = qe.resolveQuestion(q, findings)
	}
	response.Questions = questions

	return response, nil
}

// GenerateCAIQ generates a CAIQ (Consensus Assessments Initiative
// Questionnaire) response for the given organization, mapping scanner
// results to the CAIQ question bank.
func (qe *QuestionnaireEngine) GenerateCAIQ(organizationName string, scanResults map[string]interface{}) (*QuestionnaireResponse, error) {
	if organizationName == "" {
		return nil, fmt.Errorf("organization name cannot be empty")
	}
	if len(scanResults) == 0 {
		return nil, fmt.Errorf("scan results cannot be empty")
	}

	findings := flattenResults(scanResults)

	response := &QuestionnaireResponse{
		Framework:        "CAIQ",
		Version:          "4.0.1",
		GeneratedAt:      time.Now().UTC(),
		OrganizationName: organizationName,
	}

	questions := make([]Question, len(qe.caiqBank))
	for i, q := range qe.caiqBank {
		questions[i] = qe.resolveQuestion(q, findings)
	}
	response.Questions = questions

	return response, nil
}

// resolveQuestion maps a single question to an answer based on
// scanner findings. It uses question-specific keyword matching: each
// question has a set of relevant answer rule keys. Only answer rules
// whose keys are relevant to the question are considered. This ensures
// that e.g. "mfa" findings only answer MFA-related questions, not every
// question in the survey.
//
// The matching priority is:
//  1. Direct keyword match from a relevant answer rule (automated_scan, 0.8-1.0)
//  2. Category-based inference from any finding in the same category (policy_inference, 0.5-0.7)
//  3. No evidence found (manual_review, 0.0-0.4)
func (qe *QuestionnaireEngine) resolveQuestion(q Question, findings map[string]string) Question {
	result := Question{
		ID:       q.ID,
		Category: q.Category,
		Text:     q.Text,
	}

	// Step 1: Determine which answer rule keys are relevant to this
	// question based on its ID, category, and text content.
	relevantKeys := questionRelevantKeys(q)

	// Step 2: Try matching relevant answer rules against findings.
	bestConfidence := -1.0
	bestAnswer := ""
	bestSource := "manual_review"
	bestEvidence := []string{}

	for _, key := range relevantKeys {
		rule, ok := qe.answerMap[key]
		if !ok {
			continue
		}
		matched := false
		for _, kw := range rule.Keywords {
			if val, ok := findings[kw]; ok {
				matched = true
				if bestEvidence == nil {
					bestEvidence = []string{}
				}
				bestEvidence = append(bestEvidence, fmt.Sprintf("%s=%s", kw, val))
			}
		}
		if matched && rule.Confidence > bestConfidence {
			bestConfidence = rule.Confidence
			bestAnswer = rule.Answer
			bestSource = rule.Source
		}
	}

	if bestConfidence > 0 {
		result.Answer = bestAnswer
		result.Confidence = bestConfidence
		result.Source = bestSource
		result.Evidence = bestEvidence
		return result
	}

	// Step 3: Category-based inference — if we have findings relevant to
	// this question's category, provide a partial answer with lower confidence.
	categoryKeywords := categoryKeywordMap()
	if catKws, ok := categoryKeywords[q.Category]; ok {
		for _, kw := range catKws {
			if val, found := findings[kw]; found {
				result.Answer = fmt.Sprintf("Partial: %s detected (%s). Manual review recommended for full compliance verification.", kw, val)
				result.Confidence = 0.6
				result.Source = "policy_inference"
				result.Evidence = []string{fmt.Sprintf("%s=%s", kw, val)}
				return result
			}
		}
	}

	// Step 4: No evidence found — manual review required.
	result.Answer = "Requires manual review — no automated evidence available for this control."
	result.Confidence = 0.0
	result.Source = "manual_review"
	result.Evidence = []string{}
	return result
}

// questionRelevantKeys returns the answer rule keys that are relevant to a
// given question. This is determined by matching the question's ID, category,
// and text content against known keyword patterns. This ensures that findings
// only answer questions they are semantically relevant to.
func questionRelevantKeys(q Question) []string {
	relevant := make(map[string]bool)

	// Map from question ID prefixes and text patterns to answer rule keys.
	// Each entry maps a pattern (substring of question ID or text) to one or
	// more answer rule keys that could answer it.
	patternToKeys := map[string][]string{
		// Security patterns
		"SEC-001": {"mfa"},
		"SEC-002": {"mfa"},
		"SEC-003": {"access_control"},
		"SEC-004": {"access_control"},
		"SEC-005": {"encryption_at_rest"},
		"SEC-006": {"encryption_in_transit"},
		"SEC-007": {"firewall", "network_security"},
		"SEC-008": {"firewall"},
		"SEC-009": {"vulnerability_scan"},
		"SEC-010": {"vulnerability_scan"},
		"SEC-011": {"patch_management"},
		"SEC-012": {"endpoint_security"},
		"SEC-013": {"audit_trail", "security_logging"},
		"SEC-014": {"audit_trail"},
		"SEC-015": {"security_logging"},
		"SEC-016": {"incident_response"},
		"SEC-017": {"access_control"},
		"SEC-018": {"access_control"},
		"SEC-019": {"encryption_at_rest"},
		"SEC-020": {"network_security"},
		"SEC-021": {"patch_management"},
		"SEC-022": {"vulnerability_scan"},
		"SEC-023": {"patch_management"},
		"SEC-024": {"vulnerability_scan"},
		"SEC-025": {"vulnerability_scan"},
		// Availability patterns
		"AVL-001": {"backup"},
		"AVL-002": {"backup"},
		"AVL-003": {"disaster_recovery"},
		"AVL-004": {"disaster_recovery"},
		"AVL-005": {"disaster_recovery"},
		"AVL-006": {"disaster_recovery"},
		"AVL-007": {"disaster_recovery"},
		"AVL-008": {"disaster_recovery"},
		"AVL-009": {"business_continuity"},
		"AVL-010": {"incident_response"},
		"AVL-011": {"security_logging"},
		"AVL-012": {"change_management"},
		"AVL-013": {"disaster_recovery"},
		"AVL-014": {"disaster_recovery"},
		"AVL-015": {"backup"},
		"AVL-016": {"change_management"},
		"AVL-017": {"incident_response"},
		"AVL-018": {"third_party_risk"},
		"AVL-019": {"backup"},
		"AVL-020": {"security_logging"},
		// Processing Integrity patterns
		"PI-001": {"data_classification"},
		"PI-002": {"data_classification"},
		"PI-003": {"change_management"},
		"PI-004": {"change_management"},
		"PI-005": {"audit_trail"},
		"PI-006": {"data_classification"},
		"PI-007": {"incident_response"},
		"PI-008": {"audit_trail"},
		"PI-009": {"audit_trail"},
		"PI-010": {"change_management"},
		"PI-011": {"audit_trail"},
		"PI-012": {"change_management"},
		"PI-013": {"access_control"},
		"PI-014": {"audit_trail"},
		"PI-015": {"data_retention"},
		"PI-016": {"audit_trail"},
		"PI-017": {"change_management"},
		"PI-018": {"change_management"},
		"PI-019": {"audit_trail"},
		"PI-020": {"encryption_at_rest"},
		// Confidentiality patterns
		"CON-001": {"data_classification"},
		"CON-002": {"access_control"},
		"CON-003": {"encryption_at_rest"},
		"CON-004": {"encryption_in_transit"},
		"CON-005": {"access_control"},
		"CON-006": {"data_masking"},
		"CON-007": {"data_masking", "access_control"},
		"CON-008": {"access_control"},
		"CON-009": {"access_control"},
		"CON-010": {"access_control"},
		"CON-011": {"access_control"},
		"CON-012": {"encryption_at_rest"},
		"CON-013": {"data_retention"},
		"CON-014": {"access_control"},
		"CON-015": {"access_control", "firewall"},
		"CON-016": {"data_masking"},
		"CON-017": {"encryption_in_transit"},
		"CON-018": {"access_control"},
		"CON-019": {"data_masking"},
		"CON-020": {"audit_trail"},
		// Privacy patterns
		"PRI-001": {"privacy_policy"},
		"PRI-002": {"consent_management"},
		"PRI-003": {"data_subject_rights"},
		"PRI-004": {"dpias"},
		"PRI-005": {"data_retention"},
		"PRI-006": {"privacy_policy"},
		"PRI-007": {"privacy_policy"},
		"PRI-008": {"third_party_risk"},
		"PRI-009": {"data_classification"},
		"PRI-010": {"incident_response"},
		"PRI-011": {"dpias"},
		"PRI-012": {"privacy_policy"},
		"PRI-013": {"privacy_policy"},
		"PRI-014": {"data_retention"},
		"PRI-015": {"data_masking"},
		// Cloud Security patterns (CAIQ)
		"CS-001": {"mfa"},
		"CS-002": {"access_control"},
		"CS-003": {"access_control"},
		"CS-004": {"access_control"},
		"CS-005": {"encryption_at_rest"},
		"CS-006": {"encryption_in_transit"},
		"CS-007": {"encryption_at_rest"},
		"CS-008": {"firewall"},
		"CS-009": {"firewall", "network_security"},
		"CS-010": {"network_security"},
		"CS-011": {"vulnerability_scan"},
		"CS-012": {"vulnerability_scan"},
		"CS-013": {"access_control"},
		"CS-014": {"change_management"},
		"CS-015": {"vulnerability_scan"},
		"CS-016": {"vulnerability_scan"},
		"CS-017": {"audit_trail"},
		"CS-018": {"access_control"},
		"CS-019": {"encryption_at_rest"},
		"CS-020": {"audit_trail", "security_logging"},
		"CS-021": {"security_logging"},
		"CS-022": {"endpoint_security"},
		"CS-023": {"patch_management"},
		"CS-024": {"encryption_at_rest"},
		"CS-025": {"access_control"},
		"CS-026": {"change_management"},
		"CS-027": {"security_logging"},
		"CS-028": {"encryption_in_transit"},
		"CS-029": {"security_logging"},
		"CS-030": {"security_logging"},
		"CS-031": {"security_logging"},
		"CS-032": {"patch_management"},
		"CS-033": {"security_logging"},
		"CS-034": {"access_control"},
		"CS-035": {"access_control"},
		// Compliance patterns (CAIQ)
		"CMP-001": {"audit_trail"},
		"CMP-002": {"audit_trail"},
		"CMP-003": {"audit_trail"},
		"CMP-004": {"audit_trail"},
		"CMP-005": {"audit_trail"},
		"CMP-006": {"audit_trail"},
		"CMP-007": {"audit_trail"},
		"CMP-008": {"change_management"},
		"CMP-009": {"change_management"},
		"CMP-010": {"third_party_risk"},
		"CMP-011": {"privacy_policy"},
		"CMP-012": {"privacy_policy"},
		"CMP-013": {"change_management"},
		"CMP-014": {"privacy_policy"},
		"CMP-015": {"data_classification"},
		"CMP-016": {"audit_trail"},
		"CMP-017": {"audit_trail"},
		"CMP-018": {"third_party_risk"},
		"CMP-019": {"change_management"},
		"CMP-020": {"access_control"},
		"CMP-021": {"access_control"},
		"CMP-022": {"access_control"},
		"CMP-023": {"change_management"},
		"CMP-024": {"audit_trail"},
		"CMP-025": {"risk_assessment"},
		"CMP-026": {"vulnerability_scan"},
		"CMP-027": {"incident_response"},
		"CMP-028": {"audit_trail"},
		"CMP-029": {"vulnerability_scan"},
		"CMP-030": {"audit_trail"},
		// Data Privacy patterns (CAIQ)
		"DP-001": {"privacy_policy"},
		"DP-002": {"consent_management"},
		"DP-003": {"data_subject_rights"},
		"DP-004": {"data_subject_rights"},
		"DP-005": {"dpias"},
		"DP-006": {"privacy_policy"},
		"DP-007": {"data_retention"},
		"DP-008": {"data_retention"},
		"DP-009": {"data_classification"},
		"DP-010": {"data_masking"},
		"DP-011": {"privacy_policy"},
		"DP-012": {"third_party_risk"},
		"DP-013": {"data_classification"},
		"DP-014": {"incident_response"},
		"DP-015": {"dpias"},
		"DP-016": {"dpias"},
		"DP-017": {"privacy_policy"},
		"DP-018": {"privacy_policy"},
		"DP-019": {"data_retention"},
		"DP-020": {"consent_management"},
		"DP-021": {"consent_management"},
		"DP-022": {"data_subject_rights"},
		"DP-023": {"privacy_policy"},
		"DP-024": {"data_classification"},
		"DP-025": {"data_subject_rights"},
		"DP-026": {"data_classification"},
		"DP-027": {"data_masking"},
		"DP-028": {"privacy_policy"},
		"DP-029": {"third_party_risk"},
		"DP-030": {"audit_trail"},
		// Incident Response patterns (CAIQ)
		"IR-001": {"incident_response"},
		"IR-002": {"incident_response"},
		"IR-003": {"incident_response"},
		"IR-004": {"incident_response"},
		"IR-005": {"security_logging"},
		"IR-006": {"security_logging"},
		"IR-007": {"incident_response"},
		"IR-008": {"incident_response"},
		"IR-009": {"incident_response"},
		"IR-010": {"incident_response"},
		"IR-011": {"change_management"},
		"IR-012": {"incident_response"},
		"IR-013": {"incident_response"},
		"IR-014": {"incident_response"},
		"IR-015": {"security_logging"},
		"IR-016": {"audit_trail"},
		"IR-017": {"patch_management"},
		"IR-018": {"third_party_risk"},
		"IR-019": {"third_party_risk"},
		"IR-020": {"incident_response"},
		"IR-021": {"business_continuity"},
		"IR-022": {"security_logging"},
		"IR-023": {"security_logging"},
		"IR-024": {"incident_response"},
		"IR-025": {"incident_response"},
		"IR-026": {"vulnerability_scan"},
		"IR-027": {"patch_management"},
		"IR-028": {"incident_response"},
		"IR-029": {"risk_assessment"},
		"IR-030": {"change_management"},
		// Risk Management patterns (CAIQ)
		"RM-001": {"risk_assessment"},
		"RM-002": {"risk_assessment"},
		"RM-003": {"risk_assessment"},
		"RM-004": {"third_party_risk"},
		"RM-005": {"risk_assessment"},
		"RM-006": {"risk_assessment"},
		"RM-007": {"business_continuity", "disaster_recovery"},
		"RM-008": {"risk_assessment"},
		"RM-009": {"risk_assessment"},
		"RM-010": {"risk_assessment"},
		"RM-011": {"third_party_risk"},
		"RM-012": {"risk_assessment"},
		"RM-013": {"risk_assessment"},
		"RM-014": {"risk_assessment"},
		"RM-015": {"risk_assessment"},
		"RM-016": {"risk_assessment"},
		"RM-017": {"risk_assessment"},
		"RM-018": {"risk_assessment"},
		"RM-019": {"risk_assessment"},
		"RM-020": {"change_management"},
		"RM-021": {"risk_assessment"},
		"RM-022": {"risk_assessment"},
		"RM-023": {"security_logging"},
		"RM-024": {"change_management"},
		"RM-025": {"risk_assessment"},
	}

	// Match question ID against known patterns.
	qid := q.ID
	for pattern, keys := range patternToKeys {
		if strings.Contains(qid, pattern) {
			for _, k := range keys {
				relevant[k] = true
			}
		}
	}

	// Convert to slice.
	result := make([]string, 0, len(relevant))
	for k := range relevant {
		result = append(result, k)
	}
	return result
}

// ExportToCSV exports a QuestionnaireResponse to CSV format.
// The CSV has columns: ID, Category, Text, Answer, Confidence, Source, Evidence.
func ExportToCSV(response *QuestionnaireResponse) ([]byte, error) {
	if response == nil {
		return nil, fmt.Errorf("response cannot be nil")
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Header
	header := []string{"ID", "Category", "Text", "Answer", "Confidence", "Source", "Evidence"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Data rows
	for _, q := range response.Questions {
		evidence := strings.Join(q.Evidence, "; ")
		row := []string{
			q.ID,
			q.Category,
			q.Text,
			q.Answer,
			fmt.Sprintf("%.2f", q.Confidence),
			q.Source,
			evidence,
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row for %s: %w", q.ID, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV write error: %w", err)
	}

	return buf.Bytes(), nil
}

// ExportToPDF exports a QuestionnaireResponse to a real PDF document
// using the AegisGate PDF renderer (pkg/pdf). The generated PDF includes
// a title page, per-category headings, question/answer tables with
// confidence scores, and a summary section.
//
// The PDF is self-contained (no external dependencies like wkhtmltopdf)
// and suitable for compliance audits, vendor assessments, and regulatory
// submissions.
func ExportToPDF(response *QuestionnaireResponse) ([]byte, error) {
	if response == nil {
		return nil, fmt.Errorf("response cannot be nil")
	}

	// Build PDF sections from the questionnaire response.
	var sections []pdf.Section

	// Document metadata header.
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf("Organization: %s", response.OrganizationName),
	})
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf("Generated: %s", response.GeneratedAt.Format(time.RFC3339)),
	})

	// Compute summary statistics.
	total, autoCount, policyCount, manualCount, avgConfidence := SummaryStats(response)
	summaryTable := pdf.Table{
		Rows: [][]string{
			{"Metric", "Value"},
			{"Total Questions", fmt.Sprintf("%d", total)},
			{"Auto-Answered", fmt.Sprintf("%d", autoCount)},
			{"Policy-Inferred", fmt.Sprintf("%d", policyCount)},
			{"Manual Review", fmt.Sprintf("%d", manualCount)},
			{"Avg Confidence", fmt.Sprintf("%.2f", avgConfidence)},
		},
	}
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionHeading,
		Text: "Summary",
	})
	sections = append(sections, pdf.Section{
		Kind:  pdf.SectionTable,
		Table: summaryTable,
	})

	// Group questions by category for structured output.
	categories := make(map[string][]Question)
	var catOrder []string
	for _, q := range response.Questions {
		if _, ok := categories[q.Category]; !ok {
			catOrder = append(catOrder, q.Category)
		}
		categories[q.Category] = append(categories[q.Category], q)
	}

	// Render each category as a heading + question table.
	for _, cat := range catOrder {
		questions := categories[cat]

		sections = append(sections, pdf.Section{
			Kind: pdf.SectionPageBreak,
		})
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionHeading,
			Text: cat,
		})

		// Build question table: ID | Question | Answer | Confidence | Source
		rows := [][]string{
			{"ID", "Question", "Answer", "Confidence", "Source"},
		}
		for _, q := range questions {
			answer := q.Answer
			if len(answer) > 80 {
				answer = answer[:77] + "..."
			}
			questionText := q.Text
			if len(questionText) > 120 {
				questionText = questionText[:117] + "..."
			}
			rows = append(rows, []string{
				q.ID,
				questionText,
				answer,
				fmt.Sprintf("%.2f", q.Confidence),
				q.Source,
			})
		}

		sections = append(sections, pdf.Section{
			Kind: pdf.SectionTable,
			Table: pdf.Table{
				Rows: rows,
			},
		})

		// Add evidence section for questions with evidence.
		var evidenceQuestions []Question
		for _, q := range questions {
			if len(q.Evidence) > 0 {
				evidenceQuestions = append(evidenceQuestions, q)
			}
		}
		if len(evidenceQuestions) > 0 {
			sections = append(sections, pdf.Section{
				Kind: pdf.SectionHeading,
				Text: fmt.Sprintf("%s — Evidence", cat),
			})
			evidenceRows := [][]string{
				{"Question ID", "Evidence"},
			}
			for _, q := range evidenceQuestions {
				evidenceRows = append(evidenceRows, []string{
					q.ID,
					strings.Join(q.Evidence, "; "),
				})
			}
			sections = append(sections, pdf.Section{
				Kind: pdf.SectionTable,
				Table: pdf.Table{
					Rows: evidenceRows,
				},
			})
		}
	}

	// Render the PDF.
	req := &pdf.RenderRequest{
		Title:        fmt.Sprintf("%s Questionnaire — Version %s", response.Framework, response.Version),
		Author:       "AegisGate Security Platform",
		Subject:      fmt.Sprintf("%s %s Questionnaire for %s", response.Framework, response.Version, response.OrganizationName),
		Keywords:     fmt.Sprintf("%s, questionnaire, compliance, vendor assessment", response.Framework),
		Sections:     sections,
		Footer:       fmt.Sprintf("%s Questionnaire — %s", response.Framework, response.OrganizationName),
		Header:       "AegisGate",
		HeaderSubtitle: response.Version,
		FooterURL:    "https://aegisgatesecurity.io",
		GeneratedAt:  response.GeneratedAt,
	}

	return pdf.RenderReport(req)
}

// flattenResults converts nested scanner results into a flat
// keyword-to-string map that the answer engine can match against.
// It handles string, bool, float64, and nested map[string]interface{}
// values, flattening keys with dot notation.
func flattenResults(results map[string]interface{}) map[string]string {
	flat := make(map[string]string)
	flattenRecursive(results, "", flat)
	return flat
}

func flattenRecursive(data map[string]interface{}, prefix string, out map[string]string) {
	for key, val := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			out[fullKey] = v
			out[key] = v // also index by short key
		case bool:
			if v {
				out[fullKey] = "true"
				out[key] = "true"
			} else {
				out[fullKey] = "false"
				out[key] = "false"
			}
		case float64:
			s := fmt.Sprintf("%.2f", v)
			out[fullKey] = s
			out[key] = s
		case json.Number:
			out[fullKey] = v.String()
			out[key] = v.String()
		case map[string]interface{}:
			flattenRecursive(v, fullKey, out)
		case []interface{}:
			// Serialize arrays as comma-joined strings.
			parts := make([]string, 0, len(v))
			for _, item := range v {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			s := strings.Join(parts, ", ")
			out[fullKey] = s
			out[key] = s
		default:
			if v != nil {
				out[fullKey] = fmt.Sprintf("%v", v)
				out[key] = fmt.Sprintf("%v", v)
			}
		}
	}
}

// categoryKeywordMap returns a mapping from questionnaire categories to
// the scanner result keywords that are relevant to that category. This
// enables category-based inference when direct keyword matching fails.
func categoryKeywordMap() map[string][]string {
	return map[string][]string{
		"Security":             {"mfa", "encryption_at_rest", "encryption_in_transit", "access_control", "firewall", "vulnerability_scan", "patch_management", "iam", "security_logging"},
		"Availability":         {"backup", "disaster_recovery", "redundancy", "uptime", "incident_response", "business_continuity", "load_balancing"},
		"Processing Integrity": {"data_validation", "audit_trail", "change_management", "quality_assurance", "processing_controls", "data_integrity"},
		"Confidentiality":      {"encryption_at_rest", "encryption_in_transit", "access_control", "data_classification", "nda", "confidentiality_controls", "data_masking"},
		"Privacy":              {"privacy_policy", "data_retention", "consent_management", "dpias", "gdpr", "ccpa", "data_subject_rights", "privacy_impact_assessment"},
		"Cloud Security":       {"mfa", "encryption_at_rest", "encryption_in_transit", "iam", "network_security", "vulnerability_scan", "security_logging", "access_control", "endpoint_security"},
		"Compliance":           {"compliance_framework", "audit_trail", "regulatory_reporting", "third_party_risk", "vendor_management", "policy_review"},
		"Data Privacy":         {"privacy_policy", "data_retention", "consent_management", "dpias", "data_classification", "data_masking", "data_subject_rights"},
		"Incident Response":    {"incident_response", "security_logging", "forensic_analysis", "communication_plan", "post_incident_review", "vulnerability_scan"},
		"Risk Management":      {"risk_assessment", "risk_register", "third_party_risk", "vendor_management", "business_continuity", "disaster_recovery"},
	}
}

// defaultAnswerMap returns the standard keyword-to-answer rules. Each
// rule specifies what answer to give when scanner results contain the
// listed keywords, with a confidence score and source classification.
func defaultAnswerMap() map[string]AnswerRule {
	return map[string]AnswerRule{
		"mfa": {
			Answer:     "Yes, multi-factor authentication is enabled",
			Confidence: 0.95,
			Source:     "automated_scan",
			Keywords:   []string{"mfa", "multi_factor_auth", "two_factor", "2fa"},
		},
		"encryption_at_rest": {
			Answer:     "Yes, data is encrypted at rest using AES-256",
			Confidence: 0.9,
			Source:     "automated_scan",
			Keywords:   []string{"encryption_at_rest", "aes_256", "data_encryption_rest", "disk_encryption"},
		},
		"encryption_in_transit": {
			Answer:     "Yes, data is encrypted in transit using TLS 1.2+",
			Confidence: 0.9,
			Source:     "automated_scan",
			Keywords:   []string{"encryption_in_transit", "tls", "ssl", "https_enforced"},
		},
		"access_control": {
			Answer:     "Yes, role-based access control (RBAC) is implemented and enforced",
			Confidence: 0.85,
			Source:     "automated_scan",
			Keywords:   []string{"access_control", "rbac", "iam", "role_based_access"},
		},
		"firewall": {
			Answer:     "Yes, network firewall controls are in place with documented rules",
			Confidence: 0.85,
			Source:     "automated_scan",
			Keywords:   []string{"firewall", "waf", "network_security", "firewall_rules"},
		},
		"vulnerability_scan": {
			Answer:     "Yes, regular vulnerability scanning is performed and findings are remediated",
			Confidence: 0.8,
			Source:     "automated_scan",
			Keywords:   []string{"vulnerability_scan", "vuln_scan", "security_scan", "pen_test"},
		},
		"patch_management": {
			Answer:     "Yes, a formal patch management process is in place with SLA-driven remediation timelines",
			Confidence: 0.75,
			Source:     "automated_scan",
			Keywords:   []string{"patch_management", "patching", "security_patches", "update_management"},
		},
		"security_logging": {
			Answer:     "Yes, comprehensive security logging and monitoring is implemented",
			Confidence: 0.85,
			Source:     "automated_scan",
			Keywords:   []string{"security_logging", "audit_logging", "siem", "log_monitoring", "security_monitoring"},
		},
		"backup": {
			Answer:     "Yes, regular data backups are performed with tested restoration procedures",
			Confidence: 0.8,
			Source:     "automated_scan",
			Keywords:   []string{"backup", "data_backup", "backup_recovery", "backup_procedures"},
		},
		"disaster_recovery": {
			Answer:     "Yes, a disaster recovery plan is documented and regularly tested",
			Confidence: 0.7,
			Source:     "policy_inference",
			Keywords:   []string{"disaster_recovery", "dr_plan", "dr_testing", "business_continuity"},
		},
		"incident_response": {
			Answer:     "Yes, an incident response plan is documented with defined roles and escalation procedures",
			Confidence: 0.7,
			Source:     "policy_inference",
			Keywords:   []string{"incident_response", "ir_plan", "incident_management", "security_incident"},
		},
		"risk_assessment": {
			Answer:     "Yes, regular risk assessments are performed with documented findings and remediation plans",
			Confidence: 0.7,
			Source:     "policy_inference",
			Keywords:   []string{"risk_assessment", "risk_register", "risk_analysis", "threat_modeling"},
		},
		"privacy_policy": {
			Answer:     "Yes, a privacy policy is published and reviewed annually",
			Confidence: 0.65,
			Source:     "policy_inference",
			Keywords:   []string{"privacy_policy", "data_privacy", "privacy_notice"},
		},
		"data_retention": {
			Answer:     "Yes, data retention policies are defined and enforced with automated deletion controls",
			Confidence: 0.65,
			Source:     "policy_inference",
			Keywords:   []string{"data_retention", "retention_policy", "data_lifecycle"},
		},
		"consent_management": {
			Answer:     "Yes, consent management mechanisms are implemented for data collection and processing",
			Confidence: 0.6,
			Source:     "policy_inference",
			Keywords:   []string{"consent_management", "consent", "cookie_consent"},
		},
		"data_classification": {
			Answer:     "Yes, data classification schemes are implemented and enforced across all data stores",
			Confidence: 0.6,
			Source:     "policy_inference",
			Keywords:   []string{"data_classification", "classification_scheme", "data_labeling"},
		},
		"third_party_risk": {
			Answer:     "Yes, third-party vendor risk assessments are conducted before onboarding and reviewed annually",
			Confidence: 0.55,
			Source:     "policy_inference",
			Keywords:   []string{"third_party_risk", "vendor_risk", "vendor_management", "supply_chain_risk"},
		},
		"audit_trail": {
			Answer:     "Yes, comprehensive audit trails are maintained for all system activities with tamper protection",
			Confidence: 0.85,
			Source:     "automated_scan",
			Keywords:   []string{"audit_trail", "audit_log", "audit_trail_integrity"},
		},
		"dpias": {
			Answer:     "Yes, Data Protection Impact Assessments are conducted for high-risk processing activities",
			Confidence: 0.55,
			Source:     "policy_inference",
			Keywords:   []string{"dpias", "dpia", "privacy_impact_assessment", "data_protection_impact"},
		},
		"change_management": {
			Answer:     "Yes, formal change management procedures are in place with approval workflows",
			Confidence: 0.65,
			Source:     "policy_inference",
			Keywords:   []string{"change_management", "change_control", "change_approval"},
		},
		"data_masking": {
			Answer:     "Yes, data masking and anonymization techniques are applied in non-production environments",
			Confidence: 0.7,
			Source:     "automated_scan",
			Keywords:   []string{"data_masking", "data_anonymization", "data_pseudonymization", "tokenization"},
		},
		"endpoint_security": {
			Answer:     "Yes, endpoint security controls including EDR and device management are deployed",
			Confidence: 0.8,
			Source:     "automated_scan",
			Keywords:   []string{"endpoint_security", "edr", "device_management", "mdm"},
		},
		"network_security": {
			Answer:     "Yes, network segmentation and monitoring controls are implemented",
			Confidence: 0.8,
			Source:     "automated_scan",
			Keywords:   []string{"network_security", "network_segmentation", "ids_ips", "ids"},
		},
		"business_continuity": {
			Answer:     "Yes, a business continuity plan is documented and tested annually",
			Confidence: 0.6,
			Source:     "policy_inference",
			Keywords:   []string{"business_continuity", "bcp", "continuity_planning"},
		},
		"data_subject_rights": {
			Answer:     "Yes, mechanisms are in place to handle data subject access requests within regulatory timeframes",
			Confidence: 0.55,
			Source:     "policy_inference",
			Keywords:   []string{"data_subject_rights", "subject_access_request", "sar", "right_to_deletion"},
		},
	}
}

// GetSIGBank returns a copy of the SIG question bank.
func (qe *QuestionnaireEngine) GetSIGBank() []Question {
	out := make([]Question, len(qe.sigBank))
	copy(out, qe.sigBank)
	return out
}

// GetCAIQBank returns a copy of the CAIQ question bank.
func (qe *QuestionnaireEngine) GetCAIQBank() []Question {
	out := make([]Question, len(qe.caiqBank))
	copy(out, qe.caiqBank)
	return out
}

// SummaryStats returns aggregate statistics about a questionnaire response.
func SummaryStats(response *QuestionnaireResponse) (total int, autoCount int, policyCount int, manualCount int, avgConfidence float64) {
	if response == nil || len(response.Questions) == 0 {
		return 0, 0, 0, 0, 0
	}

	total = len(response.Questions)
	var sumConf float64

	for _, q := range response.Questions {
		sumConf += q.Confidence
		switch q.Source {
		case "automated_scan":
			autoCount++
		case "policy_inference":
			policyCount++
		case "manual_review":
			manualCount++
		}
	}

	avgConfidence = sumConf / float64(total)
	return
}

// SortQuestionsByConfidence sorts questions in descending order of confidence.
func SortQuestionsByConfidence(response *QuestionnaireResponse) {
	if response == nil {
		return
	}
	sort.SliceStable(response.Questions, func(i, j int) bool {
		return response.Questions[i].Confidence > response.Questions[j].Confidence
	})
}

// FilterByConfidence returns only questions at or above the given confidence threshold.
func FilterByConfidence(response *QuestionnaireResponse, minConfidence float64) []Question {
	if response == nil {
		return nil
	}
	filtered := make([]Question, 0)
	for _, q := range response.Questions {
		if q.Confidence >= minConfidence {
			filtered = append(filtered, q)
		}
	}
	return filtered
}
