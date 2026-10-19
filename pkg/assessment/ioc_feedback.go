// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Posture Assessment Module
// Phase 2: IOC Feedback Loop — Self-improving gap detection & federation
//
// ioc_feedback.go connects assessment results to the federated IOC database.
// When scenarios are missed (not blocked by any detection layer), the feedback
// loop:
//
//  1. Records each gap as an IOC in the store (IOCTypeComplianceViolation,
//     Pattern="assessment_gap:<scenario_id>"). The fingerprint is computed
//     from a Detection struct that encodes the OWASP category + scenario ID,
//     so two instances that miss the same scenario produce the same
//     fingerprint — enabling federation ("1 customer's gap = all customers
//     aware").
//  2. Generates an actionable GapAnalysisReport with per-gap
//     PatternRecommendation entries (suggested regex, ML threshold change, or
//     response guard enhancement).
//  3. Supports pre/post-update validation: run assessment before and after
//     applying new patterns, diff the results, confirm gaps are closed.
//  4. Checks gap corroboration: if peer instances have also recorded the same
//     gap IOC, the gap is marked as "federated" — widespread gaps get higher
//     priority in the recommendation report.
//
// The feedback loop is OPTIONAL: the Runner works without it. The caller
// creates a feedback loop, runs the assessment, then calls ProcessResults().
// If no IOC store is provided, the loop still generates the gap analysis
// report — only IOC recording and federation are skipped.

package assessment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
)

// =========================================================================
// Configuration
// =========================================================================

// IOCFeedbackConfig configures the IOC feedback loop.
type IOCFeedbackConfig struct {
	// EnableIOCRecording records gaps as IOCs in the store.
	// Requires a non-nil store. Default: true.
	EnableIOCRecording bool

	// EnableFederation marks gap IOCs with AffectsGateway=true so they
	// are included in the next gossip sync cycle. Default: true.
	EnableFederation bool

	// EnableGapAnalysis generates the actionable GapAnalysisReport.
	// Default: true. Even with IOC recording disabled, the gap analysis
	// is useful — it tells you exactly what to fix.
	EnableGapAnalysis bool

	// EnableCorroboration checks if peer instances have also observed the
	// same gap IOC. Requires a non-nil store. Default: true.
	EnableCorroboration bool

	// MinGapSeverity is the minimum OWASP severity for a gap to be
	// recorded as an IOC. Gaps below this severity are still analyzed
	// but not federated. Default: ioc.SeverityHigh.
	MinGapSeverity ioc.Severity
}

// DefaultIOCFeedbackConfig returns the default configuration with all
// features enabled.
func DefaultIOCFeedbackConfig() IOCFeedbackConfig {
	return IOCFeedbackConfig{
		EnableIOCRecording:  true,
		EnableFederation:    true,
		EnableGapAnalysis:   true,
		EnableCorroboration: true,
		MinGapSeverity:      ioc.SeverityHigh,
	}
}

// =========================================================================
// Gap Record — a structured record of a missed scenario
// =========================================================================

// GapType classifies which detection layer missed the scenario.
type GapType string

const (
	// GapTypeRegexMiss: the regex scanner did not match the payload.
	// Fix: add a new scanner pattern.
	GapTypeRegexMiss GapType = "regex_miss"

	// GapTypeMLMiss: the ML detector was enabled but did not flag the
	// payload as a threat (score below threshold).
	// Fix: retrain model with this payload variant or lower threshold.
	GapTypeMLMiss GapType = "ml_miss"

	// GapTypeResponseMiss: the response guard did not detect the threat
	// in the response payload.
	// Fix: add or enhance a response guard detector.
	GapTypeResponseMiss GapType = "response_miss"

	// GapTypeAllMiss: all enabled detection layers missed the payload.
	// This is the most critical gap type.
	GapTypeAllMiss GapType = "all_miss"
)

// GapRecord is a structured record of a single missed scenario.
type GapRecord struct {
	// ScenarioID is the assessment scenario identifier (e.g., "LLM01-007").
	ScenarioID string `json:"scenario_id"`

	// Name is the human-readable scenario name.
	Name string `json:"name"`

	// OWASP is the OWASP LLM Top 10 category (e.g., "LLM01").
	OWASP string `json:"owasp"`

	// GapType classifies which layer missed the scenario.
	GapType GapType `json:"gap_type"`

	// DetectionLayer is the layer that DID catch it, or "none" if
	// nothing caught it. This is copied from ScenarioResult.DetectionLayer.
	DetectionLayer string `json:"detection_layer"`

	// MLScore is the ML threat score (if ML was enabled), or 0.0.
	MLScore float64 `json:"ml_score,omitempty"`

	// PayloadHash is the SHA-256 of the raw payload. This is used for
	// deduplication and logging — it is NOT shared via federation (the
	// IOC fingerprint is based on the Detection struct, not the payload).
	PayloadHash string `json:"payload_hash"`

	// Recommendation is the actionable suggestion for this gap.
	Recommendation PatternRecommendation `json:"recommendation"`

	// Federated is true if peer instances have also observed this gap
	// (the gap IOC exists in the store with a peer source).
	Federated bool `json:"federated,omitempty"`

	// PeerCount is the number of peer instances that have also recorded
	// this gap IOC. 0 if no peers or corroboration is disabled.
	PeerCount int `json:"peer_count,omitempty"`

	// Timestamp is when the gap was recorded.
	Timestamp time.Time `json:"timestamp"`
}

// =========================================================================
// Pattern Recommendation — actionable fix suggestion
// =========================================================================

// RecommendationPriority ranks the urgency of a pattern recommendation.
type RecommendationPriority string

const (
	PriorityCritical RecommendationPriority = "critical"
	PriorityHigh     RecommendationPriority = "high"
	PriorityMedium   RecommendationPriority = "medium"
	PriorityLow      RecommendationPriority = "low"
)

// PatternRecommendation is a specific, actionable suggestion for closing
// a detection gap.
type PatternRecommendation struct {
	// OWASP is the OWASP LLM Top 10 category.
	OWASP string `json:"owasp"`

	// GapType is the type of gap this recommendation addresses.
	GapType GapType `json:"gap_type"`

	// FixType classifies the type of fix: "new_pattern", "ml_retrain",
	// "ml_threshold", "response_guard", "response_enhancement".
	FixType string `json:"fix_type"`

	// Suggestion is a human-readable description of the recommended fix.
	Suggestion string `json:"suggestion"`

	// CandidateRegex is a suggested regex pattern that would close the
	// gap (if FixType is "new_pattern"). This is a STARTING POINT — it
	// must be reviewed by a human before being added to the scanner.
	// Empty for non-regex recommendations.
	CandidateRegex string `json:"candidate_regex,omitempty"`

	// TargetLayer is the detection layer the fix targets: "scanner",
	// "ml", or "response".
	TargetLayer string `json:"target_layer"`

	// Priority ranks the urgency of this recommendation.
	Priority RecommendationPriority `json:"priority"`

	// AffectedScenarios is the list of scenario IDs that this
	// recommendation would fix.
	AffectedScenarios []string `json:"affected_scenarios"`
}

// =========================================================================
// Gap Analysis Report
// =========================================================================

// GapAnalysisReport is the complete output of the feedback loop's analysis
// of a single assessment run.
type GapAnalysisReport struct {
	// AssessmentID is the ID of the assessment run that was analyzed.
	AssessmentID string `json:"assessment_id"`

	// Timestamp is when the analysis was performed.
	Timestamp time.Time `json:"timestamp"`

	// TotalGaps is the total number of gaps found.
	TotalGaps int `json:"total_gaps"`

	// GapRecords is the list of all gap records.
	GapRecords []GapRecord `json:"gap_records"`

	// PerOWASP maps each OWASP category to the number of gaps in that
	// category.
	PerOWASP map[string]int `json:"per_owasp"`

	// Recommendations is the deduplicated, prioritized list of pattern
	// recommendations. Multiple gaps that can be fixed by the same
	// pattern are merged into a single recommendation with multiple
	// AffectedScenarios.
	Recommendations []PatternRecommendation `json:"recommendations"`

	// FederatedGaps is the number of gaps that were also observed by
	// peer instances (via IOC corroboration).
	FederatedGaps int `json:"federated_gaps"`

	// IOCsRecorded is the number of gap IOCs that were written to the
	// IOC store. 0 if IOC recording is disabled or no store is provided.
	IOCsRecorded int `json:"iocs_recorded"`

	// FederationReady is true if gap IOCs were marked for federation
	// (AffectsGateway=true). The IOCs will be included in the next
	// gossip sync cycle.
	FederationReady bool `json:"federation_ready"`
}

// =========================================================================
// Validation Report — pre/post-update comparison
// =========================================================================

// ValidationReport compares two assessment runs (before and after a
// pattern update) to verify that the update closed gaps without
// introducing regressions.
type ValidationReport struct {
	// PreAssessmentID is the ID of the pre-update assessment.
	PreAssessmentID string `json:"pre_assessment_id"`

	// PostAssessmentID is the ID of the post-update assessment.
	PostAssessmentID string `json:"post_assessment_id"`

	// PreScore is the pre-update assessment score (0.0–1.0).
	PreScore float64 `json:"pre_score"`

	// PostScore is the post-update assessment score (0.0–1.0).
	PostScore float64 `json:"post_score"`

	// ScoreDelta is PostScore - PreScore.
	ScoreDelta float64 `json:"score_delta"`

	// GapsClosed is the list of scenario IDs that were missed before
	// but are now blocked.
	GapsClosed []string `json:"gaps_closed"`

	// Regressions is the list of scenario IDs that were blocked before
	// but are now missed. This should be empty — any regression means
	// the pattern update broke something.
	Regressions []string `json:"regressions"`

	// StillMissed is the list of scenario IDs that were missed both
	// before and after the update.
	StillMissed []string `json:"still_missed"`

	// NewGaps is the list of scenario IDs that were blocked before but
	// are now missed AND were not in the original gap list. This is a
	// subset of Regressions (regressions = scenarios that were blocked
	// before, now missed). NewGaps are scenarios that didn't exist in
	// the pre-assessment.
	NewGaps []string `json:"new_gaps"`

	// Passed is true if the update closed at least one gap and
	// introduced zero regressions.
	Passed bool `json:"passed"`

	// Summary is a human-readable summary.
	Summary string `json:"summary"`
}

// =========================================================================
// IOC Feedback Loop
// =========================================================================

// IOCFeedbackLoop connects assessment results to the federated IOC database.
// It is the self-improving mechanism: missed payloads become IOCs that
// federate across instances, and the gap analysis report provides actionable
// recommendations for closing gaps.
//
// The feedback loop is safe for concurrent use. It does not hold locks
// across IOC store operations — each gap is processed independently.
//
// Lifecycle:
//
//	store, _ := ioc.NewStore(ioc.StoreConfig{})
//	fb := NewIOCFeedbackLoop(DefaultIOCFeedbackConfig(), store)
//	runner, _ := NewRunner(cfg)
//	result, _ := runner.Run()
//	report := fb.ProcessResults(result)
//	// report.Recommendations → apply fixes → re-run → fb.ValidateUpdate(pre, post)
type IOCFeedbackLoop struct {
	cfg   IOCFeedbackConfig
	store ioc.StoreInterface // nil = no IOC recording
}

// NewIOCFeedbackLoop creates a feedback loop with the given config and
// optional IOC store. If store is nil, IOC recording and federation are
// disabled (the loop still generates gap analysis reports).
func NewIOCFeedbackLoop(cfg IOCFeedbackConfig, store ioc.StoreInterface) *IOCFeedbackLoop {
	if cfg.MinGapSeverity == "" {
		cfg.MinGapSeverity = ioc.SeverityHigh
	}
	if store == nil {
		// No store — disable IOC-dependent features.
		cfg.EnableIOCRecording = false
		cfg.EnableFederation = false
		cfg.EnableCorroboration = false
	}
	return &IOCFeedbackLoop{cfg: cfg, store: store}
}

// ProcessResults analyzes an assessment result, records gaps as IOCs
// (if enabled), and returns an actionable gap analysis report.
//
// The report contains:
//   - One GapRecord per missed scenario
//   - Deduplicated PatternRecommendations sorted by priority
//   - Federation status (how many gaps were corroborated by peers)
func (f *IOCFeedbackLoop) ProcessResults(result *AssessmentResult) *GapAnalysisReport {
	report := &GapAnalysisReport{
		AssessmentID: result.ID,
		Timestamp:    time.Now().UTC(),
		PerOWASP:     make(map[string]int),
	}

	if !f.cfg.EnableGapAnalysis && !f.cfg.EnableIOCRecording {
		return report
	}

	now := time.Now().UTC()
	iocsRecorded := 0
	federatedGaps := 0

	for _, sr := range result.ScenarioResults {
		if sr.Blocked {
			continue // Not a gap — scenario was caught.
		}

		gapType := classifyGap(sr)
		rec := recommendForGap(sr, gapType)
		severity := owaspSeverity(sr.OWASP)

		gap := GapRecord{
			ScenarioID:     sr.ScenarioID,
			Name:           sr.Name,
			OWASP:          sr.OWASP,
			GapType:        gapType,
			DetectionLayer: sr.DetectionLayer,
			MLScore:        sr.MLScore,
			PayloadHash:    hashPayload(f.payloadForScenario(sr.ScenarioID)),
			Recommendation: rec,
			Timestamp:      now,
		}

		// Record as IOC if enabled and severity meets threshold.
		if f.cfg.EnableIOCRecording && ioc.WorseSeverity(ioc.Severity(severity), f.cfg.MinGapSeverity) == ioc.Severity(severity) {
			iocRecord := f.buildGapIOC(sr, severity, now)
			if iocRecord != nil {
				if _, err := f.store.Observe(context.Background(), *iocRecord); err == nil {
					iocsRecorded++
				}
			}
		}

		// Check peer corroboration.
		if f.cfg.EnableCorroboration {
			peerCount := f.checkGapCorroboration(sr)
			if peerCount > 0 {
				gap.Federated = true
				gap.PeerCount = peerCount
				federatedGaps++
			}
		}

		report.GapRecords = append(report.GapRecords, gap)
		report.PerOWASP[sr.OWASP]++
	}

	report.TotalGaps = len(report.GapRecords)
	report.IOCsRecorded = iocsRecorded
	report.FederatedGaps = federatedGaps
	report.FederationReady = f.cfg.EnableFederation && iocsRecorded > 0

	// Build deduplicated recommendations.
	report.Recommendations = deduplicateRecommendations(report.GapRecords)

	return report
}

// ValidateUpdate compares a pre-update and post-update assessment to
// verify that gaps were closed without regressions.
//
// The pre-assessment should be run BEFORE applying pattern updates.
// The post-assessment should be run AFTER applying the updates.
// This method diffs the two and returns a ValidationReport.
func (f *IOCFeedbackLoop) ValidateUpdate(pre, post *AssessmentResult) *ValidationReport {
	vr := &ValidationReport{
		PreAssessmentID:  pre.ID,
		PostAssessmentID: post.ID,
		PreScore:         pre.Score,
		PostScore:        post.Score,
		ScoreDelta:       post.Score - pre.Score,
	}

	// Build maps of blocked/missed scenario IDs.
	preMissed := make(map[string]bool)
	preBlocked := make(map[string]bool)
	for _, sr := range pre.ScenarioResults {
		if sr.Blocked {
			preBlocked[sr.ScenarioID] = true
		} else {
			preMissed[sr.ScenarioID] = true
		}
	}

	postMissed := make(map[string]bool)
	postBlocked := make(map[string]bool)
	for _, sr := range post.ScenarioResults {
		if sr.Blocked {
			postBlocked[sr.ScenarioID] = true
		} else {
			postMissed[sr.ScenarioID] = true
		}
	}

	// Gaps closed: missed before, blocked now.
	for id := range preMissed {
		if postBlocked[id] {
			vr.GapsClosed = append(vr.GapsClosed, id)
		}
	}

	// Regressions: blocked before, missed now.
	for id := range preBlocked {
		if postMissed[id] {
			vr.Regressions = append(vr.Regressions, id)
		}
	}

	// Still missed: missed both before and after.
	for id := range preMissed {
		if postMissed[id] {
			vr.StillMissed = append(vr.StillMissed, id)
		}
	}

	// New gaps: missed after but not in pre-assessment at all.
	for id := range postMissed {
		if !preMissed[id] && !preBlocked[id] {
			vr.NewGaps = append(vr.NewGaps, id)
		}
	}

	// Passed if at least one gap closed and zero regressions.
	vr.Passed = len(vr.GapsClosed) > 0 && len(vr.Regressions) == 0

	vr.Summary = fmt.Sprintf(
		"Score: %.1f%% → %.1f%% (+%.1f%%) | Gaps closed: %d | Regressions: %d | Still missed: %d",
		pre.Score*100, post.Score*100, vr.ScoreDelta*100,
		len(vr.GapsClosed), len(vr.Regressions), len(vr.StillMissed),
	)
	if len(vr.Regressions) > 0 {
		vr.Summary += " | ⚠️ REGRESSIONS DETECTED"
	} else if vr.Passed {
		vr.Summary += " | ✅ PASSED"
	}

	return vr
}

// =========================================================================
// Internal: Gap IOC construction
// =========================================================================

// buildGapIOC constructs an IOC from a missed scenario. The IOC uses
// IOCTypeComplianceViolation with Pattern="assessment_gap:<scenario_id>"
// and AffectsGateway=true for federation.
//
// The fingerprint is computed from a Detection struct that encodes the
// OWASP category and scenario ID. Two instances that miss the same
// scenario produce the same fingerprint, enabling federation.
func (f *IOCFeedbackLoop) buildGapIOC(sr ScenarioResult, severity string, now time.Time) *ioc.IOC {
	d := ioc.Detection{
		Type:                "assessment_gap",
		Severity:            ioc.Severity(severity),
		Pattern:             "assessment_gap:" + sr.ScenarioID,
		ThreatType:          sr.OWASP,
		ThreatLevel:         "potential",
		ComplianceFramework: "OWASP_LLM_Top10",
		ComplianceControl:   sr.OWASP,
	}

	fp := ioc.Fingerprint(d)
	if fp == "" {
		return nil
	}

	iocRecord := ioc.IOC{
		Fingerprint:    fp,
		Type:           ioc.IOCTypeComplianceViolation,
		Severity:       ioc.Severity(severity),
		FirstSeen:      now,
		LastSeen:       now,
		Count:          1,
		Source:         "assessment",
		AffectsGateway: f.cfg.EnableFederation,
	}

	if !iocRecord.Valid() {
		return nil
	}
	return &iocRecord
}

// checkGapCorroboration checks if peer instances have also recorded the
// same gap IOC. Returns the peer count (0 if no peers or no store).
func (f *IOCFeedbackLoop) checkGapCorroboration(sr ScenarioResult) int {
	if f.store == nil {
		return 0
	}

	d := ioc.Detection{
		Type:                "assessment_gap",
		Severity:            ioc.Severity(owaspSeverity(sr.OWASP)),
		Pattern:             "assessment_gap:" + sr.ScenarioID,
		ThreatType:          sr.OWASP,
		ComplianceFramework: "OWASP_LLM_Top10",
		ComplianceControl:   sr.OWASP,
	}
	fp := ioc.Fingerprint(d)
	if fp == "" {
		return 0
	}

	existing, err := f.store.Get(context.Background(), fp)
	if err != nil || existing == nil {
		return 0
	}

	// Check if the IOC has a peer source (federated from another instance).
	if strings.HasPrefix(existing.Source, "peer:") {
		return 1 // At least one peer has corroborated this gap.
	}
	if ioc.IsExternalSource(existing.Source) {
		_, weight, _ := ioc.ParseExternalSource(existing.Source)
		if weight >= 0.5 {
			return 1
		}
	}
	return 0
}

// =========================================================================
// Internal: Gap classification
// =========================================================================

// classifyGap determines the GapType from a ScenarioResult.
func classifyGap(sr ScenarioResult) GapType {
	switch sr.DetectionLayer {
	case "none":
		// Check if ML was enabled (MLScore > 0 means ML was tried).
		if sr.MLScore > 0 {
			return GapTypeMLMiss
		}
		return GapTypeAllMiss
	case "regex":
		return GapTypeRegexMiss // Should not happen if Blocked=true, but handle it.
	case "ml":
		return GapTypeMLMiss
	case "response":
		return GapTypeResponseMiss
	default:
		return GapTypeAllMiss
	}
}

// =========================================================================
// Internal: Recommendation engine
// =========================================================================

// recommendForGap generates a PatternRecommendation for a specific gap.
// The recommendation is based on the scenario's OWASP category, name,
// and gap type.
func recommendForGap(sr ScenarioResult, gapType GapType) PatternRecommendation {
	rec := PatternRecommendation{
		OWASP:             sr.OWASP,
		GapType:           gapType,
		AffectedScenarios: []string{sr.ScenarioID},
		Priority:          owaspPriority(sr.OWASP),
	}

	switch gapType {
	case GapTypeRegexMiss, GapTypeAllMiss:
		rec.FixType = "new_pattern"
		rec.TargetLayer = "scanner"
		rec.Suggestion, rec.CandidateRegex = regexSuggestion(sr)
	case GapTypeMLMiss:
		rec.FixType = "ml_threshold"
		rec.TargetLayer = "ml"
		rec.Suggestion = fmt.Sprintf(
			"ML model scored %.4f (below threshold). Retrain with this payload variant or lower threshold from 0.50 to 0.40.",
			sr.MLScore,
		)
	case GapTypeResponseMiss:
		rec.FixType = "response_guard"
		rec.TargetLayer = "response"
		rec.Suggestion, rec.CandidateRegex = responseSuggestion(sr)
	}

	return rec
}

// regexSuggestion returns a human-readable suggestion and candidate regex
// for a scanner-pattern gap.
func regexSuggestion(sr ScenarioResult) (suggestion, candidateRegex string) {
	base := fmt.Sprintf("Add scanner pattern for %s (%s)", sr.Name, sr.OWASP)

	// Generate a candidate regex based on the scenario's characteristics.
	// These are STARTING POINTS — a human must review before adding.
	switch sr.OWASP {
	case "LLM01":
		if strings.Contains(strings.ToLower(sr.Name), "non-english") || strings.Contains(sr.Name, "language switch") {
			return base + " — CJK characters with injection keywords (忽略/覆盖/绕过 + 指令/系统/提示)",
				`(?:忽略|覆盖|绕过|禁用|無視|覆蓋|繞過).{0,20}(?:指令|系统|提示|配置|規則|規定)`
		}
		if strings.Contains(strings.ToLower(sr.Name), "base64") {
			return base + " — base64-encoded prompt injection (decode and scan)",
				`(?:[A-Za-z0-9+/]{40,}={0,2})`
		}
		if strings.Contains(strings.ToLower(sr.Name), "homoglyph") || strings.Contains(strings.ToLower(sr.Name), "unicode") {
			return base + " — unicode homoglyphs in injection keywords (Cyrillic/Greek lookalikes)",
				`[ІіАаВсЕеКкМНнОоРрТуХх][a-zA-Z\s]{0,30}(?:ignorе|instuctiоn|systеm|prоmpt)`
		}
		return base + " — prompt injection variant not matched by existing patterns", ""

	case "LLM02":
		return base + " — sensitive data pattern not matched by existing PII/secret detectors", ""

	case "LLM03":
		if strings.Contains(strings.ToLower(sr.Name), "eval") {
			return base + " — dangerous function call (eval/exec/Function) with user input",
				`(?i)(?:eval|exec|Function)\s*\(\s*(?:input|user|request|query|param|data|args?|raw|untrusted)\b`
		}
		if strings.Contains(strings.ToLower(sr.Name), "tool description") || strings.Contains(strings.ToLower(sr.Name), "malicious tool") {
			return base + " — dangerous tool description with arbitrary code execution",
				`(?i)(?:executes?\s+(?:arbitrary|any|all)\s+(?:shell\s+)?(?:command|code|script|program))`
		}
		return base + " — supply chain vulnerability pattern", ""

	case "LLM04":
		if strings.Contains(strings.ToLower(sr.Name), "embed") {
			return base + " — RAG poisoning via embedding manipulation",
				`(?i)(?:embed\s+(?:this|the\s+following)\s+(?:document|text|content)\s+(?:in|into)\s+(?:the\s+)?(?:knowledge\s+base|vector\s+store|embedding))`
		}
		if strings.Contains(strings.ToLower(sr.Name), "training") {
			return base + " — training data injection",
				`(?i)(?:add\s+(?:this\s+)?to\s+(?:the\s+)?training\s+(?:set|data|corpus|dataset))`
		}
		return base + " — data and model poisoning pattern", ""

	case "LLM05":
		return base + " — response content threat not matched by response guard", ""

	case "LLM06":
		if strings.Contains(strings.ToLower(sr.Name), "privilege") || strings.Contains(strings.ToLower(sr.Name), "admin") {
			return base + " — privilege escalation to admin role",
				`(?i)(?:role\s*=\s*admin|update_role\s+.*role\s*=\s*admin|grant\s+(?:me\s+)?admin\s+access)`
		}
		return base + " — excessive agency / unauthorized action pattern", ""

	case "LLM07":
		return base + " — system prompt extraction pattern", ""

	case "LLM08":
		if strings.Contains(strings.ToLower(sr.Name), "retrieval") || strings.Contains(strings.ToLower(sr.Name), "context") {
			return base + " — RAG retrieval manipulation with injected context override",
				`(?i)(?:\[(?:CONTEXT\s+FROM\s+RAG|RETRIEVED\s+CONTEXT)\]).*(?:override|approved?\s+without|without\s+verification|security\s+policy)`
		}
		return base + " — vector store / embedding attack pattern", ""

	case "LLM09":
		return base + " — hallucination or toxic output not caught by response guard", ""

	case "LLM10":
		if strings.Contains(strings.ToLower(sr.Name), "token overflow") || strings.Contains(strings.ToLower(sr.Name), "excessive length") {
			return base + " — unbounded token consumption via excessive generation request",
				`(?i)(?:generate|write|produce)\s+(?:a\s+)?\d{5,}\s+word`
		}
		return base + " — resource exhaustion pattern", ""
	}

	return base, ""
}

// responseSuggestion returns a human-readable suggestion and candidate regex
// for a response-guard gap.
func responseSuggestion(sr ScenarioResult) (suggestion, candidateRegex string) {
	base := fmt.Sprintf("Enhance response guard for %s (%s)", sr.Name, sr.OWASP)

	switch sr.OWASP {
	case "LLM05":
		if strings.Contains(strings.ToLower(sr.Name), "api key") || strings.Contains(strings.ToLower(sr.Name), "secret") {
			return base + " — add sk- prefix to secret detector API key pattern",
				`(?i)sk-[a-zA-Z0-9]{20,}`
		}
		if strings.Contains(strings.ToLower(sr.Name), "dangerous") || strings.Contains(strings.ToLower(sr.Name), "import") {
			return base + " — add dangerous import detection to compliance scanner",
				`(?i)(?:import\s+os|import\s+subprocess|from\s+os\s+import|require\(['"]child_process['"]\))`
		}
		return base + " — response content detection gap", ""

	case "LLM09":
		if strings.Contains(strings.ToLower(sr.Name), "hallucination") || strings.Contains(strings.ToLower(sr.Name), "fabricated") {
			return base + " — add fabricated source/DOI detection to hallucination detector",
				`(?i)(?:according to\s+(?:a\s+)?(?:study|research|paper|report)\s+by\s+.{5,80}(?:\(\d{4}\))?.*(?:doi:\s*\d+\.\d+/\S+|source:\s*\S+))`
		}
		if strings.Contains(strings.ToLower(sr.Name), "toxic") || strings.Contains(strings.ToLower(sr.Name), "harmful") {
			return base + " — extend toxicity filter with additional self-harm and harassment patterns",
				`(?i)(?:hurt\s*yourself|nobody\s+cares\s+about\s+you|better\s+off\s+without\s+you|everyone\s+would\s+be\s+better\s+off)`
		}
		return base + " — response guard detection gap", ""
	}

	return base, ""
}

// =========================================================================
// Internal: OWASP severity and priority mapping
// =========================================================================

// owaspSeverity maps an OWASP LLM Top 10 category to an IOC severity.
func owaspSeverity(owasp string) string {
	switch owasp {
	case "LLM01": // Prompt Injection
		return string(ioc.SeverityCritical)
	case "LLM03": // Supply Chain
		return string(ioc.SeverityCritical)
	case "LLM06": // Excessive Agency
		return string(ioc.SeverityCritical)
	case "LLM02": // Sensitive Info Disclosure
		return string(ioc.SeverityHigh)
	case "LLM04": // Data & Model Poisoning
		return string(ioc.SeverityHigh)
	case "LLM05": // Improper Output Handling
		return string(ioc.SeverityHigh)
	case "LLM07": // System Prompt Leakage
		return string(ioc.SeverityHigh)
	case "LLM08": // Vector & Embedding Weaknesses
		return string(ioc.SeverityHigh)
	case "LLM09": // Misinformation & Hallucination
		return string(ioc.SeverityMedium)
	case "LLM10": // Unbounded Consumption
		return string(ioc.SeverityMedium)
	default:
		return string(ioc.SeverityMedium)
	}
}

// owaspPriority maps an OWASP category to a recommendation priority.
func owaspPriority(owasp string) RecommendationPriority {
	sev := owaspSeverity(owasp)
	switch ioc.Severity(sev) {
	case ioc.SeverityCritical:
		return PriorityCritical
	case ioc.SeverityHigh:
		return PriorityHigh
	case ioc.SeverityMedium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

// =========================================================================
// Internal: Helpers
// =========================================================================

// deduplicateRecommendations merges gaps that can be fixed by the same
// recommendation into a single PatternRecommendation with multiple
// AffectedScenarios. Recommendations are sorted by priority (critical first).
func deduplicateRecommendations(gaps []GapRecord) []PatternRecommendation {
	// Group by (OWASP, FixType, Suggestion) — if the suggestion is the same,
	// the gaps can be fixed by the same action.
	type key struct {
		owasp      string
		fixType    string
		suggestion string
	}
	groups := make(map[key]*PatternRecommendation)

	for _, gap := range gaps {
		k := key{
			owasp:      gap.Recommendation.OWASP,
			fixType:    gap.Recommendation.FixType,
			suggestion: gap.Recommendation.Suggestion,
		}
		if existing, ok := groups[k]; ok {
			existing.AffectedScenarios = append(existing.AffectedScenarios, gap.ScenarioID)
		} else {
			rec := gap.Recommendation
			rec.AffectedScenarios = []string{gap.ScenarioID}
			groups[k] = &rec
		}
	}

	// Collect and sort by priority.
	recs := make([]PatternRecommendation, 0, len(groups))
	for _, rec := range groups {
		recs = append(recs, *rec)
	}

	// Sort: critical > high > medium > low.
	priorityOrder := map[RecommendationPriority]int{
		PriorityCritical: 0,
		PriorityHigh:     1,
		PriorityMedium:   2,
		PriorityLow:      3,
	}
	for i := 0; i < len(recs); i++ {
		for j := i + 1; j < len(recs); j++ {
			if priorityOrder[recs[i].Priority] > priorityOrder[recs[j].Priority] {
				recs[i], recs[j] = recs[j], recs[i]
			}
		}
	}

	return recs
}

// hashPayload computes the SHA-256 hash of a payload string.
// Used for deduplication in the GapRecord — NOT for IOC fingerprints.
func hashPayload(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// payloadForScenario looks up the payload for a given scenario ID.
// This is used to compute the payload hash for the GapRecord.
func (f *IOCFeedbackLoop) payloadForScenario(scenarioID string) string {
	for _, sc := range DefaultScenarios() {
		if sc.ID == scenarioID {
			return sc.Payload
		}
	}
	return ""
}

// Summary returns a human-readable summary of the gap analysis report.
func (r *GapAnalysisReport) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Gap Analysis Report for %s\n", r.AssessmentID))
	sb.WriteString(fmt.Sprintf("  Total gaps: %d\n", r.TotalGaps))
	sb.WriteString(fmt.Sprintf("  IOCs recorded: %d\n", r.IOCsRecorded))
	sb.WriteString(fmt.Sprintf("  Federated gaps: %d\n", r.FederatedGaps))
	sb.WriteString(fmt.Sprintf("  Recommendations: %d\n\n", len(r.Recommendations)))

	if len(r.PerOWASP) > 0 {
		sb.WriteString("  Gaps by OWASP category:\n")
		for owasp, count := range r.PerOWASP {
			sb.WriteString(fmt.Sprintf("    %s: %d gap(s)\n", owasp, count))
		}
	}

	if len(r.Recommendations) > 0 {
		sb.WriteString("\n  Prioritized recommendations:\n")
		for i, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("    %d. [%s] %s\n", i+1, rec.Priority, rec.Suggestion))
			sb.WriteString(fmt.Sprintf("       Fix type: %s, Target: %s, Scenarios: %s\n",
				rec.FixType, rec.TargetLayer, strings.Join(rec.AffectedScenarios, ", ")))
			if rec.CandidateRegex != "" {
				sb.WriteString(fmt.Sprintf("       Candidate regex: %s\n", rec.CandidateRegex))
			}
		}
	}

	return sb.String()
}

// Summary returns a human-readable summary of the validation report.
func (r *ValidationReport) String() string {
	return r.Summary
}
