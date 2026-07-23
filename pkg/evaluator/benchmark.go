// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Adversarial Benchmark Suite
//
// benchmark.go implements the v3.8 adversarial benchmark suite that
// runs Lens SXC corpus records against the Platform's security
// scanners (ResponseGuard, PIIScanner, SecretDetector, ToxicityFilter,
// HallucinationDetector, AnomalyDetector).
//
// The benchmark suite provides:
//   - ScannerTarget: adapts Platform's ResponseGuard as an evaluator Target
//   - SXCBenchmarkResult: per-record and aggregate benchmark results
//   - BenchmarkRunner: orchestrates the SXC corpus against Platform scanners
//   - Report generation (JSON, text)
//
// The benchmark answers two questions for each SXC record:
//   - True Positive (TP): positive record correctly detected (expected=1, detected=1)
//   - True Negative (TN): negative record correctly not flagged (expected=0, detected=0)
//   - False Positive (FP): negative record incorrectly flagged (expected=0, detected=1)
//   - False Negative (FN): positive record not detected (expected=1, detected=0)
//
// The SXC corpus is designed for precision/recall measurement. The ATLAS
// corpus (corpus.go) is designed for pass/fail adversarial evals. Both
// are needed for a complete assessment.

package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/response"
)

// init registers the "benchmark" subject kind with the attestation package
// so SignBenchmarkResult can create attestation envelopes.
func init() {
	_ = attestation.RegisterKind("benchmark")
}

// =====================================================================
// Benchmark types
// =====================================================================

// BenchmarkScanner is the interface that Platform security scanners
// implement to participate in the benchmark suite. The canonical
// implementation wraps response.ResponseGuard.
type BenchmarkScanner interface {
	// Scan runs a single SXCRecord through the scanner and returns
	// whether the input was detected as a threat and details about
	// the detection.
	Scan(ctx context.Context, record SXCRecord) (*BenchmarkDetection, error)
	// Name returns the scanner's human-readable name (e.g., "ResponseGuard").
	Name() string
}

// BenchmarkDetection is the result of scanning a single SXCRecord.
type BenchmarkDetection struct {
	// Detected is true if the scanner flagged the input.
	Detected bool `json:"detected"`
	// Threats is the list of threats found (if any).
	Threats []BenchmarkThreat `json:"threats,omitempty"`
	// LatencyMillis is the scan latency.
	LatencyMillis int64 `json:"latency_millis"`
}

// BenchmarkThreat represents a single detected threat.
type BenchmarkThreat struct {
	// Type is the threat type (e.g., "secret", "pii", "xss", "toxicity").
	Type string `json:"type"`
	// Severity is the threat severity (1-5).
	Severity int `json:"severity"`
	// Message describes the threat.
	Message string `json:"message"`
	// Category is the detection category (e.g., "secret_aws_key", "xss_script_tag").
	Category string `json:"category"`
}

// =====================================================================
// Benchmark result types
// =====================================================================

// SXCRecordResult is the outcome for a single SXC record.
type SXCRecordResult struct {
	// RecordID is the SXC record ID.
	RecordID string `json:"record_id"`
	// Facet is the record's facet (secrets, xss, compliance).
	Facet SXCFacet `json:"facet"`
	// Category is the record's category.
	Category SXCCategory `json:"category"`
	// ExpectedLabel is the ground-truth label (1=should detect, 0=should not flag).
	ExpectedLabel int `json:"expected_label"`
	// Detected is true if the scanner detected a threat.
	Detected bool `json:"detected"`
	// Outcome is the classification: TP, TN, FP, or FN.
	Outcome string `json:"outcome"`
	// Threats is the list of detected threats (empty if not detected).
	Threats []BenchmarkThreat `json:"threats,omitempty"`
	// LatencyMillis is the scan latency.
	LatencyMillis int64 `json:"latency_millis"`
}

// SXCRunResult is the aggregate result of an SXC benchmark run.
// It is the payload of the signed envelope (after canonicalization).
type SXCRunResult struct {
	// RunID is the unique run identifier (UUIDv4).
	RunID string `json:"run_id"`
	// RunTimestamp is when the run started (UTC, RFC 3339).
	RunTimestamp time.Time `json:"run_timestamp"`
	// CorpusID is the SXC corpus identifier.
	CorpusID string `json:"corpus_id"`
	// CorpusVersion is the SXC corpus version.
	CorpusVersion string `json:"corpus_version"`
	// ScannerName is the scanner that was benchmarked.
	ScannerName string `json:"scanner_name"`
	// TotalRecords is the total number of SXC records tested.
	TotalRecords int `json:"total_records"`
	// TruePositives is the count of positive records correctly detected.
	TruePositives int `json:"true_positives"`
	// TrueNegatives is the count of negative records correctly not flagged.
	TrueNegatives int `json:"true_negatives"`
	// FalsePositives is the count of negative records incorrectly flagged.
	FalsePositives int `json:"false_positives"`
	// FalseNegatives is the count of positive records not detected.
	FalseNegatives int `json:"false_negatives"`
	// Precision is TP / (TP + FP). 0 if TP+FP is 0.
	Precision float64 `json:"precision"`
	// Recall is TP / (TP + FN). 0 if TP+FN is 0.
	Recall float64 `json:"recall"`
	// F1Score is the harmonic mean of precision and recall.
	F1Score float64 `json:"f1_score"`
	// Accuracy is (TP + TN) / TotalRecords.
	Accuracy float64 `json:"accuracy"`
	// FacetBreakdown breaks down the results by facet.
	FacetBreakdown map[SXCFacet]*SXCFacetResult `json:"facet_breakdown"`
	// CategoryBreakdown breaks down the results by category.
	CategoryBreakdown map[SXCCategory]*SXCCategoryResult `json:"category_breakdown"`
	// Results is the per-record outcome, sorted by RecordID.
	Results []SXCRecordResult `json:"results"`
	// DurationMillis is the total wall-clock time for the run.
	DurationMillis int64 `json:"duration_millis"`
	// RunnerVersion is the AegisGate version that ran this benchmark.
	RunnerVersion string `json:"runner_version"`
}

// SXCFacetResult is the aggregate result for a single facet.
type SXCFacetResult struct {
	TotalRecords   int     `json:"total_records"`
	TruePositives  int     `json:"true_positives"`
	TrueNegatives  int     `json:"true_negatives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1Score        float64 `json:"f1_score"`
	Accuracy       float64 `json:"accuracy"`
}

// SXCCategoryResult is the aggregate result for a single category.
type SXCCategoryResult struct {
	TotalRecords   int     `json:"total_records"`
	TruePositives  int     `json:"true_positives"`
	TrueNegatives  int     `json:"true_negatives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1Score        float64 `json:"f1_score"`
	Accuracy       float64 `json:"accuracy"`
}

// =====================================================================
// ResponseGuard scanner adapter
// =====================================================================

// ResponseGuardScanner adapts a response.ResponseGuard as a
// BenchmarkScanner. This is the canonical scanner for the SXC
// benchmark suite — it runs PIIScanner → SecretDetector →
// ToxicityFilter → HallucinationDetector in sequence.
type ResponseGuardScanner struct {
	guard *response.ResponseGuard
}

// NewResponseGuardScanner creates a BenchmarkScanner from a
// ResponseGuard. If guard is nil, a default guard is created.
func NewResponseGuardScanner(guard *response.ResponseGuard) *ResponseGuardScanner {
	if guard == nil {
		guard = response.NewResponseGuard()
	}
	return &ResponseGuardScanner{guard: guard}
}

// Name returns the scanner's name.
func (s *ResponseGuardScanner) Name() string {
	return "ResponseGuard"
}

// Scan runs a single SXCRecord through the ResponseGuard and returns
// the detection result. A positive record (expected_label=1) should
// produce at least one threat; a negative record (expected_label=0)
// should produce zero threats.
func (s *ResponseGuardScanner) Scan(ctx context.Context, record SXCRecord) (*BenchmarkDetection, error) {
	start := time.Now()
	result, err := s.guard.Scan(ctx, record.Text)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("benchmark: scan %s: %w", record.ID, err)
	}
	threats := make([]BenchmarkThreat, 0, len(result.Threats))
	for _, t := range result.Threats {
		threats = append(threats, BenchmarkThreat{
			Type:     t.Type,
			Severity: t.Severity,
			Message:  t.Message,
			Category: t.Pattern,
		})
	}
	return &BenchmarkDetection{
		Detected:      len(result.Threats) > 0 || !result.Allowed,
		Threats:       threats,
		LatencyMillis: elapsed.Milliseconds(),
	}, nil
}

// =====================================================================
// Benchmark runner
// =====================================================================

// BenchmarkRunner orchestrates an SXC benchmark run against a
// BenchmarkScanner. It is safe for concurrent use (no mutable state).
type BenchmarkRunner struct {
	scanner       BenchmarkScanner
	keyRing       *ioc.KeyRing
	runnerVersion string
}

// NewBenchmarkRunner creates a BenchmarkRunner. Returns an error if
// scanner is nil.
func NewBenchmarkRunner(scanner BenchmarkScanner, keyRing *ioc.KeyRing) (*BenchmarkRunner, error) {
	if scanner == nil {
		return nil, fmt.Errorf("benchmark: scanner is required")
	}
	if keyRing == nil {
		return nil, fmt.Errorf("benchmark: keyRing is required")
	}
	return &BenchmarkRunner{
		scanner:       scanner,
		keyRing:       keyRing,
		runnerVersion: RunnerVersion,
	}, nil
}

// BenchmarkOption configures a benchmark run.
type BenchmarkOption func(*benchmarkOptions)

// benchmarkOptions holds per-run configuration.
type benchmarkOptions struct {
	facet     SXCFacet    // filter to a single facet (empty = all)
	category  SXCCategory // filter to a single category (empty = all)
	recordIDs []string    // filter to specific record IDs
}

// WithFacet filters the SXC corpus to a single facet.
func WithFacet(facet SXCFacet) BenchmarkOption {
	return func(o *benchmarkOptions) { o.facet = facet }
}

// WithCategory filters the SXC corpus to a single category.
func WithCategory(cat SXCCategory) BenchmarkOption {
	return func(o *benchmarkOptions) { o.category = cat }
}

// WithRecordIDs filters the SXC corpus to specific record IDs.
func WithRecordIDs(ids []string) BenchmarkOption {
	return func(o *benchmarkOptions) { o.recordIDs = ids }
}

// RunBenchmark executes the SXC benchmark against the scanner.
// It runs each record through the scanner, classifies the outcome
// (TP/TN/FP/FN), and computes aggregate metrics.
func (r *BenchmarkRunner) RunBenchmark(ctx context.Context, opts ...BenchmarkOption) (*SXCRunResult, error) {
	o := benchmarkOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	// 1. Filter the corpus.
	records := r.filterCorpus(o)

	if len(records) == 0 {
		return nil, fmt.Errorf("benchmark: no records match the filter criteria")
	}

	// 2. Run each record.
	startedAt := time.Now().UTC()
	results := make([]SXCRecordResult, 0, len(records))

	for i := range records {
		rec := records[i]
		det, err := r.scanner.Scan(ctx, rec)
		if err != nil {
			// Scanner error: treat as a false negative (missed detection).
			results = append(results, SXCRecordResult{
				RecordID:      rec.ID,
				Facet:         rec.Facet,
				Category:      rec.Category,
				ExpectedLabel: rec.ExpectedLabel,
				Detected:      false,
				Outcome:       "FN",
				LatencyMillis: 0,
			})
			continue
		}
		outcome := classifyOutcome(rec.ExpectedLabel, det.Detected)
		threats := det.Threats
		if threats == nil {
			threats = []BenchmarkThreat{}
		}
		results = append(results, SXCRecordResult{
			RecordID:      rec.ID,
			Facet:         rec.Facet,
			Category:      rec.Category,
			ExpectedLabel: rec.ExpectedLabel,
			Detected:      det.Detected,
			Outcome:       outcome,
			Threats:       threats,
			LatencyMillis: det.LatencyMillis,
		})

	}

	totalDuration := time.Since(startedAt)

	// 3. Aggregate.
	agg := r.aggregate(results, startedAt, totalDuration, o)
	return agg, nil
}

// filterCorpus applies the filter options to the SXC corpus.
func (r *BenchmarkRunner) filterCorpus(o benchmarkOptions) []SXCRecord {
	corpus := SXCCorpus()
	if o.facet != "" {
		var filtered []SXCRecord
		for _, rec := range corpus {
			if rec.Facet == o.facet {
				filtered = append(filtered, rec)
			}
		}
		corpus = filtered
	}
	if o.category != "" {
		var filtered []SXCRecord
		for _, rec := range corpus {
			if rec.Category == o.category {
				filtered = append(filtered, rec)
			}
		}
		corpus = filtered
	}
	if len(o.recordIDs) > 0 {
		keep := make(map[string]struct{}, len(o.recordIDs))
		for _, id := range o.recordIDs {
			keep[id] = struct{}{}
		}
		var filtered []SXCRecord
		for _, rec := range corpus {
			if _, ok := keep[rec.ID]; ok {
				filtered = append(filtered, rec)
			}
		}
		corpus = filtered
	}
	return corpus
}

// classifyOutcome returns TP, TN, FP, or FN based on expected and detected.
func classifyOutcome(expectedLabel int, detected bool) string {
	if expectedLabel == 1 && detected {
		return "TP" // True Positive: should detect, did detect
	}
	if expectedLabel == 0 && !detected {
		return "TN" // True Negative: should not flag, did not flag
	}
	if expectedLabel == 0 && detected {
		return "FP" // False Positive: should not flag, did flag
	}
	// expectedLabel == 1 && !detected
	return "FN" // False Negative: should detect, did not detect
}

// aggregate computes the aggregate metrics from the per-record results.
func (r *BenchmarkRunner) aggregate(results []SXCRecordResult, startedAt time.Time, totalDuration time.Duration, o benchmarkOptions) *SXCRunResult {
	sort.Slice(results, func(i, j int) bool {
		return results[i].RecordID < results[j].RecordID
	})

	var tp, tn, fp, fn int
	facetBreakdown := make(map[SXCFacet]*SXCFacetResult)
	categoryBreakdown := make(map[SXCCategory]*SXCCategoryResult)

	for _, res := range results {
		switch res.Outcome {
		case "TP":
			tp++
		case "TN":
			tn++
		case "FP":
			fp++
		case "FN":
			fn++
		}

		// Facet breakdown.
		if facetBreakdown[res.Facet] == nil {
			facetBreakdown[res.Facet] = &SXCFacetResult{}
		}
		fb := facetBreakdown[res.Facet]
		fb.TotalRecords++
		switch res.Outcome {
		case "TP":
			fb.TruePositives++
		case "TN":
			fb.TrueNegatives++
		case "FP":
			fb.FalsePositives++
		case "FN":
			fb.FalseNegatives++
		}

		// Category breakdown.
		if categoryBreakdown[res.Category] == nil {
			categoryBreakdown[res.Category] = &SXCCategoryResult{}
		}
		cb := categoryBreakdown[res.Category]
		cb.TotalRecords++
		switch res.Outcome {
		case "TP":
			cb.TruePositives++
		case "TN":
			cb.TrueNegatives++
		case "FP":
			cb.FalsePositives++
		case "FN":
			cb.FalseNegatives++
		}
	}

	// Compute derived metrics.
	precision := safeDiv(float64(tp), float64(tp+fp))
	recall := safeDiv(float64(tp), float64(tp+fn))
	f1 := safeDiv(2*precision*recall, precision+recall)
	accuracy := safeDiv(float64(tp+tn), float64(len(results)))

	// Compute facet-level metrics.
	for _, fb := range facetBreakdown {
		fb.Precision = safeDiv(float64(fb.TruePositives), float64(fb.TruePositives+fb.FalsePositives))
		fb.Recall = safeDiv(float64(fb.TruePositives), float64(fb.TruePositives+fb.FalseNegatives))
		fb.F1Score = safeDiv(2*fb.Precision*fb.Recall, fb.Precision+fb.Recall)
		fb.Accuracy = safeDiv(float64(fb.TruePositives+fb.TrueNegatives), float64(fb.TotalRecords))
	}

	// Compute category-level metrics.
	for _, cb := range categoryBreakdown {
		cb.Precision = safeDiv(float64(cb.TruePositives), float64(cb.TruePositives+cb.FalsePositives))
		cb.Recall = safeDiv(float64(cb.TruePositives), float64(cb.TruePositives+cb.FalseNegatives))
		cb.F1Score = safeDiv(2*cb.Precision*cb.Recall, cb.Precision+cb.Recall)
		cb.Accuracy = safeDiv(float64(cb.TruePositives+cb.TrueNegatives), float64(cb.TotalRecords))
	}

	return &SXCRunResult{
		RunID:             generateBenchmarkID(),
		RunTimestamp:      startedAt,
		CorpusID:          SXCCorpusID,
		CorpusVersion:     SXCCorpusVersion,
		ScannerName:       r.scanner.Name(),
		TotalRecords:      len(results),
		TruePositives:     tp,
		TrueNegatives:     tn,
		FalsePositives:    fp,
		FalseNegatives:    fn,
		Precision:         precision,
		Recall:            recall,
		F1Score:           f1,
		Accuracy:          accuracy,
		FacetBreakdown:    facetBreakdown,
		CategoryBreakdown: categoryBreakdown,
		Results:           results,
		DurationMillis:    totalDuration.Milliseconds(),
		RunnerVersion:     r.runnerVersion,
	}
}

// safeDiv returns a/b, or 0 if b is 0.
func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

// generateBenchmarkID returns a deterministic ID derived from timestamp
// and scanner name. For production use, callers should use UUIDv4.
func generateBenchmarkID() string {
	// Use timestamp-based ID for simplicity. The signed result
	// uses the keyring for attestation.
	return fmt.Sprintf("bench-%d", time.Now().UnixMilli())
}

// =====================================================================
// Report generation
// =====================================================================

// BenchmarkReportJSON serializes the SXCRunResult to JSON.
func BenchmarkReportJSON(result *SXCRunResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// BenchmarkReportText returns a human-readable summary of the benchmark.
func BenchmarkReportText(result *SXCRunResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AegisGate SXC Benchmark Report\n")
	fmt.Fprintf(&b, "==============================\n")
	fmt.Fprintf(&b, "Run ID:          %s\n", result.RunID)
	fmt.Fprintf(&b, "Timestamp:       %s\n", result.RunTimestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Corpus:          %s @ %s\n", result.CorpusID, result.CorpusVersion)
	fmt.Fprintf(&b, "Scanner:         %s\n", result.ScannerName)
	fmt.Fprintf(&b, "Records:         %d\n", result.TotalRecords)
	fmt.Fprintf(&b, "Duration:        %dms\n", result.DurationMillis)
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "Aggregate Metrics\n")
	fmt.Fprintf(&b, "-----------------\n")
	fmt.Fprintf(&b, "True Positives:  %d\n", result.TruePositives)
	fmt.Fprintf(&b, "True Negatives:  %d\n", result.TrueNegatives)
	fmt.Fprintf(&b, "False Positives: %d\n", result.FalsePositives)
	fmt.Fprintf(&b, "False Negatives: %d\n", result.FalseNegatives)
	fmt.Fprintf(&b, "Precision:       %.4f\n", result.Precision)
	fmt.Fprintf(&b, "Recall:          %.4f\n", result.Recall)
	fmt.Fprintf(&b, "F1 Score:        %.4f\n", result.F1Score)
	fmt.Fprintf(&b, "Accuracy:        %.4f\n", result.Accuracy)
	fmt.Fprintf(&b, "\n")

	if len(result.FacetBreakdown) > 0 {
		fmt.Fprintf(&b, "Facet Breakdown\n")
		fmt.Fprintf(&b, "---------------\n")
		facets := make([]SXCFacet, 0, len(result.FacetBreakdown))
		for f := range result.FacetBreakdown {
			facets = append(facets, f)
		}
		sort.Slice(facets, func(i, j int) bool { return string(facets[i]) < string(facets[j]) })
		for _, f := range facets {
			fb := result.FacetBreakdown[f]
			fmt.Fprintf(&b, "  %s: TP=%d TN=%d FP=%d FN=%d P=%.4f R=%.4f F1=%.4f Acc=%.4f\n",
				f, fb.TruePositives, fb.TrueNegatives, fb.FalsePositives, fb.FalseNegatives,
				fb.Precision, fb.Recall, fb.F1Score, fb.Accuracy)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(result.CategoryBreakdown) > 0 {
		fmt.Fprintf(&b, "Category Breakdown\n")
		fmt.Fprintf(&b, "------------------\n")
		cats := make([]SXCCategory, 0, len(result.CategoryBreakdown))
		for c := range result.CategoryBreakdown {
			cats = append(cats, c)
		}
		sort.Slice(cats, func(i, j int) bool { return string(cats[i]) < string(cats[j]) })
		for _, c := range cats {
			cb := result.CategoryBreakdown[c]
			fmt.Fprintf(&b, "  %s: TP=%d TN=%d FP=%d FN=%d P=%.4f R=%.4f F1=%.4f Acc=%.4f\n",
				c, cb.TruePositives, cb.TrueNegatives, cb.FalsePositives, cb.FalseNegatives,
				cb.Precision, cb.Recall, cb.F1Score, cb.Accuracy)
		}
		fmt.Fprintf(&b, "\n")
	}

	// False positive details (most actionable for improvement).
	fps := 0
	fns := 0
	for _, r := range result.Results {
		if r.Outcome == "FP" {
			fps++
		}
		if r.Outcome == "FN" {
			fns++
		}
	}
	if fps > 0 {
		fmt.Fprintf(&b, "False Positives (%d)\n", fps)
		fmt.Fprintf(&b, "--------------------\n")
		for _, r := range result.Results {
			if r.Outcome == "FP" {
				threatTypes := make([]string, 0, len(r.Threats))
				for _, t := range r.Threats {
					threatTypes = append(threatTypes, t.Type)
				}
				fmt.Fprintf(&b, "  %s [%s/%s]: flagged as {%s} (expected negative)\n",
					r.RecordID, r.Facet, r.Category, strings.Join(threatTypes, ", "))
			}
		}
		fmt.Fprintf(&b, "\n")
	}
	if fns > 0 {
		fmt.Fprintf(&b, "False Negatives (%d)\n", fns)
		fmt.Fprintf(&b, "--------------------\n")
		for _, r := range result.Results {
			if r.Outcome == "FN" {
				fmt.Fprintf(&b, "  %s [%s/%s]: not detected (expected positive)\n",
					r.RecordID, r.Facet, r.Category)
			}
		}
	}

	return b.String()
}

// =====================================================================
// Signed benchmark result
// =====================================================================

// TypeBenchmarkRun is the attestation type for SXC benchmark results.
const TypeBenchmarkRun attestation.Type = "benchmark.sxc.v1"

// SignBenchmarkResult signs an SXCRunResult with the attestation
// envelope. This produces a tamper-evident result that an auditor
// can verify offline.
func SignBenchmarkResult(result *SXCRunResult, keyRing *ioc.KeyRing) (*attestation.Envelope, error) {
	if keyRing == nil {
		return nil, fmt.Errorf("benchmark: sign: keyRing is required")
	}
	payloadBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("benchmark: marshal result: %w", err)
	}
	subject := "aegisgate://benchmark/" + result.RunID
	instanceID := "bench:shortfp:" + shortFingerprint(generateFingerprint(result))
	keyID := keyRing.CurrentKeyID()
	issuer := instanceID + ":" + keyID
	env, err := attestation.Sign(payloadBytes, subject, TypeBenchmarkRun, issuer, keyRing, 0)
	if err != nil {
		return nil, fmt.Errorf("benchmark: sign: %w", err)
	}
	return env, nil
}

// generateFingerprint creates a deterministic fingerprint for the
// benchmark result by hashing the RunID and scanner name.
func generateFingerprint(result *SXCRunResult) string {
	h := sha256.Sum256([]byte(result.RunID + ":" + result.ScannerName))
	return "sha256:" + hex.EncodeToString(h[:])
}
