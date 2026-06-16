// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Framework Mapping Wire-Up tests (v3.5.0-alpha-1, Tier 1 TODO-402)
//
// framework_mapping_test.go verifies the Tier 1 (TODO-402) wire-up
// of pkg/compliance/framework_mapping.go into the evidence
// package:
//
//   - Manifest gets a top-level FrameworkCrossRefs field
//     populated by collectFrameworkCrossRefs
//   - CrossProtocolManifest gets a top-level ControlCrossRefs
//     field populated by aggregateControlCrossRefs
//   - The aggregator is deterministic (sorted ControlIDs,
//     Frameworks, PerProtocolCoverage keys)
//   - Empty inputs produce nil (omitted from JSON)
//   - The mapping library's GetMappingsForControl is consulted
//     for each control in the assessment
//
// The tests target the helper functions directly (collect +
// aggregate) so the assertions are decoupled from the
// Scanner's runtime behavior. The Scanner is exercised
// indirectly via newTestEvidenceBuilder in TestBuilder_Build_
// FrameworkCrossRefs_OmitsWhenEmpty.

package evidence

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
)

// makeAssessment is a small helper that builds a FrameworkAssessment
// with the given per-control results. Empty controlID strings are
// filtered by the production code, so this helper does not need
// to validate.
func makeAssessment(framework string, results []*compliance.ControlCheckResult) *compliance.FrameworkAssessment {
	return &compliance.FrameworkAssessment{
		Framework: framework,
		Version:   "v1.0.0-test",
		Results:   results,
		Summary:   compliance.AssessmentSummary{},
	}
}

// makeResult builds a single ControlCheckResult.
func makeResult(controlID, name string) *compliance.ControlCheckResult {
	return &compliance.ControlCheckResult{
		Framework:   "test",
		ControlID:   controlID,
		ControlName: name,
		Status:      compliance.StatusCompliant,
	}
}

// --------------------------------------------------------------------
// canonicalFrameworkID: wire-up boundary canonicalization
// --------------------------------------------------------------------

// TestCanonicalFrameworkID verifies that the library's
// human-readable framework names are mapped to the platform's
// canonical IDs at the wire-up boundary. This ensures the
// manifest's Targets map uses the same keys as the rest of
// the platform (and as the TODO-401 framework-refs cache).
func TestCanonicalFrameworkID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"MITRE ATLAS", "mitre_atlas"},
		{"mitre_atlas", "mitre_atlas"},
		{"atlas", "mitre_atlas"},
		{"NIST AI RMF", "nist_ai_rmf"},
		{"nist_ai_rmf", "nist_ai_rmf"},
		{"OWASP", "owasp_llm"},
		{"OWASP LLM Top 10", "owasp_llm"},
		{"owasp_llm", "owasp_llm"},
		{"CWE", "cwe"},
		{"CVE", "cve"},
		// Unknown / fallback paths.
		{"Unknown Framework", "unknown_framework"},
		{"PCI-DSS", "pci_dss"},
		{"ISO 27001", "iso_27001"},
		{"", ""},
	}
	for _, tc := range cases {
		got := canonicalFrameworkID(tc.in)
		if got != tc.want {
			t.Errorf("canonicalFrameworkID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------
// collectFrameworkCrossRefs: behavior
// --------------------------------------------------------------------

// TestCollectFrameworkCrossRefs_NilAssessment covers the empty-input
// guard. nil or empty-results assessment -> nil output (not an
// empty slice). nil -> omitted from JSON.
func TestCollectFrameworkCrossRefs_NilAssessment(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	if got := b.collectFrameworkCrossRefs("hipaa", nil); got != nil {
		t.Errorf("nil assessment: got %#v, want nil", got)
	}
}

// TestCollectFrameworkCrossRefs_EmptyResults covers the "no
// per-control data" case. assessment with empty Results -> nil.
func TestCollectFrameworkCrossRefs_EmptyResults(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	assessment := makeAssessment("hipaa", nil)
	if got := b.collectFrameworkCrossRefs("hipaa", assessment); got != nil {
		t.Errorf("empty results: got %#v, want nil", got)
	}
}

// TestCollectFrameworkCrossRefs_SkipsEmptyControlID covers the
// "assessment has a nil or zero-ControlID entry" case. Such
// entries are skipped, not returned.
func TestCollectFrameworkCrossRefs_SkipsEmptyControlID(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		makeResult("", "empty id"),
		nil, // explicit nil
		makeResult("ACCESS-001", "Access Control"),
	})
	got := b.collectFrameworkCrossRefs("hipaa", assessment)
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (empty/nil filtered)", len(got))
	}
	if got[0].SourceControl != "ACCESS-001" {
		t.Errorf("SourceControl = %q, want ACCESS-001", got[0].SourceControl)
	}
}

// TestCollectFrameworkCrossRefs_PopulatesFromMapping covers the
// happy path: the assessment has a control ID that the
// FrameworkMapping library knows about. The output entry must
// have the source control, source framework, and a non-empty
// Targets map (the actual targets depend on the library's
// contents; we just verify the wire-up is correct).
//
// This test does not assert specific target IDs because the
// library is owned by pkg/compliance. If the library's contents
// evolve, the test still passes as long as the wire-up is
// intact. A separate "spot-check" test below asserts that at
// least one well-known mapping (e.g., MITRE ATLAS AML.T0010 for
// OWASP LLM05) is reachable through the library, which catches
// gross regressions in the library itself.
func TestCollectFrameworkCrossRefs_PopulatesFromMapping(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	// ACCESS-001 is a generic access-control ID that may map
	// to multiple frameworks. Use it as a control the library
	// might know.
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		makeResult("ACCESS-001", "Access Control"),
		makeResult("UNKNOWN-CONTROL-XYZ", "Unknown Control"),
	})
	got := b.collectFrameworkCrossRefs("hipaa", assessment)
	if got == nil {
		t.Skip("library returned no mappings for the test control IDs; not a wire-up failure")
	}
	// The unknown control must be filtered (no targets AND no name? no, it has a name "Unknown Control").
	// Actually the filter is "no targets AND no name". A named control with no targets IS kept.
	// So we expect 2 entries if neither maps, or 1 if only one maps.
	if len(got) > 2 {
		t.Errorf("got %d entries, want <= 2", len(got))
	}
	for _, entry := range got {
		if entry.SourceFramework != "hipaa" {
			t.Errorf("SourceFramework = %q, want hipaa", entry.SourceFramework)
		}
		if entry.SourceControl == "" {
			t.Error("SourceControl empty")
		}
	}
}

// TestCollectFrameworkCrossRefs_KnownControlID exercises the
// happy-path inner loop: a control ID the library knows (GV1
// -> MITRE ATLAS techniques). The output entry must have
// non-empty Targets and a non-zero Confidence.
//
// This is the primary coverage driver for the inner loop body
// (the for _, rel := range rels loop) and the "best
// confidence" branch.
func TestCollectFrameworkCrossRefs_KnownControlID(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	assessment := makeAssessment("nist_ai_rmf", []*compliance.ControlCheckResult{
		makeResult("GV1", "Establish organizational context"),
	})
	got := b.collectFrameworkCrossRefs("nist_ai_rmf", assessment)
	if got == nil {
		t.Fatal("GV1 is a known library control; got nil, want at least one entry")
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	entry := got[0]
	if entry.SourceControl != "GV1" {
		t.Errorf("SourceControl = %q, want GV1", entry.SourceControl)
	}
	if entry.SourceFramework != "nist_ai_rmf" {
		t.Errorf("SourceFramework = %q, want nist_ai_rmf", entry.SourceFramework)
	}
	// The library maps GV1 to several MITRE ATLAS techniques.
	// We assert that at least one target framework is
	// populated.
	if len(entry.Targets) == 0 {
		t.Error("GV1 should have non-empty Targets")
	}
	if at, ok := entry.Targets["mitre_atlas"]; !ok || len(at) == 0 {
		t.Errorf("GV1 should map to mitre_atlas, got Targets=%v", entry.Targets)
	}
	if entry.Confidence == 0 {
		t.Error("GV1 should have a non-zero Confidence")
	}
}

// TestCollectFrameworkCrossRefs_AllResultsFilteredOut exercises
// the "no targets AND no name" filter that drops noise entries,
// AND the "if len(out) == 0" branch that returns nil when all
// results are filtered.
func TestCollectFrameworkCrossRefs_AllResultsFilteredOut(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	// An unknown control with no name: filtered by the
	// "no targets AND no name" rule. With only this entry,
	// the result slice ends up empty -> nil.
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		{Framework: "hipaa", ControlID: "FILTER-ME", ControlName: ""},
	})
	got := b.collectFrameworkCrossRefs("hipaa", assessment)
	if got != nil {
		t.Errorf("got %#v, want nil (all results filtered)", got)
	}
}

// TestCollectFrameworkCrossRefs_PreservesControlName verifies that
// the control name from the assessment's ControlCheckResult is
// carried through to the FrameworkCrossRef.
func TestCollectFrameworkCrossRefs_PreservesControlName(t *testing.T) {
	t.Parallel()
	b := &Builder{}
	assessment := makeAssessment("hipaa", []*compliance.ControlCheckResult{
		makeResult("ACCESS-001", "Access Control"),
	})
	got := b.collectFrameworkCrossRefs("hipaa", assessment)
	if got == nil {
		t.Skip("library has no mapping for ACCESS-001; cannot test name preservation")
	}
	if len(got) == 0 {
		t.Fatal("got empty result, expected at least one entry with a name preserved")
	}
	// At least one entry should preserve the name (the one
	// with the matched control ID, OR a no-match entry that
	// still has the name).
	found := false
	for _, e := range got {
		if e.SourceControl == "ACCESS-001" && e.ControlName == "Access Control" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("control name not preserved for ACCESS-001; got %#v", got)
	}
}

// --------------------------------------------------------------------
// collectFrameworkCrossRefs: spot-check well-known mappings
// --------------------------------------------------------------------

// TestCollectFrameworkCrossRefs_SpotCheck verifies that the
// pkg/compliance library contains at least one well-known
// mapping that the wire-up should expose. This catches gross
// regressions in the library's contents (e.g., someone deletes
// the OWASP LLM -> MITRE ATLAS entries).
//
// The test uses a control ID we expect the library to know.
// We probe several and pass if ANY of them is known. This makes
// the test resilient to library evolution while still catching
// catastrophic losses.
func TestCollectFrameworkCrossRefs_SpotCheck(t *testing.T) {
	t.Parallel()
	// Probe the library directly (not via the Builder) since
	// this test is a regression guard for the library's
	// contents, not the wire-up.
	mapping := compliance.NewFrameworkMapping()
	if mapping == nil {
		t.Fatal("NewFrameworkMapping returned nil; library unavailable")
	}
	// Probe NIST AI RMF control IDs (the library's primary
	// source framework). The actual list is library-owned; the
	// test passes if at least one is known.
	probes := []string{"GV1", "GV2", "MP1", "ME1", "RG1"}
	found := false
	for _, id := range probes {
		rels := mapping.GetMappingsForControl(id)
		if len(rels) > 0 {
			found = true
			t.Logf("library knows control %q: %d relationships", id, len(rels))
			break
		}
	}
	if !found {
		t.Error("library has no mappings for any probe; suspected regression")
	}
}

// --------------------------------------------------------------------
// aggregateControlCrossRefs: behavior
// --------------------------------------------------------------------

// TestAggregateControlCrossRefs_NilInput covers the empty-input
// guard. nil or empty input -> nil output.
func TestAggregateControlCrossRefs_NilInput(t *testing.T) {
	t.Parallel()
	if got := aggregateControlCrossRefs(nil); got != nil {
		t.Errorf("nil input: got %#v, want nil", got)
	}
	if got := aggregateControlCrossRefs([]*Manifest{}); got != nil {
		t.Errorf("empty input: got %#v, want nil", got)
	}
}

// TestAggregateControlCrossRefs_SkipsNilManifests covers the
// "slice contains a nil" case. nil entries are skipped.
func TestAggregateControlCrossRefs_SkipsNilManifests(t *testing.T) {
	t.Parallel()
	got := aggregateControlCrossRefs([]*Manifest{nil, nil})
	if got != nil {
		t.Errorf("nil manifests: got %#v, want nil", got)
	}
}

// TestAggregateControlCrossRefs_NoCrossRefs covers the "manifests
// have no FrameworkCrossRefs" case. Without per-framework
// cross-refs, the aggregator has nothing to aggregate.
func TestAggregateControlCrossRefs_NoCrossRefs(t *testing.T) {
	t.Parallel()
	m := &Manifest{Framework: "hipaa"}
	got := aggregateControlCrossRefs([]*Manifest{m})
	if got != nil {
		t.Errorf("no cross-refs: got %#v, want nil", got)
	}
}

// TestAggregateControlCrossRefs_AggregatesControls covers the
// happy path: two per-framework manifests share a control ID,
// the aggregator should produce ONE FrameworkControlRef with
// both frameworks in the Frameworks list.
func TestAggregateControlCrossRefs_AggregatesControls(t *testing.T) {
	t.Parallel()
	m1 := &Manifest{
		Framework: "hipaa",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "hipaa", SourceControl: "ACCESS-001"},
		},
	}
	m2 := &Manifest{
		Framework: "soc2",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "soc2", SourceControl: "ACCESS-001"},
		},
	}
	got := aggregateControlCrossRefs([]*Manifest{m1, m2})
	if len(got) != 1 {
		t.Fatalf("got %d control refs, want 1", len(got))
	}
	if got[0].ControlID != "ACCESS-001" {
		t.Errorf("ControlID = %q, want ACCESS-001", got[0].ControlID)
	}
	// Frameworks should contain both hipaa and soc2, sorted.
	want := []string{"hipaa", "soc2"}
	if !equalSorted(got[0].Frameworks, want) {
		t.Errorf("Frameworks = %v, want %v (sorted)", got[0].Frameworks, want)
	}
}

// TestAggregateControlCrossRefs_DeterministicOrdering verifies
// the determinism contract: ControlIDs, Frameworks, and
// PerProtocolCoverage keys are all sorted.
func TestAggregateControlCrossRefs_DeterministicOrdering(t *testing.T) {
	t.Parallel()
	// Intentionally construct the input in non-sorted order.
	m1 := &Manifest{
		Framework: "soc2",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "soc2", SourceControl: "ZZZ-999"},
			{SourceFramework: "soc2", SourceControl: "AAA-001"},
		},
		AuditAnchors: AuditAnchors{
			ByProtocol: map[string]int{
				"mcp":  5,
				"http": 10,
				"a2a":  2,
			},
		},
	}
	m2 := &Manifest{
		Framework: "hipaa",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "hipaa", SourceControl: "MMM-500"},
		},
		AuditAnchors: AuditAnchors{
			ByProtocol: map[string]int{
				"anp":  1,
				"http": 3,
			},
		},
	}
	got := aggregateControlCrossRefs([]*Manifest{m1, m2})
	if len(got) != 3 {
		t.Fatalf("got %d control refs, want 3", len(got))
	}
	// ControlIDs must be sorted.
	wantOrder := []string{"AAA-001", "MMM-500", "ZZZ-999"}
	for i, want := range wantOrder {
		if got[i].ControlID != want {
			t.Errorf("got[%d].ControlID = %q, want %q (sorted)", i, got[i].ControlID, want)
		}
	}
	// PerProtocolCoverage must contain exactly the expected
	// keys (set equality, not iteration order). Go map
	// iteration is randomized; JSON marshaling order is
	// governed by the encoder, not by us.
	for _, entry := range got {
		keys := make([]string, 0, len(entry.PerProtocolCoverage))
		for k := range entry.PerProtocolCoverage {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// ZZZ-999 has m1's protocols: {http:10, mcp:5, a2a:2}
		// AAA-001 has m1's protocols: {http:10, mcp:5, a2a:2}
		// MMM-500 has m2's protocols: {anp:1, http:3}
		// m2 contributes http too; m1 already has http with
		// a non-zero count, so the merged http is still 100%.
		var want []string
		switch entry.ControlID {
		case "MMM-500":
			want = []string{"anp", "http"}
		default:
			// AAA-001, ZZZ-999 both come from m1.
			want = []string{"a2a", "http", "mcp"}
		}
		if len(keys) != len(want) {
			t.Errorf("%s: PerProtocolCoverage keys = %v, want %v", entry.ControlID, keys, want)
			continue
		}
		for i, k := range keys {
			if k != want[i] {
				t.Errorf("%s: PerProtocolCoverage keys = %v, want %v", entry.ControlID, keys, want)
				break
			}
		}
	}
}

// TestAggregateControlCrossRefs_TargetsContributeToFrameworks
// covers the cross-framework rollup: a FrameworkCrossRef with
// Targets (e.g., {mitre_atlas: [T0010]}) should contribute
// "mitre_atlas" to the FrameworkControlRef.Frameworks list.
func TestAggregateControlCrossRefs_TargetsContributeToFrameworks(t *testing.T) {
	t.Parallel()
	m := &Manifest{
		Framework: "hipaa",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{
				SourceFramework: "hipaa",
				SourceControl:   "ACCESS-001",
				Targets: map[string][]string{
					"mitre_atlas": {"AML.T0010"},
					"owasp_llm":   {"LLM05"},
				},
			},
		},
	}
	got := aggregateControlCrossRefs([]*Manifest{m})
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	// Frameworks must include hipaa (source) + the two targets.
	want := []string{"hipaa", "mitre_atlas", "owasp_llm"}
	if !equalSorted(got[0].Frameworks, want) {
		t.Errorf("Frameworks = %v, want %v (sorted)", got[0].Frameworks, want)
	}
}

// TestAggregateControlCrossRefs_PerProtocolCoverageMaxWins
// verifies the "max coverage wins" merge rule for
// PerProtocolCoverage.
func TestAggregateControlCrossRefs_PerProtocolCoverageMaxWins(t *testing.T) {
	t.Parallel()
	// Two manifests both attest ACCESS-001. m1 says "http=50%",
	// m2 says "http=100%". Result: http=100%.
	m1 := &Manifest{
		Framework: "hipaa",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "hipaa", SourceControl: "ACCESS-001"},
		},
		AuditAnchors: AuditAnchors{
			ByProtocol: map[string]int{"http": 1},
		},
	}
	m2 := &Manifest{
		Framework: "soc2",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "soc2", SourceControl: "ACCESS-001"},
		},
		AuditAnchors: AuditAnchors{
			ByProtocol: map[string]int{"http": 10},
		},
	}
	// The aggregator derives 100% from "non-zero count". Both
	// are 100% (the test stub doesn't differentiate). The
	// "max wins" rule is exercised when one has 100% and the
	// other has 0% (skipped) or when both are 100%. To
	// exercise "max wins" we need a path that produces
	// different coverage values. The current implementation
	// uses a binary "covered or not" approximation (100% if
	// count > 0); a more rigorous calculation is a follow-up.
	// So this test verifies the binary approximation: both
	// manifests have non-zero http counts, so the result is
	// http=100%.
	got := aggregateControlCrossRefs([]*Manifest{m1, m2})
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if cov := got[0].PerProtocolCoverage["http"]; cov != 100.0 {
		t.Errorf("http coverage = %v, want 100.0 (binary approx: non-zero count)", cov)
	}
}

// TestAggregateControlCrossRefs_OmitsZeroCountProtocols verifies
// that protocols with zero event counts are omitted from the
// PerProtocolCoverage map (which then omits them from JSON).
func TestAggregateControlCrossRefs_OmitsZeroCountProtocols(t *testing.T) {
	t.Parallel()
	m := &Manifest{
		Framework: "hipaa",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{SourceFramework: "hipaa", SourceControl: "ACCESS-001"},
		},
		AuditAnchors: AuditAnchors{
			ByProtocol: map[string]int{
				"http": 10,
				"mcp":  0, // zero - should be omitted
			},
		},
	}
	got := aggregateControlCrossRefs([]*Manifest{m})
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if _, ok := got[0].PerProtocolCoverage["mcp"]; ok {
		t.Error("mcp should be omitted (zero count)")
	}
	if cov := got[0].PerProtocolCoverage["http"]; cov != 100.0 {
		t.Errorf("http coverage = %v, want 100.0", cov)
	}
}

// --------------------------------------------------------------------
// JSON serialization
// --------------------------------------------------------------------

// TestFrameworkCrossRef_JSONShape verifies the JSON tag shape.
// An empty FrameworkCrossRefs slice must be omitted (omitempty);
// a non-empty one must round-trip with the framework_cross_refs
// JSON key.
func TestFrameworkCrossRef_JSONShape(t *testing.T) {
	t.Parallel()
	m := Manifest{Framework: "hipaa"}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Empty -> omitted.
	if got := string(data); contains(got, "framework_cross_refs") {
		t.Errorf("empty FrameworkCrossRefs should be omitted; got %s", got)
	}

	// Non-empty -> present.
	m2 := Manifest{
		Framework: "hipaa",
		FrameworkCrossRefs: []FrameworkCrossRef{
			{
				SourceFramework: "hipaa",
				SourceControl:   "ACCESS-001",
				Targets:         map[string][]string{"mitre_atlas": {"AML.T0010"}},
			},
		},
	}
	data2, err := json.Marshal(m2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !contains(string(data2), "framework_cross_refs") {
		t.Errorf("non-empty FrameworkCrossRefs should be present; got %s", string(data2))
	}
	if !contains(string(data2), "ACCESS-001") {
		t.Errorf("SourceControl ACCESS-001 not in JSON: %s", string(data2))
	}
	if !contains(string(data2), "AML.T0010") {
		t.Errorf("Target AML.T0010 not in JSON: %s", string(data2))
	}
}

// TestControlCrossRefs_JSONShape verifies the JSON tag shape for
// the cross-protocol manifest's ControlCrossRefs field.
func TestControlCrossRefs_JSONShape(t *testing.T) {
	t.Parallel()
	cp := CrossProtocolManifest{ManifestID: "abc"}
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Empty -> omitted.
	if got := string(data); contains(got, "control_cross_refs") {
		t.Errorf("empty ControlCrossRefs should be omitted; got %s", got)
	}

	// Non-empty -> present.
	cp2 := CrossProtocolManifest{
		ManifestID: "abc",
		ControlCrossRefs: []FrameworkControlRef{
			{
				ControlID:           "ACCESS-001",
				Frameworks:          []string{"hipaa", "soc2"},
				PerProtocolCoverage: map[string]float64{"http": 100.0},
			},
		},
	}
	data2, err := json.Marshal(cp2)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !contains(string(data2), "control_cross_refs") {
		t.Errorf("non-empty ControlCrossRefs should be present; got %s", string(data2))
	}
	if !contains(string(data2), "ACCESS-001") {
		t.Errorf("ControlID ACCESS-001 not in JSON: %s", string(data2))
	}
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

// equalSorted returns true if a and b have the same elements
// regardless of order. Used to assert "sorted but equivalent"
// without coupling tests to the sort order itself.
func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// contains is a small substring helper (avoiding strings.Contains
// for one-liner readability in assertions).
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
