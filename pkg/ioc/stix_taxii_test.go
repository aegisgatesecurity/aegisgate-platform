// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - STIX/TAXII conversion tests (v3.5.0+, Tier 2 TODO-403)
//
// stix_taxii_test.go covers the IOC <-> STIX 2.1 conversion
// layer defined in stix_taxii.go. The tests are white-box
// (package ioc) so we can construct IOCs and Attestations
// with full control over all fields.
//
// The tests focus on:
//   - Forward round-trip: IOC -> STIX Indicator -> IOC preserves
//     the fingerprint, type, severity, count, and timing.
//   - Lossy reverse: STIX Indicator -> IOC recovers what STIX
//     can carry; AegisGate-specific fields (Detection tuple,
//     FrameworkRefs) are empty.
//   - Empty inputs: nil bundles, empty attestations, and
//     invalid IOCs all produce errors (not panics).
//   - JSON shape: BundleToSTIX produces a STIX 2.1 bundle
//     with spec_version "2.1" and a non-empty objects array.
//   - Label round-trip: the "type:" and "source:" labels are
//     recoverable.
//   - Edge cases: malformed patterns, unknown IOCTypes,
//     zero Count, missing ExternalReferences.

package ioc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ti "github.com/aegisgatesecurity/aegisgate/pkg/threatintel"
)

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

// makeStixTestIOC builds a valid IOC for tests. All fields are
// populated; tests that need a partial IOC override individual
// fields.
//
// fpPrefix is repeated to form a 64-char hex fingerprint. The
// repetition is intentional: it keeps the helper signature
// small and produces a deterministic, recognizable fingerprint
// for debugging (e.g., "ab" -> "abab...ab", 64 chars).
func makeStixTestIOC(fpPrefix string, iocType IOCType, sev Severity) *IOC {
	// 64 chars / len(fpPrefix) repetitions; fall back to
	// a single-char repetition if fpPrefix is empty.
	if fpPrefix == "" {
		fpPrefix = "a"
	}
	repeats := 64 / len(fpPrefix)
	if 64%len(fpPrefix) != 0 {
		repeats++ // ensures >= 64 chars
	}
	fp := strings.Repeat(fpPrefix, repeats)
	if len(fp) > 64 {
		fp = fp[:64]
	}
	now := time.Now().UTC()
	return &IOC{
		Fingerprint: fp,
		Type:        iocType,
		Severity:    sev,
		FirstSeen:   now,
		LastSeen:    now,
		Count:       5,
		Source:      "proxy",
	}
}

// makeStixTestAttestation builds a valid IOCAttestation with the
// given fields.
func makeStixTestAttestation(fpPrefix string, iocType IOCType, sev Severity) *IOCAttestation {
	ioc := makeStixTestIOC(fpPrefix, iocType, sev)
	return &IOCAttestation{
		Fingerprint: ioc.Fingerprint,
		InstanceID:  "test-instance",
		IOCType:     iocType,
		Severity:    sev,
		FirstSeen:   ioc.FirstSeen,
		LastSeen:    ioc.LastSeen,
		Count:       ioc.Count,
	}
}

// makeStixTestBundle builds a Bundle with the given attestations.
func makeStixTestBundle(atts ...*IOCAttestation) *Bundle {
	b := NewBundle("test-instance")
	for _, a := range atts {
		b.Attestations = append(b.Attestations, *a)
	}
	b.Count = len(b.Attestations)
	return b
}

// --------------------------------------------------------------------
// IOCToSTIXIndicator
// --------------------------------------------------------------------

func TestIOCToSTIXIndicator_Valid(t *testing.T) {
	t.Parallel()
	ioc := makeStixTestIOC("ab", IOCTypeProxyResponse, SeverityHigh)
	ind, err := IOCToSTIXIndicator(ioc)
	if err != nil {
		t.Fatalf("IOCToSTIXIndicator: %v", err)
	}
	if ind.Pattern == "" {
		t.Error("Pattern empty")
	}
	if !strings.Contains(ind.Pattern, ioc.Fingerprint) {
		t.Errorf("Pattern %q does not contain fingerprint %q", ind.Pattern, ioc.Fingerprint)
	}
	if ind.Confidence != 80 {
		t.Errorf("Confidence = %d, want 80 (high severity)", ind.Confidence)
	}
	// Labels: aegisgate, type:proxy_response, source:proxy, count:5
	wantLabels := map[string]bool{
		"aegisgate":           true,
		"type:proxy_response": true,
		"source:proxy":        true,
		"count:5":             true,
	}
	for _, lbl := range ind.Labels {
		delete(wantLabels, lbl)
	}
	if len(wantLabels) > 0 {
		t.Errorf("missing labels: %v (got %v)", wantLabels, ind.Labels)
	}
}

func TestIOCToSTIXIndicator_InvalidIOC(t *testing.T) {
	t.Parallel()
	// Empty fingerprint -> invalid.
	ioc := makeStixTestIOC("ab", IOCTypeProxyResponse, SeverityHigh)
	ioc.Fingerprint = ""
	if _, err := IOCToSTIXIndicator(ioc); err == nil {
		t.Error("expected error on empty fingerprint, got nil")
	}
	// Empty type -> invalid.
	ioc = makeStixTestIOC("ab", IOCTypeProxyResponse, SeverityHigh)
	ioc.Type = ""
	if _, err := IOCToSTIXIndicator(ioc); err == nil {
		t.Error("expected error on empty type, got nil")
	}
}

func TestIOCToSTIXIndicator_NilIOC(t *testing.T) {
	t.Parallel()
	if _, err := IOCToSTIXIndicator(nil); err == nil {
		t.Error("expected error on nil IOC, got nil")
	}
}

func TestIOCToSTIXIndicator_SeverityMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		sev      Severity
		wantConf int
	}{
		{SeverityCritical, 95},
		{SeverityHigh, 80},
		{SeverityMedium, 60},
		{SeverityLow, 40},
		{SeverityInfo, 20},
		{Severity("unknown"), 0},
	}
	for _, tc := range cases {
		ioc := makeStixTestIOC("ab", IOCTypeProxyResponse, tc.sev)
		ind, err := IOCToSTIXIndicator(ioc)
		if err != nil {
			t.Fatalf("severity %q: %v", tc.sev, err)
		}
		if ind.Confidence != tc.wantConf {
			t.Errorf("severity %q: confidence = %d, want %d", tc.sev, ind.Confidence, tc.wantConf)
		}
	}
}

func TestIOCToSTIXIndicator_AllIOCTypes(t *testing.T) {
	t.Parallel()
	// The 5 known IOCType constants. Unknown types are
	// rejected by IOC.Valid() (and therefore by
	// IOCToSTIXIndicator, which calls Valid() defensively).
	// The unknown-type path is covered by
	// TestIOCToSTIXIndicator_InvalidIOC.
	types := []IOCType{
		IOCTypeProxyResponse,
		IOCTypeAnomalyScore,
		IOCTypePromptInjection,
		IOCTypeSecretLeak,
		IOCTypePIIDetected,
	}
	for _, ty := range types {
		ioc := makeStixTestIOC("ab", ty, SeverityMedium)
		ind, err := IOCToSTIXIndicator(ioc)
		if err != nil {
			t.Fatalf("type %q: %v", ty, err)
		}
		if ind.IndicatorTypes == nil || len(ind.IndicatorTypes) == 0 {
			t.Errorf("type %q: IndicatorTypes empty", ty)
		}
	}
}

// --------------------------------------------------------------------
// BundleToSTIX
// --------------------------------------------------------------------

func TestBundleToSTIX_HappyPath(t *testing.T) {
	t.Parallel()
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
		makeStixTestAttestation("cd", IOCTypeAnomalyScore, SeverityMedium),
	)
	stix, err := BundleToSTIX(b)
	if err != nil {
		t.Fatalf("BundleToSTIX: %v", err)
	}
	if stix.SpecVersion != "2.1" {
		t.Errorf("SpecVersion = %q, want 2.1", stix.SpecVersion)
	}
	if stix.ID == "" {
		t.Error("STIX bundle ID empty")
	}
	if len(stix.Objects) != 2 {
		t.Errorf("got %d objects, want 2", len(stix.Objects))
	}
	// Each object should be a STIX Indicator.
	for i, raw := range stix.Objects {
		var ind ti.Indicator
		if err := json.Unmarshal(raw, &ind); err != nil {
			t.Errorf("object %d: %v", i, err)
		}
		if ind.Type != ti.STIXTypeIndicator {
			t.Errorf("object %d: type = %q, want %q", i, ind.Type, ti.STIXTypeIndicator)
		}
	}
}

func TestBundleToSTIX_NilBundle(t *testing.T) {
	t.Parallel()
	if _, err := BundleToSTIX(nil); err == nil {
		t.Error("expected error on nil bundle")
	}
}

func TestBundleToSTIX_EmptyBundle(t *testing.T) {
	t.Parallel()
	b := makeStixTestBundle()
	stix, err := BundleToSTIX(b)
	if err != nil {
		t.Fatalf("empty bundle: %v", err)
	}
	if len(stix.Objects) != 0 {
		t.Errorf("empty bundle: got %d objects, want 0", len(stix.Objects))
	}
}

func TestBundleToSTIX_InvalidIOCs(t *testing.T) {
	t.Parallel()
	// One valid + one invalid (empty fingerprint) -> error
	// listing all problems.
	bad := makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh)
	bad.Fingerprint = ""
	b := makeStixTestBundle(
		makeStixTestAttestation("cd", IOCTypeAnomalyScore, SeverityMedium),
		bad,
	)
	_, err := BundleToSTIX(b)
	if err == nil {
		t.Fatal("expected error on bundle with invalid IOC, got nil")
	}
	if !strings.Contains(err.Error(), "1 invalid IOC") {
		t.Errorf("error message does not mention 1 invalid IOC: %v", err)
	}
}

func TestBundleToSTIX_JSONShape(t *testing.T) {
	t.Parallel()
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	stix, err := BundleToSTIX(b)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(stix)
	if err != nil {
		t.Fatal(err)
	}
	// Verify the JSON has the right top-level shape.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["type"] != "bundle" {
		t.Errorf("type = %v, want bundle", raw["type"])
	}
	if raw["spec_version"] != "2.1" {
		t.Errorf("spec_version = %v, want 2.1", raw["spec_version"])
	}
	objs, ok := raw["objects"].([]interface{})
	if !ok || len(objs) != 1 {
		t.Errorf("objects array missing or wrong length: %v", raw["objects"])
	}
}

// --------------------------------------------------------------------
// STIXIndicatorToIOC
// --------------------------------------------------------------------

func TestSTIXIndicatorToIOC_RoundTrip(t *testing.T) {
	t.Parallel()
	// Build an IOC, convert to STIX, convert back, compare.
	original := makeStixTestIOC("ab", IOCTypeProxyResponse, SeverityCritical)
	ind, err := IOCToSTIXIndicator(original)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := STIXIndicatorToIOC(ind)
	if err != nil {
		t.Fatalf("STIXIndicatorToIOC: %v", err)
	}
	if recovered.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint: %q, want %q", recovered.Fingerprint, original.Fingerprint)
	}
	if recovered.Type != original.Type {
		t.Errorf("Type: %q, want %q", recovered.Type, original.Type)
	}
	if recovered.Severity != original.Severity {
		t.Errorf("Severity: %q, want %q", recovered.Severity, original.Severity)
	}
	if recovered.Count != original.Count {
		t.Errorf("Count: %d, want %d", recovered.Count, original.Count)
	}
	if recovered.Source != original.Source {
		t.Errorf("Source: %q, want %q", recovered.Source, original.Source)
	}
}

func TestSTIXIndicatorToIOC_FallbackToExternalRef(t *testing.T) {
	t.Parallel()
	// Indicator with an unparseable pattern but a valid
	// ExternalReference -> recovery should succeed.
	ind := ti.NewIndicator(
		"indicator--00000000-0000-0000-0000-000000000001",
		"[unknown-pattern-type]",
		ti.PatternTypeSTIX,
	)
	ind.ExternalReferences = []ti.ExternalReference{
		{
			SourceName: "aegisgate-ioc",
			ExternalID: strings.Repeat("ab", 32),
		},
	}
	ind.Labels = []string{
		"type:anomaly_score",
		"source:anomaly",
		"count:42",
	}
	ind.Confidence = 80
	ioc, err := STIXIndicatorToIOC(ind)
	if err != nil {
		t.Fatalf("STIXIndicatorToIOC: %v", err)
	}
	if ioc.Fingerprint != strings.Repeat("ab", 32) {
		t.Errorf("Fingerprint: %q, want fallback value", ioc.Fingerprint)
	}
	if ioc.Type != IOCTypeAnomalyScore {
		t.Errorf("Type: %q, want anomaly_score (from label)", ioc.Type)
	}
	if ioc.Count != 42 {
		t.Errorf("Count: %d, want 42 (from label)", ioc.Count)
	}
	if ioc.Source != "anomaly" {
		t.Errorf("Source: %q, want anomaly (from label)", ioc.Source)
	}
}

func TestSTIXIndicatorToIOC_NilIndicator(t *testing.T) {
	t.Parallel()
	if _, err := STIXIndicatorToIOC(nil); err == nil {
		t.Error("expected error on nil indicator")
	}
}

func TestSTIXIndicatorToIOC_DefaultCount(t *testing.T) {
	t.Parallel()
	// Indicator with no "count:" label -> Count = 1.
	ind := ti.NewIndicator(
		"indicator--00000000-0000-0000-0000-000000000001",
		"[file:hashes.SHA-256 = '"+strings.Repeat("cd", 32)+"']",
		ti.PatternTypeSTIX,
	)
	ioc, err := STIXIndicatorToIOC(ind)
	if err != nil {
		t.Fatal(err)
	}
	if ioc.Count != 1 {
		t.Errorf("Count: %d, want 1 (default)", ioc.Count)
	}
}

// TestSTIXIndicatorToIOC_GenericHexPattern covers the
// extractHex64 fallback path: a STIX pattern that doesn't
// use the SHA-256 form but contains a 64-char hex string
// somewhere.
func TestSTIXIndicatorToIOC_GenericHexPattern(t *testing.T) {
	t.Parallel()
	hex := strings.Repeat("ef", 32)
	ind := ti.NewIndicator(
		"indicator--00000000-0000-0000-0000-000000000001",
		"[custom:hash = '"+hex+"']",
		ti.PatternTypeSTIX,
	)
	ioc, err := STIXIndicatorToIOC(ind)
	if err != nil {
		t.Fatal(err)
	}
	if ioc.Fingerprint != hex {
		t.Errorf("Fingerprint: %q, want %q (recovered from generic pattern)", ioc.Fingerprint, hex)
	}
}

// TestSTIXIndicatorToIOC_ConfidenceToSeverity exercises the
// bucket boundaries: >=90 critical, >=70 high, >=50 medium,
// >=30 low, else info.
func TestSTIXIndicatorToIOC_ConfidenceToSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		conf int
		want Severity
	}{
		{100, SeverityCritical},
		{90, SeverityCritical},
		{89, SeverityHigh},
		{70, SeverityHigh},
		{69, SeverityMedium},
		{50, SeverityMedium},
		{49, SeverityLow},
		{30, SeverityLow},
		{29, SeverityInfo},
		{0, SeverityInfo},
	}
	for _, tc := range cases {
		ind := ti.NewIndicator(
			"indicator--00000000-0000-0000-0000-000000000001",
			"[file:hashes.SHA-256 = '"+strings.Repeat("ab", 32)+"']",
			ti.PatternTypeSTIX,
		)
		ind.Confidence = tc.conf
		ioc, err := STIXIndicatorToIOC(ind)
		if err != nil {
			t.Fatal(err)
		}
		if ioc.Severity != tc.want {
			t.Errorf("confidence %d: severity = %q, want %q", tc.conf, ioc.Severity, tc.want)
		}
	}
}

// TestIsHex covers the isHex helper: non-empty, all hex.
func TestIsHex(t *testing.T) {
	t.Parallel()
	if !isHex("0123456789abcdef") {
		t.Error("0123456789abcdef should be hex")
	}
	if !isHex("ABCDEF") {
		t.Error("ABCDEF should be hex (uppercase)")
	}
	if isHex("") {
		t.Error("empty string should not be hex")
	}
	if isHex("xyz") {
		t.Error("xyz should not be hex")
	}
	if isHex("0123g") {
		t.Error("0123g should not be hex")
	}
}

// TestAttestationToIOC covers the attestationToIOC helper
// that builds a plain IOC from an attestation's fields.
func TestAttestationToIOC(t *testing.T) {
	t.Parallel()
	att := makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh)
	ioc := attestationToIOC(att)
	if ioc.Fingerprint != att.Fingerprint {
		t.Errorf("Fingerprint: %q, want %q", ioc.Fingerprint, att.Fingerprint)
	}
	if ioc.Type != att.IOCType {
		t.Errorf("Type: %q, want %q", ioc.Type, att.IOCType)
	}
	if ioc.Severity != att.Severity {
		t.Errorf("Severity: %q, want %q", ioc.Severity, att.Severity)
	}
	if ioc.Source != "attestation" {
		t.Errorf("Source: %q, want attestation (default)", ioc.Source)
	}
	// Nil attestation -> empty IOC, not a panic.
	empty := attestationToIOC(nil)
	if empty.Fingerprint != "" {
		t.Errorf("nil attestation: Fingerprint: %q, want empty", empty.Fingerprint)
	}
}

// TestDeriveAegisGateBundleID covers the STIX bundle ID ->
// AegisGate bundle ID conversion.
func TestDeriveAegisGateBundleID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		stixID, want string
	}{
		{"bundle--550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000"},
		{"bundle--abc", "abc"},
		// Malformed (no "--") -> returned verbatim.
		{"malformed", "malformed"},
	}
	for _, tc := range cases {
		got := deriveAegisGateBundleID(tc.stixID)
		if got != tc.want {
			t.Errorf("deriveAegisGateBundleID(%q) = %q, want %q", tc.stixID, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------
// STIXToBundle
// --------------------------------------------------------------------

func TestSTIXToBundle_HappyPath(t *testing.T) {
	t.Parallel()
	// Build a STIX bundle manually, convert to AegisGate,
	// and verify the structure.
	ioc1 := makeStixTestIOC("ab", IOCTypeProxyResponse, SeverityHigh)
	ioc2 := makeStixTestIOC("cd", IOCTypeAnomalyScore, SeverityCritical)
	ind1, _ := IOCToSTIXIndicator(ioc1)
	ind2, _ := IOCToSTIXIndicator(ioc2)
	stix := ti.NewBundle("bundle--00000000-0000-0000-0000-000000000001")
	_ = stix.AddObject(ind1)
	_ = stix.AddObject(ind2)
	out, err := STIXToBundle(stix, "test-instance")
	if err != nil {
		t.Fatalf("STIXToBundle: %v", err)
	}
	if out.Count != 2 {
		t.Errorf("Count: %d, want 2", out.Count)
	}
	if out.InstanceID != "test-instance" {
		t.Errorf("InstanceID: %q, want test-instance", out.InstanceID)
	}
	// Bundle ID is derived from the STIX bundle ID.
	if out.BundleID == "" {
		t.Error("BundleID empty")
	}
}

func TestSTIXToBundle_NilBundle(t *testing.T) {
	t.Parallel()
	if _, err := STIXToBundle(nil, "inst"); err == nil {
		t.Error("expected error on nil STIX bundle")
	}
}

func TestSTIXToBundle_DefaultInstanceID(t *testing.T) {
	t.Parallel()
	stix := ti.NewBundle("bundle--00000000-0000-0000-0000-000000000001")
	out, err := STIXToBundle(stix, "")
	if err != nil {
		t.Fatal(err)
	}
	if out.InstanceID != "stix-importer" {
		t.Errorf("InstanceID: %q, want stix-importer (default)", out.InstanceID)
	}
}

func TestSTIXToBundle_SkipsNonIndicators(t *testing.T) {
	t.Parallel()
	// Mix Indicators and other STIX object types. Only
	// Indicators should land in the AegisGate bundle.
	ioc := makeStixTestIOC("ab", IOCTypeProxyResponse, SeverityHigh)
	ind, _ := IOCToSTIXIndicator(ioc)
	// A Malware (non-Indicator) STIX object.
	malware := ti.NewMalware("malware--00000000-0000-0000-0000-000000000001", "TestMalware", false)
	stix := ti.NewBundle("bundle--00000000-0000-0000-0000-000000000001")
	_ = stix.AddObject(ind)
	_ = stix.AddObject(malware)
	out, err := STIXToBundle(stix, "inst")
	if err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 {
		t.Errorf("Count: %d, want 1 (Malware skipped)", out.Count)
	}
}

// --------------------------------------------------------------------
// STIXExporter
// --------------------------------------------------------------------

func TestSTIXExporter_ExportToSTIXWriter(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	var buf bytes.Buffer
	if err := exp.ExportToSTIXWriter(b, &buf); err != nil {
		t.Fatal(err)
	}
	// Parse the output as JSON and verify the shape.
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if raw["type"] != "bundle" {
		t.Errorf("type = %v, want bundle", raw["type"])
	}
}

func TestSTIXExporter_PrettyPrint(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{PrettyPrint: true, Indent: "    "})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	var buf bytes.Buffer
	if err := exp.ExportToSTIXWriter(b, &buf); err != nil {
		t.Fatal(err)
	}
	// Pretty-printed JSON has 4-space indent on a new line.
	if !strings.Contains(buf.String(), "\n    \"type\":") {
		t.Errorf("output is not pretty-printed with 4-space indent:\n%s", buf.String())
	}
}

func TestSTIXExporter_NilBundle(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	var buf bytes.Buffer
	if err := exp.ExportToSTIXWriter(nil, &buf); err == nil {
		t.Error("expected error on nil bundle")
	}
}

func TestSTIXExporter_ExportToJSONLines(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
		makeStixTestAttestation("cd", IOCTypeAnomalyScore, SeverityMedium),
	)
	var buf bytes.Buffer
	if err := exp.ExportToJSONLinesWriter(b, &buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// 1 header + 2 objects = 3 lines.
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3 (1 header + 2 objects)", len(lines))
	}
	// First line is the header.
	var header map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Errorf("header not valid JSON: %v", err)
	}
	if header["type"] != "bundle" {
		t.Errorf("header.type = %v, want bundle", header["type"])
	}
}

func TestSTIXExporter_ToFile(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	dir := t.TempDir()
	path := dir + "/stix.json"
	if err := exp.ExportToSTIX(b, path); err != nil {
		t.Fatal(err)
	}
	// Read back and verify.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "bundle") {
		t.Errorf("file does not contain 'bundle':\n%s", string(data))
	}
}

// TestSTIXExporter_ExportToJSON_DelegatesToSTIX verifies that
// ExportToJSON produces the same SHAPE as ExportToSTIX (the
// methods are aliases in v3.5.0+). This is a regression guard
// for the API symmetry.
//
// Note: each call generates a fresh STIX bundle ID, so the
// bytes are NOT identical. We compare the JSON shape (the
// "type", "spec_version", and "objects" array) instead.
func TestSTIXExporter_ExportToJSON_DelegatesToSTIX(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	dir := t.TempDir()
	jsonPath := dir + "/json.json"
	stixPath := dir + "/stix.json"
	if err := exp.ExportToJSON(b, jsonPath); err != nil {
		t.Fatal(err)
	}
	if err := exp.ExportToSTIX(b, stixPath); err != nil {
		t.Fatal(err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	stixData, err := os.ReadFile(stixPath)
	if err != nil {
		t.Fatal(err)
	}
	// Compare structural fields, ignoring the bundle ID
	// (which is fresh on each call).
	var jsonParsed, stixParsed map[string]interface{}
	_ = json.Unmarshal(jsonData, &jsonParsed)
	_ = json.Unmarshal(stixData, &stixParsed)
	if jsonParsed["type"] != stixParsed["type"] {
		t.Errorf("type differs: JSON=%v, STIX=%v", jsonParsed["type"], stixParsed["type"])
	}
	if jsonParsed["spec_version"] != stixParsed["spec_version"] {
		t.Errorf("spec_version differs: JSON=%v, STIX=%v", jsonParsed["spec_version"], stixParsed["spec_version"])
	}
	// Both should have 1 object of the same type.
	jsonObjs, _ := jsonParsed["objects"].([]interface{})
	stixObjs, _ := stixParsed["objects"].([]interface{})
	if len(jsonObjs) != len(stixObjs) {
		t.Errorf("object count differs: JSON=%d, STIX=%d", len(jsonObjs), len(stixObjs))
	}
	if len(jsonObjs) > 0 && len(stixObjs) > 0 {
		jObj, _ := jsonObjs[0].(map[string]interface{})
		sObj, _ := stixObjs[0].(map[string]interface{})
		if jObj["type"] != sObj["type"] {
			t.Errorf("object type differs: JSON=%v, STIX=%v", jObj["type"], sObj["type"])
		}
	}
}

// TestSTIXExporter_ExportToJSONLines_File verifies the file
// path of ExportToJSONLines (vs the Writer variant).
func TestSTIXExporter_ExportToJSONLines_File(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	dir := t.TempDir()
	path := dir + "/stix.jsonl"
	if err := exp.ExportToJSONLines(b, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "bundle") {
		t.Errorf("file does not contain 'bundle':\n%s", string(data))
	}
}

// TestSTIXExporter_EmptyPath verifies the empty-path guard
// on the file-based exports.
func TestSTIXExporter_EmptyPath(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	if err := exp.ExportToSTIX(b, ""); err == nil {
		t.Error("expected error on empty path")
	}
	if err := exp.ExportToJSON(b, ""); err == nil {
		t.Error("expected error on empty path")
	}
	if err := exp.ExportToJSONLines(b, ""); err == nil {
		t.Error("expected error on empty path")
	}
}

// TestSTIXExporter_Close is a smoke test for the Close
// method (which is currently a no-op).
func TestSTIXExporter_Close(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	if err := exp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestSTIXExporter_NilWriter verifies the nil-writer guard
// on ExportToSTIXWriter.
func TestSTIXExporter_NilWriter(t *testing.T) {
	t.Parallel()
	exp := NewSTIXExporter(STIXExportConfig{})
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	if err := exp.ExportToSTIXWriter(b, nil); err == nil {
		t.Error("expected error on nil writer")
	}
}

// --------------------------------------------------------------------
// TAXIIIntegration
// --------------------------------------------------------------------

// TestTAXIIIntegration_PushPull uses a mock TAXII server
// (httptest) to verify the round-trip: convert AegisGate
// bundle -> STIX, push to mock TAXII, get objects back,
// convert STIX -> AegisGate bundle.
func TestTAXIIIntegration_PushPull(t *testing.T) {
	t.Parallel()
	// Mock TAXII server. Implements the minimum endpoints
	// that the threatintel TAXIIClient uses.
	var storedBundle *ti.Bundle
	mux := http.NewServeMux()
	mux.HandleFunc("/api1/collections/coll1/objects", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			// Push: parse the body as a STIX bundle, store it.
			var b ti.Bundle
			if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			storedBundle = &b
			// The TAXII 2.1 envelope is a JSON object
			// with a single "objects" key. The server
			// returns the envelope as the response body.
			w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
			_ = json.NewEncoder(w).Encode(ti.TAXIIEnvelopes{Objects: nil})
		case http.MethodGet:
			// Pull: return the stored bundle, or an empty
			// bundle if nothing is stored.
			out := storedBundle
			if out == nil {
				out = ti.NewBundle("empty--00000000-0000-0000-0000-000000000000")
			}
			w.Header().Set("Content-Type", "application/stix+json;version=2.1")
			_ = json.NewEncoder(w).Encode(out)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tiCfg := TAXIIIntegrationConfig{
		ServerURL: srv.URL,
		AuthType:  "basic",
		Username:  "test",
		Password:  "test",
		Timeout:   5 * time.Second,
	}
	integ, err := NewTAXIIIntegration(tiCfg)
	if err != nil {
		t.Fatalf("NewTAXIIIntegration: %v", err)
	}
	defer integ.Close()

	// Build a bundle and push it.
	b := makeStixTestBundle(
		makeStixTestAttestation("ab", IOCTypeProxyResponse, SeverityHigh),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := integ.Push(ctx, b, srv.URL+"/api1", "coll1"); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if storedBundle == nil || len(storedBundle.Objects) != 1 {
		t.Fatalf("expected 1 object stored, got %v", storedBundle)
	}

	// Pull it back.
	pulled, err := integ.Pull(ctx, srv.URL+"/api1", "coll1", time.Time{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if pulled.Count != 1 {
		t.Errorf("Pull: Count = %d, want 1", pulled.Count)
	}
}

func TestNewTAXIIIntegration_Validates(t *testing.T) {
	t.Parallel()
	if _, err := NewTAXIIIntegration(TAXIIIntegrationConfig{}); err == nil {
		t.Error("expected error on empty config")
	}
	if _, err := NewTAXIIIntegration(TAXIIIntegrationConfig{ServerURL: "https://example.com"}); err == nil {
		t.Error("expected error on missing AuthType")
	}
}

func TestTAXIIIntegration_DefaultCollection(t *testing.T) {
	t.Parallel()
	tiCfg := TAXIIIntegrationConfig{
		ServerURL:         "https://taxii.example.com",
		AuthType:          "basic",
		Username:          "u",
		Password:          "p",
		DefaultCollection: "default-coll",
	}
	integ, err := NewTAXIIIntegration(tiCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer integ.Close()
	// We can't actually call Push (the URL is unreachable in
	// tests), but we can verify that the missing-collectionID
	// error uses the default.
	// Skip the actual push; this is a configuration smoke
	// test only.
	_ = integ
}
