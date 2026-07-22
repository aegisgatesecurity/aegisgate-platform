// SPDX-License-Identifier: Apache-2.0
// Compliance Report Generator - Unit Tests

package mapping

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateReport_AllFrameworks(t *testing.T) {
	report := GenerateReport(nil)
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt should be set")
	}
	if len(report.FrameworksEnabled) < 10 {
		t.Errorf("FrameworksEnabled = %d, want at least 10", len(report.FrameworksEnabled))
	}
	if len(report.FrameworkReports) != len(report.FrameworksEnabled) {
		t.Errorf("FrameworkReports count %d != FrameworksEnabled count %d",
			len(report.FrameworkReports), len(report.FrameworksEnabled))
	}
}

func TestGenerateReport_SpecificFrameworks(t *testing.T) {
	enabled := []string{"soc2", "hipaa", "iso27001"}
	report := GenerateReport(enabled)
	if len(report.FrameworksEnabled) != 3 {
		t.Errorf("FrameworksEnabled = %d, want 3", len(report.FrameworksEnabled))
	}
	// GenerateReport sorts the frameworks internally for stable output.
	// The first one after sort should be "hipaa" (alphabetical first).
	if report.FrameworkReports[0].Framework != "hipaa" {
		t.Errorf("First framework = %q, want hipaa (alphabetical first)", report.FrameworkReports[0].Framework)
	}
	// Verify all 3 are present
	have := make(map[string]bool)
	for _, fr := range report.FrameworkReports {
		have[fr.Framework] = true
	}
	for _, want := range []string{"soc2", "hipaa", "iso27001"} {
		if !have[want] {
			t.Errorf("Missing framework %q in report", want)
		}
	}
}

func TestFrameworkReport_CoveragePct(t *testing.T) {
	report := GenerateReport([]string{"soc2", "hipaa"})
	for _, fr := range report.FrameworkReports {
		if fr.CoveragePct < 0 || fr.CoveragePct > 100 {
			t.Errorf("Framework %s coverage %.1f%% out of range [0, 100]",
				fr.Framework, fr.CoveragePct)
		}
	}
}

func TestFrameworkReport_ControlResultsSorted(t *testing.T) {
	report := GenerateReport([]string{"soc2"})
	if len(report.FrameworkReports) == 0 {
		t.Fatal("no framework reports")
	}
	fr := report.FrameworkReports[0]
	if len(fr.ControlResults) < 2 {
		t.Skip("not enough controls to test sort")
	}
	for i := 1; i < len(fr.ControlResults); i++ {
		if fr.ControlResults[i-1].ControlID > fr.ControlResults[i].ControlID {
			t.Errorf("ControlResults not sorted: %q > %q",
				fr.ControlResults[i-1].ControlID, fr.ControlResults[i].ControlID)
		}
	}
}

func TestFormatMarkdown_ContainsAllSections(t *testing.T) {
	report := GenerateReport([]string{"soc2", "hipaa", "iso27001"})
	md := report.FormatMarkdown()

	requiredSections := []string{
		"AegisGate Multi-Framework Compliance Report",
		"Executive Summary",
		"Cross-Framework Control Matrix",
		"Appendix: How to Use This Report",
		"SOC 2",
		"HIPAA",
		"ISO 27001",
		"AegisGate Controls",
		"covered",
		"manual",
	}
	for _, section := range requiredSections {
		if !strings.Contains(md, section) {
			t.Errorf("FormatMarkdown() missing section: %q", section)
		}
	}
}

func TestFormatMarkdown_HighLeverageControls(t *testing.T) {
	report := GenerateReport([]string{"soc2", "hipaa", "iso27001", "pci", "nist_csf"})
	md := report.FormatMarkdown()
	// The high-leverage control "AG-AUTH-RBAC-MFA" should appear
	// (it maps to SOC 2, ISO 27001, HIPAA, PCI, NIST CSF)
	if !strings.Contains(md, "AG-AUTH-RBAC-MFA") {
		t.Error("FormatMarkdown() missing high-leverage control AG-AUTH-RBAC-MFA")
	}
}

func TestFormatMarkdown_Deterministic(t *testing.T) {
	// Two reports with the same inputs should produce the same output
	// (within the timestamp tolerance)
	report1 := GenerateReport([]string{"soc2", "hipaa"})
	report2 := GenerateReport([]string{"soc2", "hipaa"})

	// Strip the timestamp line (which is the only non-deterministic part)
	stripTimestamp := func(md string) string {
		lines := strings.Split(md, "\n")
		var out []string
		for _, l := range lines {
			if strings.HasPrefix(l, "**Generated:**") {
				continue
			}
			out = append(out, l)
		}
		return strings.Join(out, "\n")
	}

	md1 := stripTimestamp(report1.FormatMarkdown())
	md2 := stripTimestamp(report2.FormatMarkdown())
	if md1 != md2 {
		t.Errorf("FormatMarkdown() is not deterministic (ignoring timestamp)")
	}
}

func TestFormatMarkdown_AllFrameworks(t *testing.T) {
	// Generate a report with ALL frameworks and verify it doesn't panic
	report := GenerateReport(nil)
	md := report.FormatMarkdown()
	if len(md) < 1000 {
		t.Errorf("FormatMarkdown() output too short (%d chars), expected a real report", len(md))
	}
	_ = time.Now() // suppress unused import
}
