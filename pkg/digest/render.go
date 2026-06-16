// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - CISO Digest PDF renderer + signer (TODO-601)
//
// render.go is the consumer: it renders a Digest to
// a PDF and (optionally) signs it with the envelope.
//
// The PDF is the user-facing artifact: the CISO
// hands it to auditors, boards, and customers.
// The envelope signature provides tamper-evidence
// and third-party verifiability.
//
// v0.1 PDF layout (3 sections):
//  1. Cover page: title + period + generated_at +
//     overall status
//  2. IOCs blocked: total + by-category + by-
//     framework + by-protocol
//  3. Anomalies + posture: anomaly count + posture
//     summary + regulator mappings
//
// v0.1 does NOT support:
//   - Images / charts / graphs
//   - Per-customer branding (AegisGate logo only)
//   - Multi-language digests (English only)

package digest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/pdf"
)

// RenderDigestPDF renders a Digest to PDF bytes.
// The PDF is self-contained and can be written to
// a file, sent over HTTP, or signed with SignDigest.
//
// Errors:
//   - digest is nil
//   - digest.Validate() fails
//   - the PDF renderer fails (rare; v0.1 is very
//     permissive)
func RenderDigestPDF(digest *Digest) ([]byte, error) {
	if digest == nil {
		return nil, fmt.Errorf("digest: digest is nil")
	}
	if err := digest.Validate(); err != nil {
		return nil, fmt.Errorf("digest: validate: %w", err)
	}
	// Build the PDF sections.
	sections := buildPDFSections(digest)
	// Render.
	req := &pdf.RenderRequest{
		Title:       digest.Title,
		Author:      "AegisGate Platform",
		Subject:     string(digest.Period),
		Keywords:    "aegisgate, ciso, posture, digest",
		Footer:      fmt.Sprintf("Generated %s -- AegisGate Posture Digest", time.Now().UTC().Format("2006-01-02 15:04 UTC")),
		GeneratedAt: digest.GeneratedAt,
		Sections:    sections,
	}
	return pdf.RenderReport(req)
}

// buildPDFSections converts a Digest into a slice
// of PDF sections. The layout is:
//
// 1. Cover page (title + period + overall status)
// 2. IOCs blocked (total + breakdowns)
// 3. Anomalies + posture (anomaly count + posture summary)
// 4. Regulator mappings (table)
func buildPDFSections(d *Digest) []pdf.Section {
	var sections []pdf.Section
	// 1. Cover page (heading + period + status).
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionHeading,
		Text: fmt.Sprintf("Period: %s", d.Period),
	})
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf("From: %s", d.StartTime.Format(time.RFC3339)),
	})
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf("To:   %s", d.EndTime.Format(time.RFC3339)),
	})
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf("Generated: %s", d.GeneratedAt.Format(time.RFC3339)),
	})
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionParagraph,
		Text: fmt.Sprintf("Overall status: %s", d.OverallStatus),
	})
	// Page break before the IOCs section.
	sections = append(sections, pdf.Section{Kind: pdf.SectionPageBreak})
	// 2. IOCs blocked.
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionHeading,
		Text: "IOCs Blocked",
	})
	if d.IOCsBlocked != nil {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: fmt.Sprintf("Total: %d IOCs blocked during the period.", d.IOCsBlocked.Total),
		})
		if len(d.IOCsBlocked.ByCategory) > 0 {
			sections = append(sections, pdf.Section{
				Kind:  pdf.SectionTable,
				Table: pdf.Table{Rows: mapToTable(d.IOCsBlocked.ByCategory, "Category", "Count")},
			})
		}
		if len(d.IOCsBlocked.ByFramework) > 0 {
			sections = append(sections, pdf.Section{
				Kind:  pdf.SectionTable,
				Table: pdf.Table{Rows: mapToTable(d.IOCsBlocked.ByFramework, "Framework", "Count")},
			})
		}
		if len(d.IOCsBlocked.ByProtocol) > 0 {
			sections = append(sections, pdf.Section{
				Kind:  pdf.SectionTable,
				Table: pdf.Table{Rows: mapToTable(d.IOCsBlocked.ByProtocol, "Protocol", "Count")},
			})
		}
	} else {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: "No IOC data available.",
		})
	}
	// Page break before anomalies.
	sections = append(sections, pdf.Section{Kind: pdf.SectionPageBreak})
	// 3. Anomalies + posture.
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionHeading,
		Text: "Anomalies Detected",
	})
	if d.AnomaliesDetected != nil {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: fmt.Sprintf("Total: %d anomalies detected during the period.", d.AnomaliesDetected.Total),
		})
		if len(d.AnomaliesDetected.ByProtocol) > 0 {
			sections = append(sections, pdf.Section{
				Kind:  pdf.SectionTable,
				Table: pdf.Table{Rows: mapToTable(d.AnomaliesDetected.ByProtocol, "Protocol", "Count")},
			})
		}
		if len(d.AnomaliesDetected.BySeverity) > 0 {
			sections = append(sections, pdf.Section{
				Kind:  pdf.SectionTable,
				Table: pdf.Table{Rows: mapToTable(d.AnomaliesDetected.BySeverity, "Severity", "Count")},
			})
		}
	} else {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: "No anomaly data available.",
		})
	}
	// 4. Posture.
	sections = append(sections, pdf.Section{
		Kind: pdf.SectionHeading,
		Text: "Compliance Posture",
	})
	if d.Posture != nil {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: fmt.Sprintf("Overall: %s", d.Posture.Overall),
		})
		if d.Posture.Uptime != "" {
			sections = append(sections, pdf.Section{
				Kind: pdf.SectionParagraph,
				Text: fmt.Sprintf("Uptime: %s", d.Posture.Uptime),
			})
		}
		if len(d.Posture.ComplianceFrameworks) > 0 {
			rows := [][]string{{"Framework", "Display Name", "Enforced", "Has Implementation"}}
			for _, fw := range d.Posture.ComplianceFrameworks {
				rows = append(rows, []string{
					fw.Framework,
					fw.DisplayName,
					boolToYesNo(fw.Enforced),
					boolToYesNo(fw.HasImplementation),
				})
			}
			sections = append(sections, pdf.Section{
				Kind:  pdf.SectionTable,
				Table: pdf.Table{Rows: rows},
			})
		}
	} else {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionParagraph,
			Text: "No posture data available.",
		})
	}
	// 5. Regulator mappings.
	if len(d.RegulatorMappings) > 0 {
		sections = append(sections, pdf.Section{
			Kind: pdf.SectionHeading,
			Text: "Regulator Mappings",
		})
		rows := [][]string{{"Framework", "Control ID", "Control Name", "AegisGate Feature"}}
		for _, rm := range d.RegulatorMappings {
			rows = append(rows, []string{
				rm.Framework,
				rm.ControlID,
				rm.ControlName,
				rm.AegisGateFeature,
			})
		}
		sections = append(sections, pdf.Section{
			Kind:  pdf.SectionTable,
			Table: pdf.Table{Rows: rows},
		})
	}
	return sections
}

// mapToTable converts a map[string]int to a 2-column
// table with the given headers. The output is
// sorted by key for determinism.
func mapToTable(m map[string]int, header1, header2 string) [][]string {
	rows := [][]string{{header1, header2}}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple insertion sort.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	for _, k := range keys {
		rows = append(rows, []string{k, fmt.Sprintf("%d", m[k])})
	}
	return rows
}

// boolToYesNo converts a bool to "Yes" or "No" for
// PDF display.
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// =====================================================================
// SignDigest (uses the envelope primitive)
// =====================================================================

// SignDigest signs a Digest with the envelope
// primitive. The envelope's payload is a JSON
// structure that includes both the Digest metadata
// and the rendered PDF bytes (base64-encoded by
// encoding/json's default []byte handling). The
// subject is "aegisgate://digest/<id>".
//
// Errors:
//   - digest is nil
//   - digest.Validate() fails
//   - the PDF renderer fails
//   - the envelope Sign fails
func SignDigest(d *Digest, kr *ioc.KeyRing) (*attestation.Envelope, error) {
	if d == nil {
		return nil, fmt.Errorf("digest: digest is nil")
	}
	if kr == nil {
		return nil, fmt.Errorf("digest: keyring is required")
	}
	// Render the PDF.
	pdfBytes, err := RenderDigestPDF(d)
	if err != nil {
		return nil, fmt.Errorf("digest: render PDF: %w", err)
	}
	// Sign with the envelope. The PDF is the
	// payload (JSON-encoded for compatibility with
	// the envelope's JSON requirement); the
	// rendered PDF bytes go in a side-channel
	// (the envelope is for the metadata; the PDF
	// is a separate artifact).
	//
	// Actually, since the envelope's payload must
	// be JSON, we wrap the PDF in a JSON structure
	// that includes both the PDF bytes (base64-
	// encoded) and the Digest metadata.
	wrapped := map[string]interface{}{
		"digest":    d,
		"pdf_bytes": pdfBytes, // not base64; envelope's payload is JSON
	}
	// The envelope's Sign function requires JSON
	// payload. We need to base64-encode the PDF
	// bytes to make them JSON-safe.
	// Actually, []byte is JSON-marshalable as
	// base64-encoded string by Go's encoding/json.
	// So this works.
	payloadBytes, err := json.Marshal(wrapped)
	if err != nil {
		return nil, fmt.Errorf("digest: marshal payload: %w", err)
	}
	// Sign. TTL=0 means no expiration (CVE-style
	// immutability; the digest is a permanent
	// record).
	env, err := attestation.Sign(
		payloadBytes,
		"aegisgate://digest/"+d.ID,
		attestation.TypeDigest, // digest.v1 (registered in pkg/attestation)
		"digest:shortfp:"+shortFingerprint(d.ID)+":"+kr.CurrentKeyID(),
		kr,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("digest: attestation.Sign: %w", err)
	}
	return env, nil
}

// VerifyDigest verifies a signed Digest envelope.
// Returns the Digest (from the envelope's payload)
// on success.
func VerifyDigest(env *attestation.Envelope) (*Digest, []byte, error) {
	if env == nil {
		return nil, nil, fmt.Errorf("digest: envelope is nil")
	}
	// Verify the envelope.
	if err := attestation.Verify(env); err != nil {
		return nil, nil, fmt.Errorf("digest: verify envelope: %w", err)
	}
	// Decode the payload.
	var wrapped struct {
		Digest   *Digest `json:"digest"`
		PDFBytes []byte  `json:"pdf_bytes"`
	}
	if err := json.Unmarshal([]byte(env.RawPayload), &wrapped); err != nil {
		return nil, nil, fmt.Errorf("digest: unmarshal payload: %w", err)
	}
	if wrapped.Digest == nil {
		return nil, nil, ErrDigestNotFound
	}
	return wrapped.Digest, wrapped.PDFBytes, nil
}

// shortFingerprint returns the first 16 hex chars of
// SHA-256(s). Used for the issuer's shortfp.
func shortFingerprint(s string) string {
	// We use the SHA-256 from the ioc package via
	// crypto/sha256 (we don't need to add a new
	// import for this).
	return hashSHA256HexShort(s)
}
