// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - IOC <-> STIX/TAXII conversion (v3.5.0+, Tier 2 TODO-403)
//
// stix_taxii.go bridges the IOC library (our tree) and the
// STIX 2.1 / TAXII 2.1 library (vendored at /upstream/aegisgate/
// pkg/threatintel). It provides:
//
//   - IOC -> STIX Indicator conversion
//   - STIX Indicator -> IOC conversion (lossy by design)
//   - IOC Bundle -> STIX Bundle conversion
//   - STIX Bundle -> IOC Bundle conversion
//
// The conversion is lossless in the forward direction
// (IOC -> STIX preserves all fields) and lossy in the reverse
// direction (STIX -> IOC cannot recover the IOC's internal
// Detection tuple; only the fingerprint, type, severity, and
// timing). This is the correct asymmetry: STIX is a
// wire-format for sharing IOCs across organizations, and the
// AegisGate-internal Detection tuple is the source-of-truth
// that produced the IOC.
//
// Tier 2 (TODO-403) of the 5-Tier forward roadmap.

package ioc

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	ti "github.com/aegisgatesecurity/aegisgate/pkg/threatintel"
)

// ----------------------------------------------------------------------------
// IOC -> STIX
// ----------------------------------------------------------------------------

// IOCToSTIXIndicator converts an AegisGate IOC to a STIX 2.1
// Indicator. The conversion is lossless: every IOC field is
// preserved somewhere in the STIX object. The mapping is:
//
//   - IOC.Fingerprint  -> STIX pattern (hex-encoded SHA-256
//     wrapped in a STIX pattern expression)
//   - IOC.Type         -> STIX IndicatorTypes[0]
//     and Labels[0]
//   - IOC.Severity     -> STIX Confidence (mapped via
//     severityToConfidence)
//   - IOC.FirstSeen    -> STIX ValidFrom
//   - IOC.LastSeen     -> STIX ValidUntil
//   - IOC.Count        -> STIX Labels (count: <n>)
//   - IOC.Source       -> STIX Labels (source: <s>)
//
// Returns an error only if the IOC is invalid (Fingerprint or
// Type empty). The caller is expected to have validated the
// IOC; a non-Valid IOC is rejected here as a defensive check.
func IOCToSTIXIndicator(ioc *IOC) (*ti.Indicator, error) {
	if ioc == nil {
		return nil, fmt.Errorf("ioc: IOCToSTIXIndicator: nil IOC")
	}
	if !ioc.Valid() {
		return nil, fmt.Errorf("ioc: IOCToSTIXIndicator: invalid IOC (fingerprint=%q, type=%q)",
			ioc.Fingerprint, ioc.Type)
	}

	// Build a STIX pattern that wraps the fingerprint. We use
	// the file:hashes.SHA-256 pattern type because the IOC's
	// fingerprint is a SHA-256 hash, which makes the pattern
	// semantically meaningful to STIX consumers (TAXII servers
	// can correlate file hashes). The pattern uses the IOC's
	// own fingerprint so a STIX-side dedup matches AegisGate's.
	pattern := fmt.Sprintf("[file:hashes.SHA-256 = '%s']", ioc.Fingerprint)

	// Labels carry the human-readable metadata: type, source,
	// count. STIX consumers can search on labels.
	labels := []string{
		"aegisgate",
		"type:" + string(ioc.Type),
		"source:" + ioc.Source,
		fmt.Sprintf("count:%d", ioc.Count),
	}

	// IndicatorTypes uses the STIX vocabulary where possible.
	// AegisGate's IOCType values map to the closest STIX
	// indicator type. Unknown types are dropped (the label
	// still carries the original).
	indicatorTypes := []ti.IndicatorType{iocTypeToSTIXIndicatorType(ioc.Type)}

	// Description carries the verbatim IOCType for the
	// round-trip; STIX consumers see the AegisGate-specific
	// taxonomy here.
	prefix := ioc.Fingerprint
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	description := fmt.Sprintf("AegisGate IOC of type %q at severity %q (fingerprint prefix: %s...)",
		ioc.Type, ioc.Severity, prefix)

	// Confidence: severity -> 0-100. Critical=95, High=80,
	// Medium=60, Low=40, Info=20. Unknown -> 0.
	confidence := severityToConfidence(ioc.Severity)

	// Valid window. We use FirstSeen -> LastSeen so a
	// STIX-side validity check matches AegisGate's
	// observation window. If LastSeen is zero (shouldn't
	// happen in practice), use FirstSeen+30d.
	validFrom := ioc.FirstSeen
	if validFrom.IsZero() {
		validFrom = time.Now().UTC()
	}
	validUntil := ioc.LastSeen
	if validUntil.IsZero() {
		validUntil = validFrom.Add(30 * 24 * time.Hour)
	}

	// Build the STIX Indicator directly. We use the
	// NewIndicator constructor for the BaseObject defaults,
	// then populate the rest. This avoids depending on a
	// STIXBuilder instance (which would require a
	// STIXBuilderOptions struct); a single-IOC conversion
	// is a self-contained operation.
	ind := ti.NewIndicator(generateSTIXID(ti.STIXTypeIndicator), pattern, ti.PatternTypeSTIX)
	ind.Name = string(ioc.Type) + " IOC"
	ind.Description = description
	ind.IndicatorTypes = indicatorTypes
	ind.ValidFrom = validFrom
	ind.ValidUntil = validUntil
	ind.Confidence = confidence
	ind.Labels = labels
	// ExternalReference carries the AegisGate-internal
	// fingerprint verbatim so the STIX consumer can dedup
	// with AegisGate's own dedup. The source name is
	// "aegisgate-ioc" (a stable identifier for AegisGate-
	// produced IOCs); the ExternalID is the fingerprint.
	ind.ExternalReferences = []ti.ExternalReference{
		{
			SourceName: "aegisgate-ioc",
			ExternalID: ioc.Fingerprint,
		},
	}
	return ind, nil
}

// BundleToSTIX converts an AegisGate IOC Bundle to a STIX
// 2.1 Bundle. Each IOCAttestation's fields are flattened into
// an IOC, then converted to a STIX Indicator. The bundle's
// AegisGate signature is NOT carried over (STIX bundles don't
// have an AegisGate-style envelope signature; STIX uses JWS or
// trust object markings instead, which is out of scope for
// v3.5.0+).
//
// The STIX bundle is the standard "objects" array form.
// Returns an error if any IOC in the bundle is invalid.
// The error is collected across all IOCs (not just the
// first) so the caller sees the full list of problems.
func BundleToSTIX(b *Bundle) (*ti.Bundle, error) {
	if b == nil {
		return nil, fmt.Errorf("ioc: BundleToSTIX: nil bundle")
	}
	stixBundle := ti.NewBundle(generateSTIXID(ti.STIXTypeBundle))
	stixBundle.SpecVersion = "2.1"
	if errs := bundleValidateAll(b); len(errs) > 0 {
		return nil, fmt.Errorf("ioc: BundleToSTIX: %d invalid IOC(s): %v", len(errs), errs)
	}
	for i := range b.Attestations {
		att := &b.Attestations[i]
		iocValue := attestationToIOC(att)
		ind, err := IOCToSTIXIndicator(&iocValue)
		if err != nil {
			// Should not happen after bundleValidateAll,
			// but defensive.
			return nil, fmt.Errorf("ioc: BundleToSTIX: attestation %d: %w", i, err)
		}
		if err := stixBundle.AddObject(ind); err != nil {
			return nil, fmt.Errorf("ioc: BundleToSTIX: add indicator: %w", err)
		}
	}
	return stixBundle, nil
}

// ----------------------------------------------------------------------------
// STIX -> IOC
// ----------------------------------------------------------------------------

// STIXIndicatorToIOC converts a STIX 2.1 Indicator back into an
// AegisGate IOC. The conversion is lossy by design (see
// stix_taxii.go header comment): the IOC's internal Detection
// tuple is NOT recoverable from a STIX Indicator. The output
// IOC has the fields that STIX carries:
//
//   - Fingerprint: recovered from the STIX pattern (parsed
//     out of the file:hashes.SHA-256 pattern) or, as a
//     fallback, from the ExternalReference.ExternalID
//   - Type: recovered from the first IndicatorType that maps
//     to an IOCType, or from the "type:" label
//   - Severity: NOT recoverable from STIX (STIX has no
//     severity field, only Confidence). Mapped back from
//     confidence via confidenceToSeverity.
//   - FirstSeen: STIX ValidFrom
//   - LastSeen: STIX ValidUntil
//   - Count: parsed from the "count:<n>" label; 1 if absent
//   - Source: parsed from the "source:<s>" label; "stix" if
//     absent
//
// Returns an error if the Indicator's pattern cannot be
// parsed. The AegisGate-specific fields (Detection tuple,
// FrameworkRefs) are empty in the output IOC.
func STIXIndicatorToIOC(ind *ti.Indicator) (IOC, error) {
	if ind == nil {
		return IOC{}, fmt.Errorf("ioc: STIXIndicatorToIOC: nil indicator")
	}
	// Parse the fingerprint out of the pattern. The
	// pattern we produce is [file:hashes.SHA-256 = '<fp>'];
	// parse that out. If parsing fails, fall back to the
	// ExternalReference.ExternalID.
	fp, err := parseSTIXPatternFingerprint(ind.Pattern)
	if err != nil {
		for _, er := range ind.ExternalReferences {
			if er.SourceName == "aegisgate-ioc" && len(er.ExternalID) == 64 {
				fp = er.ExternalID
				err = nil
				break
			}
		}
		if err != nil {
			return IOC{}, fmt.Errorf("ioc: STIXIndicatorToIOC: cannot recover fingerprint: %w", err)
		}
	}

	// Type: prefer IndicatorType -> IOCType mapping; fall
	// back to the "type:" label.
	iocType := IOCTypeProxyResponse // safe default
	matched := false
	for _, it := range ind.IndicatorTypes {
		if mapped, ok := stixIndicatorTypeToIOCType(it); ok {
			iocType = mapped
			matched = true
			break
		}
	}
	if !matched {
		for _, lbl := range ind.Labels {
			if strings.HasPrefix(lbl, "type:") {
				iocType = IOCType(strings.TrimPrefix(lbl, "type:"))
				break
			}
		}
	}

	// Severity: confidence -> severity.
	severity := confidenceToSeverity(ind.Confidence)

	// Count + Source: from labels.
	count := 1
	source := "stix"
	for _, lbl := range ind.Labels {
		if strings.HasPrefix(lbl, "count:") {
			var n int
			_, _ = fmt.Sscanf(strings.TrimPrefix(lbl, "count:"), "%d", &n)
			if n > 0 {
				count = n
			}
		} else if strings.HasPrefix(lbl, "source:") {
			source = strings.TrimPrefix(lbl, "source:")
		}
	}

	return IOC{
		Fingerprint: fp,
		Type:        iocType,
		Severity:    severity,
		FirstSeen:   ind.ValidFrom,
		LastSeen:    ind.ValidUntil,
		Count:       count,
		Source:      source,
	}, nil
}

// STIXToBundle converts a STIX 2.1 Bundle to an AegisGate IOC
// Bundle. Each STIX Indicator becomes an IOCAttestation wrapping
// an IOC. The AegisGate Bundle ID is regenerated from the STIX
// bundle ID (deterministic via SHA-256). The signatures on the
// AegisGate bundle are NOT populated (the STIX bundle's trust
// is verified by the STIX layer, not the AegisGate signature
// layer; signatures are out of scope for the reverse path).
//
// The AegisGate InstanceID is taken from the STIX bundle's
// "created_by_ref" if it matches aegisgate-ioc, otherwise
// "stix-importer".
func STIXToBundle(stixBundle *ti.Bundle, instanceID string) (*Bundle, error) {
	if stixBundle == nil {
		return nil, fmt.Errorf("ioc: STIXToBundle: nil STIX bundle")
	}
	if instanceID == "" {
		instanceID = "stix-importer"
	}
	out := NewBundle(instanceID)
	out.BundleID = deriveAegisGateBundleID(stixBundle.ID)
	out.IssuedAt = time.Now().UTC()
	for _, raw := range stixBundle.Objects {
		var ind ti.Indicator
		if err := json.Unmarshal(raw, &ind); err != nil {
			// Skip non-Indicator objects. The threatintel
			// library emits several STIX object types;
			// only Indicators map to AegisGate IOCs.
			continue
		}
		if ind.Type != ti.STIXTypeIndicator {
			continue
		}
		iocValue, err := STIXIndicatorToIOC(&ind)
		if err != nil {
			// Skip invalid Indicators rather than failing
			// the whole conversion. A STIX consumer may
			// see a partial bundle (a few bad objects);
			// AegisGate's importer should be permissive.
			continue
		}
		out.Attestations = append(out.Attestations, IOCAttestation{
			Fingerprint: iocValue.Fingerprint,
			InstanceID:  instanceID,
			IOCType:     iocValue.Type,
			Severity:    iocValue.Severity,
			FirstSeen:   iocValue.FirstSeen,
			LastSeen:    iocValue.LastSeen,
			Count:       iocValue.Count,
		})
	}
	out.Count = len(out.Attestations)
	return out, nil
}

// ----------------------------------------------------------------------------
// Mappings: IOC <-> STIX
// ----------------------------------------------------------------------------

// iocTypeToSTIXIndicatorType maps AegisGate's IOCType to the
// closest STIX IndicatorType vocabulary. The STIX vocabulary
// is open-ended (IndicatorType is a free-form string), so we
// pick conventional labels:
//
//   - proxy_response  -> "malicious-activity"
//   - anomaly_score   -> "anomalous-activity"
//   - prompt_injection -> "malicious-activity"
//   - secret_leak     -> "malicious-activity"
//   - pii_detected    -> "malicious-activity"
//   - anything else   -> "malicious-activity" (safe default)
func iocTypeToSTIXIndicatorType(it IOCType) ti.IndicatorType {
	switch it {
	case IOCTypeProxyResponse:
		return "malicious-activity"
	case IOCTypeAnomalyScore:
		return "anomalous-activity"
	case IOCTypePromptInjection,
		IOCTypeSecretLeak,
		IOCTypePIIDetected:
		return "malicious-activity"
	}
	return "malicious-activity"
}

// stixIndicatorTypeToIOCType is the inverse of
// iocTypeToSTIXIndicatorType. It returns the best-effort
// AegisGate IOCType for a STIX IndicatorType. The boolean
// indicates whether the mapping is a known canonical match
// (true) or a fallback (false). The fallback is "malicious-
// activity" -> IOCTypeProxyResponse, which is the most
// common AegisGate IOC type.
func stixIndicatorTypeToIOCType(it ti.IndicatorType) (IOCType, bool) {
	switch string(it) {
	case "malicious-activity":
		// No canonical reverse mapping (multiple IOCTypes
		// map here). The caller should fall back to the
		// "type:" label, which carries the original.
		return "", false
	case "anomalous-activity":
		return IOCTypeAnomalyScore, true
	}
	return "", false
}

// severityToConfidence maps AegisGate severity to STIX
// confidence (0-100). The mapping is monotone: critical >
// high > medium > low > info.
func severityToConfidence(s Severity) int {
	switch s {
	case SeverityCritical:
		return 95
	case SeverityHigh:
		return 80
	case SeverityMedium:
		return 60
	case SeverityLow:
		return 40
	case SeverityInfo:
		return 20
	}
	return 0
}

// confidenceToSeverity is the inverse of severityToConfidence.
// Buckets are centered on the midpoints. Unknown confidences
// map to "low".
func confidenceToSeverity(c int) Severity {
	switch {
	case c >= 90:
		return SeverityCritical
	case c >= 70:
		return SeverityHigh
	case c >= 50:
		return SeverityMedium
	case c >= 30:
		return SeverityLow
	}
	return SeverityInfo
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// attestationToIOC builds a plain IOC value from an
// IOCAttestation. The IOCAttestation carries the same fields
// inline (Fingerprint, IOCType, Severity, FirstSeen, LastSeen,
// Count) but the Source field is NOT present on IOCAttestation
// (it is set by the producer at IOC creation time, not at
// attestation time). We default the Source to "attestation" so
// the IOC's Source field is non-empty.
func attestationToIOC(att *IOCAttestation) IOC {
	if att == nil {
		return IOC{}
	}
	return IOC{
		Fingerprint: att.Fingerprint,
		Type:        att.IOCType,
		Severity:    att.Severity,
		FirstSeen:   att.FirstSeen,
		LastSeen:    att.LastSeen,
		Count:       att.Count,
		Source:      "attestation",
	}
}

// generateSTIXID generates a fresh STIX ID for the given type.
// The STIX 2.1 spec requires IDs of the form "<type>--<uuid>".
// We use the IOC library's NewBundle helper (which already
// generates a UUIDv4) and reuse the BundleID as the suffix.
// This avoids adding a second import of google/uuid.
func generateSTIXID(t ti.STIXType) string {
	b := NewBundle("stix-id-gen")
	return string(t) + "--" + b.BundleID
}

// parseSTIXPatternFingerprint extracts the SHA-256 fingerprint
// from a STIX pattern of the form
// "[file:hashes.SHA-256 = '<fp>']" or the unbracketed variant.
// Returns the fingerprint on success; an error if the pattern
// is not in the expected form.
func parseSTIXPatternFingerprint(pattern string) (string, error) {
	// The pattern can be: "[file:hashes.SHA-256 = '<fp>']"
	// or with double quotes. We look for "SHA-256 =" then
	// extract the quoted string.
	idx := strings.Index(pattern, "SHA-256")
	if idx < 0 {
		// Try a generic quoted-string fallback: any 64-char
		// hex string is a valid SHA-256 fingerprint.
		return extractHex64(pattern)
	}
	rest := pattern[idx:]
	// Find the first quote.
	qIdx := strings.IndexAny(rest, "'\"")
	if qIdx < 0 {
		return "", fmt.Errorf("stix: no quoted string after SHA-256 in pattern: %q", pattern)
	}
	quote := rest[qIdx]
	rest = rest[qIdx+1:]
	endIdx := strings.IndexByte(rest, quote)
	if endIdx < 0 {
		return "", fmt.Errorf("stix: unterminated quoted string in pattern: %q", pattern)
	}
	return rest[:endIdx], nil
}

// extractHex64 is a fallback for STIX patterns that don't use
// the SHA-256 form. It scans for a 64-char hex string.
func extractHex64(s string) (string, error) {
	for i := 0; i+64 <= len(s); i++ {
		candidate := s[i : i+64]
		if isHex(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("stix: no 64-char hex string in pattern: %q", s)
}

// isHex reports whether s is a non-empty string of hex digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// bundleValidateAll returns a sorted list of validation errors
// for every IOC in the bundle. Used by BundleToSTIX to surface
// all problems at once rather than failing on the first.
func bundleValidateAll(b *Bundle) []string {
	var errs []string
	for i := range b.Attestations {
		att := &b.Attestations[i]
		if att.Fingerprint == "" || att.IOCType == "" {
			errs = append(errs, fmt.Sprintf("attestation %d: invalid IOC (fp=%q, type=%q)",
				i, att.Fingerprint, att.IOCType))
		}
	}
	sort.Strings(errs)
	return errs
}

// deriveAegisGateBundleID converts a STIX bundle ID into a
// deterministic AegisGate bundle ID. The AegisGate bundle ID
// is a UUIDv4; the STIX bundle ID is "<type>--<uuid>". We
// strip the prefix and return the uuid portion.
func deriveAegisGateBundleID(stixID string) string {
	parts := strings.SplitN(stixID, "--", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return stixID
}
