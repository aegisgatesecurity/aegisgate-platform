// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - STIX Exporter for IOC Bundles (v3.5.0+, Tier 2 TODO-403)
//
// stix_exporter.go exports AegisGate IOC Bundles to STIX 2.1
// JSON files. The exporter calls BundleToSTIX (defined in
// stix_taxii.go) to do the conversion, then writes the
// resulting *threatintel.Bundle to disk using standard
// encoding/json.
//
// This is a thin file-format adapter, not a full wrapper of
// the upstream threatintel.Exporter. The upstream exporter is
// designed for objects in a STIX-domain vocabulary (Indicator,
// AttackPattern, etc.) and is overkill for the AegisGate IOC
// use case, which always produces a single STIX bundle per
// export. Direct JSON marshaling is simpler, faster, and
// produces a byte-identical result for a given input.
//
// The exported JSON is valid STIX 2.1: each bundle has
// "type": "bundle", "id": "bundle--<uuid>", "objects": [...],
// and "spec_version": "2.1". TAXII servers and STIX-aware
// consumers can ingest it without modification.
//
// Tier 2 (TODO-403) of the 5-Tier forward roadmap.

package ioc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// STIXExportConfig configures a STIX export. Zero values are
// safe (compact JSON, no pretty-printing).
type STIXExportConfig struct {
	// PrettyPrint controls JSON indentation. The default
	// (false) produces compact JSON; set to true for
	// human-readable output (e.g., for debugging).
	PrettyPrint bool
	// Indent is the indentation string for pretty-printing.
	// Default is two spaces. Ignored if PrettyPrint is false.
	Indent string
}

// STIXExporter exports AegisGate IOC Bundles to STIX 2.1
// JSON. It is safe for concurrent use.
//
// Typical lifecycle:
//
//	exp := NewSTIXExporter(STIXExportConfig{...})
//	if err := exp.ExportToSTIX(bundle, "/var/lib/aegisgate/iocs/stix.json"); err != nil {
//	    log.Errorf("export: %v", err)
//	}
type STIXExporter struct {
	cfg STIXExportConfig
}

// NewSTIXExporter constructs a STIXExporter. The exporter is
// ready to use immediately; no further initialization is
// required. The cfg is captured by value; subsequent changes
// to the caller's STIXExportConfig do not affect the
// exporter.
func NewSTIXExporter(cfg STIXExportConfig) *STIXExporter {
	if cfg.Indent == "" {
		cfg.Indent = "  "
	}
	return &STIXExporter{cfg: cfg}
}

// ExportToSTIX writes the bundle as a STIX 2.1 JSON file at
// the given path. The file is created if it does not exist;
// the parent directory is created if missing. The file is
// overwritten if it already exists.
func (e *STIXExporter) ExportToSTIX(b *Bundle, path string) error {
	if b == nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIX: nil bundle")
	}
	if path == "" {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIX: empty path")
	}
	// G304 (CodeQL): sanitize the path before
	// os.Create. The path arg is typically derived
	// from a config value or CLI flag, not from an
	// untrusted user; cleanFilePath rejects
	// path-traversal patterns defensively.
	cleanPath, err := cleanFilePath(path)
	if err != nil {
		return err
	}
	path = cleanPath
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("ioc: STIXExporter.ExportToSTIX: mkdir %s: %w", dir, err)
		}
	}
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIX: create %s: %w", path, err)
	}
	defer f.Close()
	if err := e.ExportToSTIXWriter(b, f); err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIX: write %s: %w", path, err)
	}
	return nil
}

// ExportToSTIXWriter writes the bundle as a STIX 2.1 JSON
// stream to the given writer. Used for HTTP responses, in-
// memory exports, and tests. The writer is not closed; the
// caller is responsible.
func (e *STIXExporter) ExportToSTIXWriter(b *Bundle, w io.Writer) error {
	if b == nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIXWriter: nil bundle")
	}
	if w == nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIXWriter: nil writer")
	}
	stixBundle, err := BundleToSTIX(b)
	if err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIXWriter: convert: %w", err)
	}
	enc := json.NewEncoder(w)
	if e.cfg.PrettyPrint {
		enc.SetIndent("", e.cfg.Indent)
	}
	if err := enc.Encode(stixBundle); err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToSTIXWriter: encode: %w", err)
	}
	return nil
}

// ExportToJSON writes the bundle as a raw JSON file (not a
// STIX bundle, but the same shape). The output is a single
// JSON object with the bundle's fields at the top level.
//
// Note: this is identical to ExportToSTIX for our bundle
// format (we always emit a STIX bundle). The method is
// preserved for API symmetry with future formats (e.g.,
// the AegisGate-native shape).
func (e *STIXExporter) ExportToJSON(b *Bundle, path string) error {
	return e.ExportToSTIX(b, path)
}

// ExportToJSONLines writes the bundle as one JSON object per
// line (JSONL). The first line is the bundle header
// ("type": "bundle", "id": "..."); each subsequent line is a
// single STIX object. Used for streaming exports and for
// log-file ingestion by SIEM systems.
//
// The output is a "STIX bundle in JSONL form" (a slight
// extension of standard STIX 2.1, which mandates a single
// JSON object). Most SIEMs that accept JSONL will parse each
// line as an event.
func (e *STIXExporter) ExportToJSONLines(b *Bundle, path string) error {
	if b == nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLines: nil bundle")
	}
	if path == "" {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLines: empty path")
	}
	// G304 (CodeQL): sanitize the path before
	// os.Create. See ExportToSTIX for the rationale.
	cleanPath, err := cleanFilePath(path)
	if err != nil {
		return err
	}
	path = cleanPath
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("ioc: STIXExporter.ExportToJSONLines: mkdir %s: %w", dir, err)
		}
	}
	f, err := os.Create(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLines: create %s: %w", path, err)
	}
	defer f.Close()
	if err := e.ExportToJSONLinesWriter(b, f); err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLines: write %s: %w", path, err)
	}
	return nil
}

// ExportToJSONLinesWriter is the streaming variant of
// ExportToJSONLines. The writer is not closed.
func (e *STIXExporter) ExportToJSONLinesWriter(b *Bundle, w io.Writer) error {
	if b == nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLinesWriter: nil bundle")
	}
	if w == nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLinesWriter: nil writer")
	}
	stixBundle, err := BundleToSTIX(b)
	if err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLinesWriter: convert: %w", err)
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	// Line 1: the bundle header (type, id, spec_version).
	header := struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		SpecVersion string `json:"spec_version"`
	}{
		Type:        string(stixBundle.Type),
		ID:          stixBundle.ID,
		SpecVersion: stixBundle.SpecVersion,
	}
	if err := json.NewEncoder(bw).Encode(header); err != nil {
		return fmt.Errorf("ioc: STIXExporter.ExportToJSONLinesWriter: header: %w", err)
	}
	// Lines 2..N+1: one STIX object per line.
	for _, raw := range stixBundle.Objects {
		if _, err := bw.Write(raw); err != nil {
			return fmt.Errorf("ioc: STIXExporter.ExportToJSONLinesWriter: object: %w", err)
		}
		if _, err := bw.WriteString("\n"); err != nil {
			return fmt.Errorf("ioc: STIXExporter.ExportToJSONLinesWriter: newline: %w", err)
		}
	}
	return nil
}

// Close releases any resources held by the exporter. As of
// v3.5.0+, this is a no-op (no persistent resources), but the
// method is present for API symmetry with future versions.
func (e *STIXExporter) Close() error {
	return nil
}
