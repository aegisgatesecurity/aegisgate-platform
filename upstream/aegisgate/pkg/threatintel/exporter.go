// SPDX-License-Identifier: MIT
// =========================================================================
// PROPRIETARY - AegisGate Security
// Copyright (c) 2025-2026 AegisGate Security. All rights reserved.
// =========================================================================
//
// This file contains proprietary trade secret information.
// Unauthorized reproduction, distribution, or reverse engineering is prohibited.
// =========================================================================

// Package threatintel provides export functionality for threat intelligence data.
package threatintel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// Export Configuration
// ============================================================================

// ExportConfig contains export configuration.
type ExportConfig struct {
	// Output format: stix, json, csv, misp
	Format string `json:"format"`
	// Output path (file or directory)
	OutputPath string `json:"output_path"`
	// Include identity in export
	IncludeIdentity bool `json:"include_identity"`
	// Include observables in export
	IncludeObservables bool `json:"include_observables"`
	// Include relationships in export
	IncludeRelationships bool `json:"include_relationships"`
	// Filter by object types
	ObjectTypes []string `json:"object_types,omitempty"`
	// Filter by labels
	Labels []string `json:"labels,omitempty"`
	// Filter by confidence threshold
	MinConfidence int `json:"min_confidence,omitempty"`
	// Filter by time range
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	// Maximum objects per file
	MaxObjectsPerFile int `json:"max_objects_per_file,omitempty"`
	// Compress output
	Compress bool `json:"compress"`
	// Rate limit for network exports
	RateLimit int `json:"rate_limit,omitempty"`
	// Batch size for batched exports
	BatchSize int `json:"batch_size,omitempty"`
}

// DefaultExportConfig returns default export configuration.
func DefaultExportConfig() ExportConfig {
	return ExportConfig{
		Format:               "stix",
		IncludeIdentity:      true,
		IncludeObservables:   true,
		IncludeRelationships: true,
		MaxObjectsPerFile:    10000,
		BatchSize:            100,
	}
}

// ============================================================================
// Exporter
// ============================================================================

// Exporter exports threat intelligence data in various formats.
type Exporter struct {
	config  ExportConfig
	builder *STIXBuilder
	client  *TAXIIClient
	mu      sync.Mutex
	stats   *ExportStats
}

// ExporterOptions contains options for creating an exporter.
type ExporterOptions struct {
	Config  ExportConfig
	Builder *STIXBuilder
	Client  *TAXIIClient
}

// NewExporter creates a new exporter.
func NewExporter(opts ExporterOptions) *Exporter {
	config := opts.Config
	if config.Format == "" {
		config.Format = "stix"
	}
	if config.MaxObjectsPerFile == 0 {
		config.MaxObjectsPerFile = 10000
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}

	return &Exporter{
		config:  config,
		builder: opts.Builder,
		client:  opts.Client,
		stats:   &ExportStats{},
	}
}

// ExportStats tracks export statistics.
type ExportStats struct {
	mu              sync.RWMutex
	ObjectsExported int64
	ObjectsFiltered int64
	FilesCreated    int64
	BytesWritten    int64
	BytesSent       int64
	LastExportTime  time.Time
	LastError       string
}

// GetStats returns export statistics.
func (e *Exporter) GetStats() *ExportStats {
	e.stats.mu.RLock()
	defer e.stats.mu.RUnlock()
	return &ExportStats{
		ObjectsExported: e.stats.ObjectsExported,
		ObjectsFiltered: e.stats.ObjectsFiltered,
		FilesCreated:    e.stats.FilesCreated,
		BytesWritten:    e.stats.BytesWritten,
		BytesSent:       e.stats.BytesSent,
		LastExportTime:  e.stats.LastExportTime,
		LastError:       e.stats.LastError,
	}
}

// ============================================================================
// STIX Export
// ============================================================================

// ExportToSTIX exports objects to a STIX bundle file.
func (e *Exporter) ExportToSTIX(ctx context.Context, objects []STIXObject, outputPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil
	}

	// Generate bundle ID
	bundleID, err := GenerateSTIXID(STIXTypeBundle)
	if err != nil {
		return err
	}

	// Create bundle
	bundle := NewBundle(bundleID)

	// Add identity if configured
	if e.config.IncludeIdentity && e.builder != nil && e.builder.identity != nil {
		if err := bundle.AddObject(e.builder.identity); err != nil {
			return err
		}
	}

	// Add objects
	for _, obj := range filtered {
		if err := bundle.AddObject(obj); err != nil {
			return err
		}
	}

	// Marshal to JSON
	data, err := MarshalBundleIndent(bundle)
	if err != nil {
		return NewError("export_stix", "failed to marshal bundle", false, err)
	}

	// Write to file
	if err := e.writeFile(outputPath, data); err != nil {
		return err
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.FilesCreated++
	e.stats.BytesWritten += int64(len(data))
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return nil
}

// ExportToSTIXWriter exports objects to a STIX bundle using a writer.
func (e *Exporter) ExportToSTIXWriter(ctx context.Context, objects []STIXObject, writer io.Writer) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil
	}

	// Generate bundle ID
	bundleID, err := GenerateSTIXID(STIXTypeBundle)
	if err != nil {
		return err
	}

	// Create bundle
	bundle := NewBundle(bundleID)

	// Add identity if configured
	if e.config.IncludeIdentity && e.builder != nil && e.builder.identity != nil {
		if err := bundle.AddObject(e.builder.identity); err != nil {
			return err
		}
	}

	// Add objects
	for _, obj := range filtered {
		if err := bundle.AddObject(obj); err != nil {
			return err
		}
	}

	// Marshal to JSON
	data, err := MarshalBundleIndent(bundle)
	if err != nil {
		return NewError("export_stix", "failed to marshal bundle", false, err)
	}

	// Write to writer
	n, err := writer.Write(data)
	if err != nil {
		return NewError("export_stix", "failed to write bundle", false, err)
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.BytesWritten += int64(n)
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return nil
}

// ExportToSTIXBatched exports objects to multiple STIX bundle files in batches.
func (e *Exporter) ExportToSTIXBatched(ctx context.Context, objects []STIXObject, outputDir string) ([]string, error) {
	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil, nil
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, NewError("export_stix_batched", "failed to create output directory", false, err)
	}

	var files []string
	batchSize := e.config.MaxObjectsPerFile

	for i := 0; i < len(filtered); i += batchSize {
		end := i + batchSize
		if end > len(filtered) {
			end = len(filtered)
		}

		batch := filtered[i:end]

		// Generate filename
		timestamp := time.Now().UTC().Format("20060102-150405")
		batchNum := i / batchSize
		filename := filepath.Join(outputDir, fmt.Sprintf("stix-bundle-%s-%d.json", timestamp, batchNum))

		// Generate bundle ID
		bundleID, err := GenerateSTIXID(STIXTypeBundle)
		if err != nil {
			return files, err
		}

		// Create bundle
		bundle := NewBundle(bundleID)

		// Add identity if configured
		if e.config.IncludeIdentity && e.builder != nil && e.builder.identity != nil && i == 0 {
			if err := bundle.AddObject(e.builder.identity); err != nil {
				return files, err
			}
		}

		// Add objects
		for _, obj := range batch {
			if err := bundle.AddObject(obj); err != nil {
				return files, err
			}
		}

		// Marshal to JSON
		data, err := MarshalBundleIndent(bundle)
		if err != nil {
			return files, NewError("export_stix_batched", "failed to marshal bundle", false, err)
		}

		// Write to file
		if err := e.writeFile(filename, data); err != nil {
			return files, err
		}

		files = append(files, filename)

		e.stats.mu.Lock()
		e.stats.ObjectsExported += int64(len(batch))
		e.stats.FilesCreated++
		e.stats.BytesWritten += int64(len(data))
		e.stats.mu.Unlock()
	}

	e.stats.mu.Lock()
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return files, nil
}

// ============================================================================
// JSON Export
// ============================================================================

// ExportToJSON exports objects to JSON format.
func (e *Exporter) ExportToJSON(ctx context.Context, objects []STIXObject, outputPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil
	}

	// Marshal objects
	data, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return NewError("export_json", "failed to marshal objects", false, err)
	}

	// Write to file
	if err := e.writeFile(outputPath, data); err != nil {
		return err
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.FilesCreated++
	e.stats.BytesWritten += int64(len(data))
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return nil
}

// ExportToJSONLines exports objects to JSON Lines format.
func (e *Exporter) ExportToJSONLines(ctx context.Context, objects []STIXObject, outputPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return NewError("export_json_lines", "failed to create output file", false, err)
	}
	defer func() { _ = file.Close() }()

	var totalBytes int64
	writer := io.Writer(file)

	for _, obj := range filtered {
		data, err := json.Marshal(obj)
		if err != nil {
			continue
		}

		n, err := writer.Write(data)
		if err != nil {
			return NewError("export_json_lines", "failed to write object", false, err)
		}
		totalBytes += int64(n)

		n, err = writer.Write([]byte("\n"))
		if err != nil {
			return NewError("export_json_lines", "failed to write newline", false, err)
		}
		totalBytes += int64(n)
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.FilesCreated++
	e.stats.BytesWritten += totalBytes
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return nil
}

// ============================================================================
// CSV Export
// ============================================================================

// CSVExportOptions contains options for CSV export.
type CSVExportOptions struct {
	// Headers to include in CSV
	Headers []string
	// Flatten nested objects
	Flatten bool
	// Include all fields
	IncludeAllFields bool
}

// ExportToCSV exports indicators to CSV format.
func (e *Exporter) ExportToCSV(ctx context.Context, indicators []*Indicator, outputPath string, opts CSVExportOptions) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter indicators
	filtered := e.filterIndicators(indicators)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(indicators) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return NewError("export_csv", "failed to create output file", false, err)
	}
	defer func() { _ = file.Close() }()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Determine headers
	if len(opts.Headers) == 0 {
		opts.Headers = []string{
			"id", "type", "created", "modified", "name", "description",
			"pattern", "pattern_type", "valid_from", "valid_until",
			"indicator_types", "labels", "confidence",
		}
	}

	// Write header
	if err := writer.Write(opts.Headers); err != nil {
		return NewError("export_csv", "failed to write header", false, err)
	}

	// Write rows
	for _, ind := range filtered {
		row := make([]string, len(opts.Headers))
		for i, header := range opts.Headers {
			row[i] = e.getIndicatorField(ind, header)
		}
		if err := writer.Write(row); err != nil {
			return NewError("export_csv", "failed to write row", false, err)
		}
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.FilesCreated++
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return nil
}

// getIndicatorField extracts a field value from an indicator.
func (e *Exporter) getIndicatorField(ind *Indicator, field string) string {
	switch field {
	case "id":
		return ind.ID
	case "type":
		return string(ind.Type)
	case "created":
		return ind.Created.Format(time.RFC3339)
	case "modified":
		return ind.Modified.Format(time.RFC3339)
	case "name":
		return ind.Name
	case "description":
		return ind.Description
	case "pattern":
		return ind.Pattern
	case "pattern_type":
		return string(ind.PatternType)
	case "valid_from":
		return ind.ValidFrom.Format(time.RFC3339)
	case "valid_until":
		if !ind.ValidUntil.IsZero() {
			return ind.ValidUntil.Format(time.RFC3339)
		}
		return ""
	case "indicator_types":
		types := make([]string, len(ind.IndicatorTypes))
		for i, t := range ind.IndicatorTypes {
			types[i] = string(t)
		}
		return strings.Join(types, ",")
	case "labels":
		return strings.Join(ind.Labels, ",")
	case "confidence":
		return fmt.Sprintf("%d", ind.Confidence)
	default:
		return ""
	}
}

// ============================================================================
// MISP Export
// ============================================================================

// MISPExportOptions contains options for MISP export.
type MISPExportOptions struct {
	// Event info
	EventInfo string
	// Event threat level (1-4)
	ThreatLevelID int
	// Event analysis (0-2)
	Analysis int
	// Event distribution (0-4)
	Distribution int
	// Event tags
	Tags []string
	// Org ID
	OrgID string
	// Orgc ID (owner)
	OrgcID string
	// Attribute category
	Category string
	// To IDS flag
	ToIDS bool
}

// MISPEvent represents a MISP event for export.
type MISPEvent struct {
	UUID          string          `json:"uuid"`
	Info          string          `json:"info"`
	ThreatLevelID int             `json:"threat_level_id"`
	Analysis      int             `json:"analysis"`
	Distribution  int             `json:"distribution"`
	Timestamp     int64           `json:"timestamp"`
	Date          string          `json:"date"`
	Published     bool            `json:"published"`
	OrgID         string          `json:"org_id"`
	OrgcID        string          `json:"orgc_id"`
	Attribute     []MISPAttribute `json:"Attribute"`
	EventTag      []MISPTag       `json:"EventTag"`
}

// MISPAttribute represents a MISP attribute.
type MISPAttribute struct {
	UUID         string `json:"uuid"`
	Type         string `json:"type"`
	Category     string `json:"category"`
	Value        string `json:"value"`
	ToIDS        bool   `json:"to_ids"`
	Distribution int    `json:"distribution"`
	Comment      string `json:"comment"`
	Timestamp    int64  `json:"timestamp"`
}

// MISPTag represents a MISP tag.
type MISPTag struct {
	Name   string `json:"name"`
	Colour string `json:"colour"`
}

// ExportToMISP exports indicators to MISP format.
func (e *Exporter) ExportToMISP(ctx context.Context, indicators []*Indicator, outputPath string, opts MISPExportOptions) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter indicators
	filtered := e.filterIndicators(indicators)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(indicators) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil
	}

	// Create MISP event
	event := MISPEvent{
		UUID:          generateMISPUUID(),
		Info:          opts.EventInfo,
		ThreatLevelID: opts.ThreatLevelID,
		Analysis:      opts.Analysis,
		Distribution:  opts.Distribution,
		Timestamp:     time.Now().Unix(),
		Date:          time.Now().Format("2006-01-02"),
		Published:     false,
		OrgID:         opts.OrgID,
		OrgcID:        opts.OrgcID,
		Attribute:     []MISPAttribute{},
		EventTag:      []MISPTag{},
	}

	// Set defaults
	if event.Info == "" {
		event.Info = "Exported from AegisGate AI Security Gateway"
	}
	if event.ThreatLevelID == 0 {
		event.ThreatLevelID = 2 // Medium
	}

	// Add tags
	for _, tag := range opts.Tags {
		event.EventTag = append(event.EventTag, MISPTag{
			Name:   tag,
			Colour: "ffffff",
		})
	}

	// Convert indicators to MISP attributes
	for _, ind := range filtered {
		attrs := e.indicatorToMISPAttributes(ind, opts)
		event.Attribute = append(event.Attribute, attrs...)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(event, "", "  ")
	if err != nil {
		return NewError("export_misp", "failed to marshal event", false, err)
	}

	// Write to file
	if err := e.writeFile(outputPath, data); err != nil {
		return err
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.FilesCreated++
	e.stats.BytesWritten += int64(len(data))
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return nil
}

// indicatorToMISPAttributes converts a STIX indicator to MISP attributes.
func (e *Exporter) indicatorToMISPAttributes(ind *Indicator, opts MISPExportOptions) []MISPAttribute {
	var attrs []MISPAttribute

	// Parse pattern to extract indicators
	values := e.parsePatternValues(ind.Pattern)
	for _, value := range values {
		mispType := e.mapPatternToMISPType(ind.Pattern, value)

		attr := MISPAttribute{
			UUID:         ind.ID,
			Type:         mispType,
			Category:     opts.Category,
			Value:        value,
			ToIDS:        opts.ToIDS,
			Distribution: 0, // Organization only
			Comment:      ind.Description,
			Timestamp:    time.Now().Unix(),
		}

		attrs = append(attrs, attr)
	}

	return attrs
}

// parsePatternValues extracts values from a STIX pattern.
func (e *Exporter) parsePatternValues(pattern string) []string {
	var values []string

	// Simple pattern parsing - extract quoted values
	// Pattern format: [type:property = 'value']
	inQuote := false
	var current strings.Builder

	for _, r := range pattern {
		if r == '\'' {
			inQuote = !inQuote
			if !inQuote && current.Len() > 0 {
				values = append(values, current.String())
				current.Reset()
			}
		} else if inQuote {
			current.WriteRune(r)
		}
	}

	return values
}

// mapPatternToMISPType maps a STIX pattern to a MISP attribute type.
func (e *Exporter) mapPatternToMISPType(pattern, value string) string {
	switch {
	case strings.Contains(pattern, "ipv4-addr"):
		return "ip-dst"
	case strings.Contains(pattern, "ipv6-addr"):
		return "ip-dst"
	case strings.Contains(pattern, "domain-name"):
		return "domain"
	case strings.Contains(pattern, "url"):
		return "url"
	case strings.Contains(pattern, "email-addr"):
		return "email-dst"
	case strings.Contains(pattern, "file:hashes.MD5"):
		return "md5"
	case strings.Contains(pattern, "file:hashes.'SHA-1'"):
		return "sha1"
	case strings.Contains(pattern, "file:hashes.'SHA-256'"):
		return "sha256"
	case strings.Contains(pattern, "file:hashes.'SHA-512'"):
		return "sha512"
	case strings.Contains(pattern, "file:name"):
		return "filename"
	default:
		return "other"
	}
}

// generateMISPUUID generates a MISP-compatible UUID.
func generateMISPUUID() string {
	uuid, _ := generateRandomUUID()
	return uuid
}

// ============================================================================
// TAXII Export
// ============================================================================

// ExportToTAXII exports objects to a TAXII server.
func (e *Exporter) ExportToTAXII(ctx context.Context, objects []STIXObject, apiRootURL, collectionID string) (*TAXIIEnvelopes, error) {
	if e.client == nil {
		return nil, NewError("export_taxii", "TAXII client not configured", false, nil)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil, nil
	}

	// Create bundle
	bundleID, err := GenerateSTIXID(STIXTypeBundle)
	if err != nil {
		return nil, err
	}

	bundle := NewBundle(bundleID)
	for _, obj := range filtered {
		if err := bundle.AddObject(obj); err != nil {
			return nil, err
		}
	}

	// Push to TAXII
	envelopes, err := e.client.AddObjects(ctx, apiRootURL, collectionID, bundle)
	if err != nil {
		return nil, err
	}

	e.stats.mu.Lock()
	e.stats.ObjectsExported += int64(len(filtered))
	e.stats.LastExportTime = time.Now()
	e.stats.mu.Unlock()

	return envelopes, nil
}

// ExportToTAXIIBatched exports objects to a TAXII server in batches.
func (e *Exporter) ExportToTAXIIBatched(ctx context.Context, objects []STIXObject, apiRootURL, collectionID string, batchSize int) ([]*TAXIIEnvelopes, error) {
	if e.client == nil {
		return nil, NewError("export_taxii", "TAXII client not configured", false, nil)
	}

	// Filter objects
	filtered := e.filterObjects(objects)
	e.stats.mu.Lock()
	e.stats.ObjectsFiltered += int64(len(objects) - len(filtered))
	e.stats.mu.Unlock()

	if len(filtered) == 0 {
		return nil, nil
	}

	if batchSize <= 0 {
		batchSize = e.config.BatchSize
	}

	var results []*TAXIIEnvelopes

	for i := 0; i < len(filtered); i += batchSize {
		end := i + batchSize
		if end > len(filtered) {
			end = len(filtered)
		}

		batch := filtered[i:end]

		// Create bundle for batch
		bundleID, err := GenerateSTIXID(STIXTypeBundle)
		if err != nil {
			return results, err
		}

		bundle := NewBundle(bundleID)
		for _, obj := range batch {
			if err := bundle.AddObject(obj); err != nil {
				return results, err
			}
		}

		// Push to TAXII
		envelopes, err := e.client.AddObjects(ctx, apiRootURL, collectionID, bundle)
		if err != nil {
			return results, err
		}

		results = append(results, envelopes)

		e.stats.mu.Lock()
		e.stats.ObjectsExported += int64(len(batch))
		e.stats.LastExportTime = time.Now()
		e.stats.mu.Unlock()
	}

	return results, nil
}

// ============================================================================
// Filtering
// ============================================================================

// filterObjects filters objects based on configuration.
func (e *Exporter) filterObjects(objects []STIXObject) []STIXObject {
	var filtered []STIXObject

	for _, obj := range objects {
		if !e.shouldInclude(obj) {
			continue
		}
		filtered = append(filtered, obj)
	}

	return filtered
}

// filterIndicators filters indicators based on configuration.
func (e *Exporter) filterIndicators(indicators []*Indicator) []*Indicator {
	var filtered []*Indicator

	for _, ind := range indicators {
		if !e.shouldIncludeIndicator(ind) {
			continue
		}
		filtered = append(filtered, ind)
	}

	return filtered
}

// shouldInclude determines if an object should be included.
func (e *Exporter) shouldInclude(obj STIXObject) bool {
	// Filter by type
	if len(e.config.ObjectTypes) > 0 {
		found := false
		objType := string(obj.GetType())
		for _, t := range e.config.ObjectTypes {
			if t == objType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by time range
	if !e.config.StartTime.IsZero() && obj.GetCreated().Before(e.config.StartTime) {
		return false
	}
	if !e.config.EndTime.IsZero() && obj.GetCreated().After(e.config.EndTime) {
		return false
	}

	// Check confidence for indicators
	if ind, ok := obj.(*Indicator); ok {
		if e.config.MinConfidence > 0 && ind.Confidence < e.config.MinConfidence {
			return false
		}

		// Filter by labels
		if len(e.config.Labels) > 0 && len(ind.Labels) > 0 {
			found := false
			for _, label := range e.config.Labels {
				for _, objLabel := range ind.Labels {
					if label == objLabel {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// shouldIncludeIndicator determines if an indicator should be included.
func (e *Exporter) shouldIncludeIndicator(ind *Indicator) bool {
	// Filter by confidence
	if e.config.MinConfidence > 0 && ind.Confidence < e.config.MinConfidence {
		return false
	}

	// Filter by time range
	if !e.config.StartTime.IsZero() && ind.Created.Before(e.config.StartTime) {
		return false
	}
	if !e.config.EndTime.IsZero() && ind.Created.After(e.config.EndTime) {
		return false
	}

	// Filter by labels
	if len(e.config.Labels) > 0 && len(ind.Labels) > 0 {
		found := false
		for _, label := range e.config.Labels {
			for _, objLabel := range ind.Labels {
				if label == objLabel {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// ============================================================================
// File Operations
// ============================================================================

// writeFile writes data to a file.
func (e *Exporter) writeFile(path string, data []byte) error {
	// Create directory if needed
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return NewError("export_write", "failed to create directory", false, err)
		}
	}

	// Write file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return NewError("export_write", "failed to write file", false, err)
	}

	return nil
}

// ============================================================================
// Streaming Export
// ============================================================================

// StreamExporter provides streaming export capabilities.
type StreamExporter struct {
	config  ExportConfig
	builder *STIXBuilder
}

// NewStreamExporter creates a new streaming exporter.
func NewStreamExporter(config ExportConfig, builder *STIXBuilder) *StreamExporter {
	return &StreamExporter{
		config:  config,
		builder: builder,
	}
}

// StreamToWriter exports objects as a stream to a writer.
func (se *StreamExporter) StreamToWriter(ctx context.Context, writer io.Writer, objectChan <-chan STIXObject) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	// Write opening bracket
	if _, err := writer.Write([]byte("{\n  \"type\": \"bundle\",\n  \"objects\": [\n")); err != nil {
		return err
	}

	first := true
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case obj, ok := <-objectChan:
			if !ok {
				// Channel closed, finish writing
				if _, err := writer.Write([]byte("\n  ]\n}")); err != nil {
					return err
				}
				return nil
			}

			if !first {
				if _, err := writer.Write([]byte(",\n")); err != nil {
					return err
				}
			}
			first = false

			if err := encoder.Encode(obj); err != nil {
				return err
			}
		}
	}
}

// ============================================================================
// Export Manager
// ============================================================================

// ExportManager manages multiple export destinations.
type ExportManager struct {
	mu        sync.RWMutex
	exporters map[string]*Exporter
	configs   map[string]ExportConfig
}

// NewExportManager creates a new export manager.
func NewExportManager() *ExportManager {
	return &ExportManager{
		exporters: make(map[string]*Exporter),
		configs:   make(map[string]ExportConfig),
	}
}

// AddExporter adds an exporter to the manager.
func (em *ExportManager) AddExporter(name string, exporter *Exporter, config ExportConfig) {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.exporters[name] = exporter
	em.configs[name] = config
}

// RemoveExporter removes an exporter from the manager.
func (em *ExportManager) RemoveExporter(name string) {
	em.mu.Lock()
	defer em.mu.Unlock()
	delete(em.exporters, name)
	delete(em.configs, name)
}

// GetExporter returns an exporter by name.
func (em *ExportManager) GetExporter(name string) *Exporter {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.exporters[name]
}

// ExportToAll exports to all configured destinations.
func (em *ExportManager) ExportToAll(ctx context.Context, objects []STIXObject) map[string]error {
	em.mu.RLock()
	defer em.mu.RUnlock()

	errors := make(map[string]error)
	var wg sync.WaitGroup

	for name, exporter := range em.exporters {
		wg.Add(1)
		go func(n string, e *Exporter) {
			defer wg.Done()

			config := em.configs[n]
			var err error

			switch config.Format {
			case "stix":
				err = e.ExportToSTIX(ctx, objects, config.OutputPath)
			case "json":
				err = e.ExportToJSON(ctx, objects, config.OutputPath)
			case "taxii":
				if config.OutputPath == "" {
					_, err = e.ExportToTAXII(ctx, objects, "api_root", "collection")
				}
			}

			if err != nil {
				errors[n] = err
			}
		}(name, exporter)
	}

	wg.Wait()
	return errors
}

// ============================================================================
// Utility Functions
// ============================================================================

// ComputeHash computes a hash of the exported data for integrity checking.
func ComputeHash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateExportFilename generates a filename for an export.
func GenerateExportFilename(format, prefix string) string {
	timestamp := time.Now().UTC().Format("20060102-150405")
	random := make([]byte, 4)
	rand.Read(random)
	suffix := hex.EncodeToString(random)

	if prefix == "" {
		prefix = "export"
	}

	ext := ".json"
	switch format {
	case "csv":
		ext = ".csv"
	case "stix":
		ext = ".json"
	}

	return fmt.Sprintf("%s-%s-%s%s", prefix, timestamp, suffix, ext)
}

// ValidateExport validates exported data.
func ValidateExport(data []byte, format string) error {
	switch format {
	case "stix", "json":
		var bundle Bundle
		if err := json.Unmarshal(data, &bundle); err != nil {
			return NewError("validate_export", "invalid JSON format", false, err)
		}
		if bundle.Type != STIXTypeBundle {
			return NewError("validate_export", "not a valid STIX bundle", false, nil)
		}
	case "csv":
		// Basic CSV validation - check for header row
		lines := strings.Split(string(data), "\n")
		if len(lines) == 0 {
			return NewError("validate_export", "empty CSV file", false, nil)
		}
	default:
		return NewError("validate_export", "unsupported format: "+format, false, nil)
	}
	return nil
}
