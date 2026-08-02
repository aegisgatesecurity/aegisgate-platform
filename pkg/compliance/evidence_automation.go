// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Evidence Collection Automation - Compliance Evidence Management
// =========================================================================
//
// This module automates the collection, storage, and verification of
// compliance evidence. It attaches screenshots, logs, configs, and scan
// results to compliance controls, supporting frameworks like SOC 2,
// ISO 27001, FedRAMP, HIPAA, and PCI-DSS.
//
// Key features:
//   - Automatic evidence collection via registered collector functions
//   - Content integrity verification via SHA-256 hashing
//   - Evidence lifecycle management (pending → verified → expired/superseded)
//   - Framework-wide evidence collection and reporting
//   - Export in JSON and CSV formats
//
// =========================================================================

package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// EvidenceType categorizes the kind of evidence.
type EvidenceType string

const (
	EvidenceScreenshot   EvidenceType = "screenshot"
	EvidenceLog          EvidenceType = "log"
	EvidenceConfig       EvidenceType = "config"
	EvidenceScanResult   EvidenceType = "scan_result"
	EvidenceAttestation  EvidenceType = "attestation"
	EvidencePolicyOutput EvidenceType = "policy_output"
	EvidenceMetric       EvidenceType = "metric"
	EvidenceCertificate  EvidenceType = "certificate"
	EvidenceAuditTrail   EvidenceType = "audit_trail"
)

// EvidenceStatus represents the verification status of evidence.
type EvidenceStatus string

const (
	EvidencePending    EvidenceStatus = "pending"
	EvidenceVerified   EvidenceStatus = "verified"
	EvidenceExpired    EvidenceStatus = "expired"
	EvidenceRejected   EvidenceStatus = "rejected"
	EvidenceSuperseded EvidenceStatus = "superseded"
)

// EvidenceItem is a single piece of collected evidence.
type EvidenceItem struct {
	ID          string
	Type        EvidenceType
	Framework   string
	ControlID   string
	Description string
	CollectedAt time.Time
	CollectedBy string
	Content     []byte
	ContentHash string
	Source      string
	Status      EvidenceStatus
	VerifiedAt  *time.Time
	VerifiedBy  string
	ExpiresAt   *time.Time
	Metadata    map[string]string
	Tags        []string
}

// EvidenceCollection is a group of evidence items for an assessment.
type EvidenceCollection struct {
	ID          string
	Name        string
	Description string
	Framework   string
	Items       []*EvidenceItem
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Status      EvidenceStatus
}

// EvidenceCollector manages evidence collection and verification.
type EvidenceCollector struct {
	mu          sync.RWMutex
	items       map[string]*EvidenceItem
	collections map[string]*EvidenceCollection
	collectors  map[EvidenceType]EvidenceCollectorFunc
}

// EvidenceCollectorFunc is a function that collects evidence automatically.
type EvidenceCollectorFunc func(ctx context.Context, controlID string) ([]byte, error)

// EvidenceReport is a generated evidence report.
type EvidenceReport struct {
	ID          string
	Framework   string
	GeneratedAt time.Time
	Collections []*EvidenceCollection
	Summary     EvidenceSummary
}

// EvidenceSummary provides counts and statistics.
type EvidenceSummary struct {
	TotalItems    int
	ByType        map[EvidenceType]int
	ByStatus      map[EvidenceStatus]int
	ByFramework   map[string]int
	CoveragePct   float64
	LastCollected time.Time
}

// EvidenceFilter allows querying evidence by various criteria.
type EvidenceFilter struct {
	Framework string
	ControlID string
	Type      EvidenceType
	Status    EvidenceStatus
	Since     string
	Until     string
}

// NewEvidenceCollector creates a new EvidenceCollector with initialized maps
// and default collectors registered.
func NewEvidenceCollector() *EvidenceCollector {
	ec := &EvidenceCollector{
		items:       make(map[string]*EvidenceItem),
		collections: make(map[string]*EvidenceCollection),
		collectors:  make(map[EvidenceType]EvidenceCollectorFunc),
	}
	for t, fn := range DefaultCollectors() {
		ec.collectors[t] = fn
	}
	return ec
}

// RegisterCollector registers an automatic collector function for a given
// evidence type. It overwrites any existing collector for that type.
func (ec *EvidenceCollector) RegisterCollector(evidenceType EvidenceType, fn EvidenceCollectorFunc) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.collectors[evidenceType] = fn
}

// CollectEvidence collects evidence using a registered collector for the
// given framework, controlID, and evidence type.
func (ec *EvidenceCollector) CollectEvidence(ctx context.Context, framework, controlID string, evidenceType EvidenceType) (*EvidenceItem, error) {
	ec.mu.RLock()
	fn, ok := ec.collectors[evidenceType]
	ec.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no collector registered for evidence type: %s", evidenceType)
	}

	content, err := fn(ctx, controlID)
	if err != nil {
		return nil, fmt.Errorf("collector for %s failed: %w", evidenceType, err)
	}

	item := &EvidenceItem{
		ID:          generateEvidenceID(),
		Type:        evidenceType,
		Framework:   framework,
		ControlID:   controlID,
		Description: fmt.Sprintf("Auto-collected %s evidence for %s/%s", evidenceType, framework, controlID),
		CollectedAt: time.Now().UTC(),
		CollectedBy: "evidence-automation",
		Content:     content,
		ContentHash: ComputeHash(content),
		Source:      "auto",
		Status:      EvidencePending,
		Metadata:    make(map[string]string),
	}

	ec.mu.Lock()
	ec.items[item.ID] = item
	ec.mu.Unlock()

	return item, nil
}

// CollectForFramework collects all evidence for a given framework by iterating
// through all registered collectors.
func (ec *EvidenceCollector) CollectForFramework(ctx context.Context, framework string) (*EvidenceCollection, error) {
	collection := &EvidenceCollection{
		ID:          generateCollectionID(),
		Name:        fmt.Sprintf("Evidence collection for %s", framework),
		Description: fmt.Sprintf("Automated evidence collection for framework %s", framework),
		Framework:   framework,
		Items:       []*EvidenceItem{},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		Status:      EvidencePending,
	}

	ec.mu.RLock()
	collectors := make(map[EvidenceType]EvidenceCollectorFunc, len(ec.collectors))
	for k, v := range ec.collectors {
		collectors[k] = v
	}
	ec.mu.RUnlock()

	for evidenceType, fn := range collectors {
		content, err := fn(ctx, framework)
		if err != nil {
			continue // skip failed collectors
		}

		item := &EvidenceItem{
			ID:          generateEvidenceID(),
			Type:        evidenceType,
			Framework:   framework,
			ControlID:   framework, // framework-level collection
			Description: fmt.Sprintf("Auto-collected %s evidence for %s", evidenceType, framework),
			CollectedAt: time.Now().UTC(),
			CollectedBy: "evidence-automation",
			Content:     content,
			ContentHash: ComputeHash(content),
			Source:      "auto",
			Status:      EvidencePending,
			Metadata:    make(map[string]string),
		}

		collection.Items = append(collection.Items, item)

		ec.mu.Lock()
		ec.items[item.ID] = item
		ec.mu.Unlock()
	}

	ec.mu.Lock()
	ec.collections[collection.ID] = collection
	ec.mu.Unlock()

	return collection, nil
}

// AddEvidence manually adds an evidence item to the collector.
// It computes the content hash if not already set.
func (ec *EvidenceCollector) AddEvidence(item *EvidenceItem) error {
	if item.ID == "" {
		item.ID = generateEvidenceID()
	}
	if item.ContentHash == "" && len(item.Content) > 0 {
		item.ContentHash = ComputeHash(item.Content)
	}
	if item.Status == "" {
		item.Status = EvidencePending
	}
	if item.CollectedAt.IsZero() {
		item.CollectedAt = time.Now().UTC()
	}
	if item.Metadata == nil {
		item.Metadata = make(map[string]string)
	}

	ec.mu.Lock()
	defer ec.mu.Unlock()

	if _, exists := ec.items[item.ID]; exists {
		return fmt.Errorf("evidence item with ID %s already exists", item.ID)
	}

	ec.items[item.ID] = item
	return nil
}

// VerifyEvidence marks an evidence item as verified.
func (ec *EvidenceCollector) VerifyEvidence(id string, verifiedBy string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	item, ok := ec.items[id]
	if !ok {
		return fmt.Errorf("evidence item %s not found", id)
	}

	now := time.Now().UTC()
	item.Status = EvidenceVerified
	item.VerifiedAt = &now
	item.VerifiedBy = verifiedBy
	return nil
}

// ExpireEvidence marks an evidence item as expired.
func (ec *EvidenceCollector) ExpireEvidence(id string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	item, ok := ec.items[id]
	if !ok {
		return fmt.Errorf("evidence item %s not found", id)
	}

	item.Status = EvidenceExpired
	return nil
}

// GetEvidence retrieves an evidence item by ID.
func (ec *EvidenceCollector) GetEvidence(id string) (*EvidenceItem, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	item, ok := ec.items[id]
	if !ok {
		return nil, fmt.Errorf("evidence item %s not found", id)
	}
	return item, nil
}

// QueryEvidence returns evidence items matching the given filter criteria.
func (ec *EvidenceCollector) QueryEvidence(filter EvidenceFilter) []*EvidenceItem {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	var results []*EvidenceItem
	for _, item := range ec.items {
		if filter.Framework != "" && item.Framework != filter.Framework {
			continue
		}
		if filter.ControlID != "" && item.ControlID != filter.ControlID {
			continue
		}
		if filter.Type != "" && item.Type != filter.Type {
			continue
		}
		if filter.Status != "" && item.Status != filter.Status {
			continue
		}
		if filter.Since != "" {
			since, err := time.Parse(time.RFC3339, filter.Since)
			if err == nil && item.CollectedAt.Before(since) {
				continue
			}
		}
		if filter.Until != "" {
			until, err := time.Parse(time.RFC3339, filter.Until)
			if err == nil && item.CollectedAt.After(until) {
				continue
			}
		}
		results = append(results, item)
	}

	// Sort by collection time for deterministic output.
	sort.Slice(results, func(i, j int) bool {
		return results[i].CollectedAt.Before(results[j].CollectedAt)
	})

	return results
}

// CreateCollection creates a new evidence collection.
func (ec *EvidenceCollector) CreateCollection(name, description, framework string) (*EvidenceCollection, error) {
	if name == "" {
		return nil, fmt.Errorf("collection name is required")
	}

	collection := &EvidenceCollection{
		ID:          generateCollectionID(),
		Name:        name,
		Description: description,
		Framework:   framework,
		Items:       []*EvidenceItem{},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		Status:      EvidencePending,
	}

	ec.mu.Lock()
	ec.collections[collection.ID] = collection
	ec.mu.Unlock()

	return collection, nil
}

// AddToCollection adds one or more evidence items to an existing collection.
func (ec *EvidenceCollector) AddToCollection(collectionID string, itemIDs ...string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	collection, ok := ec.collections[collectionID]
	if !ok {
		return fmt.Errorf("collection %s not found", collectionID)
	}

	for _, itemID := range itemIDs {
		item, ok := ec.items[itemID]
		if !ok {
			return fmt.Errorf("evidence item %s not found", itemID)
		}
		collection.Items = append(collection.Items, item)
	}

	collection.UpdatedAt = time.Now().UTC()
	return nil
}

// GenerateReport generates a full evidence report for a given framework.
func (ec *EvidenceCollector) GenerateReport(ctx context.Context, framework string) (*EvidenceReport, error) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	report := &EvidenceReport{
		ID:          generateReportID(),
		Framework:   framework,
		GeneratedAt: time.Now().UTC(),
	}

	// Find all collections for this framework.
	for _, collection := range ec.collections {
		if collection.Framework == framework {
			report.Collections = append(report.Collections, collection)
		}
	}

	// Compute summary.
	summary := EvidenceSummary{
		ByType:      make(map[EvidenceType]int),
		ByStatus:    make(map[EvidenceStatus]int),
		ByFramework: make(map[string]int),
	}

	var lastCollected time.Time
	for _, item := range ec.items {
		if item.Framework != framework {
			continue
		}
		summary.TotalItems++
		summary.ByType[item.Type]++
		summary.ByStatus[item.Status]++
		summary.ByFramework[item.Framework]++
		if item.CollectedAt.After(lastCollected) {
			lastCollected = item.CollectedAt
		}
	}

	summary.LastCollected = lastCollected
	summary.CoveragePct = ec.calculateCoverageLocked(framework)
	report.Summary = summary

	return report, nil
}

// CalculateCoverage returns the percentage of controls that have evidence
// for the given framework.
func (ec *EvidenceCollector) CalculateCoverage(framework string) float64 {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.calculateCoverageLocked(framework)
}

// calculateCoverageLocked computes coverage without acquiring the lock.
// It estimates coverage as a ratio of unique controls with evidence to
// a standard set of control counts per framework.
func (ec *EvidenceCollector) calculateCoverageLocked(framework string) float64 {
	controlsWithEvidence := make(map[string]bool)
	for _, item := range ec.items {
		if item.Framework == framework && item.ControlID != "" {
			controlsWithEvidence[item.ControlID] = true
		}
	}

	totalControls := frameworkControlCount(framework)
	if totalControls == 0 {
		return 0
	}

	pct := float64(len(controlsWithEvidence)) / float64(totalControls) * 100
	return math.Round(pct*100) / 100 // round to 2 decimal places
}

// frameworkControlCount returns the total number of controls for a framework.
// This uses well-known counts for standard frameworks.
func frameworkControlCount(framework string) int {
	controlCounts := map[string]int{
		"SOC2":         64,
		"ISO27001":     114,
		"ISO42001":     38,
		"NIST-800-171": 110,
		"FedRAMP":      325,
		"HIPAA":        55,
		"PCI-DSS":      265,
		"NIST-AI-RMF":  72,
		"OWASP-LLM":    10,
		"EU-AI-ACT":    82,
		"CSA-STAR":     55,
		"TISAX":        39,
		"FIPS-140":     11,
		"CMMC-L2":      17,
		"CIS":          153,
		"CCPA":         12,
		"HITRUST":      135,
	}

	if count, ok := controlCounts[framework]; ok {
		return count
	}
	// Default to 100 for unknown frameworks.
	return 100
}

// ExportCollection exports an evidence collection in the specified format.
// Supported formats: "json", "csv".
func (ec *EvidenceCollector) ExportCollection(collectionID string, format string) ([]byte, error) {
	ec.mu.RLock()
	collection, ok := ec.collections[collectionID]
	ec.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("collection %s not found", collectionID)
	}

	switch strings.ToLower(format) {
	case "json":
		return exportCollectionJSON(collection)
	case "csv":
		return exportCollectionCSV(collection)
	default:
		return nil, fmt.Errorf("unsupported export format: %s (supported: json, csv)", format)
	}
}

// exportCollectionJSON serializes a collection to JSON.
func exportCollectionJSON(collection *EvidenceCollection) ([]byte, error) {
	type exportItem struct {
		ID          string            `json:"id"`
		Type        EvidenceType      `json:"type"`
		Framework   string            `json:"framework"`
		ControlID   string            `json:"control_id"`
		Description string            `json:"description"`
		CollectedAt time.Time         `json:"collected_at"`
		CollectedBy string            `json:"collected_by"`
		ContentHash string            `json:"content_hash"`
		Source      string            `json:"source"`
		Status      EvidenceStatus    `json:"status"`
		VerifiedBy  string            `json:"verified_by,omitempty"`
		Metadata    map[string]string `json:"metadata,omitempty"`
		Tags        []string          `json:"tags,omitempty"`
	}

	type exportCollection struct {
		ID          string         `json:"id"`
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Framework   string         `json:"framework"`
		Status      EvidenceStatus `json:"status"`
		CreatedAt   time.Time      `json:"created_at"`
		UpdatedAt   time.Time      `json:"updated_at"`
		Items       []exportItem   `json:"items"`
	}

	items := make([]exportItem, 0, len(collection.Items))
	for _, item := range collection.Items {
		items = append(items, exportItem{
			ID:          item.ID,
			Type:        item.Type,
			Framework:   item.Framework,
			ControlID:   item.ControlID,
			Description: item.Description,
			CollectedAt: item.CollectedAt,
			CollectedBy: item.CollectedBy,
			ContentHash: item.ContentHash,
			Source:      item.Source,
			Status:      item.Status,
			VerifiedBy:  item.VerifiedBy,
			Metadata:    item.Metadata,
			Tags:        item.Tags,
		})
	}

	output := exportCollection{
		ID:          collection.ID,
		Name:        collection.Name,
		Description: collection.Description,
		Framework:   collection.Framework,
		Status:      collection.Status,
		CreatedAt:   collection.CreatedAt,
		UpdatedAt:   collection.UpdatedAt,
		Items:       items,
	}

	return json.MarshalIndent(output, "", "  ")
}

// exportCollectionCSV serializes a collection to CSV.
func exportCollectionCSV(collection *EvidenceCollection) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	header := []string{"id", "type", "framework", "control_id", "description", "collected_at", "collected_by", "content_hash", "source", "status", "verified_by"}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, item := range collection.Items {
		verifiedBy := item.VerifiedBy
		record := []string{
			item.ID,
			string(item.Type),
			item.Framework,
			item.ControlID,
			item.Description,
			item.CollectedAt.Format(time.RFC3339),
			item.CollectedBy,
			item.ContentHash,
			item.Source,
			string(item.Status),
			verifiedBy,
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV write error: %w", err)
	}

	return []byte(buf.String()), nil
}

// DefaultCollectors returns pre-registered collector functions for automatic
// evidence collection. These are stub implementations that return placeholder
// data since they cannot import actual scanner/metrics packages without
// creating circular dependencies.
func DefaultCollectors() map[EvidenceType]EvidenceCollectorFunc {
	return map[EvidenceType]EvidenceCollectorFunc{
		EvidenceScanResult: func(ctx context.Context, controlID string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"scan_result": "automated", "control_id": %q, "timestamp": %q, "status": "pass"}`, controlID, time.Now().UTC().Format(time.RFC3339))), nil
		},
		EvidenceAuditTrail: func(ctx context.Context, controlID string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"audit_trail": "automated", "control_id": %q, "timestamp": %q, "entries": 0}`, controlID, time.Now().UTC().Format(time.RFC3339))), nil
		},
		EvidenceConfig: func(ctx context.Context, controlID string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"config": "automated", "control_id": %q, "timestamp": %q, "settings": {}}`, controlID, time.Now().UTC().Format(time.RFC3339))), nil
		},
		EvidenceMetric: func(ctx context.Context, controlID string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"metric": "automated", "control_id": %q, "timestamp": %q, "values": {}}`, controlID, time.Now().UTC().Format(time.RFC3339))), nil
		},
	}
}

// ComputeHash computes SHA-256 of the given content and returns the hex
// encoded string.
func ComputeHash(content []byte) string {
	h := sha256.New()
	h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// generateEvidenceID creates a unique identifier for an evidence item.
func generateEvidenceID() string {
	return fmt.Sprintf("ev-%s", generateID())
}

// generateCollectionID creates a unique identifier for a collection.
func generateCollectionID() string {
	return fmt.Sprintf("col-%s", generateID())
}

// generateReportID creates a unique identifier for a report.
func generateReportID() string {
	return fmt.Sprintf("rpt-%s", generateID())
}

// generateID creates a short unique identifier based on the current time.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// VerifyContentHash checks that the content hash of an evidence item matches
// its stored ContentHash. Returns nil if the hash is valid.
func VerifyContentHash(item *EvidenceItem) error {
	if len(item.Content) == 0 && item.ContentHash == "" {
		return nil
	}
	expected := ComputeHash(item.Content)
	if item.ContentHash != expected {
		return fmt.Errorf("content hash mismatch: expected %s, got %s", expected, item.ContentHash)
	}
	return nil
}
