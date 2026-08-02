// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// Evidence Collection Automation - Tests
// =========================================================================

package compliance_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/compliance"
)

func TestNewEvidenceCollector(t *testing.T) {
	ec := compliance.NewEvidenceCollector()
	assert.NotNil(t, ec)

	// Verify default collectors are registered.
	collectors := compliance.DefaultCollectors()
	assert.Equal(t, len(collectors), 4, "should have 4 default collectors")
}

func TestRegisterCollector(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	customCollector := func(ctx context.Context, controlID string) ([]byte, error) {
		return []byte("custom evidence"), nil
	}

	ec.RegisterCollector(compliance.EvidenceScreenshot, customCollector)

	item, err := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScreenshot)
	require.NoError(t, err)
	assert.NotNil(t, item)
	assert.Equal(t, []byte("custom evidence"), item.Content)
	assert.Equal(t, compliance.EvidenceScreenshot, item.Type)
}

func TestCollectEvidence_WithCollector(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, err := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	require.NoError(t, err)
	assert.NotNil(t, item)
	assert.Equal(t, compliance.EvidenceScanResult, item.Type)
	assert.Equal(t, "SOC2", item.Framework)
	assert.Equal(t, "CC6.1", item.ControlID)
	assert.Equal(t, compliance.EvidencePending, item.Status)
	assert.NotEmpty(t, item.ContentHash)
	assert.Equal(t, "auto", item.Source)
}

func TestCollectEvidence_NoCollector(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	// EvidenceScreenshot has no default collector.
	_, err := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScreenshot)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no collector registered")
}

func TestAddEvidence(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	content := []byte("test evidence content")
	item := &compliance.EvidenceItem{
		Type:        compliance.EvidenceLog,
		Framework:   "HIPAA",
		ControlID:   "164.312(a)",
		Description: "Manual log evidence",
		Content:     content,
		Source:      "manual",
		Status:      compliance.EvidencePending,
	}

	err := ec.AddEvidence(item)
	require.NoError(t, err)
	assert.NotEmpty(t, item.ID, "should assign ID")
	assert.NotEmpty(t, item.ContentHash, "should compute content hash")
	assert.Equal(t, compliance.ComputeHash(content), item.ContentHash)
}

func TestAddEvidence_DuplicateID(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item := &compliance.EvidenceItem{
		ID:      "ev-test-dup",
		Type:    compliance.EvidenceLog,
		Content: []byte("content"),
	}

	err := ec.AddEvidence(item)
	require.NoError(t, err)

	// Add again with same ID.
	item2 := &compliance.EvidenceItem{
		ID:      "ev-test-dup",
		Type:    compliance.EvidenceLog,
		Content: []byte("different content"),
	}
	err = ec.AddEvidence(item2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestVerifyEvidence(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, err := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidencePending, item.Status)

	err = ec.VerifyEvidence(item.ID, "auditor@example.com")
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidenceVerified, item.Status)
	assert.NotNil(t, item.VerifiedAt)
	assert.Equal(t, "auditor@example.com", item.VerifiedBy)
}

func TestVerifyEvidence_NotFound(t *testing.T) {
	ec := compliance.NewEvidenceCollector()
	err := ec.VerifyEvidence("nonexistent", "auditor@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExpireEvidence(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, err := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidencePending, item.Status)

	err = ec.ExpireEvidence(item.ID)
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidenceExpired, item.Status)
}

func TestExpireEvidence_NotFound(t *testing.T) {
	ec := compliance.NewEvidenceCollector()
	err := ec.ExpireEvidence("nonexistent")
	assert.Error(t, err)
}

func TestGetEvidence(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, err := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	require.NoError(t, err)

	retrieved, err := ec.GetEvidence(item.ID)
	require.NoError(t, err)
	assert.Equal(t, item.ID, retrieved.ID)
	assert.Equal(t, item.ContentHash, retrieved.ContentHash)
}

func TestGetEvidence_NotFound(t *testing.T) {
	ec := compliance.NewEvidenceCollector()
	_, err := ec.GetEvidence("nonexistent")
	assert.Error(t, err)
}

func TestQueryEvidence_FilterByFramework(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	_, _ = ec.CollectEvidence(context.Background(), "HIPAA", "164.312(a)", compliance.EvidenceAuditTrail)
	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC7.1", compliance.EvidenceMetric)

	results := ec.QueryEvidence(compliance.EvidenceFilter{Framework: "SOC2"})
	assert.Len(t, results, 2)
	for _, item := range results {
		assert.Equal(t, "SOC2", item.Framework)
	}
}

func TestQueryEvidence_FilterByType(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC7.1", compliance.EvidenceAuditTrail)

	results := ec.QueryEvidence(compliance.EvidenceFilter{Type: compliance.EvidenceScanResult})
	assert.Len(t, results, 1)
	assert.Equal(t, compliance.EvidenceScanResult, results[0].Type)
}

func TestQueryEvidence_FilterByStatus(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item1, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC7.1", compliance.EvidenceAuditTrail)

	// Verify first item.
	_ = ec.VerifyEvidence(item1.ID, "auditor")

	results := ec.QueryEvidence(compliance.EvidenceFilter{Status: compliance.EvidenceVerified})
	assert.Len(t, results, 1)
	assert.Equal(t, compliance.EvidenceVerified, results[0].Status)
}

func TestQueryEvidence_FilterByControlID(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC7.1", compliance.EvidenceAuditTrail)

	results := ec.QueryEvidence(compliance.EvidenceFilter{ControlID: "CC6.1"})
	assert.Len(t, results, 1)
	assert.Equal(t, "CC6.1", results[0].ControlID)
}

func TestCreateCollection(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	collection, err := ec.CreateCollection("SOC2 Audit Q1", "Q1 2025 SOC2 evidence", "SOC2")
	require.NoError(t, err)
	assert.NotEmpty(t, collection.ID)
	assert.Equal(t, "SOC2 Audit Q1", collection.Name)
	assert.Equal(t, "SOC2", collection.Framework)
	assert.Equal(t, compliance.EvidencePending, collection.Status)
	assert.Empty(t, collection.Items)
}

func TestCreateCollection_EmptyName(t *testing.T) {
	ec := compliance.NewEvidenceCollector()
	_, err := ec.CreateCollection("", "description", "SOC2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestAddToCollection(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item1, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	item2, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC7.1", compliance.EvidenceAuditTrail)

	collection, err := ec.CreateCollection("SOC2 Audit", "Test collection", "SOC2")
	require.NoError(t, err)

	err = ec.AddToCollection(collection.ID, item1.ID, item2.ID)
	require.NoError(t, err)
	assert.Len(t, collection.Items, 2)
}

func TestAddToCollection_InvalidCollectionID(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	err := ec.AddToCollection("invalid-collection", item.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAddToCollection_InvalidItemID(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	collection, _ := ec.CreateCollection("SOC2 Audit", "Test collection", "SOC2")
	err := ec.AddToCollection(collection.ID, "invalid-item")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGenerateReport(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	// Collect some evidence and add to a collection.
	item, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	collection, _ := ec.CreateCollection("SOC2 Audit", "Test collection", "SOC2")
	_ = ec.AddToCollection(collection.ID, item.ID)

	report, err := ec.GenerateReport(context.Background(), "SOC2")
	require.NoError(t, err)
	assert.NotEmpty(t, report.ID)
	assert.Equal(t, "SOC2", report.Framework)
	assert.NotNil(t, report.GeneratedAt)
	assert.Len(t, report.Collections, 1)
	assert.GreaterOrEqual(t, report.Summary.TotalItems, 1)
}

func TestCalculateCoverage(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	// Collect evidence for 2 unique controls in SOC2 (which has 64 controls).
	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC7.1", compliance.EvidenceAuditTrail)

	coverage := ec.CalculateCoverage("SOC2")
	// 2 controls out of 64 = ~3.125%
	assert.Greater(t, coverage, 0.0)
	assert.Less(t, coverage, 10.0) // should be well below 10%
}

func TestCalculateCoverage_UnknownFramework(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	_, _ = ec.CollectEvidence(context.Background(), "UNKNOWN", "CTRL-1", compliance.EvidenceScanResult)

	coverage := ec.CalculateCoverage("UNKNOWN")
	// 1 control out of 100 (default) = 1%
	assert.Greater(t, coverage, 0.0)
}

func TestExportCollection_JSON(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	collection, _ := ec.CreateCollection("SOC2 Audit", "Test collection", "SOC2")
	_ = ec.AddToCollection(collection.ID, item.ID)

	data, err := ec.ExportCollection(collection.ID, "json")
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "SOC2 Audit", parsed["name"])
}

func TestExportCollection_CSV(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	collection, _ := ec.CreateCollection("SOC2 Audit", "Test collection", "SOC2")
	_ = ec.AddToCollection(collection.ID, item.ID)

	data, err := ec.ExportCollection(collection.ID, "csv")
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify it's valid CSV.
	reader := csv.NewReader(strings.NewReader(string(data)))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(records), 2) // header + at least one data row
}

func TestExportCollection_UnsupportedFormat(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	collection, _ := ec.CreateCollection("SOC2 Audit", "Test collection", "SOC2")

	_, err := ec.ExportCollection(collection.ID, "xml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestExportCollection_NotFound(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	_, err := ec.ExportCollection("nonexistent", "json")
	assert.Error(t, err)
}

func TestDefaultCollectors(t *testing.T) {
	collectors := compliance.DefaultCollectors()
	assert.Len(t, collectors, 4)

	expectedTypes := []compliance.EvidenceType{
		compliance.EvidenceScanResult,
		compliance.EvidenceAuditTrail,
		compliance.EvidenceConfig,
		compliance.EvidenceMetric,
	}
	for _, et := range expectedTypes {
		_, ok := collectors[et]
		assert.True(t, ok, "default collector for %s should be registered", et)
	}

	// Verify each default collector returns data.
	for _, et := range expectedTypes {
		data, err := collectors[et](context.Background(), "TEST-CTRL")
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
	}
}

func TestEvidenceItem_HashIntegrity(t *testing.T) {
	content := []byte("critical audit evidence data")
	expectedHash := compliance.ComputeHash(content)

	item := &compliance.EvidenceItem{
		Type:        compliance.EvidenceLog,
		Framework:   "SOC2",
		ControlID:   "CC6.1",
		Content:     content,
		ContentHash: expectedHash,
	}

	// Verify hash matches.
	err := compliance.VerifyContentHash(item)
	assert.NoError(t, err)

	// Tamper with content.
	item.Content = []byte("tampered evidence data")
	err = compliance.VerifyContentHash(item)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}

func TestEvidenceCollection_StatusTransition(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	// Create a collection.
	collection, err := ec.CreateCollection("Test Collection", "Test", "SOC2")
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidencePending, collection.Status)

	// Collect evidence and add to collection.
	item, _ := ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)
	_ = ec.AddToCollection(collection.ID, item.ID)

	// Verify the evidence.
	err = ec.VerifyEvidence(item.ID, "auditor@example.com")
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidenceVerified, item.Status)

	// Expire the evidence.
	err = ec.ExpireEvidence(item.ID)
	require.NoError(t, err)
	assert.Equal(t, compliance.EvidenceExpired, item.Status)
}

func TestCollectForFramework(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	collection, err := ec.CollectForFramework(context.Background(), "SOC2")
	require.NoError(t, err)
	assert.NotNil(t, collection)
	assert.Equal(t, "SOC2", collection.Framework)
	// Should have items from 4 default collectors.
	assert.GreaterOrEqual(t, len(collection.Items), 4)
}

func TestQueryEvidence_FilterByDateRange(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	since := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	until := time.Now().Add(1 * time.Hour).Format(time.RFC3339)

	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)

	results := ec.QueryEvidence(compliance.EvidenceFilter{
		Framework: "SOC2",
		Since:     since,
		Until:     until,
	})
	assert.GreaterOrEqual(t, len(results), 1)
}

func TestQueryEvidence_DateOutOfRange(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	// Use a date range far in the future.
	until := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)

	_, _ = ec.CollectEvidence(context.Background(), "SOC2", "CC6.1", compliance.EvidenceScanResult)

	results := ec.QueryEvidence(compliance.EvidenceFilter{
		Framework: "SOC2",
		Until:     until,
	})
	assert.Empty(t, results, "no evidence should match a past date range")
}

func TestAddEvidence_SetsDefaults(t *testing.T) {
	ec := compliance.NewEvidenceCollector()

	item := &compliance.EvidenceItem{
		Type:      compliance.EvidenceLog,
		Framework: "SOC2",
		ControlID: "CC6.1",
		Content:   []byte("test"),
	}

	err := ec.AddEvidence(item)
	require.NoError(t, err)
	assert.NotEmpty(t, item.ID)
	assert.NotEmpty(t, item.ContentHash)
	assert.Equal(t, compliance.EvidencePending, item.Status)
	assert.False(t, item.CollectedAt.IsZero())
}
