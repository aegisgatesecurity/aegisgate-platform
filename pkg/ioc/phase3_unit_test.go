// SPDX-License-Identifier: Apache-2.0

package ioc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ctxkeys"
)

// makeValidIOC creates a valid IOC with the given parameters.
// fingerprint must be unique; it will be hashed to 64 chars.
func makeValidIOC(id string, iocType IOCType, severity Severity, sourceProvider string, extra ...func(*IOC)) IOC {
	h := sha256.Sum256([]byte(id))
	fp := fmt.Sprintf("%x", h)

	ioc := IOC{
		Fingerprint:    fp,
		Type:           iocType,
		Severity:       severity,
		Count:          1,
		FirstSeen:      time.Now().UTC(),
		LastSeen:       time.Now().UTC(),
		SourceProvider: sourceProvider,
		AffectsGateway: true, // required when SourceProvider is set
	}
	for _, fn := range extra {
		fn(&ioc)
	}
	return ioc
}

// fp generates a 64-char SHA-256 hex fingerprint from a string.
func fp(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)
}

// =====================================================================
// TenantFromContext tests
// =====================================================================

func TestPhase3_TenantFromContext_WithTenant(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-123")
	ctx = context.WithValue(ctx, ctxkeys.IsAdmin, true)

	tenantID, isAdmin := TenantFromContext(ctx)
	if tenantID != "tenant-123" {
		t.Fatalf("expected tenant-123, got %s", tenantID)
	}
	if !isAdmin {
		t.Fatal("expected isAdmin=true")
	}
}

func TestPhase3_TenantFromContext_Empty(t *testing.T) {
	tenantID, isAdmin := TenantFromContext(context.Background())
	if tenantID != "" {
		t.Fatalf("expected empty tenant, got %s", tenantID)
	}
	if isAdmin {
		t.Fatal("expected isAdmin=false")
	}
}

func TestPhase3_TenantFromContext_TenantOnly(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-456")
	tenantID, isAdmin := TenantFromContext(ctx)
	if tenantID != "tenant-456" {
		t.Fatalf("expected tenant-456, got %s", tenantID)
	}
	if isAdmin {
		t.Fatal("expected isAdmin=false when only tenant set")
	}
}

// =====================================================================
// In-memory Store Query tests
// =====================================================================

func TestPhase3_Store_QueryByType(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("type-1", IOCTypeProxyResponse, SeverityHigh, "chatgpt")
	ioc2 := makeValidIOC("type-2", IOCTypePromptInjection, SeverityCritical, "claude")

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	results := store.Query(IOCQuery{Type: IOCTypeProxyResponse})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestPhase3_Store_QueryBySourceProvider(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("sp-1", IOCTypeProxyResponse, SeverityHigh, "chatgpt")
	ioc2 := makeValidIOC("sp-2", IOCTypePromptInjection, SeverityCritical, "claude")

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	// Fast path: SourceProvider index
	results := store.Query(IOCQuery{SourceProvider: "chatgpt"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestPhase3_Store_QueryBySourceProvider_NotFound(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("sp-nf", IOCTypeProxyResponse, SeverityHigh, "chatgpt")
	if _, err := store.Observe(ioc1); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	results := store.Query(IOCQuery{SourceProvider: "nonexistent"})
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestPhase3_Store_QueryBySeverityMin(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("sev-1", IOCTypeProxyResponse, SeverityLow, "sp1")
	ioc2 := makeValidIOC("sev-2", IOCTypeProxyResponse, SeverityHigh, "sp2")
	ioc3 := makeValidIOC("sev-3", IOCTypeProxyResponse, SeverityCritical, "sp3")

	for _, i := range []IOC{ioc1, ioc2, ioc3} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	results := store.Query(IOCQuery{SeverityMin: SeverityHigh})
	if len(results) != 2 {
		t.Fatalf("expected 2 results with sev>=high, got %d", len(results))
	}
}

func TestPhase3_Store_QueryByCategory(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("cat-1", IOCTypePIIDetected, SeverityHigh, "sp1", func(i *IOC) { i.Category = "pii_email" })
	ioc2 := makeValidIOC("cat-2", IOCTypeSecretLeak, SeverityHigh, "sp2", func(i *IOC) { i.Category = "secret_api_key" })

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	results := store.Query(IOCQuery{Category: "pii_email"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

func TestPhase3_Store_QueryByAffectsLens(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("lens-1", IOCTypeProxyResponse, SeverityHigh, "sp1", func(i *IOC) { i.AffectsLens = true })
	ioc2 := makeValidIOC("lens-2", IOCTypeProxyResponse, SeverityHigh, "sp2", func(i *IOC) { i.AffectsLens = false })

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	lensTrue := true
	results := store.Query(IOCQuery{AffectsLens: &lensTrue})
	if len(results) != 1 {
		t.Fatalf("expected 1 result with AffectsLens=true, got %d", len(results))
	}
}

func TestPhase3_Store_QueryByAffectsGateway(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("gw-1", IOCTypeProxyResponse, SeverityHigh, "sp1", func(i *IOC) { i.AffectsGateway = true })
	ioc2 := makeValidIOC("gw-2", IOCTypeProxyResponse, SeverityHigh, "sp2", func(i *IOC) { i.AffectsGateway = false; i.AffectsLens = true })

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	gwFalse := false
	results := store.Query(IOCQuery{AffectsGateway: &gwFalse})
	if len(results) != 1 {
		t.Fatalf("expected 1 result with AffectsGateway=false, got %d", len(results))
	}
}

func TestPhase3_Store_QueryWithTenantContext(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("tenant-1", IOCTypeProxyResponse, SeverityHigh, "sp1", func(i *IOC) { i.TenantID = "tenant-a" })
	ioc2 := makeValidIOC("tenant-2", IOCTypeProxyResponse, SeverityHigh, "sp2", func(i *IOC) { i.TenantID = "tenant-b" })

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	// Query as tenant-a (non-admin) — should only see tenant-a IOCs
	results := store.Query(IOCQuery{}, TenantContext{TenantID: "tenant-a", IsAdmin: false})
	if len(results) != 1 {
		t.Fatalf("expected 1 result for tenant-a, got %d", len(results))
	}

	// Query as admin — should see all
	results = store.Query(IOCQuery{}, TenantContext{TenantID: "tenant-a", IsAdmin: true})
	if len(results) != 2 {
		t.Fatalf("expected 2 results for admin, got %d", len(results))
	}
}

func TestPhase3_Store_Flush_NoDiskPath(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func TestPhase3_Store_Flush_WithDiskPath(t *testing.T) {
	diskPath := t.TempDir() + "/test_iocs.json"
	store, err := NewStore(StoreConfig{DiskPath: diskPath})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ioc1 := makeValidIOC("flush-1", IOCTypeProxyResponse, SeverityHigh, "sp1")
	if _, err := store.Observe(ioc1); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	if err := store.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Flush again — should be no-op (not dirty)
	if err := store.Flush(); err != nil {
		t.Fatalf("Flush 2: %v", err)
	}
}

func TestPhase3_Store_Prune(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	oldIOC := makeValidIOC("prune-old", IOCTypeProxyResponse, SeverityHigh, "sp1", func(i *IOC) { i.LastSeen = time.Now().UTC().Add(-48 * time.Hour) })
	newIOC := makeValidIOC("prune-new", IOCTypeProxyResponse, SeverityHigh, "sp2")

	for _, i := range []IOC{oldIOC, newIOC} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	removed := store.Prune(24 * time.Hour)
	if removed != 1 {
		t.Fatalf("expected 1 pruned, got %d", removed)
	}
}

func TestPhase3_Store_SnapshotSince(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now().UTC()
	ioc1 := makeValidIOC("snap-1", IOCTypeProxyResponse, SeverityHigh, "sp1", func(i *IOC) { i.LastSeen = now })
	ioc2 := makeValidIOC("snap-2", IOCTypeProxyResponse, SeverityHigh, "sp2", func(i *IOC) { i.LastSeen = now.Add(-2 * time.Hour) })

	for _, i := range []IOC{ioc1, ioc2} {
		if _, err := store.Observe(i); err != nil {
			t.Fatalf("Observe: %v", err)
		}
	}

	results := store.SnapshotSince(now.Add(-1 * time.Hour))
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// =====================================================================
// FeedManager Stop test
// =====================================================================

func TestPhase3_FeedManager_Stop_NoFeeds(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	fm, err := NewFeedManager(store, nil)
	if err != nil {
		t.Fatalf("NewFeedManager: %v", err)
	}

	fm.Stop()
}

// =====================================================================
// WithTenantContextOrPool nil pool test
// =====================================================================

func TestPhase3_WithTenantContextOrPool_NilPool(t *testing.T) {
	err := WithTenantContextOrPool(context.Background(), nil, "tenant-1", false, func(q DBQuerier) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

// =====================================================================
// mergeQuarantinedIOC test
// =====================================================================

func TestPhase3_Store_mergeQuarantinedIOC(t *testing.T) {
	store, err := NewStore(StoreConfig{})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Invalid IOC (empty fingerprint) should be skipped
	store.mergeQuarantinedIOC(IOC{Fingerprint: ""})
}
