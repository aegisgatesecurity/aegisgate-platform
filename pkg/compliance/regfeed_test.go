// SPDX-License-Identifier: Apache-2.0
// Regulatory Change Feed Tests

package compliance

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewRegulatoryChangeFeed(t *testing.T) {
	f := NewRegulatoryChangeFeed()
	if f == nil {
		t.Fatal("NewRegulatoryChangeFeed returned nil")
	}
	if f.version != "3.6.0" {
		t.Errorf("expected version 3.6.0, got %s", f.version)
	}
}

func TestAddChange_Validation(t *testing.T) {
	f := NewRegulatoryChangeFeed()

	tests := []struct {
		name    string
		change  RegulatoryChange
		wantErr bool
	}{
		{
			name: "valid change",
			change: RegulatoryChange{
				ID: "REG-001", Framework: FrameworkATLAS, ChangeType: ChangeAmendment,
				Title: "Test", Description: "Test change", EffectiveDate: time.Now(),
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			change: RegulatoryChange{
				Framework: FrameworkATLAS, ChangeType: ChangeAmendment,
				Title: "Test", Description: "Test", EffectiveDate: time.Now(),
			},
			wantErr: true,
		},
		{
			name: "missing title",
			change: RegulatoryChange{
				ID: "REG-002", Framework: FrameworkATLAS, ChangeType: ChangeAmendment,
				Description: "Test", EffectiveDate: time.Now(),
			},
			wantErr: true,
		},
		{
			name: "missing framework",
			change: RegulatoryChange{
				ID: "REG-003", ChangeType: ChangeAmendment,
				Title: "Test", Description: "Test", EffectiveDate: time.Now(),
			},
			wantErr: true,
		},
		{
			name: "missing change type",
			change: RegulatoryChange{
				ID: "REG-004", Framework: FrameworkATLAS,
				Title: "Test", Description: "Test", EffectiveDate: time.Now(),
			},
			wantErr: true,
		},
		{
			name: "missing effective date",
			change: RegulatoryChange{
				ID: "REG-005", Framework: FrameworkATLAS, ChangeType: ChangeAmendment,
				Title: "Test", Description: "Test",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := f.AddChange(tc.change)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

func TestGetChanges_Filtering(t *testing.T) {
	f := NewRegulatoryChangeFeed()

	now := time.Now()
	f.AddChange(RegulatoryChange{ID: "R1", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "ATLAS Change", Description: "Test", EffectiveDate: now, Severity: "critical"})
	f.AddChange(RegulatoryChange{ID: "R2", Framework: FrameworkOWASP, ChangeType: ChangeNewRelease, Title: "OWASP Change", Description: "Test", EffectiveDate: now.Add(-24 * time.Hour), Severity: "important"})
	f.AddChange(RegulatoryChange{ID: "R3", Framework: FrameworkATLAS, ChangeType: ChangeGuidanceUpdate, Title: "ATLAS Guidance", Description: "Test", EffectiveDate: now.Add(-48 * time.Hour), Severity: "informational"})

	// Filter by framework
	atlasChanges := f.GetChanges(time.Time{}, FrameworkATLAS)
	if len(atlasChanges) != 2 {
		t.Errorf("expected 2 ATLAS changes, got %d", len(atlasChanges))
	}

	// Filter by time
	recentChanges := f.GetChanges(now.Add(-25*time.Hour), "")
	if len(recentChanges) != 2 {
		t.Errorf("expected 2 recent changes, got %d", len(recentChanges))
	}
}

func TestGetLatest(t *testing.T) {
	f := NewRegulatoryChangeFeed()

	now := time.Now()
	f.AddChange(RegulatoryChange{ID: "R1", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "First", Description: "Test", EffectiveDate: now.Add(-48 * time.Hour)})
	f.AddChange(RegulatoryChange{ID: "R2", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Second", Description: "Test", EffectiveDate: now.Add(-24 * time.Hour)})
	f.AddChange(RegulatoryChange{ID: "R3", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Third", Description: "Test", EffectiveDate: now})

	latest2 := f.GetLatest(2)
	if len(latest2) != 2 {
		t.Errorf("expected 2 latest changes, got %d", len(latest2))
	}
	if latest2[0].Title != "Third" {
		t.Errorf("expected 'Third' as most recent, got %s", latest2[0].Title)
	}
}

func TestGetBySeverity(t *testing.T) {
	f := NewRegulatoryChangeFeed()
	now := time.Now()
	f.AddChange(RegulatoryChange{ID: "R1", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Critical", Description: "Test", EffectiveDate: now, Severity: "critical"})
	f.AddChange(RegulatoryChange{ID: "R2", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Important", Description: "Test", EffectiveDate: now, Severity: "important"})

	critical := f.GetBySeverity("critical")
	if len(critical) != 1 {
		t.Errorf("expected 1 critical change, got %d", len(critical))
	}
}

func TestGetByChangeType(t *testing.T) {
	f := NewRegulatoryChangeFeed()
	now := time.Now()
	f.AddChange(RegulatoryChange{ID: "R1", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Amendment", Description: "Test", EffectiveDate: now})
	f.AddChange(RegulatoryChange{ID: "R2", Framework: FrameworkATLAS, ChangeType: ChangeNewRelease, Title: "New Release", Description: "Test", EffectiveDate: now})

	amendments := f.GetByChangeType(ChangeAmendment)
	if len(amendments) != 1 {
		t.Errorf("expected 1 amendment, got %d", len(amendments))
	}
}

func TestExportJSON(t *testing.T) {
	f := NewRegulatoryChangeFeed()
	now := time.Now()
	f.AddChange(RegulatoryChange{ID: "R1", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Test", Description: "Test change", EffectiveDate: now, Severity: "critical"})

	data, err := f.ExportJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var changes []RegulatoryChange
	if err := json.Unmarshal(data, &changes); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(changes))
	}
}

func TestRegulatoryFeedStats(t *testing.T) {
	f := NewRegulatoryChangeFeed()
	now := time.Now()
	f.AddChange(RegulatoryChange{ID: "R1", Framework: FrameworkATLAS, ChangeType: ChangeAmendment, Title: "Test 1", Description: "Test", EffectiveDate: now, Severity: "critical"})
	f.AddChange(RegulatoryChange{ID: "R2", Framework: FrameworkOWASP, ChangeType: ChangeNewRelease, Title: "Test 2", Description: "Test", EffectiveDate: now.Add(-24 * time.Hour), Severity: "important"})

	stats := f.Stats()
	if stats.TotalChanges != 2 {
		t.Errorf("expected 2 total changes, got %d", stats.TotalChanges)
	}
	if stats.ByFramework["ATLAS"] != 1 {
		t.Errorf("expected 1 ATLAS change, got %d", stats.ByFramework["ATLAS"])
	}
	if stats.BySeverity["critical"] != 1 {
		t.Errorf("expected 1 critical, got %d", stats.BySeverity["critical"])
	}
}

func TestSeedDefaultChanges(t *testing.T) {
	f := NewRegulatoryChangeFeed()
	f.SeedDefaultChanges()

	stats := f.Stats()
	if stats.TotalChanges < 8 {
		t.Errorf("expected at least 8 seeded changes, got %d", stats.TotalChanges)
	}

	// Should have EU AI Act changes
	euChanges := f.GetChanges(time.Time{}, "eu_ai_act")
	if len(euChanges) < 2 {
		t.Errorf("expected at least 2 EU AI Act changes, got %d", len(euChanges))
	}

	// Should have critical severity
	critical := f.GetBySeverity("critical")
	if len(critical) < 2 {
		t.Errorf("expected at least 2 critical changes, got %d", len(critical))
	}
}
