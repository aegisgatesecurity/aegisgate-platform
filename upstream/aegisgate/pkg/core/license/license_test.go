// Package license provides tests for license management functionality
package license

import (
	"context"
	"testing"
)

func TestNewLicenseManager(t *testing.T) {
	features := []string{"feature1", "feature2"}
	lm := NewLicenseManager("enterprise", features)

	if lm == nil {
		t.Fatal("NewLicenseManager returned nil")
	}
	if lm.tier != "enterprise" {
		t.Errorf("expected tier enterprise, got %s", lm.tier)
	}
	if len(lm.features) != 2 {
		t.Errorf("expected 2 features, got %d", len(lm.features))
	}
}

func TestGetTier(t *testing.T) {
	ctx := context.Background()
	lm := NewLicenseManager("pro", []string{"feature1"})

	tier := lm.GetTier(ctx)
	if tier != "pro" {
		t.Errorf("expected tier pro, got %s", tier)
	}
}

func TestIsFeatureLicensed(t *testing.T) {
	ctx := context.Background()
	lm := NewLicenseManager("enterprise", []string{"feature1", "feature2"})

	if !lm.IsFeatureLicensed(ctx, "feature1") {
		t.Error("expected feature1 to be licensed")
	}
	if !lm.IsFeatureLicensed(ctx, "feature2") {
		t.Error("expected feature2 to be licensed")
	}
	if lm.IsFeatureLicensed(ctx, "feature3") {
		t.Error("expected feature3 to not be licensed")
	}
}

func TestValidate(t *testing.T) {
	ctx := context.Background()
	lm := NewLicenseManager("standard", []string{})

	err := lm.Validate(ctx)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetFeatures(t *testing.T) {
	ctx := context.Background()
	features := []string{"a", "b", "c"}
	lm := NewLicenseManager("trial", features)

	result := lm.GetFeatures(ctx)
	if len(result) != 3 {
		t.Errorf("expected 3 features, got %d", len(result))
	}

	// Test empty features
	lm2 := NewLicenseManager("free", []string{})
	result2 := lm2.GetFeatures(ctx)
	if len(result2) != 0 {
		t.Errorf("expected 0 features, got %d", len(result2))
	}
}
