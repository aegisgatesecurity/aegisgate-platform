// SPDX-License-Identifier: Apache-2.0
// ROI Calculator Tests

package analytics

import (
	"math"
	"testing"
)

func TestNewDefaultROIInput(t *testing.T) {
	input := NewDefaultROIInput()
	if input.MonthlyLLMCalls != 1_000_000 {
		t.Errorf("expected 1000000 monthly calls, got %d", input.MonthlyLLMCalls)
	}
	if input.DetectionRate != 0.788 {
		t.Errorf("expected 0.788 detection rate, got %.4f", input.DetectionRate)
	}
	if input.FalsePositiveRate != 0.0 {
		t.Errorf("expected 0.0 FPR, got %.4f", input.FalsePositiveRate)
	}
	if input.AvgCostPerBreach != 50000 {
		t.Errorf("expected $50000 breach cost, got %.2f", input.AvgCostPerBreach)
	}
}

func TestCalculateROI_Defaults(t *testing.T) {
	input := NewDefaultROIInput()
	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With 1M calls, 2/1000 = 2000 attacks/month
	// 70% single-turn * 78.8% + 30% multi-turn * 70% = 55.16% + 21% = 76.16% effective
	// Attacks prevented: 2000 * 0.7616 ≈ 1523
	if result.MonthlyAttacksPrevented <= 0 {
		t.Errorf("expected positive attacks prevented, got %d", result.MonthlyAttacksPrevented)
	}

	if result.MonthlyBreachCostAvoided <= 0 {
		t.Error("expected positive breach cost avoided")
	}

	if result.MonthlyNetBenefit <= 0 {
		t.Errorf("expected positive net benefit, got %.2f", result.MonthlyNetBenefit)
	}

	if result.AnnualNetBenefit <= 0 {
		t.Errorf("expected positive annual net benefit, got %.2f", result.AnnualNetBenefit)
	}

	if result.ROIPercentage <= 0 {
		t.Errorf("expected positive ROI percentage, got %.2f", result.ROIPercentage)
	}

	if result.PaybackPeriodMonths <= 0 || math.IsInf(result.PaybackPeriodMonths, 1) {
		t.Errorf("expected finite positive payback period, got %.2f", result.PaybackPeriodMonths)
	}
}

func TestCalculateROI_ZeroFP(t *testing.T) {
	input := NewDefaultROIInput()
	input.FalsePositiveRate = 0.0

	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.MonthlyFPInvestigations != 0 {
		t.Errorf("expected 0 FP investigations with 0 FPR, got %d", result.MonthlyFPInvestigations)
	}
	if result.MonthlyFPInvestigationCost != 0 {
		t.Errorf("expected 0 FP cost with 0 FPR, got %.2f", result.MonthlyFPInvestigationCost)
	}
}

func TestCalculateROI_WithFP(t *testing.T) {
	input := NewDefaultROIInput()
	input.FalsePositiveRate = 0.05 // 5% FPR
	input.AvgFalsePositiveCost = 50

	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1M calls * 5% FPR = 50,000 FP investigations
	if result.MonthlyFPInvestigations != 50000 {
		t.Errorf("expected 50000 FP investigations, got %d", result.MonthlyFPInvestigations)
	}
	if result.MonthlyFPInvestigationCost != 2500000 {
		t.Errorf("expected $2,500,000 FP cost, got %.2f", result.MonthlyFPInvestigationCost)
	}
}

func TestCalculateROI_Enterprise(t *testing.T) {
	input := NewDefaultROIInput()
	input.MonthlyLLMCalls = 10_000_000 // 10M calls
	input.MonthlyLicenseCost = 499       // Professional tier
	input.InfrastructureCost = 500       // $500/mo infra
	input.AvgCostPerBreach = 150000      // Enterprise breach cost

	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.MonthlyNetBenefit <= 0 {
		t.Errorf("expected positive net benefit for enterprise, got %.2f", result.MonthlyNetBenefit)
	}
}

func TestCalculateROI_ValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		input *ROIInput
	}{
		{"negative calls", &ROIInput{MonthlyLLMCalls: -1, DetectionRate: 0.5, BaselineIncidentRate: 2.0, AvgCostPerBreach: 50000}},
		{"zero calls", &ROIInput{MonthlyLLMCalls: 0, DetectionRate: 0.5, BaselineIncidentRate: 2.0, AvgCostPerBreach: 50000}},
		{"detection rate > 1", &ROIInput{MonthlyLLMCalls: 1000, DetectionRate: 1.5, BaselineIncidentRate: 2.0, AvgCostPerBreach: 50000}},
		{"detection rate < 0", &ROIInput{MonthlyLLMCalls: 1000, DetectionRate: -0.1, BaselineIncidentRate: 2.0, AvgCostPerBreach: 50000}},
		{"negative breach cost", &ROIInput{MonthlyLLMCalls: 1000, DetectionRate: 0.5, BaselineIncidentRate: 2.0, AvgCostPerBreach: -100}},
		{"negative incident rate", &ROIInput{MonthlyLLMCalls: 1000, DetectionRate: 0.5, BaselineIncidentRate: -1.0, AvgCostPerBreach: 50000}},
		{"FPR > 1", &ROIInput{MonthlyLLMCalls: 1000, DetectionRate: 0.5, FalsePositiveRate: 1.5, BaselineIncidentRate: 2.0, AvgCostPerBreach: 50000}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CalculateROI(tc.input)
			if err == nil {
				t.Errorf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestCalculateROI_EffectiveDetectionRate(t *testing.T) {
	input := NewDefaultROIInput()
	// 70% single-turn * 78.8% + 30% multi-turn * 70% = 55.16% + 21% = 76.16%
	result, err := CalculateROI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 0.7 * 0.788 + 0.3 * 0.7 = 0.5516 + 0.21 = 0.7616
	expectedRate := 0.7616
	if math.Abs(result.EffectiveDetectionRate-expectedRate) > 0.001 {
		t.Errorf("expected effective rate %.4f, got %.4f", expectedRate, result.EffectiveDetectionRate)
	}
}