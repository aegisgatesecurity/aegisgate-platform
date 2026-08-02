// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// ROI Calculator — Business Case Calculator for AegisGate Deployment
// =========================================================================
//
// This module provides a return-on-investment calculator that answers the
// CFO question: "If we deploy AegisGate, how much money do we save?"
//
// The calculator uses empirically-derived defaults from industry breach cost
// studies (IBM Cost of a Data Breach 2024, NIST economic models) and
// AegisGate's own detection benchmarks (0% FPR, 78.8% single-turn TPR,
// 70% multi-turn TPR).
// =========================================================================

package analytics

import (
	"fmt"
	"math"
)

// ROIInput contains the parameters for ROI calculation.
type ROIInput struct {
	// MonthlyLLMCalls is the total number of LLM API calls per month.
	MonthlyLLMCalls int64
	// AvgCostPerBreach is the estimated cost of a single prompt injection
	// breach in dollars (includes data exfiltration, compliance penalty,
	// incident response, and reputational damage). Default: $50,000.
	AvgCostPerBreach float64
	// DetectionRate is AegisGate's detection rate (0-1). Default: 0.788.
	DetectionRate float64
	// FalsePositiveRate is AegisGate's FPR (0-1). Default: 0.0.
	FalsePositiveRate float64
	// AvgFalsePositiveCost is the cost to investigate a false positive ($).
	// Default: $50 (15 minutes of SOC analyst time).
	AvgFalsePositiveCost float64
	// MonthlyLicenseCost is the AegisGate license cost per month ($).
	// Default: $79 (Developer tier).
	MonthlyLicenseCost float64
	// InfrastructureCost is the hosting/infra cost per month ($).
	// Default: $0 for self-hosted.
	InfrastructureCost float64
	// AnalystHoursPerIncident is SOC analyst hours per incident. Default: 4.
	AnalystHoursPerIncident float64
	// AnalystHourlyCost is SOC analyst hourly rate ($). Default: $75.
	AnalystHourlyCost float64
	// BaselineIncidentRate is attacks per 1000 calls without AegisGate.
	// Default: 2.0 (0.2% attack rate, industry average).
	BaselineIncidentRate float64
	// MultiTurnDetectionRate is detection rate for multi-turn attacks (0-1).
	// Default: 0.70.
	MultiTurnDetectionRate float64
	// MultiTurnAttackFraction is the fraction of attacks that are multi-turn.
	// Default: 0.30 (30% of attacks are multi-turn).
	MultiTurnAttackFraction float64
}

// ROIResult contains the calculated ROI metrics.
type ROIResult struct {
	MonthlyAttacksPrevented    int64   `json:"monthly_attacks_prevented"`
	MonthlyAttacksDetected     int64   `json:"monthly_attacks_detected"`
	MonthlyBreachesPrevented   int64   `json:"monthly_breaches_prevented"`
	MonthlyFPInvestigations    int64   `json:"monthly_fp_investigations"`
	MonthlyBreachCostAvoided   float64 `json:"monthly_breach_cost_avoided"`
	MonthlyFPInvestigationCost float64 `json:"monthly_fp_investigation_cost"`
	MonthlyAnalystHoursSaved   float64 `json:"monthly_analyst_hours_saved"`
	MonthlyTotalSavings        float64 `json:"monthly_total_savings"`
	MonthlyTotalCost           float64 `json:"monthly_total_cost"`
	MonthlyNetBenefit          float64 `json:"monthly_net_benefit"`
	AnnualNetBenefit           float64 `json:"annual_net_benefit"`
	ROIPercentage              float64 `json:"roi_percentage"`
	PaybackPeriodMonths        float64 `json:"payback_period_months"`
	EffectiveDetectionRate     float64 `json:"effective_detection_rate"`
}

// NewDefaultROIInput returns sensible defaults based on AegisGate benchmarks
// and industry breach cost data.
func NewDefaultROIInput() *ROIInput {
	return &ROIInput{
		MonthlyLLMCalls:         1_000_000,
		AvgCostPerBreach:        50000,
		DetectionRate:           0.788,
		FalsePositiveRate:       0.0,
		AvgFalsePositiveCost:    50,
		MonthlyLicenseCost:      79,
		InfrastructureCost:      0,
		AnalystHoursPerIncident: 4,
		AnalystHourlyCost:       75,
		BaselineIncidentRate:    2.0,
		MultiTurnDetectionRate:  0.70,
		MultiTurnAttackFraction: 0.30,
	}
}

// CalculateROI computes the return on investment for AegisGate deployment.
func CalculateROI(input *ROIInput) (*ROIResult, error) {
	if err := validateROIInput(input); err != nil {
		return nil, err
	}

	// Effective detection rate blends single-turn and multi-turn
	effectiveRate := input.DetectionRate*(1-input.MultiTurnAttackFraction) +
		input.MultiTurnDetectionRate*input.MultiTurnAttackFraction

	// Monthly baseline attacks
	monthlyAttacks := int64(float64(input.MonthlyLLMCalls) * input.BaselineIncidentRate / 1000.0)
	if monthlyAttacks == 0 {
		monthlyAttacks = 1 // minimum 1 for calculation
	}

	// Attacks prevented by AegisGate
	prevented := int64(float64(monthlyAttacks) * effectiveRate)
	// Remaining attacks that get through
	detected := prevented

	// Breaches prevented (attacks that would have succeeded without AegisGate)
	breachesPrevented := prevented

	// False positive investigations (FP calls out of total)
	fpInvestigations := int64(float64(input.MonthlyLLMCalls) * input.FalsePositiveRate)

	// Cost calculations
	breachCostAvoided := float64(breachesPrevented) * input.AvgCostPerBreach
	fpCost := float64(fpInvestigations) * input.AvgFalsePositiveCost
	analystHoursSaved := float64(breachesPrevented) * input.AnalystHoursPerIncident

	totalSavings := breachCostAvoided + fpCost*(-1) + analystHoursSaved*input.AnalystHourlyCost
	// FP cost is subtracted because it's a cost, not savings
	totalSavings = breachCostAvoided + analystHoursSaved*input.AnalystHourlyCost - fpCost

	totalCost := input.MonthlyLicenseCost + input.InfrastructureCost
	netBenefit := totalSavings - totalCost

	roiPct := 0.0
	if totalCost > 0 {
		roiPct = (netBenefit / totalCost) * 100
	}

	paybackMonths := 0.0
	if netBenefit > 0 {
		paybackMonths = totalCost / netBenefit
		if paybackMonths < 0.01 {
			paybackMonths = 0.01
		}
	} else {
		paybackMonths = math.Inf(1)
	}

	return &ROIResult{
		MonthlyAttacksPrevented:    prevented,
		MonthlyAttacksDetected:     detected,
		MonthlyBreachesPrevented:   breachesPrevented,
		MonthlyFPInvestigations:    fpInvestigations,
		MonthlyBreachCostAvoided:   breachCostAvoided,
		MonthlyFPInvestigationCost: fpCost,
		MonthlyAnalystHoursSaved:   analystHoursSaved,
		MonthlyTotalSavings:        totalSavings,
		MonthlyTotalCost:           totalCost,
		MonthlyNetBenefit:          netBenefit,
		AnnualNetBenefit:           netBenefit * 12,
		ROIPercentage:              roiPct,
		PaybackPeriodMonths:        paybackMonths,
		EffectiveDetectionRate:     effectiveRate,
	}, nil
}

func validateROIInput(input *ROIInput) error {
	if input.MonthlyLLMCalls <= 0 {
		return fmt.Errorf("MonthlyLLMCalls must be > 0, got %d", input.MonthlyLLMCalls)
	}
	if input.DetectionRate < 0 || input.DetectionRate > 1 {
		return fmt.Errorf("DetectionRate must be 0-1, got %.4f", input.DetectionRate)
	}
	if input.FalsePositiveRate < 0 || input.FalsePositiveRate > 1 {
		return fmt.Errorf("FalsePositiveRate must be 0-1, got %.4f", input.FalsePositiveRate)
	}
	if input.AvgCostPerBreach < 0 {
		return fmt.Errorf("AvgCostPerBreach must be >= 0, got %.2f", input.AvgCostPerBreach)
	}
	if input.BaselineIncidentRate <= 0 {
		return fmt.Errorf("BaselineIncidentRate must be > 0, got %.2f", input.BaselineIncidentRate)
	}
	if input.MultiTurnDetectionRate < 0 || input.MultiTurnDetectionRate > 1 {
		return fmt.Errorf("MultiTurnDetectionRate must be 0-1, got %.4f", input.MultiTurnDetectionRate)
	}
	if input.MultiTurnAttackFraction < 0 || input.MultiTurnAttackFraction > 1 {
		return fmt.Errorf("MultiTurnAttackFraction must be 0-1, got %.4f", input.MultiTurnAttackFraction)
	}
	return nil
}
