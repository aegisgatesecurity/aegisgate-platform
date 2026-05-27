// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Trust Score Calculator

package score

import (
	"context"
	"math"
	"time"
)

// Calculator calculates trust scores for agents
type Calculator struct {
	config     *Config
	baseline   BaselineEngine
}

// NewCalculator creates a new trust score calculator
func NewCalculator(config *Config, baseline BaselineEngine) *Calculator {
	if config == nil {
		config = DefaultConfig()
	}
	return &Calculator{
		config:   config,
		baseline: baseline,
	}
}

// Calculate calculates the trust score for an agent
func (c *Calculator) Calculate(ctx context.Context, agentID string) (*TrustScore, error) {
	baseline, err := c.baseline.GetBaseline(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// Start with base score
	baseScore := c.config.InitialScore

	// Apply time decay if no recent activity
	decayMultiplier := c.calculateDecay(baseline)

	// Calculate behavior multiplier based on baseline
	behaviorMult := c.calculateBehaviorMultiplier(baseline)

	// Calculate compliance multiplier (simplified - would integrate with contract system)
	complianceMult := c.calculateComplianceMultiplier(baseline)

	// Calculate final score
	finalScore := baseScore * decayMultiplier * behaviorMult * complianceMult

	// Clamp to min/max
	if finalScore < c.config.MinScore {
		finalScore = c.config.MinScore
	}
	if finalScore > c.config.MaxScore {
		finalScore = c.config.MaxScore
	}

	// Determine level
	level := c.determineLevel(finalScore)

	// Build factors breakdown
	factors := []ScoreFactor{
		{Name: "base_score", Weight: 1.0, Value: baseScore, Multiplier: 1.0},
		{Name: "decay", Weight: 0.2, Value: 1.0, Multiplier: decayMultiplier},
		{Name: "behavior", Weight: 0.5, Value: baseline.SuccessRate, Multiplier: behaviorMult},
		{Name: "compliance", Weight: 0.3, Value: 1.0, Multiplier: complianceMult},
	}

	return &TrustScore{
		AgentID:              agentID,
		Score:                math.Round(finalScore*100) / 100,
		Level:                level,
		BehaviorMultiplier:   math.Round(behaviorMult*100) / 100,
		ComplianceMultiplier: math.Round(complianceMult*100) / 100,
		BaseScore:            baseScore,
		Factors:              factors,
		CalculatedAt:        time.Now().UTC(),
	}, nil
}

// CalculateWithEvents calculates score considering recent events
func (c *Calculator) CalculateWithEvents(ctx context.Context, agentID string, events []*BehaviorEvent) (*TrustScore, error) {
	// Record events first
	for _, e := range events {
		_ = c.baseline.RecordEvent(ctx, e)
	}

	// Then calculate
	return c.Calculate(ctx, agentID)
}

func (c *Calculator) calculateDecay(baseline *BaselineMetrics) float64 {
	if baseline.LastUpdated.IsZero() {
		return 1.0
	}

	// Calculate days since last update
	daysSince := time.Since(baseline.LastUpdated).Hours() / 24.0
	if daysSince < 1 {
		return 1.0
	}

	// Apply decay
	decay := math.Pow(1-c.config.DecayRate, daysSince)
	if decay < 0.1 {
		return 0.1 // Minimum 10% after decay
	}
	return decay
}

func (c *Calculator) calculateBehaviorMultiplier(baseline *BaselineMetrics) float64 {
	if baseline.TotalEvents == 0 {
		return 1.0
	}

	// Calculate multiplier based on success rate
	// High success rate (95%+) = 1.5x multiplier
	// Medium success rate (70-95%) = 1.0x multiplier
	// Low success rate (50-70%) = 0.7x multiplier
	// Poor success rate (<50%) = 0.3x multiplier

	successRate := baseline.SuccessRate

	switch {
	case successRate >= 0.95:
		return 1.5
	case successRate >= 0.70:
		return 1.0 + (successRate-0.70)/0.25*0.5 // 1.0-1.5
	case successRate >= 0.50:
		return 0.7 + (successRate-0.50)/0.20*0.3 // 0.7-1.0
	default:
		return 0.3 * (successRate / 0.50) // < 0.3
	}
}

func (c *Calculator) calculateComplianceMultiplier(baseline *BaselineMetrics) float64 {
	if baseline.TotalEvents == 0 {
		return 1.5 // No history = neutral-positive
	}

	// Calculate compliance based on approval request ratio and anomalies
	approvalRatio := float64(baseline.ApprovalReqCount) / float64(baseline.TotalEvents)
	anomalyRatio := float64(baseline.AnomalyCount) / float64(baseline.TotalEvents)

	// Low approval requests and anomalies = higher compliance
	complianceScore := 1.0 - (approvalRatio * 0.3) - (anomalyRatio * 0.5)

	if complianceScore > 1.5 {
		return 1.5
	}
	if complianceScore < 0.3 {
		return 0.3
	}
	return complianceScore
}

func (c *Calculator) determineLevel(score float64) ScoreLevel {
	switch {
	case score >= 91:
		return ScoreLevelTrusted
	case score >= 76:
		return ScoreLevelHigh
	case score >= 51:
		return ScoreLevelMedium
	case score >= 26:
		return ScoreLevelLow
	default:
		return ScoreLevelCritical
	}
}

// GetScoreFactors returns the individual factors that contribute to a score
func (c *Calculator) GetScoreFactors(ctx context.Context, agentID string) ([]ScoreFactor, error) {
	score, err := c.Calculate(ctx, agentID)
	if err != nil {
		return nil, err
	}
	return score.Factors, nil
}

// CompareScores compares two trust scores
func CompareScores(a, b *TrustScore) int {
	if a.Score > b.Score {
		return 1
	}
	if a.Score < b.Score {
		return -1
	}
	return 0
}
