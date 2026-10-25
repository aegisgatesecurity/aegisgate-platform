package agentregistry

import (
	"log/slog"
	"time"
)

// DormancyEngine evaluates agent activity patterns against configurable
// thresholds and classifies agents into lifecycle states.
//
// The evaluation uses a waterfall model:
//
//  1. If LastActivity is zero → StatusProvisioned (registered but never used)
//  2. If LastActivity is within DormancyThreshold → StatusActive
//  3. If LastActivity exceeds DormancyThreshold but not QuarantineThreshold → StatusDormant
//  4. If LastActivity exceeds QuarantineThreshold but not AutoRevokeThreshold → StatusQuarantined
//  5. If LastActivity exceeds AutoRevokeThreshold → StatusRevoked
//
// If a threshold is zero, that stage is skipped (e.g., QuarantineThreshold=0
// means go straight from dormant to revoked if AutoRevokeThreshold is set).
type DormancyEngine struct {
	defaultThreshold time.Duration
	logger           *slog.Logger
}

// NewDormancyEngine creates a new DormancyEngine with the given default
// dormancy threshold. The default is used when a policy does not specify
// its own threshold.
func NewDormancyEngine(defaultThreshold time.Duration, logger *slog.Logger) *DormancyEngine {
	if defaultThreshold == 0 {
		defaultThreshold = 60 * 24 * time.Hour // 60 days
	}
	if logger == nil {
		logger = slog.Default().With("component", "dormancy-engine")
	}
	return &DormancyEngine{
		defaultThreshold: defaultThreshold,
		logger:           logger,
	}
}

// Evaluate checks a single agent record against dormancy thresholds and
// returns the recommended status and the duration since last activity.
//
// If the agent is quarantined or revoked (manually set), Evaluate returns
// the current status without changing it — these states require explicit
// intervention to exit.
func (d *DormancyEngine) Evaluate(record *AgentRecord, policy *LifecyclePolicy) (AgentStatus, time.Duration) {
	if record == nil {
		return StatusProvisioned, 0
	}

	// Quarantined and revoked are sticky — only manual transition can exit them
	if record.Status == StatusQuarantined || record.Status == StatusRevoked {
		return record.Status, d.inactiveDuration(record)
	}

	// Provisioned (never active) stays provisioned
	if record.LastActivity.IsZero() {
		return StatusProvisioned, 0
	}

	inactiveFor := d.inactiveDuration(record)
	threshold := d.thresholdFor(policy)

	// If auto-revoke is configured and exceeded
	if policy != nil && policy.AutoRevokeThreshold > 0 && inactiveFor >= policy.AutoRevokeThreshold {
		return StatusRevoked, inactiveFor
	}

	// If quarantine is configured and exceeded
	if policy != nil && policy.QuarantineThreshold > 0 && inactiveFor >= policy.QuarantineThreshold {
		return StatusQuarantined, inactiveFor
	}

	// If dormancy threshold exceeded
	if inactiveFor >= threshold {
		return StatusDormant, inactiveFor
	}

	return StatusActive, inactiveFor
}

// Classify runs Evaluate across all records and returns a dormancy report.
// It does NOT modify the records — it only reports the current state and
// recommended transitions. Use PolicyEngine.Enforce to apply transitions.
func (d *DormancyEngine) Classify(records []*AgentRecord, policy *LifecyclePolicy) *DormancyReport {
	now := nowFunc()
	report := &DormancyReport{
		GeneratedAt: now,
		Total:       len(records),
		Agents:      make([]DormancyEntry, 0, len(records)),
	}

	for _, record := range records {
		// Evaluate recommends the status the agent SHOULD be in
		evaluated, _ := d.Evaluate(record, policy)

		switch evaluated {
		case StatusActive:
			report.Active++
		case StatusDormant:
			report.Dormant++
		case StatusQuarantined:
			report.Quarantined++
		case StatusRevoked:
			report.Revoked++
		case StatusProvisioned:
			report.Provisioned++
		}

		dormantFor := time.Duration(0)
		if !record.LastActivity.IsZero() {
			dormantFor = now.Sub(record.LastActivity)
		}

		report.Agents = append(report.Agents, DormancyEntry{
			AgentID:        record.ID,
			Name:           record.Name,
			Status:         evaluated,
			LastActivity:   record.LastActivity,
			DormantFor:     dormantFor,
			Protocols:      record.Protocols,
			Owner:          record.Owner,
			ActiveSessions: record.ActiveSessions,
		})
	}

	return report
}

// inactiveDuration returns how long the agent has been inactive.
func (d *DormancyEngine) inactiveDuration(record *AgentRecord) time.Duration {
	if record.LastActivity.IsZero() {
		return 0
	}
	return nowFunc().Sub(record.LastActivity)
}

// thresholdFor returns the dormancy threshold from the policy, or the
// engine default if the policy is nil or has a zero threshold.
func (d *DormancyEngine) thresholdFor(policy *LifecyclePolicy) time.Duration {
	if policy != nil && policy.DormancyThreshold > 0 {
		return policy.DormancyThreshold
	}
	return d.defaultThreshold
}
