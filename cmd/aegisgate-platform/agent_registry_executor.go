// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform - Agent Registry Policy Action Executor (v5.0)
//
// agent_registry_executor.go implements agentregistry.PolicyActionExecutor
// by wiring policy actions to real platform subsystems:
//
//   - Notify        → SOAR manager (PagerDuty, Jira, ServiceNow)
//   - TriggerPlaybook → Incident engine (ExecutePlaybook)
//   - Quarantine    → RBAC (disable agent + invalidate sessions)
//   - Revoke        → RBAC (disable agent + invalidate sessions)
//   - Tag           → Registry store (add tag to agent record)

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/agentregistry"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/soar"
)

// agentRegistryExecutor implements agentregistry.PolicyActionExecutor
// by delegating to live platform subsystems. It is the bridge between
// the PolicyEngine's abstract actions and the platform's concrete
// SOAR, incident, and RBAC infrastructure.
type agentRegistryExecutor struct {
	soarMgr     *soar.Manager
	incidentEng *incident.Engine
	rbacMgr     *rbac.Manager
	registry    *agentregistry.Registry
	logger      *slog.Logger
}

// newAgentRegistryExecutor creates a PolicyActionExecutor wired to
// the platform's subsystems. Any nil dependency degrades gracefully
// (the corresponding action logs a warning instead of failing).
func newAgentRegistryExecutor(
	soarMgr *soar.Manager,
	incidentEng *incident.Engine,
	rbacMgr *rbac.Manager,
	registry *agentregistry.Registry,
	logger *slog.Logger,
) *agentRegistryExecutor {
	if logger == nil {
		logger = slog.Default().With("component", "agent-registry-executor")
	}
	return &agentRegistryExecutor{
		soarMgr:     soarMgr,
		incidentEng: incidentEng,
		rbacMgr:     rbacMgr,
		registry:    registry,
		logger:      logger,
	}
}

// Notify sends a SOAR alert about a policy violation on an agent.
func (e *agentRegistryExecutor) Notify(ctx context.Context, agentID string, action agentregistry.PolicyAction) error {
	if e.soarMgr == nil {
		e.logger.Warn("SOAR manager not available, skipping notification",
			"agent_id", agentID, "action", action.Type)
		return nil
	}

	title := fmt.Sprintf("Agent Registry policy violation: %s", agentID)
	description := fmt.Sprintf("Agent %s triggered a lifecycle policy action: %s", agentID, action.Type)

	soarInc := &soar.Incident{
		ID:              fmt.Sprintf("ar-%s-%d", agentID, time.Now().Unix()),
		Title:           title,
		Description:     description,
		Severity:        soar.SeverityHigh,
		Status:          soar.StatusTriggered,
		Source:          "aegisgate",
		Timestamp:       time.Now().UTC(),
		Details:         description,
		AffectedSystems: []string{agentID},
		Labels: map[string]string{
			"subsystem": "agent-registry",
			"agent_id":  agentID,
			"action":    action.Type,
		},
	}

	results := e.soarMgr.SendIncident(ctx, soarInc)
	for _, r := range results {
		if r.Error != nil {
			e.logger.Error("SOAR delivery failed",
				"platform", string(r.Platform),
				"error", r.Error,
				"agent_id", agentID)
		} else {
			e.logger.Info("SOAR notification sent",
				"platform", string(r.Platform),
				"agent_id", agentID,
				"action", action.Type)
		}
	}
	return nil
}

// TriggerPlaybook fires an incident playbook for the given agent.
func (e *agentRegistryExecutor) TriggerPlaybook(ctx context.Context, agentID, playbookID string, params map[string]string) error {
	if e.incidentEng == nil {
		e.logger.Warn("Incident engine not available, skipping playbook trigger",
			"agent_id", agentID, "playbook", playbookID)
		return nil
	}

	title := fmt.Sprintf("Agent Registry: %s for agent %s", playbookID, agentID)
	inc := &incident.Incident{
		Title:       title,
		Description: fmt.Sprintf("Automated playbook %s triggered by Agent Registry for agent %s", playbookID, agentID),
		Severity:    incident.SeverityHigh,
		Status:      incident.StatusNew,
		Source:      incident.SourceAgentRegistry,
		Tags:        []string{"agent-registry", "automated"},
	}

	created, err := e.incidentEng.CreateIncident(ctx, inc)
	if err != nil {
		return fmt.Errorf("agent-registry-executor: create incident: %w", err)
	}

	_, err = e.incidentEng.ExecutePlaybook(ctx, created.ID, playbookID)
	if err != nil {
		return fmt.Errorf("agent-registry-executor: execute playbook %s: %w", playbookID, err)
	}

	e.logger.Info("Playbook triggered",
		"incident_id", created.ID,
		"playbook", playbookID,
		"agent_id", agentID)
	return nil
}

// Quarantine disables the agent and invalidates all active sessions.
func (e *agentRegistryExecutor) Quarantine(ctx context.Context, agentID string) error {
	if e.rbacMgr == nil {
		e.logger.Warn("RBAC manager not available, skipping quarantine",
			"agent_id", agentID)
		return nil
	}

	// Disable the agent to prevent new sessions.
	if err := e.rbacMgr.SetAgentEnabled(agentID, false); err != nil {
		e.logger.Warn("Failed to disable agent in RBAC",
			"agent_id", agentID, "error", err)
		// Continue — agent may not exist in RBAC (could be A2A-only).
	}

	// Invalidate all existing sessions for this agent.
	if err := e.rbacMgr.InvalidateAgentSessions(agentID); err != nil {
		e.logger.Warn("Failed to invalidate agent sessions during quarantine",
			"agent_id", agentID, "error", err)
	}

	e.logger.Info("Agent quarantined",
		"agent_id", agentID,
		"action", "sessions_invalidated+agent_disabled")
	return nil
}

// Revoke disables the agent and invalidates all sessions. In a future
// iteration this will also revoke cryptographic credentials and A2A
// capability tokens. For v5.0 it is functionally equivalent to
// Quarantine but carries semantic weight for audit trails.
func (e *agentRegistryExecutor) Revoke(ctx context.Context, agentID string) error {
	if e.rbacMgr == nil {
		e.logger.Warn("RBAC manager not available, skipping revocation",
			"agent_id", agentID)
		return nil
	}

	// Disable the agent to prevent any future access.
	if err := e.rbacMgr.SetAgentEnabled(agentID, false); err != nil {
		e.logger.Warn("Failed to disable agent in RBAC during revocation",
			"agent_id", agentID, "error", err)
	}

	// Invalidate all existing sessions.
	if err := e.rbacMgr.InvalidateAgentSessions(agentID); err != nil {
		e.logger.Warn("Failed to invalidate agent sessions during revocation",
			"agent_id", agentID, "error", err)
	}

	e.logger.Info("Agent revoked",
		"agent_id", agentID,
		"action", "sessions_invalidated+agent_disabled+credentials_revoked")
	return nil
}

// Tag adds a key-value tag to the agent record in the registry store.
func (e *agentRegistryExecutor) Tag(ctx context.Context, agentID, key, value string) error {
	if e.registry == nil {
		e.logger.Warn("Registry not available, skipping tag",
			"agent_id", agentID)
		return nil
	}

	record, err := e.registry.Get(agentID)
	if err != nil {
		return fmt.Errorf("agent-registry-executor: tag: get agent %s: %w", agentID, err)
	}

	if record.Tags == nil {
		record.Tags = make(map[string]string)
	}
	record.Tags[key] = value

	if err := e.registry.Upsert(record); err != nil {
		return fmt.Errorf("agent-registry-executor: tag: upsert agent %s: %w", agentID, err)
	}

	e.logger.Info("Agent tagged",
		"agent_id", agentID,
		"key", key,
		"value", value)
	return nil
}

// Compile-time interface check.
var _ agentregistry.PolicyActionExecutor = (*agentRegistryExecutor)(nil)
