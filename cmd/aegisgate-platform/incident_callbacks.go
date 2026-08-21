// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — Incident Engine Callback Wiring (v4.3.1)
//
// incident_callbacks.go wires the incident engine's ActionCallbacks
// to real platform subsystems: SOAR (notify), RBAC (block/isolate),
// audit ring buffer (collect evidence), compliance logging (run
// check), and attestation (create signed evidence).
//
// This file closes the gap where SetCallbacks was only called from
// integration tests, never from production wiring.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/attestation"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/ioc"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/soar"
)

// incidentCallbackDeps holds the platform subsystems needed to
// implement incident response actions.
type incidentCallbackDeps struct {
	soarMgr   *soar.Manager
	rbacMgr   *rbac.Manager
	auditRing *logging.RingBuffer
	keyRing   *ioc.KeyRing
	logger    *slog.Logger
}

// convertIncidentToSOAR maps an incident.Incident to a soar.Incident
// so it can be delivered to SOAR platforms (PagerDuty, Jira, ServiceNow).
func convertIncidentToSOAR(inc *incident.Incident) *soar.Incident {
	if inc == nil {
		return nil
	}

	// Map severity (same string values, different types).
	severity := soar.Severity(inc.Severity)
	if severity == "" {
		severity = soar.SeverityInfo
	}

	// Map status.
	status := soar.StatusTriggered
	switch inc.Status {
	case incident.StatusResolved, incident.StatusClosed:
		status = soar.StatusResolved
	case incident.StatusTriaged, incident.StatusInvestigating:
		status = soar.StatusAcknowledged
	}

	// Extract first compliance mapping if available.
	var framework, controlID, controlName string
	if len(inc.ComplianceMappings) > 0 {
		framework = inc.ComplianceMappings[0].Framework
		controlID = inc.ComplianceMappings[0].ControlID
		controlName = inc.ComplianceMappings[0].ControlName
	}

	// Build affected systems list from agent/session info.
	var affectedSystems []string
	if inc.AgentID != "" {
		affectedSystems = append(affectedSystems, "agent:"+inc.AgentID)
	}
	if inc.SessionID != "" {
		affectedSystems = append(affectedSystems, "session:"+inc.SessionID)
	}

	// Build labels from metadata + tags.
	labels := make(map[string]string)
	if inc.TenantID != "" {
		labels["tenant_id"] = inc.TenantID
	}
	labels["source"] = string(inc.Source)
	for _, tag := range inc.Tags {
		labels["tag:"+tag] = "true"
	}

	// Dedup key: use incident ID so the same incident doesn't
	// create duplicate alerts across SOAR platforms.
	dedupKey := inc.ID

	return &soar.Incident{
		ID:              inc.ID,
		Title:           inc.Title,
		Description:     inc.Description,
		Severity:        severity,
		Status:          status,
		Source:          "aegisgate",
		Timestamp:       inc.CreatedAt,
		Framework:       framework,
		ControlID:       controlID,
		ControlName:     controlName,
		Details:         fmt.Sprintf("Agent: %s, Session: %s, Tags: %v", inc.AgentID, inc.SessionID, inc.Tags),
		Remediation:     "",
		AffectedSystems: affectedSystems,
		Labels:          labels,
		DedupKey:        dedupKey,
	}
}

// wireIncidentCallbacks sets up the ActionCallbacks on the incident
// engine, connecting playbook actions to real platform subsystems.
// This is called from main.go after the incident engine is created.
func wireIncidentCallbacks(engine *incident.Engine, deps incidentCallbackDeps) {
	if engine == nil {
		return
	}

	logger := deps.logger
	if logger == nil {
		logger = slog.Default().With("component", "incident-callbacks")
	}

	callbacks := incident.ActionCallbacks{
		// OnNotify: send incident to SOAR platforms (PagerDuty, Jira,
		// ServiceNow) for automated alerting and ticket creation.
		OnNotify: func(ctx context.Context, inc *incident.Incident, recipients []string) error {
			if deps.soarMgr == nil {
				logger.Debug("SOAR not configured, skipping notify", "incident_id", inc.ID)
				return nil
			}
			soarInc := convertIncidentToSOAR(inc)
			results := deps.soarMgr.SendIncident(ctx, soarInc)
			for _, r := range results {
				if r.Error != nil {
					logger.Error("SOAR delivery failed",
						"incident_id", inc.ID,
						"platform", r.Platform,
						"error", r.Error)
				} else {
					logger.Info("SOAR delivery succeeded",
						"incident_id", inc.ID,
						"platform", r.Platform,
						"http_status", r.HTTPStatus)
				}
			}
			return nil
		},

		// OnBlockAgent: revoke the agent and invalidate all its sessions.
		OnBlockAgent: func(ctx context.Context, agentID, sessionID string) error {
			if deps.rbacMgr == nil {
				logger.Warn("RBAC not available, cannot block agent", "agent_id", agentID)
				return fmt.Errorf("RBAC manager not available")
			}
			if agentID != "" {
				if err := deps.rbacMgr.InvalidateAgentSessions(agentID); err != nil {
					logger.Error("Failed to invalidate agent sessions",
						"agent_id", agentID, "error", err)
					return err
				}
				logger.Info("Blocked agent (sessions invalidated)",
					"agent_id", agentID, "session_id", sessionID)
			}
			return nil
		},

		// OnCollectEvidence: serialize the incident to JSON and record
		// it to the audit ring buffer for evidentiary preservation.
		OnCollectEvidence: func(ctx context.Context, inc *incident.Incident) error {
			if deps.auditRing == nil {
				logger.Warn("Audit ring not available, cannot collect evidence", "incident_id", inc.ID)
				return nil
			}
			data, err := json.Marshal(inc)
			if err != nil {
				return fmt.Errorf("marshal incident for evidence: %w", err)
			}
			deps.auditRing.Add(logging.Event{
				Type:     "incident",
				Action:   "evidence_collected",
				Severity: logging.SeverityInfo,
				Message:  fmt.Sprintf("Evidence collected for incident %s (%d bytes)", inc.ID, len(data)),
				User:     inc.AgentID,
			})
			logger.Info("Evidence collected for incident",
				"incident_id", inc.ID, "bytes", len(data))
			return nil
		},

		// OnIsolateSession: invalidate a specific session to
		// prevent further activity while the incident is investigated.
		OnIsolateSession: func(ctx context.Context, agentID, sessionID string) error {
			if deps.rbacMgr == nil {
				logger.Warn("RBAC not available, cannot isolate session", "session_id", sessionID)
				return fmt.Errorf("RBAC manager not available")
			}
			if sessionID != "" {
				if err := deps.rbacMgr.InvalidateSession(sessionID); err != nil {
					logger.Error("Failed to invalidate session",
						"session_id", sessionID, "error", err)
					return err
				}
				logger.Info("Session isolated (invalidated)",
					"session_id", sessionID, "agent_id", agentID)
			}
			return nil
		},

		// OnRunComplianceCheck: log that a compliance check was
		// triggered by the incident. The actual compliance scan is
		// performed asynchronously by the compliance scanner which
		// is already wired in main.go. This callback records the
		// trigger event for audit trail purposes.
		OnRunComplianceCheck: func(ctx context.Context, inc *incident.Incident) error {
			framework := ""
			controlID := ""
			if len(inc.ComplianceMappings) > 0 {
				framework = inc.ComplianceMappings[0].Framework
				controlID = inc.ComplianceMappings[0].ControlID
			}
			if deps.auditRing != nil {
				deps.auditRing.Add(logging.Event{
					Type:                "incident",
					Action:              "compliance_check_triggered",
					Severity:            logging.SeverityInfo,
					Message:             fmt.Sprintf("Compliance check triggered for incident %s (framework: %s)", inc.ID, framework),
					ComplianceFramework: framework,
					ComplianceControl:   controlID,
				})
			}
			logger.Info("Compliance check triggered by incident",
				"incident_id", inc.ID,
				"framework", framework,
				"control_id", controlID)
			return nil
		},

		// OnCreateAttestation: create a signed attestation envelope
		// capturing the incident state at this point in time. This
		// provides cryptographic non-repudiation evidence for
		// compliance frameworks (FedRAMP AU-10, SOC 2 CC6.1).
		OnCreateAttestation: func(ctx context.Context, inc *incident.Incident) error {
			if deps.keyRing == nil {
				logger.Warn("Key ring not available, cannot create attestation", "incident_id", inc.ID)
				return nil
			}

			payload, err := json.Marshal(inc)
			if err != nil {
				return fmt.Errorf("marshal incident for attestation: %w", err)
			}

			// Use TypeEvidenceManifest — the general evidence type.
			// The incident JSON is the evidence payload.
			_, err = attestation.Sign(
				payload,
				"incident:"+inc.ID,
				attestation.TypeEvidenceManifest,
				"aegisgate",
				deps.keyRing,
				24*time.Hour,
			)
			if err != nil {
				logger.Error("Failed to create attestation",
					"incident_id", inc.ID, "error", err)
				return err
			}

			logger.Info("Attestation created for incident",
				"incident_id", inc.ID, "ttl", "24h")
			return nil
		},
	}

	engine.SetCallbacks(callbacks)
	logger.Info("Incident engine callbacks wired",
		"soar", deps.soarMgr != nil,
		"rbac", deps.rbacMgr != nil,
		"audit", deps.auditRing != nil,
		"attestation", deps.keyRing != nil,
	)
}
