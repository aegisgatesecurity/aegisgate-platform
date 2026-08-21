// SPDX-License-Identifier: Apache-2.0
// AegisGate Platform — DSAR Data Providers (v4.3.1)
//
// dsar_providers.go implements DataProvider for each platform store
// (RBAC, SSO, Audit, Incident) so the DSAR service can export and
// erase user/agent data across all stores.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/incident"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/logging"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/rbac"
	"github.com/aegisgatesecurity/aegisgate-platform/pkg/sso"
)

// ---------------------------------------------------------------------------
// RBAC Data Provider
// ---------------------------------------------------------------------------

// rbacDataProvider implements dsar.DataProvider for the RBAC manager.
// It exports agent registrations and sessions for a given entity ID,
// and erases them on DSAR erasure.
type rbacDataProvider struct {
	mgr *rbac.Manager
}

func (p *rbacDataProvider) Name() string { return "rbac" }

func (p *rbacDataProvider) Export(ctx context.Context, entityID string) (json.RawMessage, error) {
	if p.mgr == nil {
		return nil, nil
	}

	data := map[string]interface{}{}

	// Try as agent
	if agent, err := p.mgr.GetAgent(entityID); err == nil && agent != nil {
		data["agent"] = agent
		sessions := p.mgr.GetAgentSessions(entityID)
		if len(sessions) > 0 {
			data["agent_sessions"] = sessions
		}
	}

	if len(data) == 0 {
		return nil, nil
	}
	return json.Marshal(data)
}

func (p *rbacDataProvider) Erase(ctx context.Context, entityID string) (int, error) {
	if p.mgr == nil {
		return 0, nil
	}
	affected := 0

	// Invalidate all agent sessions
	if err := p.mgr.InvalidateAgentSessions(entityID); err == nil {
		affected++
	}

	return affected, nil
}

// ---------------------------------------------------------------------------
// SSO Data Provider
// ---------------------------------------------------------------------------

// ssoDataProvider implements dsar.DataProvider for the SSO manager.
// It exports user sessions and erases them on DSAR erasure.
type ssoDataProvider struct {
	mgr *sso.Manager
}

func (p *ssoDataProvider) Name() string { return "sso" }

func (p *ssoDataProvider) Export(ctx context.Context, entityID string) (json.RawMessage, error) {
	if p.mgr == nil {
		return nil, nil
	}

	data := map[string]interface{}{}

	sessions, err := p.mgr.GetUserSessions(entityID)
	if err == nil && len(sessions) > 0 {
		data["sessions"] = sessions
	}

	if len(data) == 0 {
		return nil, nil
	}
	return json.Marshal(data)
}

func (p *ssoDataProvider) Erase(ctx context.Context, entityID string) (int, error) {
	if p.mgr == nil {
		return 0, nil
	}
	affected := 0

	// Terminate all user sessions
	if err := p.mgr.TerminateUserSessions(entityID); err == nil {
		affected++
	}

	return affected, nil
}

// ---------------------------------------------------------------------------
// Audit Data Provider
// ---------------------------------------------------------------------------

// auditDataProvider implements dsar.DataProvider for the audit ring buffer.
// It exports all audit events for the given user/agent and "erases" them
// by noting the erasure in the audit log (audit logs are append-only and
// cannot be deleted — instead we record a "dsar_erasure" event).
type auditDataProvider struct {
	ring *logging.RingBuffer
}

func (p *auditDataProvider) Name() string { return "audit" }

func (p *auditDataProvider) Export(ctx context.Context, entityID string) (json.RawMessage, error) {
	if p.ring == nil {
		return nil, nil
	}

	// Get all events from the ring buffer and filter by user
	// We use a large time window to capture everything
	now := time.Now()
	events := p.ring.SnapshotBetween(now.Add(-365*24*time.Hour), now)

	var userEvents []logging.Event
	for _, e := range events {
		if e.User == entityID || e.ClientID == entityID {
			userEvents = append(userEvents, e)
		}
	}

	if len(userEvents) == 0 {
		return nil, nil
	}
	return json.Marshal(map[string]interface{}{
		"events": userEvents,
		"count":  len(userEvents),
	})
}

func (p *auditDataProvider) Erase(ctx context.Context, entityID string) (int, error) {
	if p.ring == nil {
		return 0, nil
	}

	// Audit logs are append-only. Instead of deleting, we record
	// a DSAR erasure event to maintain the audit trail.
	p.ring.Add(logging.Event{
		Time:     time.Now(),
		ID:       fmt.Sprintf("dsar-erasure-%s-%d", entityID, time.Now().UnixNano()),
		Type:     "dsar",
		Action:   "erasure",
		Severity: logging.SeverityInfo,
		Message:  fmt.Sprintf("DSAR erasure requested for entity %s — audit events retained per legal/append-only policy", entityID),
		User:     entityID,
	})
	return 0, nil
}

// ---------------------------------------------------------------------------
// Incident Data Provider
// ---------------------------------------------------------------------------

// incidentDataProvider implements dsar.DataProvider for the incident engine.
// It exports incidents associated with the given entity (by agent ID) and
// resolves/resolves them on erasure.
type incidentDataProvider struct {
	engine *incident.Engine
}

func (p *incidentDataProvider) Name() string { return "incident" }

func (p *incidentDataProvider) Export(ctx context.Context, entityID string) (json.RawMessage, error) {
	if p.engine == nil {
		return nil, nil
	}

	// Query incidents by agent ID
	incidents, err := p.engine.ListIncidents(ctx, &incident.IncidentQuery{
		AgentID: entityID,
		Limit:   1000,
	})
	if err != nil || len(incidents) == 0 {
		return nil, nil
	}
	return json.Marshal(map[string]interface{}{
		"incidents": incidents,
		"count":     len(incidents),
	})
}

func (p *incidentDataProvider) Erase(ctx context.Context, entityID string) (int, error) {
	if p.engine == nil {
		return 0, nil
	}

	// List incidents for this agent and resolve them
	incidents, err := p.engine.ListIncidents(ctx, &incident.IncidentQuery{
		AgentID: entityID,
	})
	if err != nil {
		return 0, err
	}

	affected := 0
	for _, inc := range incidents {
		// Resolve the incident as part of erasure
		inc.Status = incident.StatusResolved
		inc.UpdatedAt = time.Now()
		inc.Description = fmt.Sprintf("%s — [Resolved via DSAR erasure request]", inc.Description)
		affected++
	}

	return affected, nil
}

// ---------------------------------------------------------------------------
// Registration Helper
// ---------------------------------------------------------------------------

// dsarProviderDeps holds the dependencies for creating DSAR data providers.
type dsarProviderDeps struct {
	rbacMgr    *rbac.Manager
	ssoMgr     *sso.Manager
	auditRing  *logging.RingBuffer
	incidentEn *incident.Engine
}

// registerDSARProviders registers all platform data providers with the DSAR service.
func registerDSARProviders(svc *dsarService, deps dsarProviderDeps) {
	if svc == nil {
		return
	}
	svc.RegisterProvider(&rbacDataProvider{mgr: deps.rbacMgr})
	svc.RegisterProvider(&ssoDataProvider{mgr: deps.ssoMgr})
	svc.RegisterProvider(&auditDataProvider{ring: deps.auditRing})
	svc.RegisterProvider(&incidentDataProvider{engine: deps.incidentEn})
}
