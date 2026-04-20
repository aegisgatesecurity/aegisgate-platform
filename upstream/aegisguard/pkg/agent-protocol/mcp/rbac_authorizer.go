// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGuard Security

// =========================================================================
//
// MCP RBAC Authorizer - Integrates RBAC Manager with MCP authorization
// =========================================================================

package mcp

import (
	"context"
	"fmt"

	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// RBACAuthorizer implements MCP ToolAuthorizer using AegisGuard RBAC
type RBACAuthorizer struct {
	manager *rbac.Manager
}

// NewRBACAuthorizer creates a new RBAC authorizer
func NewRBACAuthorizer(manager *rbac.Manager) *RBACAuthorizer {
	return &RBACAuthorizer{
		manager: manager,
	}
}

// Authorize checks if a tool call is authorized based on RBAC policies
func (a *RBACAuthorizer) Authorize(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error) {
	decision := &AuthorizationDecision{}

	// Validate session
	if call.SessionID == "" {
		decision.Allowed = false
		decision.Reason = "session ID is required"
		return decision, nil
	}

	// Get RBAC session
	session, err := a.manager.GetSession(call.SessionID)
	if err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("invalid session: %s", err.Error())
		return decision, nil
	}

	// Check if session is valid
	if !session.IsValid() {
		decision.Allowed = false
		decision.Reason = "session expired or invalid"
		return decision, nil
	}

	// Get agent
	agent := session.Agent
	if agent == nil {
		agentID := session.AgentID
		agent, err = a.manager.GetAgent(agentID)
		if err != nil {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("agent not found: %s", agentID)
			return decision, nil
		}
	}

	// Check if agent is enabled
	if !agent.Enabled {
		decision.Allowed = false
		decision.Reason = "agent is disabled"
		return decision, nil
	}

	// Perform authorization
	result, err := a.manager.AuthorizeToolCall(ctx, call.SessionID, call.Name)
	if err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("authorization error: %s", err.Error())
		return decision, err
	}

	decision.Allowed = result.Allowed
	decision.Reason = result.Reason
	decision.RiskScore = calculateRiskScore(call.Name, result.AgentRole)
	decision.MatchedRule = string(result.AgentRole)

	return decision, nil
}

// AuthorizeByAgentID authorizes a tool call using agent ID only
func (a *RBACAuthorizer) AuthorizeByAgentID(ctx context.Context, agentID, toolName string) (*AuthorizationDecision, error) {
	decision := &AuthorizationDecision{}

	// Get agent
	agent, err := a.manager.GetAgent(agentID)
	if err != nil {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("agent not found: %s", agentID)
		return decision, nil
	}

	// Check if agent is enabled
	if !agent.Enabled {
		decision.Allowed = false
		decision.Reason = "agent is disabled"
		return decision, nil
	}

	// Check if agent can execute the tool
	canExecute := agent.CanExecuteTool(toolName)
	if !canExecute {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("agent role '%s' does not have permission for tool '%s'", agent.Role, toolName)
		decision.RiskScore = calculateRiskScore(toolName, agent.Role)
		decision.MatchedRule = string(agent.Role)
		return decision, nil
	}

	decision.Allowed = true
	decision.Reason = "Authorized by RBAC"
	decision.RiskScore = calculateRiskScore(toolName, agent.Role)
	decision.MatchedRule = string(agent.Role)

	return decision, nil
}

// calculateRiskScore calculates risk score based on tool and role
func calculateRiskScore(toolName string, role rbac.AgentRole) int {
	highRiskTools := map[string]bool{
		"shell_command":  true,
		"bash":           true,
		"code_execute":   true,
		"database_query": true,
		"file_delete":    true,
	}

	mediumRiskTools := map[string]bool{
		"file_write":      true,
		"http_request":    true,
		"code_execute_go": true,
		"code_execute_py": true,
	}

	baseScore := 10 // Low risk

	if highRiskTools[toolName] {
		baseScore = 80
	} else if mediumRiskTools[toolName] {
		baseScore = 50
	}

	// Reduce score for higher roles (more trusted)
	switch role {
	case rbac.AgentRoleAdmin:
		baseScore = baseScore / 2
	case rbac.AgentRolePrivileged:
		baseScore = baseScore * 3 / 4
	case rbac.AgentRoleStandard:
		// Standard role keeps base score unchanged
	case rbac.AgentRoleRestricted:
		baseScore = baseScore * 4 / 3
	}

	return baseScore
}

// GetAgentPermissions returns permissions for an agent
func (a *RBACAuthorizer) GetAgentPermissions(ctx context.Context, agentID string) ([]string, error) {
	agent, err := a.manager.GetAgent(agentID)
	if err != nil {
		return nil, err
	}

	perms := make([]string, len(agent.Tools))
	for i, p := range agent.Tools {
		perms[i] = string(p)
	}
	return perms, nil
}

// GetAgentRole returns the role for an agent
func (a *RBACAuthorizer) GetAgentRole(ctx context.Context, agentID string) (rbac.AgentRole, error) {
	agent, err := a.manager.GetAgent(agentID)
	if err != nil {
		return "", err
	}
	return agent.Role, nil
}

// CanExecuteTool checks if an agent can execute a specific tool
func (a *RBACAuthorizer) CanExecuteTool(ctx context.Context, agentID, toolName string) bool {
	decision, _ := a.AuthorizeByAgentID(ctx, agentID, toolName)
	return decision.Allowed
}
