// Package rbac - Integration with existing authorization package
package rbac

import (
	"context"
)

// AuthorizationAdapter adapts the RBAC Manager for use with the existing authorization package
type AuthorizationAdapter struct {
	manager *Manager
}

// NewAuthorizationAdapter creates an adapter from an RBAC Manager
func NewAuthorizationAdapter(manager *Manager) *AuthorizationAdapter {
	return &AuthorizationAdapter{manager: manager}
}

// AuthorizeToolCall implements the ToolAuthorizer interface from pkg/authorization
func (a *AuthorizationAdapter) AuthorizeToolCall(ctx context.Context, call *AuthorizationCall) (*AuthorizationDecision, error) {
	result, err := a.manager.AuthorizeToolCall(ctx, call.SessionID, call.Name)
	if err != nil {
		return &AuthorizationDecision{
			Allowed:   false,
			Reason:    "RBAC error: " + err.Error(),
			RiskScore: 100,
		}, err
	}

	return &AuthorizationDecision{
		Allowed:     result.Allowed,
		Reason:      result.Reason,
		RiskScore:   calculateRBACRiskScore(result),
		MatchedRule: "rbac:" + string(result.AgentRole),
	}, nil
}

// AuthorizationCall represents a tool call for authorization (implements authorization.ToolCallRequest)
type AuthorizationCall struct {
	ID         string
	Name       string
	Parameters map[string]interface{}
	SessionID  string
	AgentID    string
}

// AuthorizationDecision represents the authorization decision
type AuthorizationDecision struct {
	Allowed     bool
	Reason      string
	RiskScore   int
	MatchedRule string
}

// calculateRBACRiskScore converts RBAC result to risk score
func calculateRBACRiskScore(result *AuthorizationResult) int {
	if !result.Allowed {
		return 100
	}

	// Base score by role
	roleScore := map[AgentRole]int{
		AgentRoleRestricted: 20,
		AgentRoleStandard:   40,
		AgentRolePrivileged: 60,
		AgentRoleAdmin:      80,
	}

	score := roleScore[result.AgentRole]

	// Add tool-specific risk
	toolRisk := map[string]int{
		"shell_command":  30,
		"bash":           30,
		"code_execute":   20,
		"database_query": 15,
		"file_write":     10,
		"http_request":   5,
		"file_read":      0,
		"web_search":     0,
	}

	if risk, ok := toolRisk[result.ToolName]; ok {
		score += risk
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetAgentForSession returns the agent associated with a session
func (a *AuthorizationAdapter) GetAgentForSession(ctx context.Context, sessionID string) (*Agent, error) {
	session, err := a.manager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	return session.Agent, nil
}

// CheckRateLimit checks rate limits for an agent
func (a *AuthorizationAdapter) CheckRateLimit(ctx context.Context, agentID string, toolName string) (bool, int, error) {
	agent, err := a.manager.GetAgent(agentID)
	if err != nil {
		return false, 0, err
	}

	// Get rate limits based on role
	limits := getRateLimitsForRole(agent.Role)

	limit, ok := limits[toolName]
	if !ok {
		return true, 0, nil // No limit for this tool
	}

	// In a real implementation, track actual usage
	// For now, allow all
	return true, limit, nil
}

// getRateLimitsForRole returns rate limits per tool for a role
func getRateLimitsForRole(role AgentRole) map[string]int {
	baseLimits := map[string]int{
		"file_read":      1000,
		"file_write":     100,
		"file_delete":    10,
		"web_search":     100,
		"http_request":   50,
		"code_search":    200,
		"shell_command":  5,
		"bash":           5,
		"code_execute":   20,
		"database_query": 50,
	}

	// Apply role multipliers
	multiplier := map[AgentRole]float64{
		AgentRoleRestricted: 0.5,
		AgentRoleStandard:   1.0,
		AgentRolePrivileged: 2.0,
		AgentRoleAdmin:      10.0,
	}

	mult := multiplier[role]
	result := make(map[string]int)
	for tool, limit := range baseLimits {
		result[tool] = int(float64(limit) * mult)
	}

	return result
}
