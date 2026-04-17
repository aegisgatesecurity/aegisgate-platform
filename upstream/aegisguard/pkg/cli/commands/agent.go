// Package commands provides the CLI command implementations for AegisGuard
package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/config"
	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// ============================================================================
// GLOBAL MANAGER (singleton for CLI)
// ============================================================================

var (
	manager     *rbac.Manager
	managerInit sync.Once
	managerErr  error
)

// getManager returns the singleton RBAC manager instance
func getManager(cfg *config.Config) (*rbac.Manager, error) {
	managerInit.Do(func() {
		// Build RBAC config from app config - use defaults if not set
		sessionTTL := cfg.Session.TTL
		if sessionTTL <= 0 {
			sessionTTL = 24 * time.Hour
		}
		maxSessions := cfg.Session.MaxSessions
		if maxSessions <= 0 {
			maxSessions = 100
		}

		rbacCfg := &rbac.Config{
			SessionDuration: sessionTTL,
			MaxSessions:     maxSessions,
			MaxAgents:       1000,
			DefaultRole:     rbac.AgentRoleStandard,
			RequireApproval: true,
			CleanupInterval: 5 * time.Minute,
		}
		manager, managerErr = rbac.NewManager(rbacCfg)
	})
	return manager, managerErr
}

// ============================================================================
// AGENT COMMANDS
// ============================================================================

// AgentRegister registers a new agent
func AgentRegister(cfg *config.Config, agentName, displayName, provider, apiKey string, capabilities []string) error {
	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	// Generate agent ID
	agentID := generateAgentID(agentName)

	// Determine role based on capabilities
	role := rbac.AgentRoleStandard
	for _, cap := range capabilities {
		switch cap {
		case "admin", "privileged":
			role = rbac.AgentRolePrivileged
		case "security", "audit":
			role = rbac.AgentRoleAdmin
		}
	}

	// Build metadata
	metadata := make(map[string]interface{})
	if displayName != "" {
		metadata["display_name"] = displayName
	}
	if provider != "" {
		metadata["provider"] = provider
	}
	if apiKey != "" {
		metadata["api_key_set"] = true
	}
	if len(capabilities) > 0 {
		metadata["capabilities"] = capabilities
	}

	// Create agent
	agent := &rbac.Agent{
		ID:       agentID,
		Name:     agentName,
		Role:     role,
		Tags:     make(map[string]string),
		Metadata: metadata,
		Enabled:  true,
	}

	if err := mgr.RegisterAgent(agent); err != nil {
		return fmt.Errorf("failed to register agent: %w", err)
	}

	fmt.Printf("✓ Agent registered successfully\n")
	fmt.Printf("  ID:       %s\n", agentID)
	fmt.Printf("  Name:     %s\n", agentName)
	fmt.Printf("  Role:     %s\n", role)
	if displayName != "" {
		fmt.Printf("  Display:  %s\n", displayName)
	}
	if provider != "" {
		fmt.Printf("  Provider: %s\n", provider)
	}

	return nil
}

// AgentList lists all registered agents
func AgentList() error {
	// Create a default config for listing
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	agents := mgr.ListAgents()

	if len(agents) == 0 {
		fmt.Println("No agents registered.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tROLE\tSTATUS\tCREATED\t")
	fmt.Fprintln(w, "--\t----\t----\t------\t-------\t")

	for _, agent := range agents {
		status := "active"
		if !agent.Enabled {
			status = "disabled"
		}
		created := agent.CreatedAt.Format("2006-01-02 15:04")
		if agent.CreatedAt.IsZero() {
			created = "N/A"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t\n",
			truncateID(agent.ID),
			agent.Name,
			agent.Role,
			status,
			created,
		)
	}
	w.Flush()

	fmt.Printf("\nTotal: %d agent(s)\n", len(agents))
	return nil
}

// AgentInfo shows detailed information about an agent
func AgentInfo(agentID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	agent, err := mgr.GetAgent(agentID)
	if err != nil {
		return fmt.Errorf("agent not found: %s", agentID)
	}

	// Get agent's sessions
	sessions := mgr.GetAgentSessions(agentID)

	fmt.Printf("Agent Details\n")
	fmt.Printf("============\n")
	fmt.Printf("ID:          %s\n", agent.ID)
	fmt.Printf("Name:        %s\n", agent.Name)
	if agent.Description != "" {
		fmt.Printf("Description: %s\n", agent.Description)
	}
	fmt.Printf("Role:        %s\n", agent.Role)
	fmt.Printf("Status:      ")
	if agent.Enabled {
		fmt.Printf("✓ Enabled\n")
	} else {
		fmt.Printf("✗ Disabled\n")
	}
	fmt.Printf("Created:     %s\n", agent.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated:     %s\n", agent.UpdatedAt.Format(time.RFC3339))

	if len(agent.Tools) > 0 {
		fmt.Printf("\nPermissions (%d):\n", len(agent.Tools))
		for _, tool := range agent.Tools {
			fmt.Printf("  • %s\n", tool)
		}
	}

	if len(agent.Tags) > 0 {
		fmt.Printf("\nTags:\n")
		for k, v := range agent.Tags {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	fmt.Printf("\nActive Sessions: %d\n", len(sessions))
	for _, session := range sessions {
		fmt.Printf("  • %s (expires: %s)\n", truncateID(session.ID), session.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

// AgentDelete removes an agent
func AgentDelete(agentID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	// First check if agent exists
	_, err = mgr.GetAgent(agentID)
	if err != nil {
		return fmt.Errorf("agent not found: %s", agentID)
	}

	if err := mgr.UnregisterAgent(agentID); err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}

	fmt.Printf("✓ Agent %s deleted successfully\n", truncateID(agentID))
	return nil
}

// AgentUpdate updates an agent's configuration
func AgentUpdate(cfg *config.Config, agentID string, updates *rbac.AgentUpdates) error {
	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	if err := mgr.UpdateAgent(agentID, updates); err != nil {
		return fmt.Errorf("failed to update agent: %w", err)
	}

	fmt.Printf("✓ Agent %s updated successfully\n", truncateID(agentID))
	return nil
}

// AgentEnable enables a disabled agent
func AgentEnable(agentID string) error {
	return AgentUpdate(&config.Config{}, agentID, &rbac.AgentUpdates{Enabled: true})
}

// AgentDisable disables an agent
func AgentDisable(agentID string) error {
	return AgentUpdate(&config.Config{}, agentID, &rbac.AgentUpdates{Enabled: false})
}

// ============================================================================
// HELPERS
// ============================================================================

func generateAgentID(name string) string {
	// Simple ID generation - in production this would use UUID or similar
	timestamp := time.Now().UnixNano() % 1000000
	return fmt.Sprintf("agent_%s_%d", sanitizeName(name), timestamp)
}

func sanitizeName(name string) string {
	// Remove invalid characters for IDs
	result := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			result = append(result, c)
		} else if c == ' ' {
			result = append(result, '_')
		}
	}
	return string(result)
}

func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// ValidateAgentRole validates a role string
func ValidateAgentRole(role string) error {
	switch rbac.AgentRole(role) {
	case rbac.AgentRoleRestricted, rbac.AgentRoleStandard, rbac.AgentRolePrivileged, rbac.AgentRoleAdmin:
		return nil
	default:
		return errors.New("invalid role: must be one of restricted, standard, privileged, admin")
	}
}
