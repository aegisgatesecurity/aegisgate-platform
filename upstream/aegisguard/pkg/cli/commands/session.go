// Package commands provides the CLI command implementations for AegisGuard
package commands

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/aegisguardsecurity/aegisguard/pkg/config"
	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// ============================================================================
// SESSION COMMANDS
// ============================================================================

// SessionList lists active sessions
func SessionList(showAll bool) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	agents := mgr.ListAgents()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION ID\tAGENT\tROLE\tSTATUS\tCREATED\tEXPIRES\tTTL\t")
	fmt.Fprintln(w, "----------\t-----\t----\t------\t-------\t-------\t---\t")

	activeCount := 0

	for _, agent := range agents {
		sessions := mgr.GetAgentSessions(agent.ID)
		for _, session := range sessions {
			if !showAll && !session.Active {
				continue
			}

			activeCount++
			status := "active"
			if !session.Active {
				status = "terminated"
			}

			created := session.CreatedAt.Format("15:04")
			if session.CreatedAt.IsZero() {
				created = "N/A"
			}

			expires := session.ExpiresAt.Format("15:04")
			if session.ExpiresAt.IsZero() {
				expires = "N/A"
			}

			ttl := formatDuration(session.RemainingTTL())
			if !session.Active {
				ttl = "N/A"
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
				truncateID(session.ID),
				truncateID(agent.ID),
				agent.Role,
				status,
				created,
				expires,
				ttl,
			)
		}
	}

	w.Flush()

	if !showAll {
		fmt.Printf("\nTotal active sessions: %d\n", activeCount)
	} else {
		fmt.Printf("\nTotal sessions: %d\n", activeCount)
	}

	return nil
}

// SessionInfo shows detailed session information
func SessionInfo(sessionID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	session, err := mgr.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Get agent info
	agent, _ := mgr.GetAgent(session.AgentID)

	fmt.Printf("Session Details\n")
	fmt.Printf("===============\n")
	fmt.Printf("ID:           %s\n", session.ID)
	if agent != nil {
		fmt.Printf("Agent ID:     %s\n", agent.ID)
		fmt.Printf("Agent Name:   %s\n", agent.Name)
		fmt.Printf("Role:         %s\n", agent.Role)
	} else {
		fmt.Printf("Agent ID:     %s\n", session.AgentID)
		fmt.Printf("Role:         Unknown (agent may have been deleted)\n")
	}

	fmt.Printf("\nStatus:       ")
	if session.Active {
		fmt.Printf("✓ Active\n")
	} else {
		fmt.Printf("✗ Terminated\n")
	}

	fmt.Printf("Created:      %s\n", session.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Last Activity: %s\n", session.LastActivityTime().Format(time.RFC3339))
	fmt.Printf("Expires:      %s\n", session.ExpiresAt.Format(time.RFC3339))

	ttl := session.RemainingTTL()
	fmt.Printf("TTL Remaining: %s\n", formatDuration(ttl))

	if session.IPAddress != "" {
		fmt.Printf("IP Address:   %s\n", session.IPAddress)
	}
	if session.ContextHash != "" {
		fmt.Printf("Context Hash: %s\n", session.ContextHash)
	}

	if len(session.Tags) > 0 {
		fmt.Printf("\nTags:\n")
		for k, v := range session.Tags {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	return nil
}

// SessionTerminate terminates an active session
func SessionTerminate(sessionID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	// Check if session exists
	_, err = mgr.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if err := mgr.InvalidateSession(sessionID); err != nil {
		return fmt.Errorf("failed to terminate session: %w", err)
	}

	fmt.Printf("✓ Session %s terminated successfully\n", truncateID(sessionID))
	return nil
}

// SessionCreate creates a new session for an agent
func SessionCreate(cfg *config.Config, agentID string, opts ...rbac.SessionOption) (*rbac.AgentSession, error) {
	mgr, err := getManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize manager: %w", err)
	}

	// Check if agent exists
	agent, err := mgr.GetAgent(agentID)
	if err != nil {
		return nil, fmt.Errorf("agent not found: %s", agentID)
	}

	if !agent.Enabled {
		return nil, fmt.Errorf("agent %s is disabled", agentID)
	}

	ctx := context.Background()
	session, err := mgr.CreateSession(ctx, agentID, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	fmt.Printf("✓ Session created successfully\n")
	fmt.Printf("  Session ID: %s\n", session.ID)
	fmt.Printf("  Agent ID:   %s\n", agentID)
	fmt.Printf("  Expires:    %s\n", session.ExpiresAt.Format(time.RFC3339))

	return session, nil
}

// SessionRefresh extends a session's lifetime
func SessionRefresh(sessionID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	if err := mgr.RefreshSession(sessionID); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	session, _ := mgr.GetSession(sessionID)
	if session != nil {
		fmt.Printf("✓ Session %s refreshed\n", truncateID(sessionID))
		fmt.Printf("  New expiration: %s\n", session.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

// SessionAgentList lists sessions for a specific agent
func SessionAgentList(agentID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	// Check if agent exists
	_, err = mgr.GetAgent(agentID)
	if err != nil {
		return fmt.Errorf("agent not found: %s", agentID)
	}

	sessions := mgr.GetAgentSessions(agentID)

	if len(sessions) == 0 {
		fmt.Printf("No active sessions for agent %s\n", truncateID(agentID))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "SESSION ID\tSTATUS\tCREATED\tEXPIRES\tTTL\t\n")
	fmt.Fprintf(w, "----------\t------\t-------\t-------\t---\t")

	for _, session := range sessions {
		status := "active"
		if !session.Active {
			status = "terminated"
		}

		created := session.CreatedAt.Format("15:04")
		expires := session.ExpiresAt.Format("15:04")
		ttl := formatDuration(session.RemainingTTL())

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t\n",
			truncateID(session.ID),
			status,
			created,
			expires,
			ttl,
		)
	}

	w.Flush()
	fmt.Printf("\nTotal sessions for agent %s: %d\n", truncateID(agentID), len(sessions))

	return nil
}

// SessionAgentTerminate terminates all sessions for an agent
func SessionAgentTerminate(agentID string) error {
	cfg := &config.Config{}

	mgr, err := getManager(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	// Check if agent exists
	_, err = mgr.GetAgent(agentID)
	if err != nil {
		return fmt.Errorf("agent not found: %s", agentID)
	}

	if err := mgr.InvalidateAgentSessions(agentID); err != nil {
		return fmt.Errorf("failed to terminate agent sessions: %w", err)
	}

	fmt.Printf("✓ All sessions for agent %s terminated\n", truncateID(agentID))
	return nil
}

// ============================================================================
// HELPERS
// ============================================================================

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
