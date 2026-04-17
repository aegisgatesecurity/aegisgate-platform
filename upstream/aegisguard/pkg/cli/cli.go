// Package cli provides the command-line interface for AegisGuard agent management
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/aegisguardsecurity/aegisguard/pkg/cli/commands"
	"github.com/aegisguardsecurity/aegisguard/pkg/config"
)

// AgentCLI represents the AegisGuard CLI
type AgentCLI struct {
	config  *config.Config
	context context.Context
}

// NewAgentCLI creates a new CLI instance
func NewAgentCLI(cfg *config.Config) *AgentCLI {
	return &AgentCLI{
		config:  cfg,
		context: context.Background(),
	}
}

// Execute runs the CLI with the given arguments
func (c *AgentCLI) Execute(args []string) error {
	rootCmd := c.newRootCommand()
	rootCmd.AddCommand(
		c.newAgentCommand(),
		c.newSessionCommand(),
		c.newHealthCommand(),
		c.newToolsCommand(),
		c.newVersionCommand(),
	)
	return rootCmd.Execute()
}

func (c *AgentCLI) newRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "aegisguard",
		Short: "AegisGuard - AI Agent Security Platform",
		Long: `AegisGuard secures AI agents by providing:
  • Role-Based Access Control (RBAC)
  • Tool Authorization & Sandboxing
  • Session Isolation & Context Management
  • Threat Detection & Compliance Auditing

For more information, visit: https://aegisguard.io`,
	}
}

func (c *AgentCLI) newAgentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage agents",
		Long:  "Register, list, and delete agents from AegisGuard",
	}

	cmd.AddCommand(
		c.newAgentRegisterCommand(),
		c.newAgentListCommand(),
		c.newAgentDeleteCommand(),
		c.newAgentInfoCommand(),
	)

	return cmd
}

func (c *AgentCLI) newAgentRegisterCommand() *cobra.Command {
	var apiKey string
	var name string
	var provider string
	var capabilities []string

	cmd := &cobra.Command{
		Use:   "register <agent-name>",
		Short: "Register a new agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			agentName := args[0]
			return commands.AgentRegister(c.config, agentName, name, provider, apiKey, capabilities)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Human-readable agent name")
	cmd.Flags().StringVarP(&provider, "provider", "p", "", "Agent provider (openai, anthropic, google, etc.)")
	cmd.Flags().StringVarP(&apiKey, "api-key", "k", "", "Agent API key")
	cmd.Flags().StringSliceVarP(&capabilities, "capabilities", "c", []string{}, "Agent capabilities (e.g., code, analysis, web)")

	return cmd
}

func (c *AgentCLI) newAgentListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all registered agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.AgentList()
		},
	}
	return cmd
}

func (c *AgentCLI) newAgentDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <agent-id>",
		Short: "Delete an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.AgentDelete(args[0])
		},
	}
	return cmd
}

func (c *AgentCLI) newAgentInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info <agent-id>",
		Short: "Get agent details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.AgentInfo(args[0])
		},
	}
	return cmd
}

func (c *AgentCLI) newSessionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Manage sessions",
		Long:  "List and manage agent sessions",
	}

	cmd.AddCommand(
		c.newSessionListCommand(),
		c.newSessionTerminateCommand(),
		c.newSessionInfoCommand(),
	)

	return cmd
}

func (c *AgentCLI) newSessionListCommand() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.SessionList(all)
		},
	}

	cmd.Flags().BoolVarP(&all, "all", "a", false, "Show all sessions including terminated")

	return cmd
}

func (c *AgentCLI) newSessionTerminateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "terminate <session-id>",
		Short: "Terminate a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.SessionTerminate(args[0])
		},
	}
	return cmd
}

func (c *AgentCLI) newSessionInfoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info <session-id>",
		Short: "Get session details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.SessionInfo(args[0])
		},
	}
	return cmd
}

func (c *AgentCLI) newHealthCommand() *cobra.Command {
	var watch bool

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Check AegisGuard health status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.HealthCheck(c.config, watch)
		},
	}

	cmd.Flags().BoolVarP(&watch, "watch", "w", false, "Continuously monitor health status")

	return cmd
}

func (c *AgentCLI) newToolsCommand() *cobra.Command {
	var byRisk bool
	var byCategory bool

	cmd := &cobra.Command{
		Use:   "tools",
		Short: "List available tools",
		RunE: func(cmd *cobra.Command, args []string) error {
			return commands.ToolsList(c.config, byRisk, byCategory)
		},
	}

	cmd.Flags().BoolVarP(&byRisk, "risk", "r", false, "Group tools by risk level")
	cmd.Flags().BoolVarP(&byCategory, "category", "c", false, "Group tools by category")

	return cmd
}

func (c *AgentCLI) newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("AegisGuard v0.1.0-alpha")
			fmt.Println("Build: development")
		},
	}
}

// PrintJSON prints data as formatted JSON
func PrintJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintTable prints data as a formatted table
func PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, join(headers, "\t")+"\t")
	for _, row := range rows {
		fmt.Fprintln(w, join(row, "\t")+"\t")
	}
	w.Flush()
}

func join(vals []string, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	result := vals[0]
	for i := 1; i < len(vals); i++ {
		result += sep + vals[i]
	}
	return result
}
