// Package commands provides the CLI command implementations for AegisGuard
package commands

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/aegisguardsecurity/aegisguard/pkg/config"
	"github.com/aegisguardsecurity/aegisguard/pkg/rbac"
)

// ToolInfo represents information about a tool
type ToolInfo struct {
	Name        string
	Category    string
	RiskLevel   string
	Description string
	MinRole     rbac.AgentRole
}

// ToolsList lists available tools with optional grouping
func ToolsList(cfg *config.Config, byRisk, byCategory bool) error {
	tools := getToolCatalog()

	if byRisk {
		return listToolsByRisk(tools)
	}
	if byCategory {
		return listToolsByCategory(tools)
	}

	// Default: simple list
	return listToolsSimple(tools)
}

// listToolsSimple shows a simple table of all tools
func listToolsSimple(tools []ToolInfo) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TOOL\tCATEGORY\tRISK\tMIN ROLE\t")
	fmt.Fprintln(w, "----\t--------\t----\t--------\t")

	for _, tool := range tools {
		risk := riskIndicator(tool.RiskLevel)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
			tool.Name,
			tool.Category,
			risk,
			tool.MinRole,
		)
	}

	w.Flush()
	fmt.Printf("\nTotal tools: %d\n", len(tools))
	return nil
}

// listToolsByRisk groups and displays tools by risk level
func listToolsByRisk(tools []ToolInfo) error {
	byRisk := make(map[string][]ToolInfo)
	for _, tool := range tools {
		byRisk[tool.RiskLevel] = append(byRisk[tool.RiskLevel], tool)
	}

	riskOrder := []string{"critical", "high", "medium", "low"}
	riskLabels := map[string]string{
		"critical": "🔴 CRITICAL RISK",
		"high":     "🟠 HIGH RISK",
		"medium":   "🟡 MEDIUM RISK",
		"low":      "🟢 LOW RISK",
	}

	for _, risk := range riskOrder {
		toolsForRisk, ok := byRisk[risk]
		if !ok || len(toolsForRisk) == 0 {
			continue
		}

		fmt.Println()
		fmt.Printf("%s\n", riskLabels[risk])
		fmt.Println(strings.Repeat("─", 60))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "TOOL\tCATEGORY\tMIN ROLE\tDESCRIPTION\t\n")
		fmt.Fprintf(w, "----\t--------\t--------\t-----------\t")

		for _, tool := range toolsForRisk {
			desc := tool.Description
			if len(desc) > 50 {
				desc = desc[:47] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
				tool.Name,
				tool.Category,
				tool.MinRole,
				desc,
			)
		}

		w.Flush()
		fmt.Printf("\nCount: %d tool(s)\n", len(toolsForRisk))
	}

	// Summary
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("RISK SUMMARY")
	fmt.Println("════════════════════════════════════════════════════════════")

	total := 0
	for risk, riskTools := range byRisk {
		count := len(riskTools)
		total += count
		fmt.Printf("  %-10s : %3d tools\n", strings.ToUpper(risk), count)
	}
	fmt.Printf("  %-10s : %3d tools\n", "TOTAL", total)

	return nil
}

// listToolsByCategory groups and displays tools by category
func listToolsByCategory(tools []ToolInfo) error {
	byCategory := make(map[string][]ToolInfo)
	for _, tool := range tools {
		byCategory[tool.Category] = append(byCategory[tool.Category], tool)
	}

	// Get sorted category names
	categories := make([]string, 0, len(byCategory))
	for cat := range byCategory {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	categoryEmojis := map[string]string{
		"file":          "📁",
		"web":           "🌐",
		"shell":         "💻",
		"code":          "⌨️ ",
		"database":      "🗄️ ",
		"admin":         "⚙️ ",
		"communication": "📡",
		"system":        "🖥️ ",
	}

	for _, category := range categories {
		toolsForCat := byCategory[category]
		emoji := categoryEmojis[category]
		if emoji == "" {
			emoji = "•"
		}

		fmt.Println()
		fmt.Printf("%s %s\n", emoji, strings.ToUpper(category))
		fmt.Println(strings.Repeat("─", 60))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "TOOL\tRISK\tMIN ROLE\tDESCRIPTION\t\n")
		fmt.Fprintf(w, "----\t----\t--------\t-----------\t")

		for _, tool := range toolsForCat {
			risk := riskIndicator(tool.RiskLevel)
			desc := tool.Description
			if len(desc) > 40 {
				desc = desc[:37] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t\n",
				tool.Name,
				risk,
				tool.MinRole,
				desc,
			)
		}

		w.Flush()
		fmt.Printf("\nCount: %d tool(s)\n", len(toolsForCat))
	}

	// Summary by category
	fmt.Println()
	fmt.Println("════════════════════════════════════════════════════════════")
	fmt.Println("CATEGORY SUMMARY")
	fmt.Println("════════════════════════════════════════════════════════════")

	total := 0
	for _, category := range categories {
		count := len(byCategory[category])
		total += count
		fmt.Printf("  %-15s : %3d tools\n", strings.ToUpper(category), count)
	}
	fmt.Printf("  %-15s : %3d tools\n", "TOTAL", total)

	return nil
}

// getToolCatalog returns the complete catalog of available tools
func getToolCatalog() []ToolInfo {
	return []ToolInfo{
		// File Operations
		{Name: "file:read", Category: "file", RiskLevel: "low", Description: "Read file contents", MinRole: rbac.AgentRoleRestricted},
		{Name: "file:write", Category: "file", RiskLevel: "medium", Description: "Write content to files", MinRole: rbac.AgentRoleStandard},
		{Name: "file:delete", Category: "file", RiskLevel: "high", Description: "Delete files from filesystem", MinRole: rbac.AgentRolePrivileged},
		{Name: "file:exists", Category: "file", RiskLevel: "low", Description: "Check if file exists", MinRole: rbac.AgentRoleRestricted},
		{Name: "file:list", Category: "file", RiskLevel: "low", Description: "List directory contents", MinRole: rbac.AgentRoleRestricted},
		{Name: "file:search", Category: "file", RiskLevel: "low", Description: "Search for files by pattern", MinRole: rbac.AgentRoleRestricted},

		// Web Operations
		{Name: "web:search", Category: "web", RiskLevel: "low", Description: "Search the web", MinRole: rbac.AgentRoleRestricted},
		{Name: "http:request", Category: "web", RiskLevel: "medium", Description: "Make HTTP requests", MinRole: rbac.AgentRoleStandard},
		{Name: "json:fetch", Category: "web", RiskLevel: "low", Description: "Fetch and parse JSON", MinRole: rbac.AgentRoleRestricted},
		{Name: "web:scrape", Category: "web", RiskLevel: "medium", Description: "Scrape web page content", MinRole: rbac.AgentRoleStandard},
		{Name: "web:api", Category: "web", RiskLevel: "medium", Description: "Call REST APIs", MinRole: rbac.AgentRoleStandard},

		// Shell Operations
		{Name: "shell:command", Category: "shell", RiskLevel: "critical", Description: "Execute shell commands", MinRole: rbac.AgentRolePrivileged},
		{Name: "bash", Category: "shell", RiskLevel: "critical", Description: "Execute bash commands", MinRole: rbac.AgentRolePrivileged},
		{Name: "powershell", Category: "shell", RiskLevel: "critical", Description: "Execute PowerShell commands", MinRole: rbac.AgentRolePrivileged},
		{Name: "ping", Category: "shell", RiskLevel: "low", Description: "Ping network hosts", MinRole: rbac.AgentRoleStandard},

		// Code Operations
		{Name: "code:search", Category: "code", RiskLevel: "low", Description: "Search code repositories", MinRole: rbac.AgentRoleRestricted},
		{Name: "code:execute:go", Category: "code", RiskLevel: "high", Description: "Execute Go code", MinRole: rbac.AgentRolePrivileged},
		{Name: "code:execute:python", Category: "code", RiskLevel: "high", Description: "Execute Python code", MinRole: rbac.AgentRolePrivileged},
		{Name: "code:execute:javascript", Category: "code", RiskLevel: "high", Description: "Execute JavaScript code", MinRole: rbac.AgentRolePrivileged},
		{Name: "code:execute:bash", Category: "code", RiskLevel: "critical", Description: "Execute bash scripts", MinRole: rbac.AgentRolePrivileged},
		{Name: "code:linter", Category: "code", RiskLevel: "low", Description: "Run code linters", MinRole: rbac.AgentRoleStandard},
		{Name: "code:formatter", Category: "code", RiskLevel: "low", Description: "Format code files", MinRole: rbac.AgentRoleStandard},

		// Database Operations
		{Name: "database:query", Category: "database", RiskLevel: "critical", Description: "Execute database queries", MinRole: rbac.AgentRolePrivileged},
		{Name: "database:list", Category: "database", RiskLevel: "medium", Description: "List databases", MinRole: rbac.AgentRolePrivileged},
		{Name: "database:schema", Category: "database", RiskLevel: "medium", Description: "View database schemas", MinRole: rbac.AgentRolePrivileged},
		{Name: "database:connect", Category: "database", RiskLevel: "high", Description: "Connect to database", MinRole: rbac.AgentRolePrivileged},

		// Admin Operations
		{Name: "admin:manage", Category: "admin", RiskLevel: "critical", Description: "Full administrative access", MinRole: rbac.AgentRoleAdmin},
		{Name: "admin:audit", Category: "admin", RiskLevel: "high", Description: "View audit logs", MinRole: rbac.AgentRoleAdmin},
		{Name: "admin:config", Category: "admin", RiskLevel: "high", Description: "Modify configuration", MinRole: rbac.AgentRoleAdmin},
		{Name: "admin:users", Category: "admin", RiskLevel: "critical", Description: "Manage users and permissions", MinRole: rbac.AgentRoleAdmin},

		// Communication
		{Name: "email:send", Category: "communication", RiskLevel: "high", Description: "Send emails", MinRole: rbac.AgentRolePrivileged},
		{Name: "webhook:call", Category: "communication", RiskLevel: "medium", Description: "Call webhooks", MinRole: rbac.AgentRoleStandard},
		{Name: "notification:send", Category: "communication", RiskLevel: "medium", Description: "Send notifications", MinRole: rbac.AgentRoleStandard},

		// System Operations
		{Name: "system:info", Category: "system", RiskLevel: "low", Description: "Get system information", MinRole: rbac.AgentRoleStandard},
		{Name: "system:processes", Category: "system", RiskLevel: "high", Description: "List system processes", MinRole: rbac.AgentRolePrivileged},
		{Name: "system:metrics", Category: "system", RiskLevel: "low", Description: "Get system metrics", MinRole: rbac.AgentRoleStandard},
	}
}

// riskIndicator converts risk level to visual indicator
func riskIndicator(risk string) string {
	switch risk {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

// GetToolsForRole returns all tools accessible by a given role
func GetToolsForRole(role rbac.AgentRole) []ToolInfo {
	allTools := getToolCatalog()
	allowed := []ToolInfo{}

	roleLevel := map[rbac.AgentRole]int{
		rbac.AgentRoleRestricted: 1,
		rbac.AgentRoleStandard:   2,
		rbac.AgentRolePrivileged: 3,
		rbac.AgentRoleAdmin:      4,
	}

	minLevel := roleLevel[role]

	for _, tool := range allTools {
		if roleLevel[tool.MinRole] <= minLevel {
			allowed = append(allowed, tool)
		}
	}

	return allowed
}

// CheckToolRisk returns the risk level for a tool
func CheckToolRisk(toolName string) string {
	tools := getToolCatalog()
	for _, tool := range tools {
		if tool.Name == toolName || strings.HasPrefix(toolName, tool.Name) {
			return tool.RiskLevel
		}
	}
	return "unknown"
}

// GetToolCategories returns all available categories
func GetToolCategories() []string {
	tools := getToolCatalog()
	categories := make(map[string]bool)
	for _, tool := range tools {
		categories[tool.Category] = true
	}

	result := make([]string, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}
	sort.Strings(result)
	return result
}

// GetRiskLevels returns all risk levels in order
func GetRiskLevels() []string {
	return []string{"critical", "high", "medium", "low"}
}
