// Package soar provides Security Orchestration, Automation, and Response
// integration for the AegisGate Platform.
//
// # SOAR vs SIEM
//
// This package is distinct from the SIEM package (pkg/siem/). The SIEM
// package sends raw events TO logging and observability platforms such as
// Splunk, Datadog, and ELK for storage, search, and analysis. The SOAR
// package sends structured incident alerts TO automation platforms such as
// PagerDuty, Jira, and ServiceNow that can trigger playbooks, create tickets,
// page on-call engineers, and drive remediation workflows.
//
// In short:
//   - SIEM  →  "Log this event for analysis"
//   - SOAR  →  "Alert this platform so action is taken"
//
// # Supported Platforms
//
// The package currently supports three outbound integration targets:
//
//   - PagerDuty: Sends compliance violations and security events via the
//     Events API v2 format with deduplication keys and severity mapping.
//     Supports trigger, acknowledge, and resolve event actions.
//
//   - Jira: Creates issues (bugs) in a configured Jira project with
//     framework, control ID, and severity mapped to Jira priority levels.
//     Supports basic and API key authentication.
//
//   - ServiceNow: Creates incidents in ServiceNow with custom fields for
//     framework and control ID, categorized under security > compliance.
//     Supports basic and API key authentication.
//
//   - Custom: Sends a generic JSON payload to any webhook endpoint, with
//     optional HMAC-SHA256 signing for payload integrity verification.
//
// # Severity Mapping
//
// Internal severity levels map to platform-specific values:
//
//	AegisGate  |  PagerDuty  |  Jira      |  ServiceNow
//	-----------|-------------|------------|------------
//	critical   |  critical   |  Highest   |  1
//	high       |  error      |  High      |  2
//	medium     |  warning    |  Medium    |  3
//	low        |  info       |  Low       |  4
//	info       |  info       |  Lowest    |  4
//
// # Usage
//
// Create a Manager with your platform configurations, start it, and send
// incidents:
//
//	cfg := soar.Config{
//	    Global: soar.GlobalConfig{
//	        AppName:       "aegisgate",
//	        Environment:   "production",
//	        MaxRetries:    3,
//	        RetryInterval: 5 * time.Second,
//	    },
//	    Platforms: []soar.PlatformConfig{
//	        {
//	            Platform: soar.PlatformPagerDuty,
//	            Enabled:  true,
//	            Endpoint: "https://events.pagerduty.com/v2/enqueue",
//	            Auth:     soar.AuthConfig{Type: "api_key", APIKey: "your-routing-key"},
//	        },
//	    },
//	}
//
//	mgr := soar.NewManager(cfg, slog.Default())
//	mgr.Start()
//
//	incident := &soar.Incident{
//	    ID:          "INC-001",
//	    Title:       "HIPAA Access Control Violation",
//	    Severity:    soar.SeverityCritical,
//	    Status:      soar.StatusTriggered,
//	    Framework:   "hipaa",
//	    ControlID:   "HIPAA-AC-001",
//	    DedupKey:     "aegisgate-hipaa-HIPAA-AC-001",
//	}
//
//	results := mgr.SendIncident(ctx, incident)
//
// The Manager handles retry logic (with configurable attempts and intervals),
// tracks delivery statistics per platform, and provides health checks for
// monitoring integration status.
package soar
