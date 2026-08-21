## Glossary

A reference for terms used throughout AegisGate documentation. Organized by category for easier browsing.

### AI Security

| Term | Definition |
|------|-----------|
| **A2A** | Agent-to-Agent protocol. AegisGate secures A2A communication with mTLS, HMAC integrity, and capability enforcement. See `pkg/a2a/`. |
| **ACP** | Agent Capability Policy. Controls which actions an AI agent is permitted to perform. See `pkg/acp/`. |
| **Adversarial Pattern** | A prompt or content pattern designed to bypass security controls (prompt injection, jailbreak, encoding evasion). AegisGate detects 176 such patterns. |
| **ATLAS** | MITRE ATLAS (Adversarial Threat Landscape for AI Systems). A framework cataloging attacks against AI systems. AegisGate maps detections to ATLAS techniques. |
| **CheckFunc** | The Go type for an automated compliance control check. Each `CheckFunc` evaluates a specific control and returns compliant/partial/non-compliant status. |
| **Fail-Closed** | A security principle where the system blocks traffic if it cannot scan or verify it. AegisGate is fail-closed by default — if scanning fails, the request is blocked, not allowed through. |
| **MCP** | Model Context Protocol. A protocol for AI agents to invoke external tools. AegisGate secures MCP server interactions with capability enforcement and content scanning. See `pkg/mcpserver/`. |
| **Prompt Injection** | An attack where malicious instructions are embedded in content to manipulate an AI model's behavior. AegisGate detects and blocks prompt injection patterns. |
| **PII** | Personally Identifiable Information. AegisGate detects and redacts PII (SSN, credit card, email, phone, DOB, health plan ID) in AI traffic. |
| **Trust Framework** | AegisGate's system for cryptographic agent identity, per-session trust scoring, and signed attestations. See `pkg/attestation/`. |

### Compliance

| Term | Definition |
|------|-----------|
| **Automated Control** | A compliance control that AegisGate can verify programmatically using one of 4 automation methods. 1,457 of 2,043 controls are automated (71.3%). |
| **Audit Trail Evidence** | One of 4 automation methods. Examines audit logs for required evidence artifacts (access logged, data retention enforced, incident response tracked). |
| **CCPA/CPRA** | California Consumer Privacy Act / California Privacy Rights Act. Developer-tier framework with 26 controls. |
| **CMMC L2** | Cybersecurity Maturity Model Certification Level 2. DoD framework for defense contractors. Enterprise-tier, 110 practices. |
| **Config State Verification** | One of 4 automation methods. Reads running configuration and validates it against framework requirements (TLS enabled, audit logging on). |
| **Cross-Framework Mapping** | One of 4 automation methods. Maps evidence from one framework to satisfy another's requirements (HIPAA access logging → SOC 2 CC6.1). |
| **Detection Engine State** | One of 4 automation methods. Checks that detection rules and scanners are active and covering required patterns. |
| **EU AI Act** | European Union AI Act. First comprehensive AI regulation. Professional-tier, 120 controls across 8 risk categories. |
| **FedRAMP** | Federal Risk and Authorization Management Program. U.S. government cloud security authorization. Enterprise-tier, 170 controls. |
| **Framework** | A compliance framework (HIPAA, SOC 2, EU AI Act, etc.). AegisGate supports 31 frameworks with full Go implementations. |
| **HITRUST CSF** | HITRUST Common Security Framework. Enterprise-tier framework for healthcare and regulated industries. |
| **Manual Control** | A compliance control that requires human processes (organizational policies, legal agreements, physical security, HR training). 586 of 2,043 controls are manual (28.7%). |
| **NIST AI RMF** | NIST AI Risk Management Framework 1.0. Community-tier framework with 50 controls across 4 functions: GOVERN, MAP, MEASURE, MANAGE. |
| **SOC 2** | Service Organization Control 2. Developer-tier framework for service organizations. 64 controls across Trust Services Criteria. |
| **TISAX** | Trusted Information Security Assessment Exchange. European automotive industry security assessment. Enterprise-tier. |

### Deployment

| Term | Definition |
|------|-----------|
| **Air-Gapped** | A deployment with no internet access. AegisGate supports fully offline operation with the `air-gapped` deploy profile. |
| **Config Precedence** | The order in which configuration values are resolved: CLI flags > env vars > config file > deploy profile > defaults. |
| **Deploy Profile** | A predefined configuration preset (v4.2.0+). 5 profiles: `quickstart`, `small-team`, `production`, `high-security`, `air-gapped`. Each populates all config fields with sensible defaults. |
| **Guided Setup** | The v4.2.0 initiative comprising deploy profiles, setup wizard, config validation, and maintenance windows. Makes deployment accessible without DevOps expertise. |
| **Maintenance Window** | A planned downtime period (v4.2.0+) where the platform returns 503 to proxy requests while keeping health/version endpoints accessible. Uses `atomic.Bool` for zero-overhead state checks. |
| **Setup Wizard** | Interactive or non-interactive environment detection tool (v4.2.0+). Auto-detects Docker, K8s, systemd, bare metal; recommends a profile; generates a validated config. |
| **Standalone Mode** | Running AegisGate with `--embedded-mcp` flag, which starts the MCP server in-process without external MCP infrastructure. |

### Architecture

| Term | Definition |
|------|-----------|
| **6 Pillars** | AegisGate's six protection domains: HTTP API, MCP, A2A, ACP (Agent Capability Policy), Response, and Trust. |
| **Detection Pattern** | A regex or ML-based pattern that identifies a specific threat type (secret, XSS, PII, prompt injection, etc.). 176 patterns are wired into every request/response. |
| **Graceful Degradation** | When ML detection is unavailable (no ONNX Runtime), AegisGate falls back to regex-only detection (83.1% coverage) instead of failing. |
| **ML Threat Detection** | CNN-BiLSTM neural network (1.58M params) for adversarial pattern detection with 100/100 evasion resistance. Professional+ tier. |
| **ONNX Runtime** | Open Neural Network Exchange runtime. Optional dependency for ML threat detection. Without it, AegisGate uses regex-only mode. |
| **Open-Core** | AegisGate's licensing model: Community edition is Apache 2.0 open source; Developer/Professional/Enterprise features are proprietary. |
| **RBAC** | Role-Based Access Control. Developer+ tier feature for managing user permissions. |
| **SIEM** | Security Information and Event Management. AegisGate forwards audit events to 11 SIEM platforms (Splunk, Elasticsearch, QRadar, etc.). Professional+ tier. |
| **SOAR** | Security Orchestration, Automation, and Response. AegisGate integrates with 4 SOAR platforms (PagerDuty, Jira, ServiceNow). |
| **Trust Score** | A per-session trust rating computed by the Trust Framework based on agent identity, behavior, and posture. |

_See also: [Configuration Reference](configuration.md), [CLI Reference](cli-reference.md), [Compliance Frameworks](compliance documentation on the website)._