# AegisGate Security Platform

**Complete AI Security — API Gateway + Agent Security in One Platform**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://golang.org/)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Ready-green)](https://aegisgatesecurity.io/security)

---

## What is AegisGate Platform?

AegisGate Platform is a **comprehensive AI security solution** that protects both:

1. **AI API Traffic** — Your LLM APIs, OpenAI/Anthropic connections, AI inference endpoints
2. **AI Agent Operations** — Your MCP servers, autonomous agents, tool-using AI systems

Previously offered as separate products (AegisGate and AegisGuard), now unified into a single platform for simplified deployment, maintenance, and enterprise security.

---

## Key Capabilities

### API Security (formerly AegisGate)
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC) proxy support
- gRPC and WebSocket proxying
- LLM provider routing (OpenAI, Anthropic, Azure, AWS Bedrock, Google Vertex)
- Rate limiting and request throttling
- ML-based anomaly detection
- Prompt injection detection
- Data exfiltration prevention
- PII detection and redaction

### Agent Security (formerly AegisGuard)
- Model Context Protocol (MCP) security
- Tool call authorization matrix
- Workflow approval system (human-in-the-loop)
- Agent-to-agent communication security
- Sandbox isolation for tool execution
- Risk-based permission controls
- Audit trail for all agent actions

### Enterprise Features
- **SIEM Integrations**: Splunk, QRadar, Azure Sentinel, Elastic, Sumo Logic, ArcSight, LogRhythm, Syslog
- **SSO/SAML/OIDC**: Enterprise identity provider integration
- **Compliance Frameworks**: OWASP, MITRE ATLAS, SOC2, HIPAA, PCI-DSS, GDPR, ISO 27001, ISO 42001, NIST AI RMF
- **ML Anomaly Detection**: Traffic pattern analysis, behavioral analytics, zero-day detection
- **Threat Intelligence**: STIX/TAXII feeds, IOC correlation
- **Multi-Tenancy**: Complete tenant isolation with granular permissions

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AegisGate Security Platform                  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   API Proxy │  │   Agent     │  │  Dashboard  │             │
│  │   Module    │  │  Security   │  │    & UI     │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                      │
├─────────┴────────────────┴────────────────┴────────────────────┤
│                      Core Security Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │    ML       │  │   SIEM      │  │    SSO      │             │
│  │ Anomaly    │  │ Integration │  │  /SAML/OIDC │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                      │
├─────────┴────────────────┴────────────────┴────────────────────┤
│                      Shared Infrastructure                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Audit     │  │   Policy    │  │   Tier      │             │
│  │   Logging   │  │   Engine    │  │   System    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tier System

| Feature | Community | Developer | Professional | Enterprise |
|---------|-----------|-----------|--------------|------------|
| **API Proxy** | ✅ | ✅ | ✅ | ✅ |
| **Agent Security** | ✅ | ✅ | ✅ | ✅ |
| **MCP Protocol** | ✅ | ✅ | ✅ | ✅ |
| **Rate Limiting** | 200/min | 1000/min | 5000/min | Unlimited |
| **Anomaly Detection** | Basic | Advanced | Advanced | ML+Predictive |
| **SIEM Integration** | - | - | ✅ | ✅ |
| **SSO/SAML** | - | - | ✅ | ✅ |
| **Multi-Tenancy** | - | - | ✅ | ✅ |
| **HA Deployment** | - | - | - | ✅ |
| **HSM Integration** | - | - | - | ✅ |
| **Air-Gapped** | - | - | - | ✅ |

---

## Quick Start

### Docker Compose (Recommended for Testing)

```bash
# Clone the repository
git clone https://github.com/aegisgatesecurity/aegisgate-platform.git
cd aegisgate-platform

# Start the platform
docker-compose up -d

# Check health
curl http://localhost:8080/health
```

### Kubernetes (Production)

```bash
# Add the Helm repository
helm repo add aegisgate https://helm.aegisgatesecurity.io

# Install the platform
helm install aegisgate-platform aegisgate/aegisgate-platform \
  --set tier=developer \
  --set license.key=YOUR_LICENSE_KEY
```

---

## Configuration

### Minimal Configuration

```yaml
# aegisgate-platform.yaml
server:
  host: "0.0.0.0"
  port: 8080

tier: community

modules:
  api_proxy:
    enabled: true
  agent_security:
    enabled: true

logging:
  level: info
  format: json
```

### Enterprise Configuration

```yaml
# aegisgate-platform.yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: true
    cert_file: /etc/aegisgate/tls/server.crt
    key_file: /etc/aegisgate/tls/server.key

tier: enterprise

license:
  key: ${LICENSE_KEY}
  admin_panel_url: "https://admin.aegisgatesecurity.io"

modules:
  api_proxy:
    enabled: true
    providers:
      - openai
      - anthropic
      - azure_openai
  agent_security:
    enabled: true
    mcp:
      enabled: true
    authorization:
      strict_mode: true
    workflow:
      approval_required:
        - shell_exec
        - file_delete
        - database_write

database:
  type: postgres
  url: ${DATABASE_URL}

redis:
  url: ${REDIS_URL}

siem:
  enabled: true
  platforms:
    - type: splunk
      url: ${SPLUNK_URL}
      token: ${SPLUNK_TOKEN}
    - type: sentinel
      tenant_id: ${AZURE_TENANT_ID}
      client_id: ${AZURE_CLIENT_ID}

sso:
  enabled: true
  provider: oidc
  issuer: ${OIDC_ISSUER}
  client_id: ${OIDC_CLIENT_ID}
  client_secret: ${OIDC_CLIENT_SECRET}

ml_anomaly:
  enabled: true
  sensitivity: high

audit:
  retention_days: 90
  hash_chain: true
```

---

## API Reference

### REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness probe |
| `/api/v1/proxy` | POST | Proxy AI API request |
| `/api/v1/agent/authorize` | POST | Authorize agent tool call |
| `/api/v1/agent/workflow` | POST | Create approval workflow |
| `/api/v1/audit` | GET | Query audit logs |
| `/api/v1/metrics` | GET | Prometheus metrics |

### GraphQL

```graphql
query GetThreats($timeRange: TimeRange!) {
  threats(timeRange: $timeRange) {
    id
    type
    severity
    source
    agentId
    timestamp
  }
}
```

### gRPC

See `proto/` directory for protobuf definitions.

---

## SDK

### Go

```go
import "github.com/aegisgatesecurity/aegisgate-platform/sdk/go"

client, err := aegisgate.NewClient("http://localhost:8080")
if err != nil {
    log.Fatal(err)
}

// Authorize agent tool call
authz, err := client.AuthorizeTool(ctx, &aegisgate.ToolRequest{
    AgentID:    "agent-001",
    ToolName:   "shell_exec",
    Parameters: map[string]interface{}{"command": "ls"},
})
```

### Python

```python
from aegisgate import Client

client = Client("http://localhost:8080")

# Authorize agent tool call
result = client.authorize_tool(
    agent_id="agent-001",
    tool_name="shell_exec",
    parameters={"command": "ls"}
)
```

### LangChain Integration

```python
from langchain.agents import initialize_agent
from aegisgate.langchain import AegisGateToolAuthorizer

# Wrap tools with AegisGate authorization
authorizer = AegisGateToolAuthorizer(client)
tools = authorizer.wrap_tools(existing_tools)

agent = initialize_agent(tools, llm, agent="zero-shot-react-description")
```

---

## Compliance

AegisGate Platform supports the following compliance frameworks:

| Framework | Tier |
|-----------|------|
| OWASP Top 10 | Community |
| MITRE ATLAS | Community |
| SOC 2 (View) | Community |
| SOC 2 (Full) | Professional |
| HIPAA | Professional |
| PCI-DSS | Professional |
| GDPR | Professional |
| ISO 27001 | Professional |
| ISO 42001 | Enterprise |
| NIST AI RMF | Enterprise |
| FedRAMP | Enterprise |

---

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture](docs/architecture.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- [API Reference](docs/API.md)
- [Compliance Guide](docs/COMPLIANCE_GUIDE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/aegisgatesecurity/aegisgate-platform.git
cd aegisgate-platform
make setup

# Run tests
make test

# Run linting
make lint

# Build
make build
```

---

## Security

For security concerns, please email security@aegisgatesecurity.io.

See [SECURITY.md](SECURITY.md) for our security policy.

---

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

Enterprise features are available under a commercial license. Contact sales@aegisgatesecurity.io for details.

---

## Support

| Tier | Support Level |
|------|---------------|
| Community | GitHub Issues |
| Developer | Email (48h response) |
| Professional | Priority Email (24h response) |
| Enterprise | 24/7 Dedicated Support |

---

## Migration from v1.x

If you're migrating from AegisGate v1.x or AegisGuard v1.x, see our [Migration Guide](docs/MIGRATION.md).

Key changes:
- Single binary serves both API proxy and agent security
- Unified configuration format
- Shared audit log format
- Consolidated tier features

---

## Roadmap

### v2.0.0 (Current)
- ✅ Unified platform (AegisGate + AegisGuard)
- ✅ Single configuration format
- ✅ Shared tier system
- ✅ Consolidated documentation

### v2.1.0 (Planned)
- 🔲 GraphQL API
- 🔲 Unified Python SDK
- 🔲 Enhanced ML anomaly detection for agents

### v2.2.0 (Planned)
- 🔲 Browser extension for admin
- 🔲 Advanced threat hunting
- 🔲 Custom compliance frameworks

---

## Acknowledgments

AegisGate Platform is the consolidation of:
- **AegisGate** — AI API Security Gateway
- **AegisGuard** — AI Agent Security Platform

Both projects contributed significantly to this unified platform.

---

**[AegisGate Security](https://aegisgatesecurity.io)** — Protecting AI Infrastructure