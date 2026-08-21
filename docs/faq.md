## Frequently Asked Questions

### What is AegisGate?

AegisGate is an AI security platform that acts as a gateway for your AI infrastructure. It provides:

- **Bidirectional scanning** of every API request and response
- **MCP protocol protection** for AI agent tool execution
- **A2A protocol protection** for agent-to-agent communication
- **Threat detection** across 176 patterns with ML-based adversarial detection
- **Compliance reporting** for 31 frameworks (SOC 2, HIPAA, EU AI Act, FedRAMP, and more)
- **Trust Framework** with per-session trust scoring and signed attestations

### How does AegisGate work?

AegisGate deploys as a sidecar proxy or standalone gateway. All traffic to your AI services flows through AegisGate, which:

1. Intercepts requests and responses
2. Scans content for threats, secrets, and PII
3. Applies RBAC and rate limiting policies
4. Logs all activity for audit trails with cryptographic attestation

### What AI models does AegisGate support?

AegisGate works with any AI API:

- **OpenAI** (ChatGPT, GPT-4)
- **Anthropic** (Claude)
- **Google** (Gemini)
- **Azure OpenAI**
- **AWS Bedrock**
- **Self-hosted models** via OpenAI-compatible API

### Is AegisGate self-hosted?

Yes. AegisGate runs entirely on your infrastructure with **zero external dependencies**. No data leaves your environment. The binary is 19.1MB with no runtime dependencies (excluding optional ONNX Runtime for ML detection).

### What's the performance impact?

AegisGate adds effectively zero overhead — the proxy is **-2.8ms p99** (faster than direct) due to zero-cost proxy optimization for benign traffic. Blocked requests resolve in 7.2ms p50. The scanning is optimized for speed and scales horizontally to 23,578+ RPS.

### How do I upgrade my tier?

Contact [sales@aegisgatesecurity.io](mailto:sales@aegisgatesecurity.io) for Developer, Professional, or Enterprise tiers. Community tier is free forever.

### Does AegisGate support Kubernetes?

Yes. Deploy via:

- **Helm chart**: `helm install aegisgate aegisgate/aegisgate-platform`
- **Docker**: Single 19.1MB container image
- **Bare metal**: Single binary, no runtime dependencies

### Can I try AegisGate before buying?

Start with the **Community tier** (free, Apache 2.0) to evaluate the platform. Upgrade when you're ready for SSO, RBAC, and compliance features.

---

## Guided Setup (v4.2.0+)

### What is the Guided Setup?

The Guided Setup is a set of features that make AegisGate deployment and administration accessible to teams without dedicated DevOps or Kubernetes expertise. It includes:

1. **Deploy Profiles** — 5 predefined config presets (quickstart, small-team, production, high-security, air-gapped)
2. **Setup Wizard** — auto-detects your environment and generates a validated config
3. **Config Validation** — 15+ checks before deployment to catch misconfigurations
4. **Maintenance Windows** — planned downtime with automatic 503 responses and health passthrough

### How do I get started without knowing how to write YAML?

```bash
# Build the binary
go build -o aegisgate-platform ./cmd/aegisgate-platform/

# Auto-detect your environment and generate a config
./aegisgate-platform setup --non-interactive

# Start the platform
./aegisgate-platform --config aegisgate-platform.yaml --embedded-mcp
```

The setup wizard detects Docker, Kubernetes, systemd, or bare metal; recommends a profile; generates the config; and prints next steps. No YAML editing required.

### Which deploy profile should I use?

| Profile | When to use |
|---------|-------------|
| `quickstart` | Trying AegisGate for the first time |
| `small-team` | 5–50 users, small organization |
| `production` | Live production traffic, need TLS and audit logging |
| `high-security` | Regulated industry (HIPAA, SOC 2, EU AI Act) |
| `air-gapped` | Isolated network, no internet access |

```bash
./aegisgate-platform --profile list  # See all profiles with descriptions
```

### How do I validate my config before deploying?

```bash
./aegisgate-platform config validate aegisgate-platform.yaml
```

This checks port conflicts, TLS certificate paths, log levels, rate limits, SIEM endpoints, and more. Errors are fatal (exit 1); warnings are informational.

---

## Compliance

### How many compliance frameworks does AegisGate support?

**31 compliance frameworks** with **2,043 total controls** — **1,457 automated** (71.3%) and **586 manual** (28.7%). The manual controls are genuinely human-process controls: organizational policies, legal agreements, physical security, HR training, governance, and supply chain management.

### What are the 4 automation methods?

1. **Config State Verification** — reads running configuration and validates it against framework requirements (e.g., TLS enabled, audit logging on)
2. **Audit Trail Evidence** — examines audit logs for required evidence artifacts
3. **Detection Engine State** — checks that detection rules and scanners are active
4. **Cross-Framework Mapping** — maps evidence from one framework to satisfy another's requirements

### Which compliance frameworks are free (Community tier)?

4 frameworks are free under the Apache 2.0 Community tier: OWASP LLM Top 10, OWASP Web Top 10, MITRE ATLAS, NIST AI RMF 1.0.

### Which frameworks need a paid tier?

- **Developer** ($79/mo): HIPAA, PCI-DSS, SOC 2, ISO 27001, CCPA/CPRA, GDPR (6 frameworks)
- **Professional** ($499/mo): ISO 42001, EU AI Act, FIPS, CIS, NIST CSF, CSA STAR, NIST AI 600-1, SOX, GLBA, CJIS, NERC CIP, FERPA, HITECH, FFIEC, TSA SD, ISO 21434 (16 frameworks)
- **Enterprise** (custom): FedRAMP, CMMC L2, NIST 800-171, HITRUST, TISAX (5 frameworks)

See [Compliance Frameworks](compliance documentation on the website) for the full list and [Tier Comparison](tier comparison on the website) for pricing.

---

## Troubleshooting

### The platform won't start

Run `./aegisgate-platform config validate aegisgate-platform.yaml` to check for configuration errors. The most common issues are port conflicts and missing TLS certificate paths. Use `./aegisgate-platform setup --non-interactive` to generate a valid config from scratch.

### How do I put the platform in maintenance mode?

```bash
./aegisgate-platform maintenance enable --message "Applying security patch"
```

See [Maintenance Windows](maintenance-windows.md) for the full guide.

### Where can I get more help?

- **Documentation:** [docs/](docs/)
- **CLI Reference:** [cli-reference.md](cli-reference.md)
- **Email Support:** [security@aegisgatesecurity.io](mailto:security@aegisgatesecurity.io)
- **GitHub Issues:** [https://github.com/aegisgatesecurity/aegisgate-platform/issues](https://github.com/aegisgatesecurity/aegisgate-platform/issues)