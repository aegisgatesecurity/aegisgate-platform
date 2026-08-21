
## Deploy Profiles

Deploy profiles are predefined configuration presets that eliminate the need to write YAML from scratch. Each profile is a complete, validated `*platformconfig.Config` with sensible defaults for a specific deployment scenario.

### The 5 Profiles

| Profile | Tier | TLS | Rate Limit | Persistence | Best For |
|---------|------|-----|-----------|-------------|----------|
| **quickstart** | Community | Off | 60 RPM | In-memory | First run, demos, evaluation |
| **small-team** | Community | Auto-gen | 300 RPM | File-backed | 5-50 users, small orgs |
| **production** | Developer | 1.3 (bring certs) | 1,000 RPM | File-backed | Production deployment |
| **high-security** | Enterprise | mTLS + FIPS | 5,000 RPM | File-backed + FIPS | Regulated industries |
| **air-gapped** | Enterprise | 1.3 (bring certs) | 1,000 RPM | File-backed | Isolated networks, no internet |

---

## Which Profile Should I Use?

### Decision Tree

```
Are you just trying AegisGate for the first time?
├── Yes → quickstart
└── No → Is this for a real production deployment?
    ├── No (still testing/development) → small-team
    └── Yes → Is your network air-gapped (no internet access)?
        ├── Yes → air-gapped
        └── No → Are you in a regulated industry?
            (healthcare, finance, defense, government)
            ├── Yes → high-security
            └── No → production
```

### Plain-English Guide

**"I just want to see if this works."**
→ Use `quickstart`. No TLS, no config files, auto-generated certs. Runs in 30 seconds.

**"We have a small team using AI tools and need basic protection."**
→ Use `small-team`. TLS is auto-generated, audit logs are saved to disk, rate limits are moderate. Good for a small company or dev team.

**"We're putting this in production."**
→ Use `production`. TLS 1.3 is required (you bring your own certs), CSRF protection is on, audit logging is detailed. This is the baseline for any real deployment.

**"We're in healthcare/finance/defense and have compliance requirements."**
→ Use `high-security`. Adds mutual TLS (mTLS), FIPS 140-2 cryptographic mode, SIEM integration, maximum audit retention, and higher throughput. For regulated environments.

**"We have no internet access — completely isolated network."**
→ Use `air-gapped`. All external connections disabled: no SIEM forwarding, no IOC sharing, local upstream only. Dashboard bound to localhost. For air-gapped or classified networks.

---

## Using Profiles

### CLI Flag

```bash
# Run directly with a profile (no config file needed)
./aegisgate-platform --profile quickstart --embedded-mcp

# Use a profile and override with a config file
./aegisgate-platform --profile production --config my-overrides.yaml --embedded-mcp
```

### Setup Wizard

```bash
# Interactive — wizard recommends a profile based on your environment
./aegisgate-platform setup

# Non-interactive with a specific profile
./aegisgate-platform setup --profile high-security --non-interactive
```

### List All Profiles

```bash
./aegisgate-platform --profile list
```

### Config File

Profiles can also be loaded programmatically:

```go
import "github.com/aegisgatesecurity/aegisgate-platform/pkg/profiles"

cfg, err := profiles.ConfigFor("production")
if err != nil {
    log.Fatal(err)
}
// cfg is a fully-populated *platformconfig.Config
```

---

## Profile Details

### quickstart

| Setting | Value |
|---------|-------|
| Tier | Community |
| TLS | Disabled |
| Rate limit | 60 RPM |
| Persistence | In-memory (not persisted) |
| Dashboard | Enabled, port 8443, bind 0.0.0.0 |
| CSRF | Off |
| Audit middleware | On |
| A2A / ACP / Trust | Off |
| SIEM / SOAR | Off |
| Security headers | On |

**Use when:** You're evaluating AegisGate, running a demo, or just want to see it work. Zero configuration needed. Data is not persisted — restart loses audit logs.

**Switch to small-team when:** You're ready to keep audit logs, need TLS, or have more than a few users.

### small-team

| Setting | Value |
|---------|-------|
| Tier | Community |
| TLS | Enabled, auto-generate |
| Rate limit | 300 RPM |
| Persistence | File-backed (`./data`) |
| Dashboard | Enabled, port 8443, bind 0.0.0.0 |
| CSRF | On |
| Audit middleware | On |
| A2A | Off |
| ACP | Off |
| Trust | Off |
| SIEM / SOAR | Off |
| Security headers | On |

**Use when:** You have a small team (5-50 users) using AI tools and need basic protection with persistent audit logs. TLS certs are auto-generated on first start.

**Switch to production when:** You need bring-your-own TLS certs, higher rate limits, or A2A/ACP guardrails.

### production

| Setting | Value |
|---------|-------|
| Tier | Developer |
| TLS | Enabled, min 1.3, bring your own certs |
| Rate limit | 1,000 RPM |
| Persistence | File-backed (`/data`) |
| Dashboard | Enabled, port 8443, bind 0.0.0.0 |
| CSRF | On |
| Audit middleware | On |
| A2A | Enabled |
| ACP | Enabled |
| Trust | Enabled (requires Professional+ license) |
| SIEM | Off (enable when ready) |
| SOAR | Off (enable when ready) |
| Security headers | On |
| Shutdown timeout | 30s |

**Use when:** You're deploying to production. You need TLS with your own certificates, detailed audit logging, and the full set of guardrails (A2A, ACP, Trust).

**Prerequisites:** TLS certificate and key files. Place them at the paths specified in the config (default: `/data/certs/cert.pem` and `/data/certs/key.pem`).

**Switch to high-security when:** You have compliance requirements (HIPAA, PCI, FedRAMP, etc.) that require mTLS, FIPS mode, or SIEM integration.

### high-security

| Setting | Value |
|---------|-------|
| Tier | Enterprise |
| TLS | Enabled, min 1.3, mTLS required |
| Rate limit | 5,000 RPM |
| Persistence | File-backed (`/data`) with FIPS 140-2 |
| Dashboard | Enabled, port 8443, bind 0.0.0.0 |
| CSRF | On |
| Audit middleware | On |
| A2A | Enabled |
| ACP | Enabled |
| Trust | Enabled, require_license |
| SIEM | Enabled (configure your platform) |
| SOAR | Enabled (configure your platform) |
| FIPS | Enabled, level 140-2 |
| ML shadow mode | On (safe deployment) |
| Security headers | On |

**Use when:** You're in a regulated industry (healthcare, finance, defense, government) and need maximum security posture. mTLS is required for all connections, FIPS 140-2 cryptographic mode is active, and SIEM/SOAR integrations are enabled.

**Prerequisites:**
- TLS certificate and key files
- mTLS client CA certificate
- SIEM platform endpoint and credentials
- Enterprise tier license

### air-gapped

| Setting | Value |
|---------|-------|
| Tier | Enterprise |
| TLS | Enabled, min 1.3, bring your own certs |
| Rate limit | 1,000 RPM |
| Persistence | File-backed (`/data`) |
| Dashboard | Enabled, port 8443, bind 127.0.0.1 (localhost only) |
| CSRF | On |
| Audit middleware | On |
| A2A | Off (no external agents) |
| ACP | Off |
| Trust | Enabled, require_license |
| SIEM | Off (no external connections) |
| SOAR | Off (no external connections) |
| Upstream | `http://localhost:11434` (local LLM) |
| IOC sharing | Disabled |
| IOC receiving | Disabled |

**Use when:** Your network has no internet access. All connections are local. The upstream AI service is a local LLM (e.g., Ollama at `localhost:11434`). No external calls of any kind.

**Prerequisites:**
- TLS certificate and key files (cannot auto-generate in air-gapped mode)
- Local LLM service running (e.g., Ollama, vLLM, text-generation-webui)
- Enterprise tier license

---

## Config Precedence

When using `--profile`, settings are applied in this order:

1. **CLI flags** — highest priority (e.g., `--proxy-port 9090`)
2. **Environment variables** — (e.g., `AEGISGATE_PROXY_BIND_ADDRESS`)
3. **Config file** — if `--config` is also specified, it overrides the profile
4. **Profile preset** — the base configuration from the profile
5. **Built-in defaults** — `DefaultConfig()` fallback

Example: `--profile production --config my-overrides.yaml` uses the production profile as the base, then applies settings from `my-overrides.yaml` on top.

---

## Generating a Config from a Profile

The setup wizard can generate a standalone config file from a profile:

```bash
# Generate and write to a file
./aegisgate-platform setup --profile production --output /etc/aegisgate/config.yaml

# Then edit the file as needed
vim /etc/aegisgate/config.yaml

# Validate before deploying
./aegisgate-platform config validate /etc/aegisgate/config.yaml
```

The generated file includes a header comment with the profile name and generation timestamp, making it easy to track which profile was used as the base.

---

## See Also

- [Quickstart](/docs/quickstart/) — 30-second deployment guide
- [Getting Started](getting-started.md) — Full setup wizard walkthrough
- [Configuration](configuration reference on the website) — YAML config reference
- [CLI Reference](cli-reference.md) — All commands and flags
- [Deployment](/docs/deployment/) — Production deployment options