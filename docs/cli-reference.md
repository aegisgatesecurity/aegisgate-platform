## CLI Reference

The `aegisgate-platform` binary is a single 19.1MB Go binary with zero external dependencies. This page documents all command-line flags and subcommands.

## Global Flags

These flags are available on the main command and apply to the running platform:

| Flag | Default | Description |
|------|---------|-------------|
| `--config <file>` | `aegisgate-platform.yaml` | Configuration file path |
| `--profile <name>` | _(none)_ | Deploy profile preset: `quickstart`, `small-team`, `production`, `high-security`, `air-gapped` |
| `--proxy-port <n>` | `8080` | HTTP proxy port |
| `--mcp-port <n>` | `8081` | MCP server port |
| `--dashboard-port <n>` | `8443` | Admin dashboard port |
| `--target <url>` | `https://api.openai.com` | Upstream LLM provider URL |
| `--license <key>` | _(none)_ | License key (overrides `AEGISGATE_LICENSE_KEY` env var) |
| `--tier <name>` | `community` | Display tier (read-only; actual tier derived from license) |
| `--mode <mode>` | `production` | Operation mode: `production`, `demo`, `staging` |
| `--embedded-mcp` | `false` | Start embedded MCP server (standalone mode) |
| `--version` | `false` | Show version information and exit |
| `--ioc-share` | `false` | Opt in to serving IOC manifests to peers |
| `--ioc-receive` | `false` | Opt in to fetching IOC manifests from peers (Professional+) |
| `--ioc-peers <urls>` | _(none)_ | Comma-separated peer base URLs for IOC gossip |
| `--lens-enabled` | `false` | Enable Lens telemetry backend |
| `--siem-enabled` | `false` | Enable SIEM dispatcher to forward audit events |
| `--soar-enabled` | `false` | Enable SOAR outbound webhooks (PagerDuty, Jira, ServiceNow) |
| `--tsa-enabled` | `false` | Enable RFC 3161 TSA timestamping for audit events |
| `--token-analytics` | `false` | Enable token usage analytics |

### Config Precedence

Configuration is resolved in the following order (highest priority first):

1. **CLI flags** — command-line arguments override everything
2. **Environment variables** — `AEGISGATE_*` env vars
3. **Config file** — YAML file specified with `--config`
4. **Deploy profile** — preset selected with `--profile`
5. **Built-in defaults** — hardcoded safe defaults

## Deploy Profiles

Deploy profiles (v4.2.0+) are predefined configuration presets that populate all config fields with sensible defaults for common deployment scenarios.

### Listing Profiles

```bash
./aegisgate-platform --profile list
```

### Using a Profile

```bash
# Run directly with a profile (no config file needed)
./aegisgate-platform --profile quickstart --embedded-mcp

# Use a profile as a base, override with a config file
./aegisgate-platform --profile production --config my-overrides.yaml --embedded-mcp
```

### Available Profiles

| Profile | TLS | Rate Limit | Persistence | Audit | Use Case |
|---------|-----|------------|-------------|-------|----------|
| `quickstart` | Off | 60 RPM | In-memory | Basic | Zero-config evaluation |
| `small-team` | Auto-generated self-signed | 300 RPM | File | Detailed | 5–50 users, small org |
| `production` | TLS 1.3 (bring your own certs) | 1,000 RPM | File | Detailed | Hardened production |
| `high-security` | mTLS + FIPS mode | 5,000 RPM | File | Detailed + SIEM | Regulated industries |
| `air-gapped` | TLS 1.3 (bring your own certs) | 1,000 RPM | File | Detailed | Isolated networks, no external deps |

See [Deploy Profiles](deploy-profiles (see website)) for detailed per-profile configuration values.

## Subcommands

Subcommands use a hook pattern: the binary checks `os.Args[1]` before `flag.Parse()` and dispatches to the appropriate handler. All subcommands return an exit code (0 = success, 1 = error).

### `setup` — Setup Wizard (v4.2.0+)

Interactive or non-interactive environment detection and config generation.

```bash
# Interactive mode (prompts for each step)
./aegisgate-platform setup

# Non-interactive (auto-detect everything)
./aegisgate-platform setup --non-interactive

# Skip profile selection
./aegisgate-platform setup --profile quickstart

# Custom output path
./aegisgate-platform setup --output /etc/aegisgate/config.yaml

# Overwrite existing config
./aegisgate-platform setup --force
```

| Flag | Default | Description |
|------|---------|-------------|
| `--non-interactive` | `false` | Auto-detect environment, no prompts |
| `--profile <name>` | _(auto-detected)_ | Skip profile selection, use specified profile |
| `--output <file>` | `aegisgate-platform.yaml` | Output config file path |
| `--force` | `false` | Overwrite existing config file |

The wizard detects: Docker, Kubernetes, systemd, bare metal; available ports; existing TLS certificates; and recommends the most appropriate deploy profile.

### `config` — Config Validation (v4.2.0+)

Validate and inspect configuration files.

```bash
# Validate a config file (15+ checks: ports, TLS, log levels, rate limits, SIEM)
./aegisgate-platform config validate aegisgate-platform.yaml

# Show effective config as YAML
./aegisgate-platform config show aegisgate-platform.yaml

# Show effective config as JSON
./aegisgate-platform config show --format json

# List available deploy profiles
./aegisgate-platform config profiles
```

| Subcommand | Description |
|------------|-------------|
| `validate [file]` | Check for errors and warnings (exit 1 on errors) |
| `show [file] [--format yaml\|json]` | Dump resolved config with all overrides applied |
| `profiles` | List all deploy profiles with descriptions |

Validation checks include:
- Port conflicts (proxy, MCP, dashboard, A2A on same port)
- TLS certificate path validation (files exist, readable)
- Log level validation (debug, info, warn, error)
- Rate limit sanity (proxy ≥ MCP, reasonable values)
- SIEM endpoint URL validation
- Persistence backend validation
- A2A configuration consistency

### `maintenance` — Maintenance Windows (v4.2.0+)

Manage maintenance windows for planned downtime.

```bash
# Check current maintenance status
./aegisgate-platform maintenance status

# Enable maintenance mode immediately
./aegisgate-platform maintenance enable --message "Security update in progress"

# Schedule a future maintenance window
./aegisgate-platform maintenance schedule \
  --start "2026-09-01T02:00:00Z" \
  --end "2026-09-01T04:00:00Z" \
  --reason "Quarterly security patch"

# Disable maintenance mode
./aegisgate-platform maintenance disable
```

| Subcommand | Description |
|------------|-------------|
| `status` | Show current maintenance state (active/scheduled/inactive) |
| `enable [--message "msg"]` | Enable maintenance mode immediately |
| `disable` | Disable maintenance mode |
| `schedule --start --end --reason` | Schedule a future maintenance window |

During maintenance mode:
- All proxy requests return HTTP 503 with `Retry-After` header
- Health (`/health`), version (`/version`), and maintenance (`/api/v1/maintenance`) endpoints remain accessible
- Load balancers can detect the maintenance state via `/health` and drain traffic
- The maintenance API is also available via REST: `GET/POST /api/v1/maintenance`

### `attestation` — Attestation Verification

Verify cryptographic attestations (AR-EaaS, AIBOM, Agent Intent, Prompt Cache, CVE-for-AI).

```bash
# Verify an attestation envelope
./aegisgate-platform attestation verify envelope.json
```

### `benchmark` — Performance Benchmarking

Run built-in performance benchmarks.

```bash
./aegisgate-platform benchmark --duration 60s --concurrency 100
```

### Other Subcommands

| Subcommand | Description |
|------------|-------------|
| `a2a-intent` | A2A intent signing |
| `aibom` | AI Bill of Materials generation |
| `cve` | CVE-for-AI entry publishing |
| `digest` | CISO posture digest generation |
| `evaluator` | Evaluator framework runner |
| `evidence` | Evidence manifest generation |
| `incident` | Incident response management |
| `posture` | Security posture status |
| `prompt-cache` | Prompt cache attestation |
| `report` | Report generation |
| `soc` | SOC incident timeline |
| `soc2-audit` | SOC 2 audit evidence collection |

## Environment Variables

All CLI flags have corresponding environment variables prefixed with `AEGISGATE_`:

| Variable | Flag Equivalent | Default |
|----------|----------------|---------|
| `AEGISGATE_LICENSE_KEY` | `--license` | _(community)_ |
| `AEGISGATE_LOG_LEVEL` | _(config)_ | `info` |
| `AEGISGATE_PROXY_PORT` | `--proxy-port` | `8080` |
| `AEGISGATE_MCP_PORT` | `--mcp-port` | `8081` |
| `AEGISGATE_DASHBOARD_PORT` | `--dashboard-port` | `8443` |
| `AEGISGATE_SIEM_ENABLED` | `--siem-enabled` | `false` |
| `AEGISGATE_SOAR_ENABLED` | `--soar-enabled` | `false` |
| `AEGISGATE_TSA_ENABLED` | `--tsa-enabled` | `false` |
| `AEGISGATE_TOKEN_ANALYTICS` | `--token-analytics` | `false` |
| `AEGISGATE_LENS_ENABLED` | `--lens-enabled` | `false` |
| `AEGISGATE_IOC_SHARE` | `--ioc-share` | `false` |
| `AEGISGATE_IOC_RECEIVE` | `--ioc-receive` | `false` |
| `AEGISGATE_IOC_PEERS` | `--ioc-peers` | _(none)_ |

_See also: [Configuration Reference](configuration.md), [Deploy Profiles](deploy-profiles (see website)), [Deployment Guide](deployment guide on the website)._