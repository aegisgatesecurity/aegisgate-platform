# AegisGate Posture Check (`aegisgate status`)

**Status:** Shipped in v3.3.0 (Phase 6.5)
**Audience:** Non-technical operators, on-call engineers, CI gates, monitoring integrations
**First documented:** 2026-06-14

---

## What it is

`aegisgate status` is the founder-facing "is your AegisGate doing what
you think it is doing?" signal. It answers the question in plain
language, designed to be readable by a non-technical operator per the
original Padlock spec constraint 17.

It is the operator-level signal that closes the gap between:

- the **Trust Framework** (developer-level signal)
- the public **trust page** (marketing-level signal)
- the on-call **runbook** (operator-level signal)

Posture check is **read-only**. It never mutates state. It can be
run from a system service file, a CI gate, or a health check
integration without affecting the running platform.

---

## Usage

### Default mode (plain text)

```
$ aegisgate status
AegisGate is healthy ✅
  Version:        v3.3.0 (commit: abc1234) [production mode]
  Uptime:         3d 4h 12m
  Tier:           professional (Professional)
  Customer:       acme-corp
  Expires:        2027-01-01T00:00:00Z
  Modules:        hipaa, pci

  Subsystems:
    ✅ uptime:        Process running for 3d 4h 12m
    ✅ license:       license valid (tier=professional, customer=acme-corp, modules=2)
    ✅ compliance:    7 frameworks evaluated, 2 enforced

  Compliance:
    ● HIPAA         required=developer    enforced=true
    ● PCI-DSS       required=developer    enforced=true
    ○ SOC 2         required=developer    enforced=false
    ○ ISO 42001     required=professional enforced=false
    ○ FedRAMP       required=professional enforced=false
    ○ FIPS 140      required=professional enforced=false
    ○ EU AI Act     required=professional enforced=false
```

### Verbose mode (more detail)

```
$ aegisgate status --verbose
... (default output) ...

  Generated at:   2026-06-14T22:24:03Z
  License msg:   No license key - using Community tier

  Compliance detail:
    HIPAA         framework=hipaa required_tier=developer enforced=true  impl=true  reason=enforced
    PCI-DSS       framework=pci   required_tier=developer enforced=true  impl=true  reason=enforced
    ...
```

### JSON mode (for monitoring / CI)

```
$ aegisgate status --json | jq .overall_status
"healthy"
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Healthy **or** Degraded (still operating; just needs attention) |
| `1`  | Unhealthy (operator should investigate) |
| `2`  | Posture check itself failed (e.g., cancelled context, malformed data) |

Use in CI / cron:

```bash
# Block deploys if posture is unhealthy
if ! aegisgate status > /dev/null; then
    echo "AegisGate posture is UNHEALTHY - blocking deploy"
    exit 1
fi
```

---

## HTTP API

The same data is available over HTTP for monitoring integrations:

| Endpoint | Returns |
|----------|---------|
| `GET /api/v1/posture` | JSON, default mode (summary) |
| `GET /api/v1/posture/verbose` | JSON, verbose mode (full detail) |

Both routes are served on the dashboard port (`--dashboard-port`,
default 8443) and follow the same auth model as `/api/v1/license/status`.

Example:

```bash
curl -s https://aegisgate.example.com:8443/api/v1/posture | jq .overall_status
"healthy"
```

---

## What each status means

| Status | Emoji | When |
|--------|-------|------|
| `healthy`   | ✅ | All subsystems operating as expected |
| `degraded`  | ⚠️  | One or more subsystems operating with caveats (e.g., grace-period license, missing compliance implementation) |
| `unhealthy` | ❌ | One or more subsystems broken or misconfigured |
| `unknown`   | ❔ | We could not determine the status (e.g., a dependency is nil and we have no data) |

### Per-subsystem rules

- **uptime:** healthy when StartTime is set; unknown when not set
- **license:**
  - `unknown` when no license manager is configured OR no key was supplied
  - `degraded` when license is valid but in grace period
  - `unhealthy` when license is invalid (expired past grace, malformed, etc)
  - `healthy` when license is valid and not in grace period
- **compliance:**
  - `unknown` when no compliance frameworks could be evaluated
  - `degraded` when one or more enforced frameworks lack implementation
  - `healthy` when all enforced frameworks have working implementations

### Overall status (reduction rule)

1. Any `unhealthy` subsystem → overall `unhealthy`
2. Any `degraded` subsystem → overall `degraded`
3. All `unknown` (no other signal) → overall `unknown`
4. All `healthy` → overall `healthy`

---

## How to read the output

1. **First line** = overall posture. The emoji at the end is the quickest
   at-a-glance signal for a non-technical operator.
2. **Version + commit** = what binary is running. Useful for confirming
   that a deploy actually took effect.
3. **Uptime** = how long the process has been running. Resets on every
   restart (including crash recovery).
4. **Tier + Modules** = what the license is actually entitled to. Note:
   this is the **license-derived** tier, not the `--tier` CLI flag
   (which is display-only).
5. **Subsystems** = per-subsystem verdict with a one-line summary.
6. **Compliance** = per-framework status with the required tier and
   whether it is currently enforced. `●` = enforced, `○` = not enforced.

If anything is degraded or unhealthy, the footer reminds you to run
`aegisgate status --verbose` for more detail.

---

## Operational integration

### Cron / monitoring

Add to crontab:

```cron
# Every 5 minutes, log posture and alert on non-zero exit
*/5 * * * * /usr/local/bin/aegisgate status --json >> /var/log/aegisgate/posture.log 2>&1 || echo "AegisGate posture check FAILED" | mail -s "AegisGate Alert" oncall@example.com
```

### Health check endpoint

Use the HTTP API as a Kubernetes liveness/readiness probe:

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/posture
    port: 8443
  initialDelaySeconds: 30
  periodSeconds: 60
```

Note: this will fail liveness if posture is `unhealthy`. If you want
a softer check, parse the JSON and only fail on hard failures (e.g.,
license subsystem `unhealthy`).

### Pre-deploy gate

```bash
#!/usr/bin/env bash
set -e
aegisgate status --json > /tmp/posture.json
overall=$(jq -r .overall_status /tmp/posture.json)
if [ "$overall" = "unhealthy" ]; then
    echo "Refusing to deploy: AegisGate posture is UNHEALTHY"
    cat /tmp/posture.json
    exit 1
fi
```

---

## Design notes

### Why dependency injection?

The Checker accepts injected `Deps` (license manager, gating function,
time function) so the test suite can substitute stub implementations
without touching global state. This is the same pattern as
`pkg/trust/api.go` and the rest of the platform.

### Why fail-closed in display?

Posture check is the operator signal. If a subsystem is broken, we
say so loudly. We never silently mask problems with green checkmarks.
This is the trust contract with the operator: the posture output is
honest, not aspirational.

### Why no new network calls?

Posture reads only in-process state that is already kept up to date
by the existing subsystems (license validation, compliance gating).
This means:

- posture check itself cannot be the cause of an outage
- posture check is fast (< 1ms typically)
- posture check can be called from CI without auth

### Why is the posture output not stable across releases?

The text format is human-facing and is allowed to evolve. The JSON
format is the machine contract and is stable. If you are building a
monitoring integration, consume `--json` not the text output.

---

## Related

- **Trust Framework** (`GET /api/v1/trust/score`) - per-session trust
  score with Ed25519-signed attestations
- **Compliance Scan Engine** (`GET /api/v1/compliance/scan`) -
  framework-level compliance status with control counts
- **Public trust page** (`aegisgatesecurity.io/security/`) -
  marketing-level self-attestation
- **V3.3.0-ROADMAP §6.5** - the original spec this implements

---

*Shipped in v3.3.0 (Phase 6.5). Documented 2026-06-14.*