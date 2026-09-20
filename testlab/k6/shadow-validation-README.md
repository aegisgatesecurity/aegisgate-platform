# Shadow Mode FPR Validation

## Overview

Validates that AegisGate's shadow-mode detectors produce **zero false positives**
on benign traffic while catching adversarial patterns. This is the gate for
flipping P2/P4/DIST2-5 from alert-only to blocking mode in v4.6.0.

## Shadow Detectors

| Detector | Code Location | What It Detects |
|----------|--------------|-----------------|
| P2 | `pkg/toolauth/chain_analyzer.go` | Tool call escalation/exfil/recon chains |
| P4 | `pkg/auth/anomaly_detect.go` | API key usage anomalies (volume, off-hours, geo) |
| DIST2 | `pkg/auth/distillation_detect.go` | Proxy/datacenter IP detection |
| DIST3 | `pkg/auth/distillation_detect.go` | Systematic CoT extraction patterns |
| DIST4 | `pkg/auth/distillation_detect.go` | Coordinated account clustering |
| DIST5 | `pkg/auth/distillation_detect.go` | Stolen key behavioral indicators |
| L3 | `pkg/ml/` | CharCNN-BiLSTM neural network threat detection |

All detectors operate in **alert-only mode** during v4.5.0. They log warnings
and set `X-AegisGate-Shadow-*` response headers. No blocking occurs.

## Infrastructure

### Components

| Component | File | Purpose |
|-----------|------|---------|
| k6 Script | `k6/shadow-validation-7day.js` | 500 VUs, 3 tenants, 7-day compressed simulation |
| Shadow Metrics | `upstream/aegisgate/pkg/proxy/shadow_metrics.go` | Prometheus counters + response headers |
| Compose Override | `docker-compose.shadow.yml` | Enables ML shadow mode |
| Grafana Dashboard | `grafana/dashboards/aegisgate-shadow-fpr.json` | Real-time FPR monitoring |

### Docker Stack

```bash
# Start with shadow mode enabled
cd testlab
docker compose -f docker-compose.synth.yml -f docker-compose.shadow.yml up -d

# Wait for health checks
docker compose -f docker-compose.synth.yml -f docker-compose.shadow.yml ps
```

### Seed Data

```bash
go run ./testlab/seed/ \
  -db "postgres://aegisgate:aegisgate_test_pass@localhost:5433/aegisgate_test?sslmode=disable"
```

## Running the Validation

### Quick Smoke Test (1 day, ~5 min)

```bash
k6 run --env BASE_URL=http://localhost:8080 --env DAYS=1 --env SCALE=0.2 \
  testlab/k6/shadow-validation-7day.js
```

### Standard Validation (7 days, ~2 hours)

```bash
k6 run --env BASE_URL=http://localhost:8080 --env DAYS=7 \
  testlab/k6/shadow-validation-7day.js
```

### Full Run with Orchestrator

```bash
./testlab/orchestrator.sh --script shadow-validation-7day.js --duration 2h --vus 500
```

## Traffic Profile

- **95% benign**: 200+ realistic organizational prompts (coding, writing, analysis,
  knowledge, multi-turn, tool usage, embeddings, admin)
- **5% adversarial**: Prompt injection, secret extraction, PII, tool chain attacks,
  anomaly triggers, distillation patterns
- **7-day cycle**: Each day has morning ramp → midday peak → afternoon sustained →
  evening surge → late night lull
- **Burst patterns**: Random short spikes during peak phases
- **Slow periods**: Extended low-activity during ramp and lull phases

## Metrics

### Prometheus Metrics (emitted by AegisGate)

| Metric | Labels | Description |
|--------|--------|-------------|
| `aegisgate_shadow_alerts_total` | detector | Total shadow alerts fired |
| `aegisgate_shadow_predictions_total` | detector | Total predictions (alert + clean) |

### Response Headers (per request)

| Header | Detector |
|--------|----------|
| `X-AegisGate-Shadow-P2` | Tool chain |
| `X-AegisGate-Shadow-P4` | API key anomaly |
| `X-AegisGate-Shadow-DIST2` | Proxy/datacenter IP |
| `X-AegisGate-Shadow-DIST3` | Distillation pattern |
| `X-AegisGate-Shadow-DIST4` | Account cluster |
| `X-AegisGate-Shadow-DIST5` | Stolen key |
| `X-AegisGate-Shadow-L3` | ML neural network |

### k6 Custom Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `shadow_p2_fpr` | Rate | P2 false positive rate |
| `shadow_p4_fpr` | Rate | P4 false positive rate |
| `shadow_dist2_fpr` | Rate | DIST2 false positive rate |
| `shadow_dist3_fpr` | Rate | DIST3 false positive rate |
| `shadow_dist4_fpr` | Rate | DIST4 false positive rate |
| `shadow_dist5_fpr` | Rate | DIST5 false positive rate |
| `shadow_l3_fpr` | Rate | L3 false positive rate |
| `shadow_overall_fpr` | Rate | Overall false positive rate |
| `shadow_p2_tpr` | Rate | P2 true positive rate |
| `shadow_*_tpr` | Rate | Per-detector TPR (same pattern) |
| `shadow_overall_tpr` | Rate | Overall true positive rate |

## Success Criteria

| Metric | Target | Threshold |
|--------|--------|-----------|
| Overall FPR | 0% | `< 0.01` (effectively zero) |
| Per-detector FPR | 0% | `< 0.01` per detector |
| Overall TPR | >80% | `> 0.80` |
| HTTP failures | <5% | `rate < 0.05` |

If all criteria pass → flip shadow detectors to blocking mode for v4.6.0.

## Grafana Dashboard

Access at `http://localhost:3000` (admin/admin). The "AegisGate Shadow Mode
FPR Validation" dashboard shows:

- Shadow alerts by detector (total + over time)
- Shadow predictions by detector (total + over time)
- Per-detector alert rate
- Request traffic (benign/adversarial/blocked)
- Proxy latency percentiles
- FPR validation status (PASS/FAIL)

## Files Modified

| File | Change |
|------|--------|
| `testlab/k6/shadow-validation-7day.js` | NEW — k6 simulation script |
| `upstream/aegisgate/pkg/proxy/shadow_metrics.go` | NEW — Prometheus metrics + response headers |
| `upstream/aegisgate/pkg/proxy/v450_integration.go` | Modified — record P2/P4 alerts to shadow context |
| `upstream/aegisgate/pkg/proxy/proxy.go` | Modified — wire shadow context + L3 alerts + response headers |
| `testlab/docker-compose.shadow.yml` | NEW — compose override for shadow mode |
| `testlab/grafana/dashboards/aegisgate-shadow-fpr.json` | NEW — Grafana dashboard |