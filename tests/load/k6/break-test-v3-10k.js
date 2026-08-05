// AegisGate Platform — 10K VU Break Test v3
// Purpose: Push the platform to enterprise-scale load levels.
// Phases run SEQUENTIALLY using startTime offsets.
// Phase 1: 100 VU baseline → 2: 500 → 3: 1000 → 4: 2000 → 5: 5000 → 6: 10000 → 7: Recovery

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const rpsCounter = new Counter('rps');

const DASHBOARD = __ENV.DASHBOARD_URL || 'http://localhost:8443';
const PROXY = __ENV.PROXY_URL || 'http://localhost:8080';

const endpoints = [
  { url: `${DASHBOARD}/health`, name: 'health', weight: 25 },
  { url: `${DASHBOARD}/version`, name: 'version', weight: 10 },
  { url: `${DASHBOARD}/api/v1/tier`, name: 'tier', weight: 10 },
  { url: `${DASHBOARD}/metrics`, name: 'metrics', weight: 10 },
  { url: `${PROXY}/health`, name: 'proxy_health', weight: 25 },
  { url: `${PROXY}/version`, name: 'proxy_version', weight: 10 },
  { url: `${DASHBOARD}/api/v1/compliance/scan`, name: 'compliance_scan', weight: 10 },
];

function weightedRandom() {
  const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
  let r = Math.random() * totalWeight;
  for (const e of endpoints) { r -= e.weight; if (r <= 0) return e; }
  return endpoints[0];
}

export const options = {
  scenarios: {
    // Phase 1: Baseline (100 VUs) — 0-30s
    phase1_baseline: {
      executor: 'constant-vus',
      vus: 100,
      duration: '30s',
      gracefulStop: '0s',
      startTime: '0s',
    },
    // Phase 2: Stress (500 VUs) — 35-95s
    phase2_stress: {
      executor: 'constant-vus',
      vus: 500,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '35s',
    },
    // Phase 3: Heavy (1000 VUs) — 100-180s
    phase3_heavy: {
      executor: 'constant-vus',
      vus: 1000,
      duration: '80s',
      gracefulStop: '0s',
      startTime: '100s',
    },
    // Phase 4: Extreme (2000 VUs) — 185-265s
    phase4_extreme: {
      executor: 'constant-vus',
      vus: 2000,
      duration: '80s',
      gracefulStop: '0s',
      startTime: '185s',
    },
    // Phase 5: Crush (5000 VUs) — 270-330s
    phase5_crush: {
      executor: 'constant-vus',
      vus: 5000,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '270s',
    },
    // Phase 6: Maximum (10000 VUs) — 335-395s
    phase6_maximum: {
      executor: 'constant-vus',
      vus: 10000,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '335s',
    },
    // Phase 7: Recovery (100 VUs) — 400-430s
    phase7_recovery: {
      executor: 'constant-vus',
      vus: 100,
      duration: '30s',
      gracefulStop: '0s',
      startTime: '400s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.50'],  // Less than 50% errors even at 10K VUs
    http_req_duration: ['p(99)<60000'], // p99 under 60s at max load
  },
};

export default function () {
  const endpoint = weightedRandom();
  const res = http.get(endpoint.url, { tags: { endpoint: endpoint.name } });
  rpsCounter.add(1);
  errorRate.add(res.status >= 500 ? 1 : 0);

  check(res, {
    'status received': (r) => r.status > 0,
    'not server error': (r) => r.status < 500,
  });

  sleep(Math.random() * 0.05);
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const dur = (data.state.testRunDurationMs || 1) / 1000;
  const failPct = (data.metrics.http_req_failed?.rate || 0) * 100;

  // Per-phase analysis
  const phases = [
    { name: 'Phase 1: Baseline (100 VUs)', start: 0, end: 35 },
    { name: 'Phase 2: Stress (500 VUs)', start: 35, end: 100 },
    { name: 'Phase 3: Heavy (1000 VUs)', start: 100, end: 185 },
    { name: 'Phase 4: Extreme (2000 VUs)', start: 185, end: 270 },
    { name: 'Phase 5: Crush (5000 VUs)', start: 270, end: 335 },
    { name: 'Phase 6: Maximum (10000 VUs)', start: 335, end: 400 },
    { name: 'Phase 7: Recovery (100 VUs)', start: 400, end: 435 },
  ];

  const phaseResults = phases.map(p => ({
    name: p.name,
    vus: p.name.match(/\d+/)?.[0] || '?',
  }));

  return {
    stdout: JSON.stringify({
      break_test_v3_10k: {
        version: 'v4.0.0',
        timestamp: new Date().toISOString(),
        total_requests: total,
        duration_sec: dur.toFixed(1),
        avg_rps: (total / dur).toFixed(0),
        error_rate: failPct.toFixed(3) + '%',
        overall_latency: {
          avg: data.metrics.http_req_duration?.avg?.toFixed(2),
          p50: data.metrics.http_req_duration?.values?.['p(50)']?.toFixed(2),
          p90: data.metrics.http_req_duration?.values?.['p(90)']?.toFixed(2),
          p95: data.metrics.http_req_duration?.values?.['p(95)']?.toFixed(2),
          p99: data.metrics.http_req_duration?.values?.['p(99)']?.toFixed(2),
          max: data.metrics.http_req_duration?.values?.['max']?.toFixed(2),
        },
        phases: phaseResults,
      },
    }, null, 2),
  };
}