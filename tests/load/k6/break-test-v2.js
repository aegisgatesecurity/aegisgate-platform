// AegisGate Platform — Break Test v2 (Sequential Phases)
// Purpose: Find the actual ceiling by progressively increasing load.
// Scenarios run SEQUENTIALLY using startTime offsets.
// Phase 1: 100 VU baseline → Phase 2: 200 VU → Phase 3: 500 VU → Phase 4: 1000 VU → Phase 5: 2000 VU
// Then Phase 6: Recovery (back to 100 VU to confirm platform recovers)

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const rpsCounter = new Counter('rps');

const DASHBOARD = __ENV.DASHBOARD_URL || 'http://localhost:8443';
const PROXY = __ENV.PROXY_URL || 'http://localhost:8080';

const endpoints = [
  { url: `${DASHBOARD}/health`, name: 'health', weight: 30 },
  { url: `${DASHBOARD}/version`, name: 'version', weight: 15 },
  { url: `${DASHBOARD}/api/v1/tier`, name: 'tier', weight: 15 },
  { url: `${DASHBOARD}/metrics`, name: 'metrics', weight: 10 },
  { url: `${PROXY}/health`, name: 'proxy_health', weight: 20 },
  { url: `${PROXY}/version`, name: 'proxy_version', weight: 10 },
];

function weightedRandom() {
  const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
  let r = Math.random() * totalWeight;
  for (const e of endpoints) { r -= e.weight; if (r <= 0) return e; }
  return endpoints[0];
}

export const options = {
  scenarios: {
    // Phase 1: 1x baseline (100 VUs) — 0-30s
    phase1_baseline: {
      executor: 'constant-vus',
      vus: 100,
      duration: '30s',
      gracefulStop: '0s',
      startTime: '0s',
    },
    // Phase 2: 2x burst (200 VUs) — 35-85s
    phase2_burst: {
      executor: 'constant-vus',
      vus: 200,
      duration: '50s',
      gracefulStop: '0s',
      startTime: '35s',
    },
    // Phase 3: 5x stress (500 VUs) — 90-150s
    phase3_stress: {
      executor: 'constant-vus',
      vus: 500,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '90s',
    },
    // Phase 4: 10x extreme (1000 VUs) — 155-235s
    phase4_extreme: {
      executor: 'constant-vus',
      vus: 1000,
      duration: '80s',
      gracefulStop: '0s',
      startTime: '155s',
    },
    // Phase 5: 20x crush (2000 VUs) — 240-300s
    phase5_crush: {
      executor: 'constant-vus',
      vus: 2000,
      duration: '60s',
      gracefulStop: '0s',
      startTime: '240s',
    },
    // Phase 6: Recovery (100 VUs) — 305-345s
    phase6_recovery: {
      executor: 'constant-vus',
      vus: 100,
      duration: '40s',
      gracefulStop: '0s',
      startTime: '305s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.50'],
    http_req_duration: ['p(99)<30000'],
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

  return {
    stdout: JSON.stringify({
      break_test_v2: {
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
      },
    }, null, 2),
  };
}