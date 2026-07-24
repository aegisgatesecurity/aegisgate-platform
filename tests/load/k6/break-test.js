// AegisGate Platform — Break Test
// Purpose: Find the actual ceiling. Push until latency degrades or errors appear.
// Strategy: Progressive load multiplier — 1x, 2x, 5x, 10x, 20x baseline — then sustained ceiling hold.
// What we're measuring:
//   - At what VU count does p95 exceed 100ms?
//   - At what VU count does p99 exceed 500ms?
//   - At what VU count do we see the first 5xx error?
//   - What's the maximum sustainable RPS before degradation?
//   - Does the process recover when load drops?

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const latencyP50 = new Trend('latency_p50', true);
const latencyP95 = new Trend('latency_p95', true);
const latencyP99 = new Trend('latency_p99', true);
const rpsCounter = new Counter('rps');
const statusCounter = new Counter('status_codes');
const degradation = new Rate('degraded');    // p95 > 100ms
const critical = new Rate('critical');        // p95 > 500ms or 5xx

const DASHBOARD_URL = __ENV.DASHBOARD_URL || 'http://localhost:8443';
const PROXY_URL = __ENV.PROXY_URL || 'http://localhost:8080';

// Endpoints with weights (realistic traffic mix)
const endpoints = [
  { url: `${DASHBOARD_URL}/health`, name: 'health', weight: 30 },
  { url: `${DASHBOARD_URL}/version`, name: 'version', weight: 15 },
  { url: `${DASHBOARD_URL}/api/v1/tier`, name: 'tier', weight: 15 },
  { url: `${DASHBOARD_URL}/metrics`, name: 'metrics', weight: 10 },
  { url: `${PROXY_URL}/health`, name: 'proxy_health', weight: 20 },
  { url: `${PROXY_URL}/version`, name: 'proxy_version', weight: 10 },
];

function weightedRandom() {
  const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
  let random = Math.random() * totalWeight;
  for (const e of endpoints) {
    random -= e.weight;
    if (random <= 0) return e;
  }
  return endpoints[0];
}

export const options = {
  scenarios: {
    // Phase 1: 1x baseline (100 VUs)
    baseline_1x: {
      executor: 'constant-vus',
      vus: 100,
      duration: '30s',
      gracefulStop: '5s',
    },
    // Phase 2: 2x burst (200 VUs)
    burst_2x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 200 },
        { duration: '30s', target: 200 },
        { duration: '10s', target: 0 },
      ],
      gracefulStop: '10s',
    },
    // Phase 3: 5x stress (500 VUs)
    stress_5x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '15s', target: 500 },
        { duration: '30s', target: 500 },
        { duration: '15s', target: 0 },
      ],
      gracefulStop: '10s',
    },
    // Phase 4: 10x extreme (1000 VUs)
    extreme_10x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 1000 },
        { duration: '30s', target: 1000 },
        { duration: '20s', target: 0 },
      ],
      gracefulStop: '10s',
    },
    // Phase 5: 20x crush (2000 VUs) — find the breaking point
    crush_20x: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 2000 },
        { duration: '30s', target: 2000 },
        { duration: '30s', target: 0 },
      ],
      gracefulStop: '15s',
    },
  },
  thresholds: {
    // We DON'T assert strict thresholds — we're measuring where they break
    http_req_failed: ['rate<0.50'], // Allow up to 50% failure (we want to see where it breaks)
    http_req_duration: ['p(99)<30000'], // 30s max — just ensure we get responses
  },
};

export default function () {
  const endpoint = weightedRandom();
  const res = http.get(endpoint.url, { tags: { endpoint: endpoint.name } });

  rpsCounter.add(1);

  const is5xx = res.status >= 500;
  const is429 = res.status === 429;
  const isOk = res.status === 200;
  const duration = res.timings.duration;

  errorRate.add(!isOk);
  degradation.add(duration > 100);
  critical.add(duration > 500 || is5xx);
  statusCounter.add(1, { status: String(res.status) });

  check(res, {
    'status received': (r) => r.status > 0,
    'not server error': (r) => r.status < 500,
  });

  // Minimal sleep for high-throughput stress
  sleep(Math.random() * 0.05);
}

export function handleSummary(data) {
  const total = data.metrics.http_reqs?.count || 0;
  const durationSecs = (data.state.testRunDurationMs || 1) / 1000;
  const rps = total / durationSecs;
  const failRate = (data.metrics.http_req_failed?.rate || 0) * 100;

  // Per-scenario breakdown
  const scenarios = {};
  for (const [name, scenario] of Object.entries(data.scenarios || {})) {
    if (scenario.metrics) {
      const dur = scenario.metrics.http_req_duration;
      scenarios[name] = {
        requests: scenario.metrics.http_reqs?.count || 0,
        p50: dur ? dur.values?.['p(50)']?.toFixed(2) + 'ms' : 'N/A',
        p95: dur ? dur.values?.['p(95)']?.toFixed(2) + 'ms' : 'N/A',
        p99: dur ? dur.values?.['p(99)']?.toFixed(2) + 'ms' : 'N/A',
      };
    }
  }

  const summary = {
    break_test: {
      version: 'v3.4.1',
      timestamp: new Date().toISOString(),
      total_requests: total,
      duration_sec: durationSecs.toFixed(1),
      avg_rps: rps.toFixed(0),
      overall_latency: {
        avg: data.metrics.http_req_duration?.avg?.toFixed(2) + 'ms',
        p50: data.metrics.http_req_duration?.values?.['p(50)']?.toFixed(2) + 'ms',
        p90: data.metrics.http_req_duration?.values?.['p(90)']?.toFixed(2) + 'ms',
        p95: data.metrics.http_req_duration?.values?.['p(95)']?.toFixed(2) + 'ms',
        p99: data.metrics.http_req_duration?.values?.['p(99)']?.toFixed(2) + 'ms',
        max: data.metrics.http_req_duration?.values?.['max']?.toFixed(2) + 'ms',
      },
      error_rate: failRate.toFixed(2) + '%',
      degradation_rate: (data.metrics.degraded?.rate * 100)?.toFixed(2) + '% of requests > 100ms',
      critical_rate: (data.metrics.critical?.rate * 100)?.toFixed(2) + '% of requests > 500ms or 5xx',
      peak_vus: 2000,
      findings: {
        ceiling_note: 'See per-scenario breakdown for where degradation begins',
        recovery_note: 'Observe latency returning to baseline in crush_20x ramp-down phase',
      },
    },
  };

  return {
    'tests/load/k6/results/break-test-results.json': JSON.stringify(summary, null, 2),
    stdout: JSON.stringify(summary, null, 2),
  };
}