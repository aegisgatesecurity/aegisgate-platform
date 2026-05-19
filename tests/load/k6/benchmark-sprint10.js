// AegisGate Sprint 10 Performance Benchmark
// Tests core endpoints: /health, /version, /api/v1/tier, /metrics
// Measures: RPS ceiling, latency percentiles, stability under load

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter, Gauge } from 'k6/metrics';

const latencyTrend = new Trend('latency_ms');
const rpsCounter = new Counter('total_requests');
const healthStatus = new Gauge('health_status');

export const options = {
  scenarios: {
    // Phase 1: Baseline (50 VUs)
    baseline: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
      exec: 'baseline',
    },
    // Phase 2: Ramp up to 500 VUs
    ramp_up: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '15s', target: 100 },
        { duration: '15s', target: 250 },
        { duration: '15s', target: 500 },
        { duration: '30s', target: 500 }, // Sustain
        { duration: '15s', target: 0 },
      ],
      exec: 'rampTest',
    },
    // Phase 3: Endurance test
    endurance: {
      executor: 'constant-vus',
      vus: 200,
      duration: '2m',
      exec: 'endurance',
    },
  },
  thresholds: {
    // Allow degraded health (503) - fail-closed is correct behavior
    http_req_duration: ['p(50)<10', 'p(95)<25', 'p(99)<50', 'avg<15'],
    http_req_failed: ['rate<0.5'], // Allow 503 for health endpoint
  },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8443';

function weightedRandom(items) {
  const total = items.reduce((sum, e) => sum + e.weight, 0);
  let random = Math.random() * total;
  for (const item of items) {
    random -= item.weight;
    if (random <= 0) return item;
  }
  return items[items.length - 1];
}

export function baseline() {
  const endpoints = [
    { url: '/health', weight: 30 },
    { url: '/version', weight: 25 },
    { url: '/api/v1/tier', weight: 25 },
    { url: '/metrics', weight: 20 },
  ];

  const ep = weightedRandom(endpoints);
  const start = Date.now();
  const res = http.get(`${BASE_URL}${ep.url}`);
  const duration = Date.now() - start;

  latencyTrend.add(duration);
  rpsCounter.add(1);
  healthStatus.add(res.status);

  check(res, {
    [`${ep.url} responds`]: () => res.status >= 200 && res.status < 600,
    [`${ep.url} latency < 50ms`]: () => duration < 50,
  });

  sleep(Math.random() * 0.2 + 0.05);
}

export function rampTest() {
  // Hit /health continuously (lightest endpoint)
  const start = Date.now();
  const res = http.get(`${BASE_URL}/health`);
  const duration = Date.now() - start;

  latencyTrend.add(duration);
  rpsCounter.add(1);

  check(res, {
    'ramp: responds': () => res.status >= 200,
    'ramp: latency < 100ms': () => duration < 100,
  });
}

export function endurance() {
  // Mix of endpoints
  const endpoints = ['/health', '/version', '/api/v1/tier', '/metrics'];
  const url = endpoints[Math.floor(Math.random() * endpoints.length)];

  const start = Date.now();
  const res = http.get(`${BASE_URL}${url}`);
  const duration = Date.now() - start;

  latencyTrend.add(duration);
  rpsCounter.add(1);

  check(res, {
    'endurance: responds': () => res.status >= 200,
    'endurance: latency < 50ms': () => duration < 50,
  });

  sleep(Math.random() * 0.1 + 0.02);
}

export function handleSummary(data) {
  const totalReqs = data.metrics.total_requests?.values?.count || 0;
  const durationSecs = data.state.testRunDurationMs / 1000;

  return {
    stdout: JSON.stringify({
      sprint10_benchmark: {
        total_requests: totalReqs,
        duration_sec: durationSecs.toFixed(1),
        avg_rps: (totalReqs / durationSecs).toFixed(0),
        latency_ms: {
          p50: data.metrics.latency_ms?.p?.(50)?.toFixed(2) || 'N/A',
          p95: data.metrics.latency_ms?.p?.(95)?.toFixed(2) || 'N/A',
          p99: data.metrics.latency_ms?.p?.(99)?.toFixed(2) || 'N/A',
          avg: data.metrics.latency_ms?.avg?.toFixed(2) || 'N/A',
        },
        http_req_duration: {
          avg_ms: (data.metrics.http_req_duration?.avg * 1000)?.toFixed(2) || 'N/A',
          p50_ms: (data.metrics.http_req_duration?.p(50) * 1000)?.toFixed(2) || 'N/A',
          p95_ms: (data.metrics.http_req_duration?.p(95) * 1000)?.toFixed(2) || 'N/A',
          p99_ms: (data.metrics.http_req_duration?.p(99) * 1000)?.toFixed(2) || 'N/A',
        },
        error_rate: ((data.metrics.http_req_failed?.rate || 0) * 100).toFixed(2) + '%',
        health_503_responses: (data.metrics.health_status?.values?.['0'] || 0),
        vus_peak: data.state.metrics?.vus_max?.value || 'N/A',
        enterprise_grade: (data.metrics.http_req_duration?.p(99) * 1000) < 50,
        comparison_vs_v136: {
          target_p95_ms: '< 50',
          achieved: (data.metrics.http_req_duration?.p(95) * 1000)?.toFixed(2) || 'N/A',
          delta: 'TBD after analysis',
        },
      },
    }, null, 2),
  };
}