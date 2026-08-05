// AegisGate — 10K VU Enterprise Break Test (lightweight, no JSON dump)
// Phases: 100→1K→2K→5K→10K→100 (recovery)
// Total duration: ~7 minutes

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const errorRate = new Rate('errors');
const DASHBOARD = __ENV.DASHBOARD_URL || 'http://localhost:8443';
const PROXY = __ENV.PROXY_URL || 'http://localhost:8080';

const endpoints = [
  { url: `${DASHBOARD}/health`, name: 'health', weight: 30 },
  { url: `${DASHBOARD}/version`, name: 'version', weight: 15 },
  { url: `${DASHBOARD}/api/v1/tier`, name: 'tier', weight: 15 },
  { url: `${DASHBOARD}/metrics`, name: 'metrics', weight: 10 },
  { url: `${PROXY}/health`, name: 'proxy_health', weight: 30 },
];

function weightedRandom() {
  const total = endpoints.reduce((s, e) => s + e.weight, 0);
  let r = Math.random() * total;
  for (const e of endpoints) { r -= e.weight; if (r <= 0) return e; }
  return endpoints[0];
}

export const options = {
  scenarios: {
    baseline:    { executor: 'constant-vus', vus: 100,   duration: '30s', startTime: '0s' },
    stress1k:    { executor: 'constant-vus', vus: 1000,  duration: '60s', startTime: '35s' },
    extreme2k:  { executor: 'constant-vus', vus: 2000,  duration: '60s', startTime: '100s' },
    crush5k:     { executor: 'constant-vus', vus: 5000,  duration: '60s', startTime: '165s' },
    max10k:      { executor: 'constant-vus', vus: 10000, duration: '60s', startTime: '230s' },
    recovery:    { executor: 'constant-vus', vus: 100,   duration: '30s', startTime: '295s' },
  },
  thresholds: {
    http_req_failed: ['rate<0.50'],
    http_req_duration: ['p(99)<60000'],
  },
};

export default function () {
  const ep = weightedRandom();
  const res = http.get(ep.url, { tags: { endpoint: ep.name } });
  errorRate.add(res.status >= 500 ? 1 : 0);
  check(res, { 'status received': (r) => r.status > 0, 'not 5xx': (r) => r.status < 500 });
  sleep(Math.random() * 0.05);
}