// AegisGate — Progressive Ceiling Test
// Ramps up from 200 to 5000 VUs in steps to find the actual breaking point.
// Each step holds for 30s. Uses scenarios with startTime offsets.

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
    // 200 VUs — 0-30s
    s200:  { executor: 'constant-vus', vus: 200,  duration: '30s', startTime: '0s' },
    // 500 VUs — 35-65s
    s500:  { executor: 'constant-vus', vus: 500,  duration: '30s', startTime: '35s' },
    // 1000 VUs — 70-100s
    s1k:   { executor: 'constant-vus', vus: 1000, duration: '30s', startTime: '70s' },
    // 1500 VUs — 105-135s
    s1k5:  { executor: 'constant-vus', vus: 1500, duration: '30s', startTime: '105s' },
    // 2000 VUs — 140-170s
    s2k:   { executor: 'constant-vus', vus: 2000, duration: '30s', startTime: '140s' },
    // 3000 VUs — 175-205s
    s3k:   { executor: 'constant-vus', vus: 3000, duration: '30s', startTime: '175s' },
    // 4000 VUs — 210-240s
    s4k:   { executor: 'constant-vus', vus: 4000, duration: '30s', startTime: '210s' },
    // 5000 VUs — 245-275s
    s5k:   { executor: 'constant-vus', vus: 5000, duration: '30s', startTime: '245s' },
    // Recovery 100 VUs — 280-310s
    recovery: { executor: 'constant-vus', vus: 100, duration: '30s', startTime: '280s' },
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
  check(res, { 'ok': (r) => r.status > 0 && r.status < 500 });
  sleep(Math.random() * 0.05);
}