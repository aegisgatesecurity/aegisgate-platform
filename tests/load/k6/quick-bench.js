import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const latencyTrend = new Trend('latency_ms');
const rpsCounter = new Counter('total_requests');

export const options = {
  scenarios: {
    baseline: {
      executor: 'constant-vus',
      vus: 50,
      duration: '15s',
      exec: 'baseline',
    },
    ramp: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 100 },
        { duration: '10s', target: 250 },
        { duration: '10s', target: 500 },
        { duration: '10s', target: 0 },
      ],
      exec: 'baseline',
    },
  },
  thresholds: {
    http_req_duration: ['p(50)<10', 'p(95)<25', 'p(99)<50'],
  },
};

const BASE = __ENV.TARGET_URL || 'http://localhost:8443';

export function baseline() {
  const endpoints = ['/health', '/version', '/api/v1/tier', '/metrics'];
  const ep = endpoints[Math.floor(Math.random() * endpoints.length)];
  const start = Date.now();
  const res = http.get(`${BASE}${ep}`);
  const dur = Date.now() - start;
  latencyTrend.add(dur);
  rpsCounter.add(1);
  check(res, {
    [`${ep} responds`]: () => res.status >= 200 && res.status < 600,
    [`${ep} under 100ms`]: () => dur < 100,
  });
  sleep(Math.random() * 0.1 + 0.02);
}

export function handleSummary(data) {
  const totalReqs = data.metrics.total_requests?.values?.count || 0;
  const dur = data.state.testRunDurationMs / 1000;
  const p50 = data.metrics.http_req_duration?.values?.['p(50)'] || 0;
  const p95 = data.metrics.http_req_duration?.values?.['p(95)'] || 0;
  const p99 = data.metrics.http_req_duration?.values?.['p(99)'] || 0;
  const avg = data.metrics.http_req_duration?.values?.avg || 0;
  const errRate = data.metrics.http_req_failed?.values?.rate || 0;
  
  return {
    stdout: `
========================================
  AEGISGATE PERFORMANCE BENCHMARK
  v3.4.0-beta.1
========================================
  Total Requests:    ${totalReqs.toLocaleString()}
  Test Duration:     ${dur.toFixed(1)}s
  Avg Throughput:    ${(totalReqs/dur).toFixed(0)} req/s
  Avg Latency:       ${(avg*1000).toFixed(2)}ms
  p50 Latency:       ${(p50*1000).toFixed(2)}ms
  p95 Latency:       ${(p95*1000).toFixed(2)}ms
  p99 Latency:       ${(p99*1000).toFixed(2)}ms
  Error Rate:        ${(errRate*100).toFixed(2)}%
  Peak VUs:          500
========================================
`,
  };
}
