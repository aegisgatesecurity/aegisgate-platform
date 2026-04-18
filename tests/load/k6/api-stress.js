// AegisGate Enterprise Load Test - API Endpoints Under Stress
// Simulates: Real-world API usage patterns, burst traffic
// Measures: Concurrent connection handling, memory stability, throughput ceiling

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const latencyByEndpoint = new Trend('latency_by_endpoint');
const throughputTrend = new Trend('requests_per_second');

export const options = {
  scenarios: {
    // Steady traffic - normal operations
    steady_load: {
      executor: 'constant-vus',
      vus: 50,
      duration: '2m',
      exec: 'apiCalls',
    },
    // Burst traffic - spike simulation
    burst_load: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 500 },
        { duration: '30s', target: 500 },
        { duration: '10s', target: 0 },
      ],
      exec: 'burstTraffic',
    },
    // Endurance test - memory leak detection
    endurance: {
      executor: 'constant-vus',
      vus: 100,
      duration: '5m',
      exec: 'apiCalls',
    },
  },
  thresholds: {
    http_req_duration: ['p(50)<20', 'p(95)<50', 'p(99)<100'],
    http_req_failed: ['rate<0.001'], // 0.1% error tolerance for enterprise
  },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8443';

export function apiCalls() {
  const endpoints = [
    { url: '/health', method: 'GET', weight: 40 },
    { url: '/api/v1/tier', method: 'GET', weight: 20 },
    { url: '/api/v1/version', method: 'GET', weight: 20 },
    { url: '/version', method: 'GET', weight: 10 },
    { url: '/stats', method: 'GET', weight: 10 },
  ];
  
  // Weighted random selection
  const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
  let random = Math.random() * totalWeight;
  let endpoint = endpoints[0];
  
  for (const e of endpoints) {
    random -= e.weight;
    if (random <= 0) {
      endpoint = e;
      break;
    }
  }
  
  const startTime = Date.now();
  const res = http.get(`${BASE_URL}${endpoint.url}`);
  const duration = Date.now() - startTime;
  
  latencyByEndpoint.add(duration, { endpoint: endpoint.url });
  
  check(res, {
    [`${endpoint.url} status is 200 or expected`]: (r) => r.status === 200 || r.status < 500,
    [`${endpoint.url} response time < 100ms`]: (r) => r.timings.duration < 100,
  });
  
  sleep(Math.random() * 0.3 + 0.1);
}

export function burstTraffic() {
  // High-frequency requests during burst
  const res = http.get(`${BASE_URL}/health`);
  check(res, {
    'burst: status OK': (r) => r.status === 200,
    'burst: response < 200ms': (r) => r.timings.duration < 200,
  });
  sleep(0.01); // 10ms between burst requests
}

export function handleSummary(data) {
  const endpoints = ['health', 'version', 'tier', 'stats'];
  const metrics = {};
  
  endpoints.forEach(ep => {
    const metric = data.metrics[`http_req_duration{endpoint:${ep}}`];
    if (metric) {
      metrics[ep] = {
        p50: metric.p(50),
        p95: metric.p(95),
        p99: metric.p(99),
        avg: metric.avg,
      };
    }
  });
  
  return {
    stdout: JSON.stringify({
      enterprise_load_test: {
        total_requests: data.metrics.http_reqs?.count,
        total_duration_ms: data.state.testRunDurationMs,
        avg_throughput_rps: (data.metrics.http_reqs?.count / (data.state.testRunDurationMs / 1000)).toFixed(2),
        endpoints: metrics,
        error_rate: (data.metrics.http_req_failed?.rate * 100).toFixed(3) + '%',
        enterprise_grade: data.metrics.http_req_duration?.p(99) < 100,
      },
    }, null, 2),
  };
}
