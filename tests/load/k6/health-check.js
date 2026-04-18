// AegisGate Enterprise Load Test - Health Check Baseline
// Measures: Response time, throughput, connection stability
// Target: Sub-10ms p99 latency under load

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const latencyTrend = new Trend('http_req_duration_p99');
const errorRate = new Rate('errors');
const rpsCounter = new Counter('requests_per_second');

export const options = {
  stages: [
    { duration: '30s', target: 100 },   // Ramp up to 100 users
    { duration: '1m', target: 100 },   // Steady state
    { duration: '30s', target: 200 },  // Spike to 200 users
    { duration: '1m', target: 200 },   // Sustained spike
    { duration: '30s', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<50', 'p(99)<100'], // 95% under 50ms, 99% under 100ms
    http_req_failed: ['rate<0.01'],                // Error rate under 1%
  },
};

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:8443';

export default function () {
  const startTime = Date.now();
  
  const response = http.get(`${BASE_URL}/health`, {
    tags: { endpoint: 'health' },
  });
  
  const duration = Date.now() - startTime;
  latencyTrend.add(duration);
  rpsCounter.add(1);
  
  const success = check(response, {
    'health check status is 200': (r) => r.status === 200,
    'health check response time < 100ms': (r) => r.timings.duration < 100,
    'health check has valid JSON': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch {
        return false;
      }
    },
  });
  
  if (!success) {
    errorRate.add(1);
  }
  
  sleep(Math.random() * 0.5 + 0.1); // Random sleep 100-600ms
}

export function handleSummary(data) {
  return {
    stdout: JSON.stringify({
      ...data,
      enterprise_metrics: {
        p99_latency_ms: data.metrics.http_req_duration?.p(99),
        p95_latency_ms: data.metrics.http_req_duration?.p(95),
        avg_rps: data.metrics.requests_per_second?.count / data.state.testRunDurationSecs,
        error_rate_percent: (data.metrics.errors?.rate || 0) * 100,
        enterprise_ready: data.metrics.http_req_duration?.p(99) < 100,
      },
    }, null, 2),
  };
}
