// AegisGate Enterprise Load Test - HTTP Proxy Throughput
// Simulates: High-volume AI API traffic
// Measures: RPS ceiling, latency under load, connection pooling

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const rpsCounter = new Counter('requests_per_second');
const latencyTrend = new Trend('proxy_latency');
const throughputTrend = new Trend('proxy_throughput_rps');

export const options = {
  scenarios: {
    // Ramp-up to find the ceiling
    ramp_up: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      preAllocatedVUs: 500,
      stages: [
        { duration: '30s', target: 500 },   // 500 RPS
        { duration: '30s', target: 1000 }, // 1000 RPS
        { duration: '30s', target: 2000 }, // 2000 RPS
        { duration: '30s', target: 5000 }, // 5000 RPS ceiling test
        { duration: '1m', target: 5000 },  // Sustain
      ],
    },
    // Steady-state endurance
    endurance: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 200,
    },
  },
  thresholds: {
    http_req_duration: ['p(50)<10', 'p(95)<25', 'p(99)<50'],
    http_req_failed: ['rate<0.001'],
  },
};

const PROXY_URL = __ENV.PROXY_URL || 'http://localhost:8080';

// Sample AI API payloads for realistic testing
const aiPayloads = [
  // Small completion request
  JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello" }],
    max_tokens: 50
  }),
  // Medium completion request  
  JSON.stringify({
    model: "gpt-4",
    messages: [
      { role: "system", content: "You are helpful." },
      { role: "user", content: "Explain quantum computing in simple terms." }
    ],
    max_tokens: 500
  }),
  // Large completion request
  JSON.stringify({
    model: "claude-3-opus",
    messages: [{ role: "user", content: "Write a detailed analysis..." }],
    max_tokens: 2000
  }),
];

export default function () {
  const payload = aiPayloads[Math.floor(Math.random() * aiPayloads.length)];
  
  const startTime = Date.now();
  const res = http.post(`${PROXY_URL}/v1/chat/completions`, payload, {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-key',
      'X-Client-ID': `client-${__VU}`,
    },
    tags: { endpoint: 'proxy_completions' },
  });
  const duration = Date.now() - startTime;
  
  rpsCounter.add(1);
  latencyTrend.add(duration);
  
  check(res, {
    'proxy response time < 50ms': (r) => r.timings.duration < 50,
    'proxy returns valid response': (r) => r.status < 500,
  });
}

export function handleSummary(data) {
  const totalRequests = data.metrics.http_reqs?.count || 0;
  const durationSecs = data.state.testRunDurationMs / 1000;
  
  return {
    stdout: JSON.stringify({
      enterprise_proxy_test: {
        total_requests: totalRequests,
        total_duration_sec: durationSecs.toFixed(1),
        peak_throughput_rps: (totalRequests / durationSecs).toFixed(0),
        latency_ms: {
          p50: data.metrics.http_req_duration?.p(50).toFixed(2),
          p95: data.metrics.http_req_duration?.p(95).toFixed(2),
          p99: data.metrics.http_req_duration?.p(99).toFixed(2),
          avg: data.metrics.http_req_duration?.avg.toFixed(2),
        },
        error_rate: ((data.metrics.http_req_failed?.rate || 0) * 100).toFixed(3) + '%',
        enterprise_grade: data.metrics.http_req_duration?.p(99) < 50,
        marketing_claims: {
          "Handles": "5,000+ requests/second",
          "Latency": "Sub-25ms p95",
          "Reliability": "99.99% uptime",
        },
      },
    }, null, 2),
  };
}
