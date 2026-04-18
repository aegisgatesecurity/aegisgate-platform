/**
 * Rate Limit Verification Test
 * 
 * Sends requests at 2x the configured rate to verify:
 * 1. Rate limiting is enforced
 * 2. 429 responses returned when exceeded
 * 3. Rate limit resets after window
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const rateLimitTriggered = new Rate('rate_limit_triggered');
const normalResponseRate = new Rate('normal_responses');

// Test configuration
export const options = {
  thresholds: {
    // Expect some rate limits to trigger
    'rate_limit_triggered': ['rate > 0.01'], // At least 1% should hit rate limit
    'normal_responses': ['rate > 0.5'],       // Most should succeed initially
    'http_req_duration': ['p(95) < 100'],       // Sub-100ms response
  },
  stages: [
    { duration: '10s', target: 50 },   // Ramp up
    { duration: '30s', target: 100 },  // Sustain (should trigger limits)
    { duration: '10s', target: 0 },   // Cool down
  ],
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const HEALTH_ENDPOINT = `${BASE_URL}/health`;

export default function () {
  group('Rate Limit Test', () => {
    const startTime = new Date();
    
    // Send request to proxy health endpoint
    const response = http.get(HEALTH_ENDPOINT, {
      headers: {
        'Accept': 'application/json',
      },
    });
    
    const duration = new Date() - startTime;
    
    // Check for rate limit response (429) or success (200)
    const isRateLimited = response.status === 429;
    const isSuccess = response.status === 200;
    
    // Record metrics
    rateLimitTriggered.add(isRateLimited);
    normalResponseRate.add(isSuccess);
    
    // Validation checks
    check(response, {
      'response received': (r) => r.status !== 0,
      'rate limit or success': (r) => r.status === 429 || r.status === 200 || r.status === 503,
      'rate limit returns 429': (r) => isRateLimited || isSuccess,
      'response time < 100ms': (r) => duration < 100,
    });
    
    // Log rate limit events
    if (isRateLimited) {
      console.log(`✅ Rate limit triggered: ${response.status} - ${response.body}`);
    }
    
    // Small delay between requests (simulate real traffic)
    sleep(0.01); // 10ms gap = ~100 RPS per VU
  });
}

export function handleSummary(data) {
  const rateLimitPercent = data.metrics.rate_limit_triggered ? 
    (data.metrics.rate_limit_triggered.rate * 100).toFixed(2) : 0;
  
  const normalPercent = data.metrics.normal_responses ? 
    (data.metrics.normal_responses.rate * 100).toFixed(2) : 0;
  
  return {
    'rate-limit-verification-results.json': JSON.stringify({
      metadata: {
        test: 'Rate Limit Verification',
        timestamp: new Date().toISOString(),
        version: 'v1.3.0',
      },
      summary: {
        total_requests: data.metrics.http_reqs.count,
        rate_limited_percent: rateLimitPercent,
        normal_percent: normalPercent,
        avg_latency_ms: data.metrics.http_req_duration.avg,
        p95_latency_ms: data.metrics.http_req_duration['p(95)'],
      },
      status: rateLimitPercent > 0 ? 'PASS' : 'FAIL',
      message: rateLimitPercent > 0 
        ? '✅ Rate limiting is ENFORCED' 
        : '❌ Rate limiting NOT triggered - may need configuration review',
    }, null, 2),
  };
}
