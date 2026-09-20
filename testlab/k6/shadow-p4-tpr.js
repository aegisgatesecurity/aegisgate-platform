// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate P4 API Key Anomaly Detector — TPR Validation Test
// =========================================================================
//
// Tests that the P4 AnomalyDetector detects:
//   - VolumeSpike: sudden burst of requests from one key
//   - OffHours: requests at unusual hours (simulated)
//   - GeoShift: requests from different IPs (simulated)
//   - NewTool: first-time tool usage
//
// The AnomalyDetector needs MinSamplesForBaseline=10 requests before it
// starts detecting anomalies. This test:
//   1. Sends 10+ benign requests to establish a baseline
//   2. Then sends a burst (volume spike) from the same key
//   3. Checks if P4 shadow alert fires
//
// NOTE: P4's anomaly detection is time-based (hourly counts, std dev).
// In synthetic tests all requests share the same hour, so stddev=0 and
// VolumeSpike/OffHours won't trigger. NewTool and GeoShift require
// varying tool names and source IPs, which the proxy doesn't currently
// populate (toolName="" in recordKeyUsage, all requests from same IP).
//
// This test primarily validates FPR (no false positives on benign traffic).
// TPR validation for P4 requires production traffic with natural variation.
//
// Usage:
//   k6 run --env BASE_URL=http://localhost:8080 testlab/k6/shadow-p4-tpr.js
// =========================================================================

import http from 'k6/http';
import { Counter, Rate, Trend } from 'k6/metrics';
import { check } from 'k6';
import { sleep } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

const p4Alerts = new Counter('p4_alerts');
const p4Predictions = new Counter('p4_predictions');
const p4TPR = new Rate('p4_tpr');
const p4FPR = new Rate('p4_fpr');
const anomalyLatency = new Trend('p4_latency', true);

const benignPrompts = [
  'Write a Python function to sort a list.',
  'Explain how JWT authentication works.',
  'What are SOLID principles?',
  'Create a SQL query for top 10 customers.',
  'How does garbage collection work in Go?',
  'Write a Docker Compose file for a web app.',
  'Explain the CAP theorem.',
  'What is the Actor model?',
  'How does HTTPS work?',
  'Write a regex to validate email addresses.',
];

const advKeys = [
  'acme-key-001', 'acme-key-002', 'acme-key-003',
  'acme-key-004', 'acme-key-005',
];

function sendRequest(key, prompt) {
  const body = JSON.stringify({
    model: 'gemma3:1b',
    messages: [{ role: 'user', content: prompt }],
    max_tokens: 50,
  });

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${key}`,
    'X-Tenant-ID': 'acme',
    'X-Conversation-ID': `p4-conv-${Date.now()}-${Math.random()}`,
  };

  return http.post(`${BASE_URL}/v1/chat/completions`, body, { headers, timeout: '30s' });
}

function extractP4Alert(res) {
  return res.headers['X-Aegisgate-Shadow-P4'] === '1';
}

export const options = {
  scenarios: {
    // Phase 1: Establish baselines with benign traffic (10+ per key)
    baseline: {
      executor: 'shared-iterations',
      vus: 10,
      iterations: 50,
      exec: 'baselinePhase',
      startTime: '0s',
    },
    // Phase 2: Volume spike — burst of requests from same key
    volumeSpike: {
      executor: 'shared-iterations',
      vus: 1,  // single VU to create a clear spike pattern
      iterations: 100,
      exec: 'volumeSpikePhase',
      startTime: '15s',
    },
    // Phase 3: Benign control — normal traffic, should NOT trigger
    benignControl: {
      executor: 'shared-iterations',
      vus: 5,
      iterations: 50,
      exec: 'benignControlPhase',
      startTime: '30s',
    },
  },
  thresholds: {
    'p4_fpr': ['rate<0.01'],
  },
};

export function baselinePhase() {
  const key = advKeys[__ITER % advKeys.length];
  const prompt = benignPrompts[__ITER % benignPrompts.length];
  const res = sendRequest(key, prompt);
  anomalyLatency.add(res.timings.waiting);
  // Don't count FPR/TPR — this is just building baselines
}

export function volumeSpikePhase() {
  // All requests from the SAME key — creates a volume spike
  const res = sendRequest('acme-key-001', benignPrompts[__ITER % benignPrompts.length]);
  const hasAlert = extractP4Alert(res);
  anomalyLatency.add(res.timings.waiting);
  p4TPR.add(hasAlert ? 1 : 0);
  if (hasAlert) p4Alerts.add(1);
}

export function benignControlPhase() {
  // Normal traffic pattern — should NOT trigger
  const key = advKeys[__ITER % advKeys.length];
  const prompt = benignPrompts[__ITER % benignPrompts.length];
  const res = sendRequest(key, prompt);
  const hasAlert = extractP4Alert(res);
  anomalyLatency.add(res.timings.waiting);
  p4FPR.add(hasAlert ? 1 : 0);
}

export function handleSummary(data) {
  const tpr = data.metrics['p4_tpr'] ? (data.metrics['p4_tpr'].values.rate * 100).toFixed(2) : 'N/A';
  const fpr = data.metrics['p4_fpr'] ? (data.metrics['p4_fpr'].values.rate * 100).toFixed(2) : 'N/A';
  const alerts = data.metrics['p4_alerts'] ? data.metrics['p4_alerts'].values.count : 0;

  let report = `
╔══════════════════════════════════════════════════════════════╗
║    P4 API KEY ANOMALY DETECTOR — TPR VALIDATION RESULTS      ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Test Phases:                                                ║
║    1. Baseline: 50 benign requests (build baselines)        ║
║    2. Volume Spike: 100 requests from single key            ║
║    3. Benign Control: 50 normal requests (FPR check)        ║
║                                                              ║
║  Results:                                                    ║
║    P4 Alerts Triggered: ${String(alerts).padEnd(6)}                              ║
║    TPR (volume spike): ${tpr.padEnd(6)}%                              ║
║    FPR (benign):       ${fpr.padEnd(6)}%                              ║
║                                                              ║
║  VERDICT: ${fpr === '0.00' ? '✅ PASS' : '❌ FAIL'} — FPR ${fpr === '0.00' ? '0%, no false positives' : 'false positives detected!'}              ║
╚══════════════════════════════════════════════════════════════╝
`;
  return {
    stdout: report,
    [`testlab/reports/p4-tpr-${Date.now()}.json`]: JSON.stringify(data, null, 2),
  };
}