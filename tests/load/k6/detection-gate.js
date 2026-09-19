// AegisGate Platform — k6 Detection Gate Test
// Reads adversarial payloads from tests/adversarial/corpus.yaml
// Sends each through the proxy and checks detection/blocking.
//
// CI Gate: Fails if detection_rate < 1.0 or false_positive_rate > 0.0
//
// Usage: k6 run tests/load/k6/detection-gate.js
// Requires: Platform running on localhost:8080, echo server on localhost:11435

import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { sleep } from 'k6';

// Payloads are generated from tests/adversarial/corpus.yaml by
// scripts/generate-k6-payloads.go → tests/load/k6/payloads.js
// This ensures a single source of truth: corpus.yaml.
// CI regenerates and verifies sync before running k6.
import { adversarialPayloads, benignPayloads } from './payloads.js';

// Custom metrics
const detectionRate = new Rate('detection_rate');
const fprRate = new Rate('false_positive_rate');
const latency = new Trend('response_latency_ms');
const missedPayloads = new Counter('missed_payloads');
const falsePositives = new Counter('false_positives');

// Configuration — override via env vars
const TARGET_URL = __ENV.PROXY_URL || 'http://localhost:8080/v1/chat/completions';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || 'test-key';
const HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + AUTH_TOKEN,
};

// Payloads imported from ./payloads.js (generated from corpus.yaml)

export const options = {
    scenarios: {
        adversarial_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: adversarialPayloads.length,
            maxDuration: '5m',
            exec: 'default',
        },
        benign_test: {
            executor: 'per-vu-iterations',
            vus: 1,
            iterations: benignPayloads.length,
            maxDuration: '5m',
            startTime: '30s',    // start after adversarial completes (24 × ~0.2s ≈ 5s)
            exec: 'benign',       // CRITICAL: must specify which function to run
        },
    },
    thresholds: {
        'detection_rate': ['rate>=1.0'],    // 100% detection required
        'false_positive_rate': ['rate==0.0'], // 0% FPR required
        'http_req_failed': ['rate<0.05'],
    },
};

// Adversarial scenario — each VU iteration sends one adversarial payload
export default function () {
    const idx = (__ITER || 0) % adversarialPayloads.length;
    const payload = adversarialPayloads[idx];
    const body = JSON.stringify({
        model: 'echo',
        messages: [{ role: 'user', content: payload.text }],
        max_tokens: 50,
    });

    const startTime = Date.now();
    const res = http.post(TARGET_URL, body, { headers: HEADERS });
    const elapsed = Date.now() - startTime;
    latency.add(elapsed);

    const isBlock = res.body && (res.body.includes('Content blocked') || res.body.includes('Request blocked'));
    const isEcho = res.body && res.body.includes('echo-cmpl');
    const wasBlocked = isBlock && !isEcho;

    detectionRate.add(wasBlocked ? 1 : 0);

    check(res, {
        'adversarial payload blocked': (r) => wasBlocked,
    });

    if (!wasBlocked) {
        missedPayloads.add(1);
        console.log(`MISSED [${payload.id}] pattern=${payload.pattern}: "${payload.text.substring(0, 80)}..."`);
    }

    sleep(0.1);
}

// Benign scenario — separate function for the second scenario
export function benign() {
    const idx = (__ITER || 0) % benignPayloads.length;
    const text = benignPayloads[idx];
    const body = JSON.stringify({
        model: 'echo',
        messages: [{ role: 'user', content: text }],
        max_tokens: 50,
    });

    const res = http.post(TARGET_URL, body, { headers: HEADERS });
    const isBlock = res.body && (res.body.includes('Content blocked') || res.body.includes('Request blocked'));
    const isEcho = res.body && res.body.includes('echo-cmpl');
    const wasBlocked = isBlock && !isEcho;

    fprRate.add(wasBlocked ? 1 : 0);

    check(res, {
        'benign payload allowed': (r) => !wasBlocked,
    });

    if (wasBlocked) {
        falsePositives.add(1);
        console.log(`FALSE POSITIVE: "${text}"`);
    }

    sleep(0.1);
}

export function handleSummary(data) {
    const detection = data.metrics.detection_rate?.values?.rate ?? 0;
    const fpr = data.metrics.false_positive_rate?.values?.rate ?? 0;
    const missed = data.metrics.missed_payloads?.values?.count ?? 0;
    const fps = data.metrics.false_positives?.values?.count ?? 0;

    return {
        stdout: `
╔══════════════════════════════════════════════════════════════╗
║           DETECTION GATE TEST — CI RESULTS                   ║
╠══════════════════════════════════════════════════════════════╣
║  Adversarial Payloads:  ${adversarialPayloads.length.toString().padStart(4)}                       ║
║  Benign Payloads:       ${benignPayloads.length.toString().padStart(4)}                       ║
║                                                              ║
║  Detection Rate:        ${(detection * 100).toFixed(2)}%  (target: 100%)      ${detection >= 1.0 ? '✅ PASS' : '❌ FAIL'} ║
║  False Positive Rate:   ${(fpr * 100).toFixed(2)}%  (target: 0%)      ${fpr === 0 ? '✅ PASS' : '❌ FAIL'} ║
║  Missed Payloads:       ${missed.toString().padStart(4)}                       ║
║  False Positives:       ${fps.toString().padStart(4)}                       ║
╚══════════════════════════════════════════════════════════════╝
`,
    };
}