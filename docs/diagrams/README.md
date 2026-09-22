# AegisGate Architecture Diagrams

This directory contains Mermaid source files for AegisGate architecture diagrams. All diagrams render on GitHub, in the Hugo website (via `{{< mermaid >}}`), and can be exported to PNG/SVG using the Mermaid CLI.

## Diagrams

### 1. Request Data Flow (`request-data-flow.mmd`)

**Purpose**: Complete end-to-end flow of a request through all 7 detection layers.

**Shows**:
- Ingress: 10MB body cap, method filtering, rate limiting
- P4: Entropy anomaly detection (alert-only)
- P2: Tool call chain analysis (ChainWindow=20, TTL=30min)
- L1: Regex scanner (223 patterns + normalization variants)
- L2: MITRE ATLAS compliance (52+ techniques)
- L3: Neural threat detector (CharCNN-BiLSTM v13, two-tier blocking)
- P3: Multi-turn attack detection
- Response path: Response Guard (PII/secrets/XSS)
- Blocking decision tree and audit logging

**Key details**:
- L3 high-confidence threshold: 0.95 (independent block)
- L3 standard threshold: 0.50 (requires L1/L2 corroboration)
- Scan cache: SHA-256 content hash → findings
- All blocking decisions logged to RFC 5424 audit log

---

### 2. Threat Model DFD (`threat-model-dfd.mmd`)

**Purpose**: Data Flow Diagram with trust boundaries for STRIDE threat modeling.

**Shows**:
- **Untrusted Zone**: Clients, potential attackers
- **Platform Trust Boundary**: All AegisGate components
  - Edge Ingress (body cap, method filter, rate limit)
  - Detection Engine (7 layers: P4, P2, L1, L2, L3, P3, Response Guard)
  - Decision Engine (block logic, shadow context)
  - Proxy Layer (circuit breaker, reverse proxy)
  - Persistence (audit log, scan cache, session tracker, chain store)
- **Upstream (Semi-Trusted)**: AI services, MCP tools, A2A agents
- **Observability**: SIEM/SOAR, Grafana

**STRIDE coverage**:
- **Spoofing**: SSO/RBAC identity verification
- **Tampering**: ONNX hash verification (329fd89...)
- **Repudiation**: Append-only, crypto-signed audit log
- **Information Disclosure**: Response Guard, strict mode
- **Denial of Service**: Rate limiting, 10MB body cap
- **Elevation of Privilege**: RBAC engine, policy enforcement

---

### 3. ML Pipeline (`ml-pipeline.mmd`)

**Purpose**: End-to-end ML model lifecycle from training to inference.

**Shows**:
- **Training Pipeline**:
  - Data sources: Adversarial (OWASP, ATLAS), Benign, Augmented (evasion transforms)
  - Preprocessing: Class balancing, char normalization (Latin-1, 256 vocab), encoding
  - Model architecture: CharCNN-BiLSTM (~1.6M params)
    - Embedding: 256 vocab → 64 dim
    - CNN: 3 parallel branches (kernels 3,5,7), 256 filters each → 768 channels
    - BiLSTM: 128 hidden per direction → 256 output
    - Attention: Learned weights over BiLSTM outputs
    - Dense: 256 → 64 → 1 (sigmoid)
  - Training: 50 epochs, batch 64, 80/20 split, early stopping
  - Calibration: Zero-FPR threshold (max_benign + margin, min 0.50)

- **Export & Deployment**:
  - ONNX export (input: [1,256] int32, output: [1] float32)
  - SHA-256 hash verification (v13: 329fd89afe153d0b...)
  - Deploy to Platform, Rampart, Lens

- **Runtime Inference** (~600ms):
  - Content extraction → normalization → encoding → ONNX session → score
  - Threshold check: ≥0.95 high-confidence, ≥0.50 + corroboration, <0.50 allow

- **Model Parity**:
  - Platform ONNX hash = Rampart ONNX hash
  - Lens JS weights hash: b46bbde284651319...
  - All report `char-cnn-bilstm-v13`

- **Validation**:
  - 7-day shadow validation: 0% FPR all detectors
  - Stress test: 8.5M requests, 28K RPS, 0% FPR, 99.57% TPR
  - Evasion resistance: 100.0/100 (0 misses)

---

## Rendering

### CLI (PNG/SVG)
```bash
cd docs/diagrams
npx @mermaid-js/mermaid-cli -i request-data-flow.mmd -o request-data-flow.png -s 2 -b white
npx @mermaid-js/mermaid-cli -i threat-model-dfd.mmd -o threat-model-dfd.svg
```

### GitHub
Mermaid diagrams render automatically in Markdown files on GitHub.

### Hugo Website
```markdown
{{< mermaid >}}
%%{init: {'theme': 'default'}}%%
flowchart LR
    A --> B
{{< /mermaid >}}
```

Or embed pre-rendered SVGs:
```html
<img src="/img/diagrams/request-data-flow.svg" alt="Request Data Flow" />
```

---

## Maintenance

When updating diagrams:
1. Edit the `.mmd` file
2. Validate syntax: `npx @mermaid-js/mermaid-cli -i diagram.mmd -o /tmp/test.png`
3. Check rendered output for readability
4. Commit both `.mmd` and exported `.svg` (for website fallback)

**Style guide**:
- Use `default` theme for best compatibility
- Explicit `style` directives for color-coding
- Keep node labels concise (use `<br/>` for line breaks)
- Avoid special characters in node IDs (use camelCase)

---

## Version History

| Date | Diagram | Changes |
|------|---------|---------|
| 2026-09-22 | request-data-flow.mmd | Initial creation — full 7-layer flow |
| 2026-09-22 | threat-model-dfd.mmd | Initial creation — DFD with trust boundaries |
| 2026-09-22 | ml-pipeline.mmd | Initial creation — training → inference lifecycle |
