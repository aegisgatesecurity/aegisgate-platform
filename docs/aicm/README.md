# AICM v1.1.1 Control Mapping — AegisGate Security Platform

This directory contains a control-by-control mapping of the Cloud Security Alliance's [AI Controls Matrix (AICM) v1.1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1) to the AegisGate Security Platform.

## CSA Listings

AegisGate Security is listed in two CSA programs:

- **[CSA STAR Registry](https://cloudsecurityalliance.org/star/registry/aegisgate-security)** (Level 1) — Our [AI-CAIQ self-assessment](https://cloudsecurityalliance.org/star/registry/aegisgate-security) (311 questions, 184 Yes / 127 NA) is publicly available.
- **[CSA Startup Showcase](https://cloudsecurityalliance.org/csa-startup-showcase/registry/?modal=aegisgate-security-llc)** — Featured as an AI security solution for Agentic AI Identity and Access Management.

## Files

| File | Description |
|------|-------------|
| `aicm-aegisgate-control-mapping.md` | Summary document — methodology, domain breakdown, AI-specific control coverage, implementation patterns, gap analysis |
| `aicm-aegisgate-crosswalk.csv` | Full 247-control crosswalk (text format) with columns: Control ID, Domain, Title, Type, Relevance, Features, Implementation Evidence |
| `aicm-aegisgate-crosswalk.xlsx` | Color-coded Excel workbook (3 sheets: Crosswalk, Summary, AI-Specific Controls) |
| `aicm-aegisgate-caiq-responses.xlsx` | AI-CAIQ v1.0.2 self-assessment — 311 questions answered with implementation descriptions |

## Results

| Classification | Count | Description |
|----------------|-------|-------------|
| Full | 66 | AegisGate directly implements the control's requirements |
| Partial | 77 | AegisGate contributes to but does not fully satisfy the control |
| Not Applicable | 104 | Organizational/physical controls outside software scope |
| **Total Relevant** | **143 (58%)** | Full + Partial |

### AI-Specific Controls: 29 of 32 relevant (20 Full, 9 Partial, 3 N/A)

## Methodology

All 247 AICM v1.1.1 controls were extracted from the official CSA Excel spreadsheet and evaluated against AegisGate's Go source code (400K LOC, 60+ packages). Every evidence string references specific package paths (e.g., `pkg/response/pii_scanner.go`) — the mapping is reproducible against the source code in this repository.

## License

All artifacts in this directory are licensed under the same [Apache 2.0 license](../../LICENSE) as the AegisGate Security Platform.
