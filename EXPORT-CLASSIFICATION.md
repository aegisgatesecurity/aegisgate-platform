# Export Control Self-Classification — AegisGate

## Overview

This document provides a preliminary export control self-classification for AegisGate products under the U.S. Export Administration Regulations (EAR). It is **not legal advice** — consult with export counsel before relying on this classification.

## Products Classified

| Product | Primary EAR Classification | Rationale |
|---------|---------------------------|-----------|
| AegisGate Platform | EAR99 | See analysis below |
| AegisGate Rampart | EAR99 | See analysis below |
| AegisGate Lens | EAR99 | No cryptography; pure detection |
| AegisGate Enterprise | EAR99 / 5D002 (optional) | See analysis below |

## Analysis

### AegisGate Platform

**Function:** Network proxy that inspects HTTP traffic to AI services for sensitive data detection.

**Cryptography used:**
- TLS 1.2/1.3 for inbound and outbound connections (uses Go's `crypto/tls` package)
- bcrypt for password hashing
- HMAC-SHA256 for API key validation
- AES-256-GCM for data at rest (if enabled)

**EAR analysis:**
- TLS: Uses standard, widely available TLS libraries bundled with Go. Does not implement custom cryptographic algorithms.
- The product's **primary function** is data loss prevention / content inspection, not cryptography. Cryptography is used to secure communications, not as the product's primary capability.
- Under EAR Section 734.3, items that are "generally available to the public" via open-source publication are not subject to the EAR (15 CFR 734.3(b)(3) and 734.7).
- **Classification: EAR99** — The product is open-source, generally available, and its primary function is not cryptographic.

**Note on Section 740.17 (Encryption license exception):**
- Because the source code is publicly available and open-source under Apache 2.0, the software qualifies for the "publicly available" exception under 15 CFR 734.7.
- No ECCN classification is required for publicly available open-source software that does not include cryptographic functionality as its primary purpose.
- A classification request to BIS is **not required** for open-source software meeting these criteria.

### AegisGate Rampart

**Function:** Local MITM proxy for AI coding tools.

**Cryptography used:**
- TLS for MITM interception (generates a local CA and leaf certificates)
- Standard Go `crypto/tls` library

**EAR analysis:**
- Same as Platform — open-source, publicly available, primary function is content inspection not cryptography.
- The MITM CA generation uses RSA 2048-bit or ECDSA P-256, both standard and widely available.
- **Classification: EAR99**

### AegisGate Lens

**Function:** Browser extension for on-device PII/secret detection.

**Cryptography used:** None. Lens does not implement any cryptographic operations.

**Classification: EAR99** — No cryptography involved.

### AegisGate Enterprise

**Function:** Enterprise components including Trust Framework (ECDSA P-256 identity), SIEM integration, premium compliance.

**Cryptography used:**
- ECDSA P-256 for agent identity and attestation signing
- AES-256-GCM for data at rest
- TLS for all network communication

**EAR analysis:**
- Enterprise is **proprietary** (not open-source), so the "publicly available" exception does not apply.
- The Trust Framework uses ECDSA P-256 for digital signatures. This is a standard NIST curve, widely available.
- Under ECCN 5D002, software that uses cryptography for data confidentiality could be controlled. However:
  - The primary function of the Trust Framework is **authentication and identity verification**, not data confidentiality.
  - Authentication-only cryptography is generally classified under 5D002.c.1 (which controls authentication products) but may qualify for License Exception TSU if source code is provided.
  - Since Enterprise is proprietary and distributed under a commercial license, a formal classification request to BIS may be warranted.
- **Preliminary classification: EAR99** (primary function is security policy enforcement, not cryptographic data confidentiality)
- **Recommended action:** If Enterprise is sold to international customers, file a formal self-classification request with BIS or obtain a CCATS ruling.

## Summary

| Question | Answer |
|----------|--------|
| Is any AegisGate product controlled under EAR? | **No** — open-source products are EAR99 (publicly available exception). Enterprise is likely EAR99 but may warrant formal review. |
| Is an export license required? | **No** for open-source products. Enterprise may require review for international sales. |
| Is a BIS classification request required? | **No** for open-source products. **Recommended** for Enterprise before international sales. |
| Does AegisGate use proprietary/custom cryptography? | **No** — all cryptographic operations use standard, NIST-approved algorithms via well-known libraries. |

## Disclaimer

This self-classification is based on the author's understanding of the EAR as of September 2026. Export control regulations are complex and subject to change. This document is **not a substitute for legal advice from qualified export counsel**. Before exporting any AegisGate product to foreign nationals or foreign countries, consult with an export compliance attorney.

---

*Copyright © 2026 AegisGate Security, LLC. All rights reserved.*