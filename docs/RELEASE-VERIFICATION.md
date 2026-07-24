# AegisGate Platform — Release Verification (Enterprise)

**Audience**: Enterprise security teams, procurement, compliance
auditors, and anyone evaluating AegisGate for SOC 2 / FedRAMP / ISO 27001
compliance.

**TL;DR**: Every AegisGate Lens release since `lens-v0.2.2` (2026-06-22) is
backed by a **SLSA Build Level 2 provenance attestation** signed by GitHub
OIDC and recorded in the public Sigstore Rekor transparency log. End-users
can verify with one command (`gh attestation verify`); auditors can
verify offline with `slsa-verifier`.

This document covers the **policy** behind release verification: the threat
model we close, our roadmap to Level 3, and what to expect for
out-of-band key signing and bug-bounty support.

---

## 1. Threat model

Release verification mitigates **F-13: Release artifact supply chain
attack** (see internal threat model for full details).

### Attack scenarios (without provenance)

An attacker who compromises any part of the release pipeline can publish
a backdoored Lens without detection:

| Attack vector | Without provenance |
|---|---|
| Compromised maintainer PAT | Backdoored ZIP published as a "release"; users get malware |
| Malicious Dependabot auto-merge | Backdoored dependency merged; ZIP silently ships malicious code |
| Hijacked GitHub Actions cache | Build "succeeds" but produces a backdoored ZIP |
| Mirror compromise (apt repo, CDN) | Users download a backdoored ZIP instead of ours |
| Insider threat | Authorized maintainer publishes malicious version |

### With SLSA L2 provenance

Each of the above scenarios becomes detectable:

| Attack vector | With provenance |
|---|---|
| Compromised maintainer PAT | Attestation not signed by the canonical workflow path → verification FAILS |
| Malicious Dependabot auto-merge | Build wouldn't have the canonical `release-lens.yml` provenance → FAILS |
| Hijacked cache | Re-running build from clean cache produces different artifact hash → original release becomes unverifiable → users alert us |
| Mirror compromise | `gh attestation verify` queries the canonical GitHub Attestations store, not the mirror's copy → FAILS |
| Insider threat | Provenance includes the workflow run ID; insider would need to compromise GitHub's OIDC infrastructure |

The **residual risk** after SLSA L2 is: a compromise of GitHub's OIDC
infrastructure itself, which would allow an attacker to mint arbitrary
provenance attestations. This is mitigated by **SLSA Build Level 3**
(hardened build platform) which we're targeting for 2027.

---

## 2. SLSA level and roadmap

### Current: SLSA Build Level 2

| SLSA L2 requirement | Implementation |
|---|---|
| Provenance generated | `actions/attest-build-provenance@v3` produces in-toto SLSA Provenance v1.0 |
| Provenance signed | Sigstore Fulcio (keyless OIDC), recorded in public Rekor log |
| Provenance non-forgeable by build steps | OIDC token issued at workflow start; build steps cannot modify the token |
| Source verified | Provenance records `sourceURI`, `sourceTag`, source commit SHA |

### Roadmap: SLSA Build Level 3 (target: 2027)

| SLSA L3 requirement | Plan |
|---|---|
| Hardened build platform | Replace `ubuntu-latest` runners with isolated ephemeral runners; evaluate `runs-on: blacksmith-latest` (GitHub-hosted L3-eligible runners, currently in beta) |
| Provenance non-forgeable by platform | SHA-pin the SLSA generator workflow (planned; deferred from Day 18 due to startup_failure debugging — see internal Day 18 SLSA L2 report) |
| Provenance includes all build inputs | Use the official slsa-framework/slsa-github-generator L3 reusable workflow |

Day 18 attempted the L3 path and hit startup_failure debugging costs that
weren't justified for a single-maintainer repo. We documented the
attempt and the decision matrix in
internal Day 18 SLSA L2 report. We'll revisit when we
have admin log access to GitHub Actions or when GitHub's L3-eligible
runners are GA.

---

## 3. Verification procedures

### Quick verification (1 minute, user-facing)

See `VERIFY.md` in the Lens repo. One command:

```bash
gh attestation verify aegisgate-lens-<version>.zip \
  --owner aegisgatesecurity --repo aegisgate-platform
```

### Deep verification (5 minutes, auditor-facing)

```bash
SUBJECT_SHA=$(sha256sum aegisgate-lens-<version>.zip | awk '{print $1}')
gh attestation download "$SUBJECT_SHA" \
  --owner aegisgatesecurity --repo aegisgate-platform \
  > aegisgate-lens-<version>.intoto.jsonl

# Offline verify (requires Go 1.21+):
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest
slsa-verifier verify-artifact \
  --provenance-path aegisgate-lens-<version>.intoto.jsonl \
  --source-uri github.com/aegisgatesecurity/aegisgate-platform \
  --source-tag lens-v<version> \
  aegisgate-lens-<version>.zip
```

### Provenance inspection (10 minutes)

The attestation bundle is JSON-Lines with one entry per artifact:

```bash
cat aegisgate-lens-<version>.intoto.jsonl | python3 -m json.tool
```

Look for:
- `payloadType`: `application/vnd.in-toto+json` (SLSA provenance).
- `predicate.builder.id`: should match
  `https://github.com/aegisgatesecurity/aegisgate-platform/.github/workflows/release-lens.yml@refs/tags/lens-v<version>`.
- `predicate.invocationId`: links to the specific GitHub Actions run
  ID (`https://github.com/aegisgatesecurity/aegisgate-platform/actions/runs/<run-id>`).
- `subject[0].digest.sha256`: must equal the ZIP's SHA-256.

### Independent Rekor search (audit trail)

Every attestation is also in the public Rekor log. To independently
verify the attestation was logged:

```bash
# Extract the Rekor log index from the attestation bundle.
REKOR_INDEX=$(cat *.intoto.jsonl | jq -r '.verificationMaterial.tlogEntries[0].logIndex')

# Query Rekor directly.
curl -s "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=${REKOR_INDEX}" | jq .
```

---

## 4. Key signing policy

| Key | Algorithm | Status | Used for |
|---|---|---|---|
| Ed25519 signing keypair (`keys/lens-signing-{private,public}.pem`) | Ed25519 | Active since v0.1.0 | Signs the bundled ML model (`*.bundle`) within each release ZIP |
| GitHub Actions OIDC (Fulcio) | RSA-PSS / ECDSA | Active since v0.2.2 | Signs the SLSA Build Level 2 provenance attestation |
| Out-of-band release signing key (planned 2027) | Sigstore keyless | Not yet implemented | Would provide defense-in-depth if GitHub Actions itself is compromised |

The Ed25519 keypair is **not** used for provenance signing. It's used for
the ML bundle signature inside the ZIP, which is verified at extension
install time.

---

## 5. Incident response

If verification fails for a release you downloaded:

1. **Do not install the ZIP.** Treat it as suspicious.
2. **File an issue** at github.com/aegisgatesecurity/aegisgate-platform/issues
   with:
   - The exact `gh attestation verify` output (`--verbose` flag).
   - The ZIP's SHA-256 (`sha256sum aegisgate-lens-<version>.zip`).
   - Where you downloaded it from (URL).
3. **Do not publish** the failure publicly before we've had a chance to
   triage; we typically respond within 4 business hours.
4. **Wait for our advisory.** We publish to
   github.com/aegisgatesecurity/aegisgate-platform/security/advisories.

If the failure is a false positive (e.g., tooling issue on your side),
we'll help you verify and document the workaround.

If the failure is a real attack, we will:
- Revoke the affected release within 1 hour.
- Re-publish a clean version with a new tag (`lens-v<version>-rebuild1`).
- Publish a security advisory within 4 hours.
- Notify Chrome Web Store to flag the affected version.
- Notify our bug-bounty participants.

---

## 6. Compliance mapping

| Standard | Requirement | Our coverage |
|---|---|---|
| **SOC 2 (CC7.1)** | Detect and respond to system failures | SLSA L2 provides automated build-integrity verification |
| **SOC 2 (CC8.1)** | Change management | Provenance records the exact commit and workflow for each release |
| **NIST SSDF (PW.4.4)** | Restrict access to software components | OIDC-based keyless signing restricts key access to the GitHub Actions infrastructure |
| **NIST SSDF (RV.1.2)** | Verify third-party software components | End-users and auditors can verify the ZIP's provenance in <5 minutes |
| **NIST 800-218 SSDF (PS.3.2)** | Use compiler / interpreter built-in mechanisms to prevent unauthorized code execution | The Lens runs in Chrome MV3 sandbox; all bundled JS is plain JavaScript (no eval, no innerHTML) — see F-06 in threat model |
| **ISO 27001 A.14.2.4** | Restrictions on changes to software packages | Tag-pinned releases + signed provenance |
| **EU NIS2 Art. 21(2)(d)** | Supply chain security | SLSA L2 is the current state-of-the-art for OSS supply chain attestation |
| **EO 14028 §4(e)(vii)** | Software bills of materials | The Lens's `lens_ml_build/INVENTORY.txt` is generated by the build and is part of the ZIP |

---

## 7. References

- **Day 18 SLSA L2 implementation report**: internal document
- **Threat model (F-13 closed)**: internal document
- **Build workflow**: `.github/workflows/release-lens.yml`
- **CodeQL config**: `.github/codeql/codeql-config.yml`
- **SLSA framework**: https://slsa.dev
- **in-toto attestation spec**: https://github.com/in-toto/attestation
- **Sigstore**: https://www.sigstore.dev
- **Lens user-facing VERIFY.md**: github.com/aegisgatesecurity/aegisgate-lens/blob/main/VERIFY.md
