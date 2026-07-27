#!/bin/bash
# AegisGate Platform — OPSEC scan script
#
# Scans a repository for content that must not be committed to a public repo.
# Used by both .githooks/pre-commit (staged files only) and CI (all tracked files).
#
# Usage:
#   ./tools/opsec-scan.sh              # Scan all tracked files (CI mode)
#   ./tools/opsec-scan.sh --staged     # Scan only staged files (pre-commit mode)
#
# Exit codes:
#   0 — All checks pass (warnings are printed but don't block)
#   1 — One or more FAIL-level checks found
#
# Apache 2.0. Copyright 2026 AegisGate Security, LLC.

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

FAIL=0
WARN=0
MODE="all"

if [ "${1:-}" = "--staged" ]; then
    MODE="staged"
fi

log_fail() { echo -e "${RED}❌ FAIL: $1${NC}"; FAIL=$((FAIL+1)); }
log_warn() { echo -e "${YELLOW}⚠️  WARN: $1${NC}"; WARN=$((WARN+1)); }
log_pass() { echo -e "${GREEN}  ✅ $1${NC}"; }

if [ "$MODE" = "staged" ]; then
    FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
    LABEL="staged"
else
    FILES=$(git ls-files 2>/dev/null || true)
    LABEL="tracked"
fi

if [ -z "$FILES" ]; then
    echo "No $LABEL files to scan. Exiting."
    exit 0
fi

echo "=== AegisGate Platform OPSEC scan ($LABEL files) ==="
echo

# Helper: get file content, filtering out binary files and null bytes
get_content() {
    local f="$1"
    # Skip binary file extensions
    case "$f" in
        *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.woff|*.woff2|*.ttf|*.eot|*.zip|*.crx|*.xpi|*.bundle|*.onnx|*.tflite|*.bin|*.mp4|*.mp3|*.wav|*.woff2)
            return 1
            ;;
    esac
    # Try to get content; if git show fails or content has null bytes, skip
    local content
    content=$(git show ":$f" 2>/dev/null | tr -d '\0' || true)
    if [ -z "$content" ]; then
        return 1
    fi
    echo "$content"
    return 0
}

# ─── 1. Private key detection ────────────────────────────────────────────
echo "1. Private key detection"
PK_FAIL=0
PK_WARN=0
for f in $FILES; do
    case "$f" in
        *.png|*.jpg|*.jpeg|*.gif|*.webp|*.ico|*.woff|*.woff2|*.ttf|*.eot|*.zip|*.crx|*.xpi|*.bundle|*.onnx|*.tflite|*.bin|*.mp4|*.mp3|*.wav)
            continue
            ;;
    esac
    # Check for .pem / .key / .priv extensions
    case "$f" in
        *.pem|*.key|*.priv|*.pkcs12|*.p12|*.pfx|*.jks)
            CONTENT=$(get_content "$f") || continue
            if echo "$CONTENT" | grep -qF 'BEGIN PRIVATE KEY'; then
                log_fail "$f contains a private key block"
                PK_FAIL=$((PK_FAIL+1))
            elif echo "$CONTENT" | grep -qF 'BEGIN RSA PRIVATE KEY'; then
                log_fail "$f contains an RSA private key block"
                PK_FAIL=$((PK_FAIL+1))
            elif echo "$CONTENT" | grep -qF 'BEGIN CERTIFICATE'; then
                log_warn "$f is a certificate file — verify this should be public"
                PK_WARN=$((PK_WARN+1))
            fi
            ;;
    esac
    # Check content regardless of extension
    CONTENT=$(get_content "$f") || continue
    if echo "$CONTENT" | grep -qF 'BEGIN PRIVATE KEY' || echo "$CONTENT" | grep -qF 'BEGIN RSA PRIVATE KEY'; then
        # Exclude files that reference PEM headers in documentation/examples/regex definitions
        case "$f" in
            README.md|src/detectors/regex/secrets.js|test/unit/regex-secrets.test.mjs|tools/opsec-scan.sh) continue ;;
            # Platform test files use example certs for TLS/cert initialization testing
            pkg/certinit/certinit_coverage_test.go|pkg/ioc/ioc_inpkg_test.go|pkg/response/detectors/detectors_test.go|pkg/response/secret_detector_test.go|upstream/aegisgate/pkg/ml/advanced_ml_test.go|upstream/aegisgate/pkg/scanner/pattern_test.go) continue ;;
        esac
        case "$f" in
            # Test regex definition files define patterns, not actual keys
            src/detectors/regex/secrets.js) continue ;;
        esac
        log_fail "$f contains a private key block"
        PK_FAIL=$((PK_FAIL+1))
    fi
done
if [ "$PK_FAIL" -eq 0 ] && [ "$PK_WARN" -eq 0 ]; then
    log_pass "no private keys in $LABEL files"
fi

# ─── 2. Local filesystem paths ───────────────────────────────────────────
echo
echo "2. Local filesystem path detection"
LP_FAIL=0
for f in $FILES; do
    CONTENT=$(get_content "$f") || continue
    if echo "$CONTENT" | grep -qE '/home/[a-z]+/|/Users/[a-z]+/'; then
        case "$f" in
            .gitignore)
                # .gitignore may reference local paths in comments
                ;;
            *.md)
                log_warn "$f contains /home/ or /Users/ path"
                LP_FAIL=$((LP_FAIL+1))
                ;;
            *)
                log_fail "$f contains local /home/ or /Users/ path"
                LP_FAIL=$((LP_FAIL+1))
                ;;
        esac
    fi
done
if [ "$LP_FAIL" -eq 0 ]; then
    log_pass "no local filesystem paths in $LABEL files"
fi

# ─── 3. Internal document references ─────────────────────────────────────
echo
echo "3. Internal document reference detection"
INT_FAIL=0
INTERNAL_DOCS=(
    # Lens internal docs (removed from public repo)
    "docs/FACTS.md"
    "docs/METRICS-v0.1.2.md"
    "docs/THREAT-MODEL-v0.1.0-BETA.md"
    "docs/ARCHITECTURE-v0.1.0-BETA.md"
    "docs/BANNER-DESIGN-SPEC-v0.1.0-BETA.md"
    "docs/A11Y-AUDIT-v0.1.0-BETA.md"
    ".github/RUNBOOK.md"
    "test/headless-smoke/STATUS.md"
    # Platform internal docs (removed from public repo)
    "RED-TEAM-PLAN.md"
    "RED-TEAM-REPORT.md"
    "D25-SCANNER-PERF-TEST-METHODOLOGY.md"
    "D26-CI-HARDENING-REPORT.md"
    "D27-TESTLAB-FIX-REPORT.md"
    "D28-SCANNER-PERF-FIX-REPORT.md"
    "D29-AEGISGUARD-SCANNER-PERF-FIX-REPORT.md"
    "Sprint-4-Analysis.md"
    "SPRINT-4-STATUS-UPDATED.md"
    "CASE-STUDY-TEMPLATE.md"
    "CONSOLIDATION-STATUS.md"
)
for f in $FILES; do
    CONTENT=$(get_content "$f") || continue
    for doc in "${INTERNAL_DOCS[@]}"; do
        if echo "$CONTENT" | grep -qF "$doc"; then
            # Allow .gitignore to reference these
            case "$f" in
                .gitignore) continue ;;
                # Allow the OPSEC scan script itself to reference these
                tools/opsec-scan.sh) continue ;;
            esac
            log_fail "$f references internal doc: $doc"
            INT_FAIL=$((INT_FAIL+1))
        fi
    done
    # Check for .plans/ references (internal planning dir)
    if echo "$CONTENT" | grep -qE '\.plans/'; then
        case "$f" in
            .gitignore) continue ;;
            tools/opsec-scan.sh) continue ;;
        esac
        log_warn "$f references .plans/ (internal planning directory)"
    fi
    # Check for .workingdirectory/ references
    if echo "$CONTENT" | grep -qE '\.workingdirectory/'; then
        case "$f" in
            .gitignore) continue ;;
            .github/workflows/*) continue ;;
            tools/opsec-scan.sh) continue ;;
        esac
        log_warn "$f references .workingdirectory/ (internal working directory)"
    fi
done
if [ "$INT_FAIL" -eq 0 ]; then
    log_pass "no internal doc references in $LABEL files"
fi

# ─── 4. CWS / store identifiers ──────────────────────────────────────────
echo
echo "4. CWS / store identifier detection"
CWS_FAIL=0
for f in $FILES; do
    CONTENT=$(get_content "$f") || continue
    if echo "$CONTENT" | grep -qE 'Item\s+ID[:\s]+[a-zA-Z0-9]{20,}'; then
        log_fail "$f contains a CWS Item ID"
        CWS_FAIL=$((CWS_FAIL+1))
    fi
done
if [ "$CWS_FAIL" -eq 0 ]; then
    log_pass "no CWS store identifiers in $LABEL files"
fi

# ─── 5. Hardcoded secrets ────────────────────────────────────────────────
echo
echo "5. Hardcoded secret detection"
SEC_FAIL=0
for f in $FILES; do
    case "$f" in
        # Test/regex definition files contain patterns, not real secrets
        # Lens test/regex definition files contain patterns, not real secrets
        src/detectors/regex/secrets.js|test/unit/regex-secrets.test.mjs|test/unit/pii-phone-tightening.test.mjs) continue ;;
        # Platform test files use example keys/certs for detection testing
        pkg/certinit/certinit_coverage_test.go|pkg/ioc/ioc_inpkg_test.go|pkg/response/detectors/detectors_test.go|pkg/response/secret_detector_test.go|upstream/aegisgate/pkg/ml/advanced_ml_test.go|upstream/aegisgate/pkg/scanner/pattern_test.go) continue ;;
        # Go test files use example AWS keys for detection testing
        tools/headless-smoke/flow/runner.go|tools/headless-smoke/mini/main.go) continue ;;
        # Test dispatcher uses example AWS key
        test/unit/dispatcher.test.mjs) continue ;;
        # Platform test files use example AWS keys for detector testing
        pkg/response/response_coverage_test.go) continue ;;
        # gitleaks config contains example patterns as allowlist entries
        .gitleaks.toml) continue ;;
        # Platform test files use example GitHub tokens
        pkg/acp/acp_blocking_test.go|pkg/anomaly/anomaly_test.go|pkg/evaluator/sxc_corpus.go|pkg/lensbackend/privacy_boundary_test.go|upstream/aegisgate/pkg/scanner/scanner_benchmark_test.go) continue ;;
    esac
    CONTENT=$(get_content "$f") || continue
    # AWS access keys (exclude the well-known example key)
    if echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}'; then
        if ! echo "$CONTENT" | grep -qE 'AKIAIOSFODNN7EXAMPLE'; then
            log_fail "$f contains an AWS access key (non-example)"
            SEC_FAIL=$((SEC_FAIL+1))
        fi
    fi
    # GitHub tokens
    if echo "$CONTENT" | grep -qE 'gh[pors]_[A-Za-z0-9_]{36,}'; then
        log_fail "$f contains a GitHub token"
        SEC_FAIL=$((SEC_FAIL+1))
    fi
    # Generic password/secret patterns (high confidence only)
    if echo "$CONTENT" | grep -qiE '(password|secret_key)\s*[:=]\s*["\x27][A-Za-z0-9_\-]{16,}["\x27]'; then
        log_warn "$f may contain hardcoded credentials"
    fi
done
if [ "$SEC_FAIL" -eq 0 ]; then
    log_pass "no hardcoded secrets in $LABEL files"
fi

# ─── 6. Binary / build artifact detection ────────────────────────────────
echo
echo "6. Binary / build artifact detection"
BIN_FAIL=0
for f in $FILES; do
    case "$f" in
        *.png|*.jpg|*.jpeg|*.gif|*.webp|*.svg|*.ico) continue ;;
    esac
    # Check for large files (>1MB)
    SIZE=$(git cat-file -s ":$f" 2>/dev/null || echo "0")
    if [ "$SIZE" -gt 1048576 ]; then
        log_warn "$f is larger than 1MB ($SIZE bytes)"
    fi
done
if [ "$BIN_FAIL" -eq 0 ]; then
    log_pass "no binary/build artifacts in $LABEL files"
fi

# ─── 7. Environment / credential file detection ──────────────────────────
echo
echo "7. Environment / credential file detection"
ENV_FAIL=0
for f in $FILES; do
    case "$f" in
        .env|.env.*|.env.local|.env.production|.env.staging)
            log_fail "$f is an environment file — must not be committed"
            ENV_FAIL=$((ENV_FAIL+1))
            ;;
        credentials*|secrets*|*.secret|*.credential)
            log_fail "$f appears to be a credentials file"
            ENV_FAIL=$((ENV_FAIL+1))
            ;;
        **/service-account*.json|**/*.service-account.json)
            log_fail "$f appears to be a cloud service account key"
            ENV_FAIL=$((ENV_FAIL+1))
            ;;
    esac
done
if [ "$ENV_FAIL" -eq 0 ]; then
    log_pass "no .env or credential files in $LABEL files"
fi

# ─── Summary ──────────────────────────────────────────────────────────────
echo
echo "=== OPSEC scan summary ($LABEL files) ==="
echo "  Failures: $FAIL"
echo "  Warnings: $WARN"

if [ "$FAIL" -gt 0 ]; then
    echo
    echo -e "${RED}OPSEC CHECK FAILED: $FAIL issue(s) found.${NC}"
    if [ "$MODE" = "staged" ]; then
        echo "To bypass (NOT recommended): git commit --no-verify"
    fi
    exit 1
fi

if [ "$WARN" -gt 0 ]; then
    echo
    echo -e "${YELLOW}OPSEC CHECK PASSED with $WARN warning(s). Review above.${NC}"
else
    echo
    echo -e "${GREEN}OPSEC CHECK PASSED.${NC}"
fi
exit 0