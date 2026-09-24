#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# AegisGate Platform — Triple Detection Parity Checker
#
# Compares scanner pattern names across Platform, Lens, and Rampart repos.
# Fails (exit 1) if any pattern exists in Platform but not in Lens or Rampart.
#
# Usage:
#   ./scripts/check-detection-parity.sh
#
# Requires: All three repos cloned as siblings under AegisGate/ directory.
#   - aegisgate-platform (or consolidated/aegisgate-platform)
#   - aegisgate-lens
#   - aegisgate-rampart
#
# Can also be run in CI with individual checkouts — see detection-parity.yml

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Find repo paths
PLATFORM_DIR="${PLATFORM_DIR:-}"
LENS_DIR="${LENS_DIR:-}"
RAMPART_DIR="${RAMPART_DIR:-}"

# Auto-detect paths if not set
if [[ -z "$PLATFORM_DIR" ]]; then
    # Try common locations
    for candidate in \
        "$(dirname "$0")/../../aegisgate-platform" \
        "$(dirname "$0")/../" \
        "$(dirname "$0")/../../consolidated/aegisgate-platform"; do
        if [[ -f "$candidate/pkg/scanner/patterns.go" ]]; then
            PLATFORM_DIR="$candidate"
            break
        fi
    done
fi

if [[ -z "$LENS_DIR" ]]; then
    for candidate in \
        "$(dirname "$0")/../../aegisgate-lens" \
        "$(dirname "$0")/../../../aegisgate-lens"; do
        if [[ -f "$candidate/src/detectors/regex/compliance.js" ]]; then
            LENS_DIR="$candidate"
            break
        fi
    done
fi

if [[ -z "$RAMPART_DIR" ]]; then
    for candidate in \
        "$(dirname "$0")/../../aegisgate-rampart" \
        "$(dirname "$0")/../../../aegisgate-rampart"; do
        if [[ -f "$candidate/internal/detectors/compliance.go" ]]; then
            RAMPART_DIR="$candidate"
            break
        fi
    done
fi

echo "============================================"
echo "  Triple Detection Parity Checker"
echo "============================================"
echo ""
echo "Platform: ${PLATFORM_DIR:-NOT FOUND}"
echo "Lens:     ${LENS_DIR:-NOT FOUND}"
echo "Rampart:  ${RAMPART_DIR:-NOT FOUND}"
echo ""

# Verify paths exist
if [[ -z "$PLATFORM_DIR" || ! -f "$PLATFORM_DIR/pkg/scanner/patterns.go" ]]; then
    echo -e "${RED}ERROR: Platform patterns.go not found${NC}"
    echo "Set PLATFORM_DIR environment variable"
    exit 1
fi

if [[ -z "$LENS_DIR" || ! -f "$LENS_DIR/src/detectors/regex/compliance.js" ]]; then
    echo -e "${RED}ERROR: Lens compliance.js not found${NC}"
    echo "Set LENS_DIR environment variable"
    exit 1
fi

if [[ -z "$RAMPART_DIR" || ! -f "$RAMPART_DIR/internal/detectors/compliance.go" ]]; then
    echo -e "${RED}ERROR: Rampart compliance.go not found${NC}"
    echo "Set RAMPART_DIR environment variable"
    exit 1
fi

# Extract pattern names from each product
# Compare the SHARED detection layer across all three products.
#
# Naming conventions differ:
#   - Platform uses CamelCase for prompt injection patterns: PromptInjectionSSTI
#   - Lens/Rampart use snake_case: prompt_injection_ssti
#   - Compliance patterns (owasp_llm*, atlas_*, etc.) are already snake_case everywhere
#
# We normalize CamelCase PromptInjection names to snake_case so they can be
# compared across products. Platform-only patterns (PII, secrets, OT, harmful_*,
# xss_*, credit cards, connection strings) are excluded — they don't belong in
# Lens (browser extension) or Rampart (API gateway).
#
# Shared layer: owasp_llm*, atlas_*, eu_ai_act*, anp_*, cu_*, toxicity_*,
# nist_csf*, iso_27001*, ccpa*, lgpd*, pipeda*, popia*, mitre_atlas*,
# PromptInjection* (normalized to prompt_injection_*)

# Normalize CamelCase to snake_case (e.g., PromptInjectionSSTI → prompt_injection_ssti)
normalize_name() {
    echo "$1" | sed -E 's/([a-z0-9])([A-Z])/\1_\2/g' | tr '[:upper:]' '[:lower:]'
}

# Platform: extract all names, filter to shared patterns, normalize CamelCase
ALL_PLATFORM=$(grep -oP '\{Name:\s*"\K[^"]+' "$PLATFORM_DIR/pkg/scanner/patterns.go")

# Platform-only PromptInjection patterns (Lens uses ML/heuristics for these, not regex)
# Only prompt_injection_ssti and prompt_injection_eval_atob are shared across all products.
# If a new PromptInjection pattern is shared, it will appear in Lens/Rampart and pass parity.
# If it's Platform-only, add it here to suppress the false alarm.
# MAINTAINERS: When adding a new shared PromptInjection pattern, ensure it's added
# to Lens compliance.js and Rampart compliance.go. If it's Platform-only, add it here.
PLATFORM_ONLY_PATTERNS="prompt_injection_base64 prompt_injection_code_execution prompt_injection_command prompt_injection_delimiter prompt_injection_leakage prompt_injection_prefix prompt_injection_role_play prompt_injection_unicode prompt_injection_sstiprobe"

is_platform_only() {
    local name="$1"
    for p in $PLATFORM_ONLY_PATTERNS; do
        if [[ "$name" == "$p" ]]; then
            return 0
        fi
    done
    return 1
}

# Build normalized platform pattern list
PLATFORM_PATTERNS=""
while IFS= read -r name; do
    # Include compliance patterns (already snake_case)
    if echo "$name" | grep -qE '^(owasp_llm|atlas_|eu_ai_act|anp_|cu_|toxicity|nist_csf|iso_27001|ccpa|lgpd|pipeda|popia|mitre_atlas)'; then
        PLATFORM_PATTERNS="$PLATFORM_PATTERNS$name"$'\n'
    elif echo "$name" | grep -qE '^PromptInjection'; then
        normalized=$(normalize_name "$name")
        # Skip Platform-only patterns
        if ! is_platform_only "$normalized"; then
            PLATFORM_PATTERNS="$PLATFORM_PATTERNS$normalized"$'\n'
        fi
    fi
done <<< "$ALL_PLATFORM"
PLATFORM_PATTERNS=$(echo "$PLATFORM_PATTERNS" | grep -v '^$' | sort -u)

# Lens: all pattern keys from compliance.js (all are shared compliance patterns)
LENS_PATTERNS=$(grep -oP '^\s{4}\K[a-z_][a-z0-9_]*(?=\s*:\s*\{)' "$LENS_DIR/src/detectors/regex/compliance.js" | sort -u)

# Rampart: all pattern names from compliance.go (all are shared compliance patterns)
RAMPART_PATTERNS=$(grep -oP 'Name:\s*"\K[^"]+' "$RAMPART_DIR/internal/detectors/compliance.go" | sort -u)

PLATFORM_COUNT=$(echo "$PLATFORM_PATTERNS" | wc -l)
LENS_COUNT=$(echo "$LENS_PATTERNS" | wc -l)
RAMPART_COUNT=$(echo "$RAMPART_PATTERNS" | wc -l)

echo "Pattern counts:"
echo "  Platform: $PLATFORM_COUNT"
echo "  Lens:     $LENS_COUNT"
echo "  Rampart:  $RAMPART_COUNT"
echo ""

# Save to temp files for comparison
PLATFORM_TMP=$(mktemp)
LENS_TMP=$(mktemp)
RAMPART_TMP=$(mktemp)
echo "$PLATFORM_PATTERNS" > "$PLATFORM_TMP"
echo "$LENS_PATTERNS" > "$LENS_TMP"
echo "$RAMPART_PATTERNS" > "$RAMPART_TMP"

# Check for patterns in Platform that are missing from Lens or Rampart
EXIT_CODE=0
PATTERN_FAIL=0

# Platform → Lens missing
PLATFORM_LENS_MISSING=$(comm -23 "$PLATFORM_TMP" "$LENS_TMP")
if [[ -n "$PLATFORM_LENS_MISSING" ]]; then
    MISSING_COUNT=$(echo "$PLATFORM_LENS_MISSING" | wc -l)
    echo -e "${RED}MISSING from Lens ($MISSING_COUNT patterns):${NC}"
    echo "$PLATFORM_LENS_MISSING" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
    PATTERN_FAIL=1
fi

# Platform → Rampart missing
PLATFORM_RAMPART_MISSING=$(comm -23 "$PLATFORM_TMP" "$RAMPART_TMP")
if [[ -n "$PLATFORM_RAMPART_MISSING" ]]; then
    MISSING_COUNT=$(echo "$PLATFORM_RAMPART_MISSING" | wc -l)
    echo -e "${RED}MISSING from Rampart ($MISSING_COUNT patterns):${NC}"
    echo "$PLATFORM_RAMPART_MISSING" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
    PATTERN_FAIL=1
fi

# Lens → Rampart missing (informational)
LENS_RAMPART_MISSING=$(comm -23 "$LENS_TMP" "$RAMPART_TMP")
if [[ -n "$LENS_RAMPART_MISSING" ]]; then
    MISSING_COUNT=$(echo "$LENS_RAMPART_MISSING" | wc -l)
    echo -e "${YELLOW}In Lens but not Rampart ($MISSING_COUNT patterns):${NC}"
    echo "$LENS_RAMPART_MISSING" | sed 's/^/  - /'
    echo ""
fi

# Rampart → Lens missing (informational)
RAMPART_LENS_MISSING=$(comm -23 "$RAMPART_TMP" "$LENS_TMP")
if [[ -n "$RAMPART_LENS_MISSING" ]]; then
    MISSING_COUNT=$(echo "$RAMPART_LENS_MISSING" | wc -l)
    echo -e "${YELLOW}In Rampart but not Lens ($MISSING_COUNT patterns):${NC}"
    echo "$RAMPART_LENS_MISSING" | sed 's/^/  - /'
    echo ""
fi

# Cleanup
rm -f "$PLATFORM_TMP" "$LENS_TMP" "$RAMPART_TMP"

# ---------------------------------------------------------------------------
# Phase 2: Regex content comparison for shared patterns
# Verifies that patterns with matching names also have matching regex content
# across Platform, Lens, and Rampart. Detects silent divergence where the same
# pattern name has different regex strings in different products.
# ---------------------------------------------------------------------------

echo ""
echo "=== Regex Content Comparison ==="

# Extract regex for a given pattern name from Platform (Go regexp.MustCompile)
extract_platform_regex() {
    local name="$1"
    # Pattern: {Name: "NAME", ...Regex: regexp.MustCompile(`CONTENT`)
    # Use perl to capture the backtick-delimited string after MustCompile
    grep -oP "\{Name:\s*\"${name}\".*?Regex:\s*regexp\.MustCompile\(\x60\K[^\x60]*" \
        "$PLATFORM_DIR/pkg/scanner/patterns.go" 2>/dev/null | head -1
}

# Extract regex for a given pattern name from Rampart (Go raw string)
extract_rampart_regex() {
    local name="$1"
    # Pattern: Name: "NAME", ... Regex: `CONTENT`
    grep -oP "Name:\s*\"${name}\".*?Regex:\s*\x60\K[^\x60]*" \
        "$RAMPART_DIR/internal/detectors/compliance.go" 2>/dev/null | head -1
}

# Extract regex for a given pattern name from Lens (JS regex literal)
extract_lens_regex() {
    local name="$1"
    # Pattern: name: { ... re: /CONTENT/gi
    # Capture content between the / delimiters
    local line
    line=$(grep -A5 "^\s*${name}:\s*{" "$LENS_DIR/src/detectors/regex/compliance.js" 2>/dev/null | \
           grep -oP "re:\s*/\K[^/]*(?=/[gimsuy]*)")
    echo "$line" | head -1
}

# Normalize a regex string for comparison:
# - Remove (?i) inline flag (Lens uses /i flag instead)
# - Trim leading/trailing whitespace
normalize_regex() {
    echo "$1" | sed 's/(?i)//g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

CONTENT_MISMATCHES=0

# Only check patterns that exist in all three products
SHARED_PATTERNS=$(comm -12 "$PLATFORM_TMP" <(echo "$LENS_PATTERNS") 2>/dev/null || true)
SHARED_PATTERNS=$(comm -12 <(echo "$SHARED_PATTERNS") <(echo "$RAMPART_PATTERNS") 2>/dev/null || true)

# Rebuild temp files since they were deleted
echo "$PLATFORM_PATTERNS" > "$PLATFORM_TMP"
echo "$LENS_PATTERNS" > "$LENS_TMP"
echo "$RAMPART_PATTERNS" > "$RAMPART_TMP"
SHARED_PATTERNS=$(comm -12 "$PLATFORM_TMP" "$LENS_TMP" | comm -12 - "$RAMPART_TMP")

if [[ -z "$SHARED_PATTERNS" ]]; then
    echo "No shared patterns found across all three products — skipping content check."
else
    SHARED_COUNT=$(echo "$SHARED_PATTERNS" | wc -l)
    echo "Checking $SHARED_COUNT shared patterns..."

    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue

        # Get normalized regex from each product
        p_re=$(normalize_regex "$(extract_platform_regex "$pattern")")
        l_re=$(normalize_regex "$(extract_lens_regex "$pattern")")
        r_re=$(normalize_regex "$(extract_rampart_regex "$pattern")")

        mismatches=""

        # Compare Platform vs Lens
        if [[ "$p_re" != "$l_re" && -n "$p_re" && -n "$l_re" ]]; then
            mismatches="$mismatches Platform≠Lens"
        fi

        # Compare Platform vs Rampart
        if [[ "$p_re" != "$r_re" && -n "$p_re" && -n "$r_re" ]]; then
            mismatches="$mismatches Platform≠Rampart"
        fi

        # Compare Lens vs Rampart
        if [[ "$l_re" != "$r_re" && -n "$l_re" && -n "$r_re" ]]; then
            mismatches="$mismatches Lens≠Rampart"
        fi

        if [[ -n "$mismatches" ]]; then
            echo -e "  ${YELLOW}⚠ $pattern:$mismatches${NC}"
            CONTENT_MISMATCHES=$((CONTENT_MISMATCHES + 1))
        fi
    done <<< "$SHARED_PATTERNS"

    if [[ $CONTENT_MISMATCHES -eq 0 ]]; then
        echo -e "  ${GREEN}All $SHARED_COUNT shared patterns have matching regex content${NC}"
    else
        echo ""
        echo -e "  ${YELLOW}$CONTENT_MISMATCHES pattern(s) have regex content divergence${NC}"
        echo "  This does not fail the check but indicates the regex strings differ."
        echo "  Review the patterns to ensure the differences are intentional."
        # Content mismatches are warnings, not failures — different products
        # may intentionally have slightly different regex (e.g., Go vs JS
        # regex syntax differences). The name parity check is the hard gate.
    fi
fi

# Final cleanup
rm -f "$PLATFORM_TMP" "$LENS_TMP" "$RAMPART_TMP"

if [[ $EXIT_CODE -eq 0 ]]; then
    echo ""
    echo -e "${GREEN}✅ Detection parity verified — all products have matching pattern sets${NC}"
else
    echo ""
    echo -e "${RED}❌ Detection parity check FAILED — patterns missing from one or more products${NC}"
    echo ""
    echo "To fix: add missing patterns to the product(s) above and commit."
fi

# ---------------------------------------------------------------------------
# Phase 3: Model Hash Alignment
# Verifies all three products expect the same ONNX/JS model hash.
# Drift here means one product silently rejects the model (as happened
# with Platform's v11b→v13 hash mismatch).
# ---------------------------------------------------------------------------
echo ""
echo "=== Model Hash Alignment ==="

# Platform: ExpectedModelHash in pkg/ml/detector.go
PLATFORM_HASH=$(grep -oP 'ExpectedModelHash\s*=\s*"\K[^"]+' "$PLATFORM_DIR/pkg/ml/detector.go" 2>/dev/null | head -1)
# Rampart: ExpectedModelHash in internal/ml/detector.go
RAMPART_HASH=$(grep -oP 'ExpectedModelHash\s*=\s*"\K[^"]+' "$RAMPART_DIR/internal/ml/detector.go" 2>/dev/null | head -1)
# Lens: hash in threat-detector-js.js (EXPECTED_HASH or similar)
LENS_HASH=$(grep -oP "(?:EXPECTED_HASH|expectedHash|MODEL_HASH)\s*[:=]\s*['\"]\K[a-f0-9]{64}" "$LENS_DIR/src/detectors/ml/threat-detector-js.js" 2>/dev/null | head -1)

echo "  Platform: ${PLATFORM_HASH:-NOT FOUND}"
echo "  Rampart:  ${RAMPART_HASH:-NOT FOUND}"
echo "  Lens:     ${LENS_HASH:-NOT FOUND}"

HASH_MISMATCH=0
if [[ -n "$PLATFORM_HASH" && -n "$RAMPART_HASH" && "$PLATFORM_HASH" != "$RAMPART_HASH" ]]; then
    echo -e "  ${RED}❌ Platform ≠ Rampart model hash mismatch${NC}"
    HASH_MISMATCH=1
    EXIT_CODE=1
fi
if [[ -n "$PLATFORM_HASH" && -n "$LENS_HASH" && "$PLATFORM_HASH" != "$LENS_HASH" ]]; then
    echo -e "  ${YELLOW}⚠ Platform ≠ Lens model hash (expected: different architectures — ONNX vs pure JS)${NC}"
    # Lens uses pure JS inference with different weight format — hash will differ.
    # This is informational, not a failure.
fi
if [[ -n "$RAMPART_HASH" && -n "$LENS_HASH" && "$RAMPART_HASH" != "$LENS_HASH" ]]; then
    echo -e "  ${YELLOW}⚠ Rampart ≠ Lens model hash (expected: different architectures — ONNX vs pure JS)${NC}"
fi

if [[ $HASH_MISMATCH -eq 0 && -n "$PLATFORM_HASH" && -n "$RAMPART_HASH" ]]; then
    echo -e "  ${GREEN}✅ Platform and Rampart use the same model hash${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 4: Evasion Suite Payload Count
# Verifies all three products' evasion tests use the same number of payloads.
# Drift here means scores aren't comparable (apples-to-oranges).
# ---------------------------------------------------------------------------
echo ""
echo "=== Evasion Suite Payload Count ==="

# Platform: count entries in atlasPayloads struct
PLATFORM_PAYLOADS=$(grep -cP '\{"(T\d+\.\d+|V450\.[A-Z0-9]+\.\d+)"' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null || echo "0")
# Rampart: count entries in atlasPayloads struct
RAMPART_PAYLOADS=$(grep -cP '\{"(T\d+\.\d+|V450\.[A-Z0-9]+\.\d+)"' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null || echo "0")
# Lens: count entries in ATLAS_PAYLOADS array
LENS_PAYLOADS=$(grep -cP "id:\s*['\"]([A-Z0-9.]+\.\d+)['\"]" "$LENS_DIR/test/unit/ml-evasion-suite.test.mjs" 2>/dev/null || echo "0")

echo "  Platform: $PLATFORM_PAYLOADS payloads"
echo "  Rampart:  $RAMPART_PAYLOADS payloads"
echo "  Lens:     $LENS_PAYLOADS payloads"

if [[ "$PLATFORM_PAYLOADS" != "$RAMPART_PAYLOADS" || "$PLATFORM_PAYLOADS" != "$LENS_PAYLOADS" ]]; then
    echo -e "  ${RED}❌ Payload count mismatch — scores are NOT comparable${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ All products use $PLATFORM_PAYLOADS payloads${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 5: Transform Count
# Verifies all three products' evasion tests define 50 transforms (10 per 5 categories).
# ---------------------------------------------------------------------------
echo ""
echo "=== Transform Count ==="

# Platform: count variant keys in each category map
PLATFORM_TRANSFORMS=$(grep -oP '"[a-z_]+":\s+\w+,' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null | grep -v '^\s*"category"' | wc -l || echo "0")
# Rampart: same approach
RAMPART_TRANSFORMS=$(grep -oP '"[a-z_]+":\s+\w+,' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null | grep -v '^\s*"category"' | wc -l || echo "0")
# Lens: count transform function entries (key: (s) => ...)
LENS_TRANSFORMS=$(grep -cP '^\s+\w+:\s*\(s\)\s*=>' "$LENS_DIR/test/unit/ml-evasion-suite.test.mjs" 2>/dev/null || echo "0")

echo "  Platform: $PLATFORM_TRANSFORMS transform keys"
echo "  Rampart:  $RAMPART_TRANSFORMS transform keys"
echo "  Lens:     $LENS_TRANSFORMS transform keys"

# Note: Platform/Rampart counts may include non-transform map entries.
# The expected count is 50 (10 per category × 5 categories).
# Lens counts arrow functions which should be exactly 50.
EXPECTED_TRANSFORMS=50
if [[ "$LENS_TRANSFORMS" -ne "$EXPECTED_TRANSFORMS" ]]; then
    echo -e "  ${YELLOW}⚠ Lens has $LENS_TRANSFORMS transforms (expected $EXPECTED_TRANSFORMS)${NC}"
fi
if [[ "$PLATFORM_TRANSFORMS" -ne "$EXPECTED_TRANSFORMS" ]]; then
    echo -e "  ${YELLOW}⚠ Platform has $PLATFORM_TRANSFORMS transform keys (expected $EXPECTED_TRANSFORMS — may include extra map entries)${NC}"
fi
if [[ "$RAMPART_TRANSFORMS" -ne "$EXPECTED_TRANSFORMS" ]]; then
    echo -e "  ${YELLOW}⚠ Rampart has $RAMPART_TRANSFORMS transform keys (expected $EXPECTED_TRANSFORMS — may include extra map entries)${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 6: ML Threshold Alignment
# Verifies all three products use the same ML detection threshold (0.5).
# Drift here means one product is more/less sensitive than the others.
# ---------------------------------------------------------------------------
echo ""
echo "=== ML Threshold Alignment ==="

# Platform: Threshold in evasion test newEvasionDetector
PLATFORM_THRESH=$(grep -oP 'Threshold\s*[:=]\s*\K[0-9.]+' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null | head -1)
# Rampart: Threshold in evasion test newEvasionDetector
RAMPART_THRESH=$(grep -oP 'Threshold\s*[:=]\s*\K[0-9.]+' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null | head -1)
# Lens: THRESHOLD in threat-detector-js.js
LENS_THRESH=$(grep -oP 'THRESHOLD\s*=\s*\K[0-9.]+' "$LENS_DIR/src/detectors/ml/threat-detector-js.js" 2>/dev/null | head -1)

echo "  Platform evasion test: $PLATFORM_THRESH"
echo "  Rampart evasion test:  $RAMPART_THRESH"
echo "  Lens ML model:         $LENS_THRESH"

# Compare numerically (0.50 == 0.5)
THRESH_MISMATCH=0
for pair in "Platform:Rampart:$PLATFORM_THRESH:$RAMPART_THRESH" "Platform:Lens:$PLATFORM_THRESH:$LENS_THRESH" "Rampart:Lens:$RAMPART_THRESH:$LENS_THRESH"; do
    IFS=: read -r name1 name2 val1 val2 <<< "$pair"
    if [[ -n "$val1" && -n "$val2" ]]; then
        # Use awk for numeric comparison (0.50 == 0.5)
        if ! awk -v a="$val1" -v b="$val2" 'BEGIN { exit (a == b) ? 0 : 1 }'; then
            echo -e "  ${RED}❌ $name1 ($val1) ≠ $name2 ($val2) threshold mismatch${NC}"
            THRESH_MISMATCH=1
            EXIT_CODE=1
        fi
    fi
done

if [[ $THRESH_MISMATCH -eq 0 && -n "$PLATFORM_THRESH" && -n "$RAMPART_THRESH" && -n "$LENS_THRESH" ]]; then
    echo -e "  ${GREEN}✅ All products use threshold $PLATFORM_THRESH${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 7: Evasion Test Detection Logic Check
# Verifies that each product's evasion test uses (regexHit || mlHit) logic,
# not ML-only. This catches the bug where Lens's test was ML-only.
# ---------------------------------------------------------------------------
echo ""
echo "=== Evasion Test Detection Logic ==="

# Check if Lens evasion test uses regex detection (regexDetect or similar)
LENS_HAS_REGEX=$(grep -c 'regexDetect\|regexHit\|regex.*detect\|facet.*detect' "$LENS_DIR/test/unit/ml-evasion-suite.test.mjs" 2>/dev/null || echo "0")
if [[ "$LENS_HAS_REGEX" -eq 0 ]]; then
    echo -e "  ${RED}❌ Lens evasion test does NOT use regex detection (ML-only)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ Lens evasion test uses regex + ML detection${NC}"
fi

# Check if Platform evasion test uses scanner/ATLAS detection
PLATFORM_HAS_REGEX=$(grep -c 'scannerHit\|atlasHit\|scanner.*Scan\|atlas.*Check' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null || echo "0")
if [[ "$PLATFORM_HAS_REGEX" -eq 0 ]]; then
    echo -e "  ${RED}❌ Platform evasion test does NOT use regex/ATLAS detection (ML-only?)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ Platform evasion test uses scanner + ATLAS + ML detection${NC}"
fi

# Check if Rampart evasion test uses regex detection
RAMPART_HAS_REGEX=$(grep -c 'detectorHit\|DetectAll\|detect.*regex' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null || echo "0")
if [[ "$RAMPART_HAS_REGEX" -eq 0 ]]; then
    echo -e "  ${RED}❌ Rampart evasion test does NOT use regex detection (ML-only?)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ Rampart evasion test uses regex + ML detection${NC}"
fi

# ---------------------------------------------------------------------------
# Final Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "  Parity Check Summary"
echo "============================================"
echo "  Pattern names:     $([ $PATTERN_FAIL -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Regex content:     $([ $CONTENT_MISMATCHES -eq 0 ] && echo 'PASS' || echo "WARN ($CONTENT_MISMATCHES)")"
echo "  Model hash:        $([ $HASH_MISMATCH -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Payload count:     $(([[ "$PLATFORM_PAYLOADS" == "$RAMPART_PAYLOADS" && "$PLATFORM_PAYLOADS" == "$LENS_PAYLOADS" ]]) && echo 'PASS' || echo 'FAIL')"
echo "  Transform count:   $(([[ "$LENS_TRANSFORMS" -eq 50 ]]) && echo 'PASS' || echo 'WARN')"
echo "  ML threshold:      $([ $THRESH_MISMATCH -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Detection logic:   $(([[ "$LENS_HAS_REGEX" -gt 0 && "$PLATFORM_HAS_REGEX" -gt 0 && "$RAMPART_HAS_REGEX" -gt 0 ]]) && echo 'PASS' || echo 'FAIL')"
echo "============================================"

exit $EXIT_CODE