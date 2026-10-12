#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# AegisGate Platform — Detection Parity Checker
#
# Compares detection patterns across Platform, Lens, Rampart, and Scanner repos.
#
# Parity model:
#   Platform ↔ Rampart: FULL parity — ALL pattern names AND regex content must match.
#   Scanner ↔ Rampart: SUPERSET parity — ALL Rampart patterns must be present in Scanner.
#                       Scanner may have extra patterns (dangerous functions, URL/base64 detection).
#                       Regex content for matching patterns must be identical (copy integrity check).
#   Lens: Compliance-only parity — Lens patterns must be a subset of Platform/Rampart.
#         Regex content is compared with JS↔Go normalization (warnings for syntax diffs).
#
# Usage:
#   ./scripts/check-detection-parity.sh
#
# Requires: Repos cloned as siblings under AegisGate/ directory.
#   - aegisgate-platform (or consolidated/aegisgate-platform)
#   - aegisgate-lens
#   - aegisgate-rampart
#   - aegisgate-scanner (optional — Scanner checks are skipped if not found)

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
SCANNER_DIR="${SCANNER_DIR:-}"

# Auto-detect paths if not set
if [[ -z "$PLATFORM_DIR" ]]; then
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

if [[ -z "$SCANNER_DIR" ]]; then
    for candidate in \
        "$(dirname "$0")/../../aegisgate-scanner" \
        "$(dirname "$0")/../../../aegisgate-scanner"; do
        if [[ -f "$candidate/internal/detectors/compliance.go" ]]; then
            SCANNER_DIR="$candidate"
            break
        fi
    done
fi

echo "============================================"
echo "  Detection Parity Checker"
echo "============================================"
echo ""
echo "Platform: ${PLATFORM_DIR:-NOT FOUND}"
echo "Lens:     ${LENS_DIR:-NOT FOUND}"
echo "Rampart:  ${RAMPART_DIR:-NOT FOUND}"
echo "Scanner:  ${SCANNER_DIR:-NOT FOUND}"
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

# Scanner is optional — warn but don't fail
SCANNER_ENABLED=0
if [[ -z "$SCANNER_DIR" || ! -f "$SCANNER_DIR/internal/detectors/compliance.go" ]]; then
    echo -e "${YELLOW}WARNING: Scanner compliance.go not found. Set SCANNER_DIR environment variable${NC}"
    echo -e "${YELLOW}         Scanner parity checks will be skipped.${NC}"
    echo ""
else
    SCANNER_ENABLED=1
fi

# ===========================================================================
# Phase 1: Pattern Name Parity
# Platform ↔ Rampart: FULL parity (ALL patterns must match)
# Scanner ↔ Rampart: FULL parity (ALL patterns must match — copy integrity)
# Lens: Subset check (all Lens patterns must exist in Platform and Rampart)
# ===========================================================================
echo "=== Phase 1: Pattern Name Parity ==="
echo ""

# Platform: extract ALL pattern names from patterns.go
ALL_PLATFORM=$(grep -oP '\{Name:\s*"\K[^"]+' "$PLATFORM_DIR/pkg/scanner/patterns.go" | sort -u)

# Rampart: extract ALL pattern names from ALL detector .go files (excluding tests)
ALL_RAMPART=""
for rampart_file in "$RAMPART_DIR"/internal/detectors/*.go; do
    [[ "$rampart_file" == *_test.go ]] && continue
    [[ ! -f "$rampart_file" ]] && continue
    names=$(grep -oP 'Name:\s*"\K[^"]+' "$rampart_file" 2>/dev/null || true)
    ALL_RAMPART="$ALL_RAMPART$names"$'\n'
done
ALL_RAMPART=$(echo "$ALL_RAMPART" | grep -v '^$' | sort -u)

# Scanner: extract ALL pattern names from ALL detector .go files (excluding tests)
ALL_SCANNER=""
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    for scanner_file in "$SCANNER_DIR"/internal/detectors/*.go; do
        [[ "$scanner_file" == *_test.go ]] && continue
        [[ ! -f "$scanner_file" ]] && continue
        names=$(grep -oP 'Name:\s*"\K[^"]+' "$scanner_file" 2>/dev/null || true)
        ALL_SCANNER="$ALL_SCANNER$names"$'\n'
    done
    ALL_SCANNER=$(echo "$ALL_SCANNER" | grep -v '^$' | sort -u)
fi

# Lens: extract pattern keys from compliance.js
ALL_LENS=$(grep -oP '^\s{4}\K[a-z_][a-z0-9_]*(?=\s*:\s*\{)' "$LENS_DIR/src/detectors/regex/compliance.js" | sort -u)

PLATFORM_COUNT=$(echo "$ALL_PLATFORM" | wc -l)
RAMPART_COUNT=$(echo "$ALL_RAMPART" | wc -l)
SCANNER_COUNT=0
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    SCANNER_COUNT=$(echo "$ALL_SCANNER" | wc -l)
fi
LENS_COUNT=$(echo "$ALL_LENS" | wc -l)

echo "Pattern counts:"
echo "  Platform: $PLATFORM_COUNT"
echo "  Rampart:  $RAMPART_COUNT"
echo "  Scanner:  ${SCANNER_COUNT}$([[ $SCANNER_ENABLED -eq 0 ]] && echo ' (not found)')"
echo "  Lens:     $LENS_COUNT (compliance only)"
echo ""

# Save to temp files
PLATFORM_TMP=$(mktemp)
RAMPART_TMP=$(mktemp)
LENS_TMP=$(mktemp)
SCANNER_TMP=$(mktemp)
echo "$ALL_PLATFORM" > "$PLATFORM_TMP"
echo "$ALL_RAMPART" > "$RAMPART_TMP"
echo "$ALL_LENS" > "$LENS_TMP"
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    echo "$ALL_SCANNER" > "$SCANNER_TMP"
fi

EXIT_CODE=0
PATTERN_FAIL=0
SCANNER_PATTERN_FAIL=0

# Platform ↔ Rampart: FULL parity (hard gate)
PLATFORM_RAMPART_MISSING=$(comm -23 "$PLATFORM_TMP" "$RAMPART_TMP")
RAMPART_PLATFORM_MISSING=$(comm -13 "$PLATFORM_TMP" "$RAMPART_TMP")

if [[ -n "$PLATFORM_RAMPART_MISSING" ]]; then
    MISSING_COUNT=$(echo "$PLATFORM_RAMPART_MISSING" | wc -l)
    echo -e "${RED}MISSING from Rampart ($MISSING_COUNT patterns):${NC}"
    echo "$PLATFORM_RAMPART_MISSING" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
    PATTERN_FAIL=1
fi

if [[ -n "$RAMPART_PLATFORM_MISSING" ]]; then
    MISSING_COUNT=$(echo "$RAMPART_PLATFORM_MISSING" | wc -l)
    echo -e "${RED}MISSING from Platform ($MISSING_COUNT patterns):${NC}"
    echo "$RAMPART_PLATFORM_MISSING" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
    PATTERN_FAIL=1
fi

if [[ -z "$PLATFORM_RAMPART_MISSING" && -z "$RAMPART_PLATFORM_MISSING" ]]; then
    echo -e "${GREEN}✅ Platform ↔ Rampart: $PLATFORM_COUNT patterns match exactly${NC}"
    echo ""
fi

# Scanner ↔ Rampart: SUPERSET parity — all Rampart patterns must be in Scanner.
# Scanner may have extra patterns (dangerous functions, URL/base64 detection).
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    # comm -23: lines in Scanner only (extra patterns — OK)
    # comm -13: lines in Rampart only (missing from Scanner — FAIL)
    SCANNER_EXTRA=$(comm -23 "$SCANNER_TMP" "$RAMPART_TMP")
    SCANNER_MISSING=$(comm -13 "$SCANNER_TMP" "$RAMPART_TMP")

    if [[ -n "$SCANNER_MISSING" ]]; then
        MISSING_COUNT=$(echo "$SCANNER_MISSING" | wc -l)
        echo -e "${RED}MISSING from Scanner ($MISSING_COUNT Rampart patterns not found):${NC}"
        echo "$SCANNER_MISSING" | sed 's/^/  - /'
        echo ""
        EXIT_CODE=1
        SCANNER_PATTERN_FAIL=1
    fi

    if [[ -n "$SCANNER_EXTRA" ]]; then
        EXTRA_COUNT=$(echo "$SCANNER_EXTRA" | wc -l)
        echo -e "${YELLOW}ℹ Scanner has $EXTRA_COUNT extra patterns (not in Rampart — expected for scanner-specific detection):${NC}"
        echo "$SCANNER_EXTRA" | sed 's/^/  - /'
        echo ""
        # Extra patterns are OK — Scanner is a superset of Rampart.
    fi

    if [[ -z "$SCANNER_MISSING" ]]; then
        if [[ -n "$SCANNER_EXTRA" ]]; then
            EXTRA_COUNT=$(echo "$SCANNER_EXTRA" | wc -l)
            echo -e "${GREEN}✅ Scanner is superset of Rampart: all $RAMPART_COUNT Rampart patterns present + $EXTRA_COUNT scanner-specific patterns${NC}"
        else
            echo -e "${GREEN}✅ Scanner ↔ Rampart: $SCANNER_COUNT patterns match exactly${NC}"
        fi
        echo ""
    fi
fi

# Lens subset check: all Lens patterns must exist in Platform
LENS_NOT_IN_PLATFORM=$(comm -23 "$LENS_TMP" "$PLATFORM_TMP")
if [[ -n "$LENS_NOT_IN_PLATFORM" ]]; then
    MISSING_COUNT=$(echo "$LENS_NOT_IN_PLATFORM" | wc -l)
    echo -e "${RED}In Lens but not Platform ($MISSING_COUNT patterns):${NC}"
    echo "$LENS_NOT_IN_PLATFORM" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
    PATTERN_FAIL=1
fi

# Lens subset check: all Lens patterns must exist in Rampart
LENS_NOT_IN_RAMPART=$(comm -23 "$LENS_TMP" "$RAMPART_TMP")
if [[ -n "$LENS_NOT_IN_RAMPART" ]]; then
    MISSING_COUNT=$(echo "$LENS_NOT_IN_RAMPART" | wc -l)
    echo -e "${RED}In Lens but not Rampart ($MISSING_COUNT patterns):${NC}"
    echo "$LENS_NOT_IN_RAMPART" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
    PATTERN_FAIL=1
fi

if [[ -z "$LENS_NOT_IN_PLATFORM" && -z "$LENS_NOT_IN_RAMPART" ]]; then
    echo -e "${GREEN}✅ Lens patterns are subset of Platform and Rampart${NC}"
    echo ""
fi

# Informational: patterns in Platform/Rampart but not Lens (expected — Lens is compliance-only)
PLATFORM_NOT_IN_LENS=$(comm -23 "$PLATFORM_TMP" "$LENS_TMP")
if [[ -n "$PLATFORM_NOT_IN_LENS" ]]; then
    INFO_COUNT=$(echo "$PLATFORM_NOT_IN_LENS" | wc -l)
    echo -e "${YELLOW}ℹ In Platform/Rampart but not Lens ($INFO_COUNT patterns — expected for non-compliance):${NC}"
    # Show first 10 as sample
    echo "$PLATFORM_NOT_IN_LENS" | head -10 | sed 's/^/  - /'
    if [[ $INFO_COUNT -gt 10 ]]; then
        echo "  ... and $((INFO_COUNT - 10)) more"
    fi
    echo ""
fi

# ===========================================================================
# Phase 2: Regex Content Parity
# Platform ↔ Rampart: ALL patterns — regex must match (HARD gate)
# Scanner ↔ Rampart: ALL patterns — regex must match (HARD gate — copy integrity)
# Lens: Compliance patterns — regex compared with JS↔Go normalization (warning)
# ===========================================================================
echo "=== Phase 2: Regex Content Parity ==="
echo ""

# Extract regex for a given pattern name from Platform (Go regexp.MustCompile)
# Handles both backtick raw strings and string concatenation
extract_platform_regex() {
    local name="$1"
    # Try backtick raw string first: {Name: "NAME", ...Regex: regexp.MustCompile(`CONTENT`)
    local regex
    regex=$(grep -oP "\{Name:\s*\"${name}\".*?Regex:\s*regexp\.MustCompile\(\x60\K[^\x60]*" \
        "$PLATFORM_DIR/pkg/scanner/patterns.go" 2>/dev/null | head -1)
    if [[ -n "$regex" ]]; then
        echo "$regex"
        return
    fi
    # Fallback: string concatenation (e.g., regexp.MustCompile("[" + "\u200b" + ...))
    # This is rare — only for patterns with actual unicode chars in Go string syntax
    # Return a sentinel that won't match — these patterns need manual verification
    echo "__STRING_CONCAT__"
}

# Extract regex for a given pattern name from any Rampart detector file
extract_rampart_regex() {
    local name="$1"
    local regex
    for rampart_file in "$RAMPART_DIR"/internal/detectors/*.go; do
        [[ "$rampart_file" == *_test.go ]] && continue
        [[ ! -f "$rampart_file" ]] && continue
        regex=$(grep -oP "Name:\s*\"${name}\".*?Regex:\s*\x60\K[^\x60]*" \
            "$rampart_file" 2>/dev/null | head -1)
        if [[ -n "$regex" ]]; then
            echo "$regex"
            return
        fi
    done
}

# Extract regex for a given pattern name from any Scanner detector file
extract_scanner_regex() {
    local name="$1"
    local regex
    if [[ $SCANNER_ENABLED -ne 1 ]]; then
        return
    fi
    for scanner_file in "$SCANNER_DIR"/internal/detectors/*.go; do
        [[ "$scanner_file" == *_test.go ]] && continue
        [[ ! -f "$scanner_file" ]] && continue
        regex=$(grep -oP "Name:\s*\"${name}\".*?Regex:\s*\x60\K[^\x60]*" \
            "$scanner_file" 2>/dev/null | head -1)
        if [[ -n "$regex" ]]; then
            echo "$regex"
            return
        fi
    done
}

# Extract regex for a given pattern name from Lens (JS regex literal)
extract_lens_regex() {
    local name="$1"
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

# --- Platform ↔ Rampart regex content check (HARD gate) ---
CONTENT_MISMATCHES=0
CONTENT_TOTAL=0

while IFS= read -r pattern; do
    [[ -z "$pattern" ]] && continue
    CONTENT_TOTAL=$((CONTENT_TOTAL + 1))

    p_re=$(normalize_regex "$(extract_platform_regex "$pattern")")
    r_re=$(normalize_regex "$(extract_rampart_regex "$pattern")")

    if [[ "$p_re" == "__STRING_CONCAT__" ]]; then
        echo -e "  ${YELLOW}⚠ $pattern: Platform uses string concatenation — manual verification needed${NC}"
        continue
    fi

    if [[ "$p_re" != "$r_re" ]]; then
        if [[ -z "$r_re" ]]; then
            # Pattern not found in Rampart (already reported in Phase 1)
            continue
        fi
        echo -e "  ${RED}❌ $pattern: Platform ≠ Rampart${NC}"
        echo "     Platform: ${p_re:0:120}${p_re:120:+...}"
        echo "     Rampart:  ${r_re:0:120}${r_re:120:+...}"
        CONTENT_MISMATCHES=$((CONTENT_MISMATCHES + 1))
    fi
done <<< "$ALL_PLATFORM"

if [[ $CONTENT_MISMATCHES -eq 0 ]]; then
    echo -e "${GREEN}✅ Platform ↔ Rampart: All $CONTENT_TOTAL patterns have matching regex content${NC}"
else
    echo ""
    echo -e "${RED}$CONTENT_MISMATCHES pattern(s) have regex content divergence between Platform and Rampart${NC}"
    EXIT_CODE=1
fi
echo ""

# --- Scanner ↔ Rampart regex content check (HARD gate) — copy integrity ---
SCANNER_REGEX_MISMATCHES=0
SCANNER_REGEX_TOTAL=0

if [[ $SCANNER_ENABLED -eq 1 ]]; then
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        SCANNER_REGEX_TOTAL=$((SCANNER_REGEX_TOTAL + 1))

        s_re=$(normalize_regex "$(extract_scanner_regex "$pattern")")
        r_re=$(normalize_regex "$(extract_rampart_regex "$pattern")")

        if [[ -z "$r_re" ]]; then
            # Pattern not found in Rampart (already reported in Phase 1)
            continue
        fi

        if [[ "$s_re" != "$r_re" ]]; then
            echo -e "  ${RED}❌ $pattern: Scanner ≠ Rampart${NC}"
            echo "     Scanner:  ${s_re:0:120}${s_re:120:+...}"
            echo "     Rampart:  ${r_re:0:120}${r_re:120:+...}"
            SCANNER_REGEX_MISMATCHES=$((SCANNER_REGEX_MISMATCHES + 1))
        fi
    done <<< "$ALL_SCANNER"

    if [[ $SCANNER_REGEX_MISMATCHES -eq 0 ]]; then
        echo -e "${GREEN}✅ Scanner ↔ Rampart: All $SCANNER_REGEX_TOTAL patterns have matching regex content${NC}"
    else
        echo ""
        echo -e "${RED}$SCANNER_REGEX_MISMATCHES pattern(s) have regex content divergence between Scanner and Rampart${NC}"
        EXIT_CODE=1
    fi
fi
echo ""

# --- Lens regex content check (warning — JS vs Go syntax differences) ---
LENS_MISMATCHES=0
LENS_SHARED=$(comm -12 "$PLATFORM_TMP" "$LENS_TMP")

if [[ -n "$LENS_SHARED" ]]; then
    LENS_SHARED_COUNT=$(echo "$LENS_SHARED" | wc -l)
    echo "Checking $LENS_SHARED_COUNT Lens compliance patterns..."

    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue

        p_re=$(normalize_regex "$(extract_platform_regex "$pattern")")
        l_re=$(normalize_regex "$(extract_lens_regex "$pattern")")

        if [[ -n "$p_re" && -n "$l_re" && "$p_re" != "$l_re" && "$p_re" != "__STRING_CONCAT__" ]]; then
            echo -e "  ${YELLOW}⚠ $pattern: Platform ≠ Lens (may be JS↔Go syntax diff)${NC}"
            LENS_MISMATCHES=$((LENS_MISMATCHES + 1))
        fi
    done <<< "$LENS_SHARED"

    if [[ $LENS_MISMATCHES -eq 0 ]]; then
        echo -e "  ${GREEN}✅ All Lens compliance patterns match Platform regex${NC}"
    else
        echo -e "  ${YELLOW}$LENS_MISMATCHES Lens pattern(s) differ from Platform (review for JS↔Go syntax differences)${NC}"
    fi
fi

# Cleanup temp files
rm -f "$PLATFORM_TMP" "$RAMPART_TMP" "$LENS_TMP" "$SCANNER_TMP"

# ---------------------------------------------------------------------------
# Phase 3: Model Hash Alignment
# Verifies all products expect the same ONNX/JS model hash.
# Drift here means one product silently rejects the model (as happened
# with Platform's v11b→v13 hash mismatch).
# Scanner's ML stack was copied from MCP — Scanner hash should match Rampart
# and Platform.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 3: Model Hash Alignment ==="

PLATFORM_HASH=$(grep -oP 'ExpectedModelHash\s*=\s*"\K[^"]+' "$PLATFORM_DIR/pkg/ml/detector.go" 2>/dev/null | head -1)
RAMPART_HASH=$(grep -oP 'ExpectedModelHash\s*=\s*"\K[^"]+' "$RAMPART_DIR/internal/ml/detector.go" 2>/dev/null | head -1)
LENS_HASH=$(grep -oP "(?:EXPECTED_HASH|expectedHash|MODEL_HASH)\s*[:=]\s*['\"]\K[a-f0-9]{64}" "$LENS_DIR/src/detectors/ml/threat-detector-js.js" 2>/dev/null | head -1)

SCANNER_HASH=""
SCANNER_HASH_MISMATCH=0
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    SCANNER_HASH=$(grep -oP 'ExpectedModelHash\s*=\s*"\K[^"]+' "$SCANNER_DIR/internal/ml/detector.go" 2>/dev/null | head -1)
fi

echo "  Platform: ${PLATFORM_HASH:-NOT FOUND}"
echo "  Rampart:  ${RAMPART_HASH:-NOT FOUND}"
echo "  Scanner:  ${SCANNER_HASH:-NOT FOUND}$([[ $SCANNER_ENABLED -eq 0 ]] && echo ' (not found)')"
echo "  Lens:     ${LENS_HASH:-NOT FOUND}"

HASH_MISMATCH=0
if [[ -n "$PLATFORM_HASH" && -n "$RAMPART_HASH" && "$PLATFORM_HASH" != "$RAMPART_HASH" ]]; then
    echo -e "  ${RED}❌ Platform ≠ Rampart model hash mismatch${NC}"
    HASH_MISMATCH=1
    EXIT_CODE=1
fi
if [[ -n "$PLATFORM_HASH" && -n "$LENS_HASH" && "$PLATFORM_HASH" != "$LENS_HASH" ]]; then
    echo -e "  ${YELLOW}⚠ Platform ≠ Lens model hash (expected: different architectures — ONNX vs pure JS)${NC}"
fi
if [[ -n "$RAMPART_HASH" && -n "$LENS_HASH" && "$RAMPART_HASH" != "$LENS_HASH" ]]; then
    echo -e "  ${YELLOW}⚠ Rampart ≠ Lens model hash (expected: different architectures — ONNX vs pure JS)${NC}"
fi

# Scanner ↔ Rampart and Scanner ↔ Platform hash parity
if [[ $SCANNER_ENABLED -eq 1 && -n "$SCANNER_HASH" ]]; then
    if [[ -n "$RAMPART_HASH" && "$SCANNER_HASH" != "$RAMPART_HASH" ]]; then
        echo -e "  ${RED}❌ Scanner ≠ Rampart model hash mismatch${NC}"
        SCANNER_HASH_MISMATCH=1
        EXIT_CODE=1
    fi
    if [[ -n "$PLATFORM_HASH" && "$SCANNER_HASH" != "$PLATFORM_HASH" ]]; then
        echo -e "  ${RED}❌ Scanner ≠ Platform model hash mismatch${NC}"
        SCANNER_HASH_MISMATCH=1
        EXIT_CODE=1
    fi
    if [[ $SCANNER_HASH_MISMATCH -eq 0 ]]; then
        echo -e "  ${GREEN}✅ Scanner model hash matches Platform and Rampart${NC}"
    fi
fi

if [[ $HASH_MISMATCH -eq 0 && -n "$PLATFORM_HASH" && -n "$RAMPART_HASH" ]]; then
    echo -e "  ${GREEN}✅ Platform and Rampart use the same model hash${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 4: Evasion Suite Payload Count
# Verifies all products' evasion tests use the same number of payloads.
# Drift here means scores aren't comparable (apples-to-oranges).
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 4: Evasion Suite Payload Count ==="

PLATFORM_PAYLOADS=$(grep -cP '\{"(T\d+\.\d+|V450\.[A-Z0-9]+\.\d+)"' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null || echo "0")
RAMPART_PAYLOADS=$(grep -cP '\{"(T\d+\.\d+|V450\.[A-Z0-9]+\.\d+)"' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null || echo "0")
LENS_PAYLOADS=$(grep -cP "id:\s*['\"]([A-Z0-9.]+\.\d+)['\"]" "$LENS_DIR/test/unit/ml-evasion-suite.test.mjs" 2>/dev/null || echo "0")

SCANNER_PAYLOADS=0
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    SCANNER_PAYLOADS=$(grep -cP '\{"(T\d+\.\d+|V450\.[A-Z0-9]+\.\d+)"' "$SCANNER_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null || echo "0")
fi

echo "  Platform: $PLATFORM_PAYLOADS payloads"
echo "  Rampart:  $RAMPART_PAYLOADS payloads"
echo "  Scanner:  $SCANNER_PAYLOADS payloads$([[ $SCANNER_ENABLED -eq 0 ]] && echo ' (not found)')"
echo "  Lens:     $LENS_PAYLOADS payloads"

if [[ "$PLATFORM_PAYLOADS" != "$RAMPART_PAYLOADS" || "$PLATFORM_PAYLOADS" != "$LENS_PAYLOADS" ]]; then
    echo -e "  ${RED}❌ Payload count mismatch — scores are NOT comparable${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ All products use $PLATFORM_PAYLOADS payloads${NC}"
fi

# Scanner payload count comparison
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    if [[ "$SCANNER_PAYLOADS" != "$RAMPART_PAYLOADS" ]]; then
        echo -e "  ${RED}❌ Scanner payload count ($SCANNER_PAYLOADS) ≠ Rampart ($RAMPART_PAYLOADS)${NC}"
        EXIT_CODE=1
    else
        echo -e "  ${GREEN}✅ Scanner payload count matches Rampart ($SCANNER_PAYLOADS)${NC}"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 5: Transform Count
# Verifies all products' evasion tests define 50 transforms (10 per 5 categories).
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 5: Transform Count ==="

PLATFORM_TRANSFORMS=$(grep -oP '"[a-z_]+":\s+\w+,' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null | grep -v '^\s*"category"' | wc -l || echo "0")
RAMPART_TRANSFORMS=$(grep -oP '"[a-z_]+":\s+\w+,' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null | grep -v '^\s*"category"' | wc -l || echo "0")
LENS_TRANSFORMS=$(grep -cP '^\s+\w+:\s*\(s\)\s*=>' "$LENS_DIR/test/unit/ml-evasion-suite.test.mjs" 2>/dev/null || echo "0")

SCANNER_TRANSFORMS=0
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    SCANNER_TRANSFORMS=$(grep -oP '"[a-z_]+":\s+\w+,' "$SCANNER_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null | grep -v '^\s*"category"' | wc -l || echo "0")
fi

echo "  Platform: $PLATFORM_TRANSFORMS transform keys"
echo "  Rampart:  $RAMPART_TRANSFORMS transform keys"
echo "  Scanner:  $SCANNER_TRANSFORMS transform keys$([[ $SCANNER_ENABLED -eq 0 ]] && echo ' (not found)')"
echo "  Lens:     $LENS_TRANSFORMS transform keys"

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
if [[ $SCANNER_ENABLED -eq 1 && "$SCANNER_TRANSFORMS" -ne "$EXPECTED_TRANSFORMS" ]]; then
    echo -e "  ${YELLOW}⚠ Scanner has $SCANNER_TRANSFORMS transform keys (expected $EXPECTED_TRANSFORMS — may include extra map entries)${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 6: ML Threshold Alignment
# Verifies all products use the same ML detection threshold (0.5).
# Drift here means one product is more/less sensitive than the others.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 6: ML Threshold Alignment ==="

PLATFORM_THRESH=$(grep -oP 'Threshold\s*[:=]\s*\K[0-9.]+' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null | head -1)
RAMPART_THRESH=$(grep -oP 'Threshold\s*[:=]\s*\K[0-9.]+' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null | head -1)
LENS_THRESH=$(grep -oP 'THRESHOLD\s*=\s*\K[0-9.]+' "$LENS_DIR/src/detectors/ml/threat-detector-js.js" 2>/dev/null | head -1)

SCANNER_THRESH=""
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    SCANNER_THRESH=$(grep -oP 'Threshold\s*[:=]\s*\K[0-9.]+' "$SCANNER_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null | head -1)
fi

echo "  Platform evasion test: $PLATFORM_THRESH"
echo "  Rampart evasion test:  $RAMPART_THRESH"
echo "  Scanner evasion test:  ${SCANNER_THRESH:-NOT FOUND}$([[ $SCANNER_ENABLED -eq 0 ]] && echo ' (not found)')"
echo "  Lens ML model:         $LENS_THRESH"

THRESH_MISMATCH=0
for pair in "Platform:Rampart:$PLATFORM_THRESH:$RAMPART_THRESH" "Platform:Lens:$PLATFORM_THRESH:$LENS_THRESH" "Rampart:Lens:$RAMPART_THRESH:$LENS_THRESH"; do
    IFS=: read -r name1 name2 val1 val2 <<< "$pair"
    if [[ -n "$val1" && -n "$val2" ]]; then
        if ! awk -v a="$val1" -v b="$val2" 'BEGIN { exit (a == b) ? 0 : 1 }'; then
            echo -e "  ${RED}❌ $name1 ($val1) ≠ $name2 ($val2) threshold mismatch${NC}"
            THRESH_MISMATCH=1
            EXIT_CODE=1
        fi
    fi
done

# Scanner threshold comparison with Rampart and Platform
SCANNER_THRESH_MISMATCH=0
if [[ $SCANNER_ENABLED -eq 1 && -n "$SCANNER_THRESH" ]]; then
    if [[ -n "$RAMPART_THRESH" ]] && ! awk -v a="$SCANNER_THRESH" -v b="$RAMPART_THRESH" 'BEGIN { exit (a == b) ? 0 : 1 }'; then
        echo -e "  ${RED}❌ Scanner ($SCANNER_THRESH) ≠ Rampart ($RAMPART_THRESH) threshold mismatch${NC}"
        SCANNER_THRESH_MISMATCH=1
        EXIT_CODE=1
    fi
    if [[ -n "$PLATFORM_THRESH" ]] && ! awk -v a="$SCANNER_THRESH" -v b="$PLATFORM_THRESH" 'BEGIN { exit (a == b) ? 0 : 1 }'; then
        echo -e "  ${RED}❌ Scanner ($SCANNER_THRESH) ≠ Platform ($PLATFORM_THRESH) threshold mismatch${NC}"
        SCANNER_THRESH_MISMATCH=1
        EXIT_CODE=1
    fi
    if [[ $SCANNER_THRESH_MISMATCH -eq 0 ]]; then
        echo -e "  ${GREEN}✅ Scanner threshold ($SCANNER_THRESH) matches Platform and Rampart${NC}"
    fi
fi

if [[ $THRESH_MISMATCH -eq 0 && -n "$PLATFORM_THRESH" && -n "$RAMPART_THRESH" && -n "$LENS_THRESH" ]]; then
    echo -e "  ${GREEN}✅ All products use threshold $PLATFORM_THRESH${NC}"
fi

# ---------------------------------------------------------------------------
# Phase 7: Evasion Test Detection Logic Check
# Verifies that each product's evasion test uses (regexHit || mlHit) logic,
# not ML-only. This catches the bug where Lens's test was ML-only.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 7: Evasion Test Detection Logic ==="

LENS_HAS_REGEX=$(grep -c 'regexDetect\|regexHit\|regex.*detect\|facet.*detect' "$LENS_DIR/test/unit/ml-evasion-suite.test.mjs" 2>/dev/null || echo "0")
if [[ "$LENS_HAS_REGEX" -eq 0 ]]; then
    echo -e "  ${RED}❌ Lens evasion test does NOT use regex detection (ML-only)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ Lens evasion test uses regex + ML detection${NC}"
fi

PLATFORM_HAS_REGEX=$(grep -c 'scannerHit\|atlasHit\|scanner.*Scan\|atlas.*Check' "$PLATFORM_DIR/upstream/aegisgate/pkg/proxy/evasion_suite_test.go" 2>/dev/null || echo "0")
if [[ "$PLATFORM_HAS_REGEX" -eq 0 ]]; then
    echo -e "  ${RED}❌ Platform evasion test does NOT use regex/ATLAS detection (ML-only?)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ Platform evasion test uses scanner + ATLAS + ML detection${NC}"
fi

RAMPART_HAS_REGEX=$(grep -c 'detectorHit\|DetectAll\|detect.*regex' "$RAMPART_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null || echo "0")
if [[ "$RAMPART_HAS_REGEX" -eq 0 ]]; then
    echo -e "  ${RED}❌ Rampart evasion test does NOT use regex detection (ML-only?)${NC}"
    EXIT_CODE=1
else
    echo -e "  ${GREEN}✅ Rampart evasion test uses regex + ML detection${NC}"
fi

# Scanner detection logic check
SCANNER_HAS_REGEX=0
if [[ $SCANNER_ENABLED -eq 1 ]]; then
    SCANNER_HAS_REGEX=$(grep -c 'DetectAll\|detect.*regex' "$SCANNER_DIR/internal/detectors/evasion_suite_test.go" 2>/dev/null || echo "0")
    if [[ "$SCANNER_HAS_REGEX" -eq 0 ]]; then
        echo -e "  ${RED}❌ Scanner evasion test does NOT use regex detection (ML-only?)${NC}"
        EXIT_CODE=1
    else
        echo -e "  ${GREEN}✅ Scanner evasion test uses regex + ML detection${NC}"
    fi
fi

# ---------------------------------------------------------------------------
# Final Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "  Parity Check Summary"
echo "============================================"
echo "  Pattern names (P↔R): $([ $PATTERN_FAIL -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Scanner patterns:    $([[ $SCANNER_ENABLED -eq 0 ]] && echo 'SKIP' || ([ $SCANNER_PATTERN_FAIL -eq 0 ] && echo 'PASS' || echo 'FAIL'))"
echo "  Regex content (P↔R): $([ $CONTENT_MISMATCHES -eq 0 ] && echo 'PASS' || echo "FAIL ($CONTENT_MISMATCHES)")"
echo "  Scanner regex:       $([[ $SCANNER_ENABLED -eq 0 ]] && echo 'SKIP' || ([ $SCANNER_REGEX_MISMATCHES -eq 0 ] && echo 'PASS' || echo "FAIL ($SCANNER_REGEX_MISMATCHES)"))"
echo "  Lens subset:         $([[ -z "${LENS_NOT_IN_PLATFORM:-}" && -z "${LENS_NOT_IN_RAMPART:-}" ]] && echo 'PASS' || echo 'FAIL')"
echo "  Lens regex:          $([ $LENS_MISMATCHES -eq 0 ] && echo 'PASS' || echo "WARN ($LENS_MISMATCHES)")"
echo "  Model hash:          $([ $HASH_MISMATCH -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Scanner model hash:  $([[ $SCANNER_ENABLED -eq 0 ]] && echo 'SKIP' || ([ $SCANNER_HASH_MISMATCH -eq 0 ] && echo 'PASS' || echo 'FAIL'))"
echo "  Payload count:       $([[ "$PLATFORM_PAYLOADS" == "$RAMPART_PAYLOADS" && "$PLATFORM_PAYLOADS" == "$LENS_PAYLOADS" ]] && echo 'PASS' || echo 'FAIL')"
echo "  Scanner payload:     $([[ $SCANNER_ENABLED -eq 0 ]] && echo 'SKIP' || ([[ "$SCANNER_PAYLOADS" == "$RAMPART_PAYLOADS" ]] && echo 'PASS' || echo 'FAIL'))"
echo "  Transform count:     $([[ "$LENS_TRANSFORMS" -eq 50 ]] && echo 'PASS' || echo 'WARN')"
echo "  ML threshold:        $([ $THRESH_MISMATCH -eq 0 ] && echo 'PASS' || echo 'FAIL')"
echo "  Scanner threshold:   $([[ $SCANNER_ENABLED -eq 0 ]] && echo 'SKIP' || ([ $SCANNER_THRESH_MISMATCH -eq 0 ] && echo 'PASS' || echo 'FAIL'))"
echo "  Detection logic:     $([[ "$LENS_HAS_REGEX" -gt 0 && "$PLATFORM_HAS_REGEX" -gt 0 && "$RAMPART_HAS_REGEX" -gt 0 ]] && echo 'PASS' || echo 'FAIL')"
echo "  Scanner det. logic:  $([[ $SCANNER_ENABLED -eq 0 ]] && echo 'SKIP' || ([[ "$SCANNER_HAS_REGEX" -gt 0 ]] && echo 'PASS' || echo 'FAIL'))"
echo "============================================"

exit $EXIT_CODE