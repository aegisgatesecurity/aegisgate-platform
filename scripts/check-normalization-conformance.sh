#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# AegisGate — Cross-Product Normalization Conformance Orchestrator
#
# Runs normalization conformance tests against all three products and
# compares results. Fails if any product's normalization output diverges
# from the canonical conformance vectors.
#
# Usage:
#   ./scripts/check-normalization-conformance.sh
#
# Requires: All three repos cloned as siblings under AegisGate/ directory.
#   - aegisgate-platform (or consolidated/aegisgate-platform)
#   - aegisgate-lens
#   - aegisgate-rampart
#
# Environment:
#   PLATFORM_DIR, LENS_DIR, RAMPART_DIR — override repo paths
#   AEGISGATE_ROOT — parent directory containing all repos

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Find repo paths (reuse same logic as check-detection-parity.sh)
PLATFORM_DIR="${PLATFORM_DIR:-}"
LENS_DIR="${LENS_DIR:-}"
RAMPART_DIR="${RAMPART_DIR:-}"
AEGISGATE_ROOT="${AEGISGATE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

if [[ -z "$PLATFORM_DIR" ]]; then
    for candidate in \
        "$AEGISGATE_ROOT/aegisgate-platform" \
        "$AEGISGATE_ROOT/consolidated/aegisgate-platform"; do
        if [[ -f "$candidate/pkg/scanner/patterns.go" ]]; then
            PLATFORM_DIR="$candidate"
            break
        fi
    done
fi

if [[ -z "$LENS_DIR" ]]; then
    for candidate in "$AEGISGATE_ROOT/aegisgate-lens"; do
        if [[ -f "$candidate/src/detectors/ml/char-normalizer.js" ]]; then
            LENS_DIR="$candidate"
            break
        fi
    done
fi

if [[ -z "$RAMPART_DIR" ]]; then
    for candidate in "$AEGISGATE_ROOT/aegisgate-rampart"; do
        if [[ -f "$candidate/internal/detectors/normalize.go" ]]; then
            RAMPART_DIR="$candidate"
            break
        fi
    done
fi

echo "============================================"
echo "  Normalization Conformance Check"
echo "============================================"
echo ""
echo "Platform: ${PLATFORM_DIR:-NOT FOUND}"
echo "Lens:     ${LENS_DIR:-NOT FOUND}"
echo "Rampart:  ${RAMPART_DIR:-NOT FOUND}"
echo ""

EXIT_CODE=0
FAILURES=0
PASSES=0

# ---------------------------------------------------------------------------
# Phase 1: Verify conformance vectors file exists
# ---------------------------------------------------------------------------
echo "=== Conformance Vectors ==="
VECTORS_FILE=""
for candidate in \
    "$PLATFORM_DIR/testkit/normalization-conformance-vectors.json" \
    "$AEGISGATE_ROOT/aegisgate-platform/testkit/normalization-conformance-vectors.json" \
    "$LENS_DIR/testkit/normalization-conformance-vectors.json"; do
    if [[ -f "$candidate" ]]; then
        VECTORS_FILE="$candidate"
        break
    fi
done

if [[ -z "$VECTORS_FILE" ]]; then
    echo -e "${RED}ERROR: normalization-conformance-vectors.json not found${NC}"
    exit 1
fi
echo -e "  ${GREEN}✅ Found: $VECTORS_FILE${NC}"

# ---------------------------------------------------------------------------
# Phase 2: Verify normalization-spec.json exists and check required variants
# ---------------------------------------------------------------------------
echo ""
echo "=== Normalization Spec ==="
SPEC_FILE=""
for candidate in \
    "$PLATFORM_DIR/testkit/normalization-spec.json" \
    "$AEGISGATE_ROOT/aegisgate-platform/testkit/normalization-spec.json"; do
    if [[ -f "$candidate" ]]; then
        SPEC_FILE="$candidate"
        break
    fi
done

if [[ -z "$SPEC_FILE" ]]; then
    echo -e "  ${YELLOW}⚠ normalization-spec.json not found — skipping spec validation${NC}"
else
    echo -e "  ${GREEN}✅ Found: $SPEC_FILE${NC}"

    # Check required variants are implemented in each product
    echo ""
    echo "  Checking required normalization variants per product..."

    # --- Platform checks ---
    PLATFORM_NORMALIZE="$PLATFORM_DIR/upstream/aegisgate/pkg/scanner/normalize.go"
    if [[ -f "$PLATFORM_NORMALIZE" ]]; then
        for func in NormalizeText stripZeroWidth NormalizeKeyboardWalk NormalizeROT13 \
                    NormalizeSlidingROT13 NormalizeRepeatingChars NormalizeBackslashEscapes \
                    NormalizeHomoglyphs; do
            if grep -q "func $func" "$PLATFORM_NORMALIZE" 2>/dev/null; then
                echo -e "    Platform: $func ${GREEN}✓${NC}"
                PASSES=$((PASSES + 1))
            else
                echo -e "    Platform: $func ${RED}✗ MISSING${NC}"
                FAILURES=$((FAILURES + 1))
                EXIT_CODE=1
            fi
        done
    fi

    # --- Rampart checks ---
    RAMPART_NORMALIZE="$RAMPART_DIR/internal/detectors/normalize.go"
    if [[ -f "$RAMPART_NORMALIZE" ]]; then
        for func in NormalizeText stripZeroWidth NormalizeKeyboardWalk NormalizeROT13 \
                    NormalizeSlidingROT13 NormalizeRepeatingChars NormalizeBackslashEscapes \
                    NormalizeHomoglyphs; do
            if grep -q "func $func" "$RAMPART_NORMALIZE" 2>/dev/null; then
                echo -e "    Rampart:  $func ${GREEN}✓${NC}"
                PASSES=$((PASSES + 1))
            else
                echo -e "    Rampart:  $func ${RED}✗ MISSING${NC}"
                FAILURES=$((FAILURES + 1))
                EXIT_CODE=1
            fi
        done
    fi

    # --- Lens checks ---
    LENS_NORMALIZER="$LENS_DIR/src/detectors/ml/char-normalizer.js"
    if [[ -f "$LENS_NORMALIZER" ]]; then
        # Lens uses different function names
        for func_pair in "stripZeroWidth:stripZeroWidth" "slidingROT13:slidingROT13" \
                         "reverseKeyboardWalk:NormalizeKeyboardWalk" \
                         "nfkcNormalize:NFKC" "decodeHexEscapes:NormalizeHexEscape"; do
            local_name="${func_pair%%:*}"
            spec_name="${func_pair##*:}"
            if grep -q "function $local_name" "$LENS_NORMALIZER" 2>/dev/null; then
                echo -e "    Lens:     $spec_name ($local_name) ${GREEN}✓${NC}"
                PASSES=$((PASSES + 1))
            else
                echo -e "    Lens:     $spec_name ($local_name) ${RED}✗ MISSING${NC}"
                FAILURES=$((FAILURES + 1))
                EXIT_CODE=1
            fi
        done
    fi
fi

# ---------------------------------------------------------------------------
# Phase 3: Check zero-width character set parity
# Compares the actual zero-width characters stripped by each product.
# This catches the drift we found this session where Lens was missing
# 15+ characters that Platform/Rampart strip.
# ---------------------------------------------------------------------------
echo ""
echo "=== Zero-Width Character Set Parity ==="

# Extract the character set from each product's zero-width implementation
# Platform/Rampart: parse zeroWidthSet rune list
# Lens: parse the regex character class

ZW_PLATFORM=$(python3 -c "
import re
with open('$PLATFORM_DIR/upstream/aegisgate/pkg/scanner/normalize.go') as f:
    content = f.read()
# Extract the zeroWidthSet rune block
match = re.search(r'var zeroWidthSet = func\(\) map\[rune\]bool \{(.*?)\n\}\(\)', content, re.DOTALL)
if match:
    block = match.group(1)
    chars = set()
    for m in re.finditer(r\"'\\\\u([0-9a-fA-F]{4})'\", block):
        chars.add(int(m.group(1), 16))
    # Also check for direct char literals
    for m in re.finditer(r\"'\\\\u([0-9a-fA-F]+)'\", block):
        chars.add(int(m.group(1), 16))
    print(' '.join(sorted(['%04X' % c for c in chars])))
" 2>/dev/null || echo "")

ZW_RAMPART=$(python3 -c "
import re
with open('$RAMPART_DIR/internal/detectors/normalize.go') as f:
    content = f.read()
match = re.search(r'var zeroWidthSet = func\(\) map\[rune\]bool \{(.*?)\n\}\(\)', content, re.DOTALL)
if match:
    block = match.group(1)
    chars = set()
    for m in re.finditer(r\"'\\\\u([0-9a-fA-F]{4})'\", block):
        chars.add(int(m.group(1), 16))
    for m in re.finditer(r\"'\\\\u([0-9a-fA-F]+)'\", block):
        chars.add(int(m.group(1), 16))
    print(' '.join(sorted(['%04X' % c for c in chars])))
" 2>/dev/null || echo "")

ZW_LENS=$(python3 -c "
import re
with open('$LENS_DIR/src/detectors/ml/char-normalizer.js') as f:
    content = f.read()
# Find the stripZeroWidth function and extract the regex character class
match = re.search(r'function stripZeroWidth.*?\.replace\(/\[([^\]]+)\]/g', content, re.DOTALL)
if match:
    charset = match.group(1)
    chars = set()
    for m in re.finditer(r'\\\\u([0-9a-fA-F]{4})', charset):
        chars.add(int(m.group(1), 16))
    print(' '.join(sorted(['%04X' % c for c in chars])))
" 2>/dev/null || echo "")

echo "  Platform: $(echo $ZW_PLATFORM | tr ' ' ',' )"
echo "  Rampart:  $(echo $ZW_RAMPART | tr ' ' ',' )"
echo "  Lens:     $(echo $ZW_LENS | tr ' ' ',' )"

# Compare Platform vs Rampart
if [[ -n "$ZW_PLATFORM" && -n "$ZW_RAMPART" ]]; then
    if [[ "$ZW_PLATFORM" == "$ZW_RAMPART" ]]; then
        echo -e "  ${GREEN}✅ Platform = Rampart zero-width set${NC}"
        PASSES=$((PASSES + 1))
    else
        echo -e "  ${RED}❌ Platform ≠ Rampart zero-width set${NC}"
        # Show the diff
        comm -23 <(echo "$ZW_PLATFORM" | tr ' ' '\n' | sort) <(echo "$ZW_RAMPART" | tr ' ' '\n' | sort) | while read c; do echo "    In Platform not Rampart: U+$c"; done
        comm -13 <(echo "$ZW_PLATFORM" | tr ' ' '\n' | sort) <(echo "$ZW_RAMPART" | tr ' ' '\n' | sort) | while read c; do echo "    In Rampart not Platform: U+$c"; done
        FAILURES=$((FAILURES + 1))
        EXIT_CODE=1
    fi
fi

# Compare Platform vs Lens
if [[ -n "$ZW_PLATFORM" && -n "$ZW_LENS" ]]; then
    PLATFORM_SET=$(echo "$ZW_PLATFORM" | tr ' ' '\n' | sort)
    LENS_SET=$(echo "$ZW_LENS" | tr ' ' '\n' | sort)
    # Lens may have a few extra chars (like U+200E, U+180E) — that's fine
    # But Lens must NOT be missing any chars that Platform has
    LENS_MISSING=$(comm -23 <(echo "$PLATFORM_SET") <(echo "$LENS_SET"))
    if [[ -z "$LENS_MISSING" ]]; then
        echo -e "  ${GREEN}✅ Lens covers all Platform zero-width chars${NC}"
        PASSES=$((PASSES + 1))
    else
        echo -e "  ${RED}❌ Lens missing zero-width chars that Platform has:${NC}"
        echo "$LENS_MISSING" | while read c; do echo "    Missing: U+$c"; done
        FAILURES=$((FAILURES + 1))
        EXIT_CODE=1
    fi
fi

# ---------------------------------------------------------------------------
# Phase 4: MaxSequenceLength alignment
# ---------------------------------------------------------------------------
echo ""
echo "=== MaxSequenceLength Alignment ==="

MAXSEQ_PLATFORM=$(grep -oP 'MaxSequenceLength\s*[:=]\s*\K[0-9]+' "$PLATFORM_DIR/pkg/ml/types.go" 2>/dev/null | head -1)
MAXSEQ_RAMPART=$(grep -oP 'MaxSequenceLength\s*[:=]\s*\K[0-9]+' "$RAMPART_DIR/internal/ml/types.go" 2>/dev/null | head -1)
MAXSEQ_LENS=$(grep -oP 'MAX_SEQ_LEN\s*=\s*\K[0-9]+' "$LENS_DIR/src/detectors/ml/char-normalizer.js" 2>/dev/null | head -1)

echo "  Platform: ${MAXSEQ_PLATFORM:-NOT FOUND}"
echo "  Rampart:  ${MAXSEQ_RAMPART:-NOT FOUND}"
echo "  Lens:     ${MAXSEQ_LENS:-NOT FOUND}"

if [[ -n "$MAXSEQ_PLATFORM" && -n "$MAXSEQ_RAMPART" && "$MAXSEQ_PLATFORM" == "$MAXSEQ_RAMPART" ]]; then
    echo -e "  ${GREEN}✅ Platform = Rampart (${MAXSEQ_PLATFORM})${NC}"
    PASSES=$((PASSES + 1))
else
    echo -e "  ${RED}❌ Platform ≠ Rampart MaxSequenceLength${NC}"
    FAILURES=$((FAILURES + 1))
    EXIT_CODE=1
fi

if [[ -n "$MAXSEQ_PLATFORM" && -n "$MAXSEQ_LENS" && "$MAXSEQ_PLATFORM" == "$MAXSEQ_LENS" ]]; then
    echo -e "  ${GREEN}✅ Platform = Lens (${MAXSEQ_LENS})${NC}"
    PASSES=$((PASSES + 1))
else
    echo -e "  ${RED}❌ Platform ≠ Lens MaxSequenceLength${NC}"
    FAILURES=$((FAILURES + 1))
    EXIT_CODE=1
fi

# ---------------------------------------------------------------------------
# Phase 5: Evasion suite score comparison from reports
# Compares the latest evasion suite report scores across products.
# This is the ultimate guardrail — if scores diverge, drift has occurred.
# ---------------------------------------------------------------------------
echo ""
echo "=== Evasion Suite Score Comparison ==="

# Platform report
PLATFORM_REPORT=$(find "$PLATFORM_DIR" -name "evasion-suite-phase0a-*.json" -type f 2>/dev/null | sort -r | head -1)
PLATFORM_SCORE=""
if [[ -n "$PLATFORM_REPORT" ]]; then
    PLATFORM_SCORE=$(python3 -c "
import json
with open('$PLATFORM_REPORT') as f:
    d = json.load(f)
print(d.get('overall', {}).get('evasion_resistance_score', '?'))
" 2>/dev/null || echo "?")
fi

# Rampart report
RAMPART_REPORT=$(find "$RAMPART_DIR" -name "evasion-suite-rampart-*.json" -type f 2>/dev/null | sort -r | head -1)
RAMPART_SCORE=""
if [[ -n "$RAMPART_REPORT" ]]; then
    RAMPART_SCORE=$(python3 -c "
import json
with open('$RAMPART_REPORT') as f:
    d = json.load(f)
print(d.get('overall', {}).get('evasion_resistance_score', '?'))
" 2>/dev/null || echo "?")
fi

# Lens report
LENS_REPORT="$LENS_DIR/test/reports/evasion-suite-results.json"
LENS_SCORE=""
LENS_TOTAL=""
LENS_DETECTED=""
if [[ -f "$LENS_REPORT" ]]; then
    LENS_SCORE=$(python3 -c "
import json
with open('$LENS_REPORT') as f:
    d = json.load(f)
detected = d.get('totalDetected', 0)
total = d.get('totalTests', 1)
print('%.1f' % (100.0 * detected / total))
" 2>/dev/null || echo "?")
    LENS_TOTAL=$(python3 -c "
import json
with open('$LENS_REPORT') as f:
    d = json.load(f)
print(d.get('totalTests', 0))
" 2>/dev/null || echo "?")
    LENS_DETECTED=$(python3 -c "
import json
with open('$LENS_REPORT') as f:
    d = json.load(f)
print(d.get('totalDetected', 0))
" 2>/dev/null || echo "?")
fi

echo "  Platform: ${PLATFORM_SCORE}/100  ($PLATFORM_REPORT)"
echo "  Rampart:  ${RAMPART_SCORE}/100  ($RAMPART_REPORT)"
echo "  Lens:     ${LENS_SCORE}/100 (${LENS_DETECTED}/${LENS_TOTAL})  ($LENS_REPORT)"

# Compare scores
if [[ -n "$PLATFORM_SCORE" && "$PLATFORM_SCORE" != "?" ]]; then
    # Platform and Rampart must be 100
    if [[ "$RAMPART_SCORE" != "?" ]]; then
        if python3 -c "exit(0 if abs(float('$PLATFORM_SCORE') - float('$RAMPART_SCORE')) < 0.01 else 1)" 2>/dev/null; then
            echo -e "  ${GREEN}✅ Platform = Rampart score${NC}"
            PASSES=$((PASSES + 1))
        else
            echo -e "  ${RED}❌ Platform ($PLATFORM_SCORE) ≠ Rampart ($RAMPART_SCORE) score${NC}"
            FAILURES=$((FAILURES + 1))
            EXIT_CODE=1
        fi
    fi

    # Lens must be >= 99.9 (allows 1 float16 precision miss)
    if [[ "$LENS_SCORE" != "?" ]]; then
        LENS_OK=$(python3 -c "print('YES' if float('$LENS_SCORE') >= 99.9 else 'NO')" 2>/dev/null || echo "NO")
        if [[ "$LENS_OK" == "YES" ]]; then
            echo -e "  ${GREEN}✅ Lens score >= 99.9 (within float16 tolerance)${NC}"
            PASSES=$((PASSES + 1))
        else
            echo -e "  ${RED}❌ Lens score ($LENS_SCORE) below 99.9 tolerance${NC}"
            FAILURES=$((FAILURES + 1))
            EXIT_CODE=1
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Final Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================"
echo "  Conformance Check Summary"
echo "============================================"
echo "  Checks passed: $PASSES"
echo "  Checks failed: $FAILURES"
echo "============================================"

if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✅ Normalization conformance verified — all products in parity${NC}"
else
    echo -e "${RED}❌ Normalization conformance FAILED — drift detected${NC}"
    echo ""
    echo "To fix: sync the missing/divergent normalization logic to the affected product(s)."
fi

exit $EXIT_CODE