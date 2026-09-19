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
PLATFORM_ONLY_PATTERNS="prompt_injection_base64 prompt_injection_code_execution prompt_injection_command prompt_injection_delimiter prompt_injection_leakage prompt_injection_prefix prompt_injection_role_play prompt_injection_unicode"

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

# Platform → Lens missing
PLATFORM_LENS_MISSING=$(comm -23 "$PLATFORM_TMP" "$LENS_TMP")
if [[ -n "$PLATFORM_LENS_MISSING" ]]; then
    MISSING_COUNT=$(echo "$PLATFORM_LENS_MISSING" | wc -l)
    echo -e "${RED}MISSING from Lens ($MISSING_COUNT patterns):${NC}"
    echo "$PLATFORM_LENS_MISSING" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
fi

# Platform → Rampart missing
PLATFORM_RAMPART_MISSING=$(comm -23 "$PLATFORM_TMP" "$RAMPART_TMP")
if [[ -n "$PLATFORM_RAMPART_MISSING" ]]; then
    MISSING_COUNT=$(echo "$PLATFORM_RAMPART_MISSING" | wc -l)
    echo -e "${RED}MISSING from Rampart ($MISSING_COUNT patterns):${NC}"
    echo "$PLATFORM_RAMPART_MISSING" | sed 's/^/  - /'
    echo ""
    EXIT_CODE=1
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

if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✅ Detection parity verified — all products have matching pattern sets${NC}"
else
    echo -e "${RED}❌ Detection parity check FAILED — patterns missing from one or more products${NC}"
    echo ""
    echo "To fix: add missing patterns to the product(s) above and commit."
fi

exit $EXIT_CODE