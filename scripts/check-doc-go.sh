#!/bin/bash
# =========================================================================
# AegisGate Security Platform - Package doc.go Enforcement
# =========================================================================
# Verifies that every Go package under pkg/ has a doc.go file with the
# required SPDX-License-Identifier header and a package declaration.
#
# This is the "26/45 packages lack doc.go" guard (per the
# PLATFORM-DEEP-DIVE-ASSESSMENT-2026-07-21.md, Criterion 6
# Documentation). When this script exits non-zero, CI fails and
# the PR is blocked.
#
# Exit codes:
#   0 - all packages have doc.go
#   1 - one or more packages lack doc.go, or doc.go is malformed
#
# Usage:
#   ./scripts/check-doc-go.sh
#
# To exempt a package temporarily, add it to the EXEMPT_PACKAGES list
# below with a comment explaining why. Permanent exemptions should
# be added to a tracking issue.
# =========================================================================

set -euo pipefail

# Packages that are exempt (with reason). Keep this list SHORT and
# add an issue/ticket for each one. Empty list = zero exemptions.
EXEMPT_PACKAGES=(
    # "pkg/foo"  # reason: not a public package
)

cd "$(dirname "$0")/.."

missing=0
malformed=0
checked=0

echo "=== Package doc.go check ==="
echo ""

for d in pkg/*/; do
    pkg=$(basename "$d")

    # Skip exempt packages
    skip=0
    for ex in "${EXEMPT_PACKAGES[@]}"; do
        if [ "$ex" = "$d" ]; then
            skip=1
            break
        fi
    done
    if [ "$skip" = "1" ]; then
        continue
    fi

    # Skip subpackages of compliance (each subpackage has its own
    # doc.go like pkg/compliance/eu-ai-act/doc.go, but the parent
    # pkg/compliance/doc.go covers all of them).
    if [[ "$d" == pkg/compliance/*/ ]]; then
        continue
    fi

    checked=$((checked + 1))

    if [ ! -f "$d/doc.go" ]; then
        echo "❌ MISSING: $d/doc.go"
        missing=$((missing + 1))
        continue
    fi

    # Check SPDX header
    if ! head -1 "$d/doc.go" | grep -q "SPDX-License-Identifier"; then
        echo "❌ NO SPDX HEADER: $d/doc.go"
        malformed=$((malformed + 1))
        continue
    fi

    # Check that the file contains a package declaration
    if ! grep -q "^package " "$d/doc.go"; then
        echo "❌ NO PACKAGE DECL: $d/doc.go"
        malformed=$((malformed + 1))
        continue
    fi
done

echo ""
echo "=== Summary ==="
echo "Checked:    $checked packages"
echo "Missing:    $missing"
echo "Malformed:  $malformed"
echo "Exempt:     ${#EXEMPT_PACKAGES[@]}"
echo ""

if [ "$missing" -gt 0 ] || [ "$malformed" -gt 0 ]; then
    echo "❌ FAIL: $missing missing, $malformed malformed"
    echo ""
    echo "Every public package MUST have a doc.go file. See:"
    echo "  plans/PLATFORM-DEEP-DIVE-ASSESSMENT-2026-07-21.md (Criterion 6)"
    echo "  pkg/acp/doc.go, pkg/aibom/doc.go for the template format"
    exit 1
fi

echo "✅ All $checked packages have valid doc.go files"
exit 0
