#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Platform - Lab Tests Reproduction Script (v3.3.0+)
# =========================================================================
#
# Runs the full lab test suite for the new Track 1-6 packages:
#   - pkg/posture  (posture check)
#   - pkg/evidence (compliance evidence packages)
#   - pkg/logging  (audit event ring buffer)
#   - pkg/ioc      (federated IOC library; Track 6 Task 3+4)
#
# Lab tests exercise real implementations end-to-end using a fresh
# process for each test (no testlab docker stack required for the
# in-process tests; the testlab is used for cross-instance and
# external-service tests in pkg/sso/, pkg/email/, etc.).
#
# Usage:
#   bash scripts/run-lab-tests.sh
#
# Environment variables (optional):
#   LAB_TIMEOUT    Per-test timeout (default: 60s)
#   LAB_PACKAGES   Space-separated package list (default: posture evidence logging ioc)
#   LAB_VERBOSE    If set, runs go test with -v
#
# See also:
#   - pkg/posture/posture_lab_test.go   (8 tests)
#   - pkg/evidence/evidence_lab_test.go (8 tests)
#   - pkg/logging/ringbuffer_lab_test.go (8 tests)
#   - pkg/ioc/ioc_test.go + ioc_coverage_test.go (74 tests)
#   - testlab/cross_instance_ioc_lab_test.go (4 lab tests; requires lab build tag)
#   - pkg/evidence/testfixtures_test.go (shared fixtures)
#
# v3.5.0+ Track 1-6.

set -euo pipefail

# Default values
LAB_TIMEOUT="${LAB_TIMEOUT:-60s}"
LAB_PACKAGES="${LAB_PACKAGES:-posture evidence logging ioc}"
LAB_VERBOSE_FLAG=""
if [[ -n "${LAB_VERBOSE:-}" ]]; then
    LAB_VERBOSE_FLAG="-v"
fi

# Resolve project root (parent of the scripts/ directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "AegisGate Lab Tests - Track 1-6 (v3.5.0+)"
echo "=========================================="
echo "Project root: $PROJECT_ROOT"
echo "Timeout:      $LAB_TIMEOUT"
echo "Packages:     $LAB_PACKAGES"
echo "Verbose:      ${LAB_VERBOSE:+yes}${LAB_VERBOSE:-no}"
echo "=========================================="
echo

# Build the package list
PACKAGE_ARGS=()
for pkg in $LAB_PACKAGES; do
    PACKAGE_ARGS+=("./pkg/$pkg/...")
done

# Run the lab tests with the lab build tag and LAB_ENABLED=1
LAB_ENABLED=1 go test \
    -tags=lab \
    -count=1 \
    -timeout="$LAB_TIMEOUT" \
    $LAB_VERBOSE_FLAG \
    "${PACKAGE_ARGS[@]}"

EXIT_CODE=$?

echo
if [[ $EXIT_CODE -eq 0 ]]; then
    echo "=========================================="
    echo "✅ All lab tests passed"
    echo "=========================================="
else
    echo "=========================================="
    echo "❌ Some lab tests failed (exit $EXIT_CODE)"
    echo "=========================================="
fi

exit $EXIT_CODE
