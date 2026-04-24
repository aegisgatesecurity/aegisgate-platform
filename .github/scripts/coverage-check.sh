#!/bin/bash

# Calculate overall coverage
COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | tr -d '%')

echo "=== Coverage Report ==="
echo "Overall coverage: $COVERAGE%"

# Check if overall meets threshold
if (( $(echo "$COVERAGE >= 80" | bc -l) )); then
    echo "✅ Coverage meets 80% threshold"
    exit 0
else
    echo "❌ Coverage below 80% (required threshold)"
    exit 1
fi
