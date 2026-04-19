#!/bin/bash
set -e

GO_VERSION="1.25.9"

# First fix illegal rune literals (smart quotes) in security integration test files
# Fix aegisgate integration_test.go
sed -i 's/\xe2\x80\x9c/"/g; s/\xe2\x80\x9d/"/g' /home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/upstream/aegisgate/pkg/security/integration_test.go

# Fix aegisgate-source integration_test.go  
sed -i 's/\xe2\x80\x9c/"/g; s/\xe2\x80\x9d/"/g' /home/chaos/Desktop/AegisGate/consolidated/aegisgate-source/pkg/security/integration_test.go

# Run gofmt on all Go files to ensure proper formatting
echo "Running gofmt on aegisgate platform..."
/usr/local/go/bin/gofmt -w /home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/pkg/
/usr/local/go/bin/gofmt -w /home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/upstream/aegisgate/pkg/

echo "Running gofmt on aegisgate-source..."
/usr/local/go/bin/gofmt -w /home/chaos/Desktop/AegisGate/consolidated/aegisgate-source/pkg/

echo ""
echo "=== VERIFICATION ==="
echo ""
echo "Format check (should be empty for platform):"
/usr/local/go/bin/gofmt -l /home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/pkg/ 2>&1 | head -20
echo ""
echo "Format check (should be empty for upstream):"
/usr/local/go/bin/gofmt -l /home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/upstream/aegisgate/pkg/ 2>&1 | head -20
echo ""
echo "Format check (should be empty for source):"
/usr/local/go/bin/gofmt -l /home/chaos/Desktop/AegisGate/consolidated/aegisgate-source/pkg/ 2>&1 | head -20

echo ""
echo "Illegal runes check (should show no errors):"
if grep -n "illegal rune" /home/chaos/Desktop/AegisGate/consolidated/aegisgate-platform/upstream/aegisgate/pkg/security/integration_test.go 2>/dev/null; then
  echo "ERROR: Illegal runes still found in aegisgate"
  exit 1
else
  echo "✓ No illegal runes found in aegisgate"
fi

if grep -n "illegal rune" /home/chaos/Desktop/AegisGate/consolidated/aegisgate-source/pkg/security/integration_test.go 2>/dev/null; then
  echo "ERROR: Illegal runes still found in aegisgate-source"
  exit 1
else
  echo "✓ No illegal runes found in aegisgate-source"
fi

echo ""
echo "=== ALL FIXES APPLIED SUCCESSFULLY ==="
