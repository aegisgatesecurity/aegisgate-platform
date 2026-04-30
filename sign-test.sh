#!/bin/bash
# =============================================================================
# AegisGate Security Platform — Local Cosign Signing Test
# =============================================================================
# This script tests the cosign signing workflow locally (without GitHub Actions).
# 
# Usage: ./sign-test.sh [--verify-only]
#
# Requirements:
#   - cosign installed: go install github.com/sigstore/cosign/v3/cmd/cosign@latest
#   - Docker installed and running
#   - OCI registry (GHCR, GCR, or local) with write access
#
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="${IMAGE_NAME:-ghcr.io/aegisgatesecurity/aegisgate-platform}"
IMAGE_TAG="${IMAGE_TAG:-test-signing}"
SIGNING_KEY="${SIGNING_KEY:-}"  # Optional: use key-based signing

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

# Check prerequisites
check_prereqs() {
    log_info "Checking prerequisites..."
    
    # Check cosign
    if ! command -v cosign &> /dev/null; then
        log_error "cosign not found. Install with:"
        log_error "  go install github.com/sigstore/cosign/v3/cmd/cosign@latest"
        exit 1
    fi
    log_success "cosign: $(cosign version 2>/dev/null | head -1)"
    
    # Check docker
    if ! command -v docker &> /dev/null; then
        log_error "docker not found"
        exit 1
    fi
    log_success "docker: $(docker --version)"
    
    log_info "Prerequisites OK"
}

# Build test image
build_image() {
    log_info "Building test image: ${IMAGE_NAME}:${IMAGE_TAG}"
    docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" .
    docker build -t "${IMAGE_NAME}:latest" .
    log_success "Image built"
}

# Sign image with cosign (keyless)
sign_keyless() {
    log_info "Signing image (keyless via OIDC)..."
    log_info "Registry: ${IMAGE_NAME}:${IMAGE_TAG}"
    
    # Keyless signing requires OIDC (GitHub Actions, Google, Microsoft)
    # For local testing, use --generate-new-identity or key-based signing
    cosign sign --yes "${IMAGE_NAME}:${IMAGE_TAG}" 2>&1 || {
        log_warn "Keyless signing requires OIDC provider (GitHub Actions, Azure, GCP)"
        log_info "For local testing, use key-based signing:"
        log_info "  cosign generate-key-pair"
        log_info "  SIGNING_KEY=./cosign.key ${IMAGE_NAME}:${IMAGE_TAG}"
        return 1
    }
    
    log_success "Image signed (keyless)"
}

# Sign image with key (alternative for local testing)
sign_with_key() {
    if [ -z "${SIGNING_KEY:-}" ]; then
        log_warn "SIGNING_KEY not set, skipping key-based signing"
        return 0
    fi
    
    log_info "Signing image with key: ${SIGNING_KEY}"
    cosign sign --yes --key "${SIGNING_KEY}" "${IMAGE_NAME}:${IMAGE_TAG}"
    log_success "Image signed with key"
}

# Verify signature
verify() {
    log_info "Verifying signature..."
    
    if cosign verify "${IMAGE_NAME}:${IMAGE_TAG}" 2>&1 | grep -q "keyless"; then
        log_success "Signature verified (keyless)"
    elif cosign verify --key "${SIGNING_KEY:-cosign.pub}" "${IMAGE_NAME}:${IMAGE_TAG}" 2>&1 | grep -q "keyless"; then
        log_success "Signature verified (key)"
    else
        log_warn "Could not verify signature (may need OIDC or correct key)"
    fi
}

# Generate attestation (SBOM)
attest_sbom() {
    log_info "Generating SBOM attestation..."
    
    # Create a simple SBOM for testing
    cat > sbom-test.json << 'EOF'
{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "aegisgate-platform",
  "documentNamespace": "https://aegisgatesecurity.io/sbom/test",
  "creationInfo": {
    "created": "2026-04-30T00:00:00Z"
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package",
      "name": "aegisgate-platform",
      "versionInfo": "test",
      "supplier": "AegisGate Security"
    }
  ]
}
EOF
    
    # Attest SBOM to image
    cosign attest --yes --type spdxjson \
        --predicate sbom-test.json \
        "${IMAGE_NAME}:${IMAGE_TAG}" 2>&1 || {
        log_warn "SBOM attestation requires keyless OIDC"
        rm -f sbom-test.json
        return 0
    }
    
    rm -f sbom-test.json
    log_success "SBOM attested"
}

# Push image
push() {
    log_info "Pushing image to registry..."
    docker push "${IMAGE_NAME}:${IMAGE_TAG}"
    docker push "${IMAGE_NAME}:latest"
    log_success "Image pushed"
}

# Cleanup
cleanup() {
    log_info "Cleaning up test artifacts..."
    docker rmi "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || true
    rm -f cosign.key cosign.pub 2>/dev/null || true
    log_success "Cleanup complete"
}

# Print help
usage() {
    cat << EOF
AegisGate Cosign Signing Test Script

Usage: ./sign-test.sh [command]

Commands:
    build     Build the Docker image (default)
    sign      Sign the image with cosign
    attest    Generate and attest SBOM
    verify    Verify signature
    push      Push image to registry
    all       Run full workflow (build, sign, attest, verify, push)
    clean     Clean up test artifacts
    help      Show this help message

Environment Variables:
    IMAGE_NAME    Registry image name (default: ghcr.io/aegisgatesecurity/aegisgate-platform)
    IMAGE_TAG     Image tag (default: test-signing)
    SIGNING_KEY   Path to cosign private key (optional)

Examples:
    # Build and sign locally
    ./sign-test.sh build
    SIGNING_KEY=./cosign.key ./sign-test.sh sign
    
    # Full workflow
    ./sign-test.sh all
    
    # Verify only
    ./sign-test.sh verify

EOF
}

# Main
main() {
    check_prereqs
    
    case "${1:-help}" in
        build)   build_image ;;
        sign)    sign_keyless; sign_with_key ;;
        attest)  attest_sbom ;;
        verify)  verify ;;
        push)    push ;;
        all)
            build_image
            sign_keyless || sign_with_key
            attest_sbom
            verify
            push
            ;;
        clean)   cleanup ;;
        help|--help|-h) usage ;;
        *)
            log_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
