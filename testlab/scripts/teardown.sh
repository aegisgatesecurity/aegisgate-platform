#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Test Lab - Teardown Script
# =========================================================================
#
# This script stops and cleans up the test lab environment:
# 1. Stops Docker Compose services
# 2. Removes volumes (optional)
# 3. Cleans up environment files
#
# Usage:
#   ./scripts/teardown.sh        # Stop services
#   ./scripts/teardown.sh -v    # Stop and remove volumes
#
# =========================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
cd "$LAB_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

REMOVE_VOLUMES=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--volumes)
            REMOVE_VOLUMES=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [-v|--volumes]"
            echo "  -v, --volumes    Remove Docker volumes (WARNING: destroys data)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Stop services
stop_services() {
    log_info "Stopping Docker Compose services..."
    
    # Check if docker-compose or docker compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    if $COMPOSE_CMD ps &> /dev/null; then
        $COMPOSE_CMD down
        
        if [ "$REMOVE_VOLUMES" = true ]; then
            log_warn "Removing volumes..."
            $COMPOSE_CMD down -v
        fi
        
        log_info "Services stopped"
    else
        log_info "No running services found"
    fi
}

# Clean up environment files
cleanup_env() {
    log_info "Cleaning up environment files..."
    
    if [ -f "$LAB_DIR/.env" ]; then
        rm -f "$LAB_DIR/.env"
        log_info "Removed .env file"
    fi
}

# Main
main() {
    log_info "AegisGate Test Lab Teardown"
    log_info "==========================="
    
    if [ "$REMOVE_VOLUMES" = true ]; then
        log_warn "WARNING: Volumes will be removed - all data will be lost!"
        read -p "Continue? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Cancelled"
            exit 0
        fi
    fi
    
    stop_services
    cleanup_env
    
    log_info "=========================================="
    log_info "Teardown Complete!"
    log_info "=========================================="
    log_info ""
    log_info "To restart the lab:"
    log_info "  ./scripts/setup.sh"
    log_info ""
}

main "$@"
