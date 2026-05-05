#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# =========================================================================
# AegisGate Test Lab - Setup Script
# =========================================================================
#
# This script sets up the test lab environment:
# 1. Starts Docker Compose services
# 2. Waits for Keycloak to be ready
# 3. Exports environment variables for tests
#
# Usage:
#   ./scripts/setup.sh
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

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Start services
start_services() {
    log_info "Starting Docker Compose services..."
    
    # Check if docker-compose or docker compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    $COMPOSE_CMD up -d
    
    log_info "Services started"
}

# Wait for Keycloak to be ready
wait_for_keycloak() {
    log_info "Waiting for Keycloak to be ready..."
    
    KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
    MAX_RETRIES=30
    RETRY_COUNT=0
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if curl -sf "${KEYCLOAK_URL}/health/ready" > /dev/null 2>&1; then
            log_info "Keycloak is ready"
            return 0
        fi
        
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_info "Waiting for Keycloak... ($RETRY_COUNT/$MAX_RETRIES)"
        sleep 2
    done
    
    log_error "Keycloak did not become ready in time"
    return 1
}

# Wait for PostgreSQL to be ready
wait_for_postgres() {
    log_info "Waiting for PostgreSQL to be ready..."
    
    MAX_RETRIES=20
    RETRY_COUNT=0
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if docker exec aegisgate-postgres-test pg_isready -U aegisgate > /dev/null 2>&1; then
            log_info "PostgreSQL is ready"
            return 0
        fi
        
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_info "Waiting for PostgreSQL... ($RETRY_COUNT/$MAX_RETRIES)"
        sleep 1
    done
    
    log_error "PostgreSQL did not become ready in time"
    return 1
}

# Wait for Redis to be ready
wait_for_redis() {
    log_info "Waiting for Redis to be ready..."
    
    MAX_RETRIES=20
    RETRY_COUNT=0
    
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        if docker exec aegisgate-redis-test redis-cli ping 2>/dev/null | grep -q PONG; then
            log_info "Redis is ready"
            return 0
        fi
        
        RETRY_COUNT=$((RETRY_COUNT + 1))
        log_info "Waiting for Redis... ($RETRY_COUNT/$MAX_RETRIES)"
        sleep 1
    done
    
    log_error "Redis did not become ready in time"
    return 1
}

# Export environment variables
export_env_vars() {
    log_info "Exporting environment variables..."
    
    export LAB_ENABLED=1
    export KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
    export KEYCLOAK_REALM="aegisgate"
    export KEYCLOAK_ADMIN="admin"
    export KEYCLOAK_ADMIN_PASSWORD="admin"
    export OIDC_CLIENT_ID="aegisgate-platform"
    export OIDC_CLIENT_SECRET="aegisgate-oidc-secret"
    export OIDC_ISSUER_URL="${KEYCLOAK_URL}/realms/aegisgate"
    export DATABASE_URL="postgres://aegisgate:aegisgate_test_pass@localhost:5432/aegisgate_test?sslmode=disable"
    export REDIS_URL="redis://localhost:6379/0"
    export AEGISGATE_TEST_URL="http://localhost:8443"
    
    # Write to .env file for docker-compose
    cat > "$LAB_DIR/.env" << EOF
LAB_ENABLED=1
KEYCLOAK_URL=${KEYCLOAK_URL}
KEYCLOAK_REALM=aegisgate
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin
OIDC_CLIENT_ID=aegisgate-platform
OIDC_CLIENT_SECRET=aegisgate-oidc-secret
OIDC_ISSUER_URL=${KEYCLOAK_URL}/realms/aegisgate
DATABASE_URL=postgres://aegisgate:aegisgate_test_pass@localhost:5432/aegisgate_test?sslmode=disable
REDIS_URL=redis://localhost:6379/0
AEGISGATE_TEST_URL=http://localhost:8443
EOF
    
    log_info "Environment variables exported to $LAB_DIR/.env"
}

# Print summary
print_summary() {
    log_info "=========================================="
    log_info "Test Lab Setup Complete!"
    log_info "=========================================="
    log_info ""
    log_info "Services:"
    log_info "  Keycloak:    ${KEYCLOAK_URL:-http://localhost:8080}"
    log_info "  PostgreSQL:   localhost:5432"
    log_info "  Redis:       localhost:6379"
    log_info "  AegisGate:   localhost:8443"
    log_info ""
    log_info "Test Users:"
    log_info "  admin/admin (admin role)"
    log_info "  operator/operator (operator role)"
    log_info "  developer/developer (developer role)"
    log_info "  viewer/viewer (viewer role)"
    log_info ""
    log_info "Run tests with:"
    log_info "  cd .. && source testlab/.env && go test -tags=lab -v ./pkg/sso/..."
    log_info ""
    log_info "Stop services with:"
    log_info "  docker-compose down"
    log_info ""
}

# Main
main() {
    log_info "AegisGate Test Lab Setup"
    log_info "========================"
    
    check_prerequisites
    start_services
    wait_for_keycloak
    wait_for_postgres
    wait_for_redis
    export_env_vars
    print_summary
}

main "$@"
