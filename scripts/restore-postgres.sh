#!/bin/bash
# =========================================================================
# AegisGate Platform — PostgreSQL Restore Script
# =========================================================================
#
# USAGE:
#   ./restore-postgres.sh [OPTIONS] <backup_file>
#
# OPTIONS:
#   -d, --database   Database name (default: aegisgate)
#   -u, --user       Database user (default: aegisgate)
#   -h, --host       Database host (default: localhost)
#   -p, --port       Database port (default: 5432)
#   -f, --force      Force restore (drops existing database) [DANGEROUS]
#   -v, --verbose    Verbose output [optional]
#   -t, --test       Test restore (dry run, no changes) [optional]
#   -l, --list       List available backups [optional]
#   -h, --help       Show this help
#
# EXAMPLES:
#   # List available backups
#   ./restore-postgres.sh -l
#
#   # Restore from specific backup
#   ./restore-postgres.sh /var/backups/aegisgate/aegisgate_backup_20260814_020000.sql.gz
#
#   # Restore with custom database (dry run)
#   ./restore-postgres.sh -t -d aegisgate_test /path/to/backup.sql
#
#   # FORCE RESTORE (DROPS EXISTING DATABASE - USE WITH CAUTION)
#   ./restore-postgres.sh -f /path/to/backup.sql.gz
#
# WARNING:
#   - Force restore WILL DROP the existing database
#   - Always test restore in a non-production environment first
#   - Ensure you have a recent backup before restoring
#
# =========================================================================

set -euo pipefail

# Defaults
DATABASE="aegisgate"
USER="aegisgate"
HOST="localhost"
PORT="5432"
FORCE=false
VERBOSE=false
TEST=false
LIST=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    fi
}

log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

show_help() {
    head -50 "$0" | tail -40
    exit 0
}

list_backups() {
    local backup_dir="/var/backups/aegisgate"
    
    if [[ ! -d "$backup_dir" ]]; then
        log_error "Backup directory not found: $backup_dir"
        exit 1
    fi
    
    echo "Available backups in $backup_dir:"
    echo "================================"
    ls -lht "$backup_dir"/aegisgate_backup_*.sql* 2>/dev/null | head -20
    echo ""
    echo "Total backups: $(find "$backup_dir" -name 'aegisgate_backup_*.sql*' -type f | wc -l)"
    exit 0
}

# Parse arguments
BACKUP_FILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--database)
            DATABASE="$2"
            shift 2
            ;;
        -u|--user)
            USER="$2"
            shift 2
            ;;
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -t|--test)
            TEST=true
            shift
            ;;
        -l|--list)
            LIST=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help
            ;;
        *)
            BACKUP_FILE="$1"
            shift
            ;;
    esac
done

# List backups if requested
if [[ "$LIST" == true ]]; then
    list_backups
fi

# Validate backup file
if [[ -z "$BACKUP_FILE" ]]; then
    log_error "No backup file specified"
    show_help
fi

if [[ ! -f "$BACKUP_FILE" ]]; then
    log_error "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Validate prerequisites
command -v psql >/dev/null 2>&1 || { log_error "psql not found. Install postgresql-client."; exit 1; }

log_info "Starting PostgreSQL restore"
log "Backup file: $BACKUP_FILE"
log "Database: $DATABASE"
log "Host: $HOST:$PORT"
log "User: $USER"
log "Force: $FORCE"
log "Test mode: $TEST"

# Determine if backup is compressed
if [[ "$BACKUP_FILE" == *.gz ]]; then
    DECOMPRESS="gunzip -c"
    log "Detected compressed backup"
else
    DECOMPRESS="cat"
fi

# Test mode - just validate backup file
if [[ "$TEST" == true ]]; then
    log_info "Test mode - validating backup file..."
    if $DECOMPRESS "$BACKUP_FILE" | head -20 | grep -q "PostgreSQL database dump"; then
        log_info "Backup file appears valid"
    else
        log_error "Backup file does not appear to be a valid PostgreSQL dump"
        exit 1
    fi
    log_info "Test completed successfully (no changes made)"
    exit 0
fi

# Force restore - drop existing database
if [[ "$FORCE" == true ]]; then
    log_warn "FORCE RESTORE: Dropping existing database '$DATABASE'"
    read -p "Are you ABSOLUTELY SURE? This will DELETE all data in '$DATABASE' (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        log_info "Restore cancelled"
        exit 0
    fi
    
    log "Dropping database..."
    PGPASSWORD="${POSTGRES_PASSWORD:-}" psql \
        -h "$HOST" \
        -p "$PORT" \
        -U "$USER" \
        -d postgres \
        -c "DROP DATABASE IF EXISTS $DATABASE;" 2>/dev/null || true
    
    log "Creating fresh database..."
    PGPASSWORD="${POSTGRES_PASSWORD:-}" psql \
        -h "$HOST" \
        -p "$PORT" \
        -U "$USER" \
        -d postgres \
        -c "CREATE DATABASE $DATABASE;" 2>/dev/null
fi

# Restore backup
log_info "Restoring backup..."
if $DECOMPRESS "$BACKUP_FILE" | PGPASSWORD="${POSTGRES_PASSWORD:-}" psql \
    -h "$HOST" \
    -p "$PORT" \
    -U "$USER" \
    -d "$DATABASE" >/dev/null 2>&1; then
    log_info "Restore completed successfully"
else
    log_error "Restore failed!"
    exit 1
fi

log_info "Restore process completed"
exit 0
