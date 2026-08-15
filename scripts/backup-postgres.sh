#!/bin/bash
# =========================================================================
# AegisGate Platform — PostgreSQL Backup Script
# =========================================================================
#
# USAGE:
#   ./backup-postgres.sh [OPTIONS]
#
# OPTIONS:
#   -d, --database   Database name (default: aegisgate)
#   -u, --user       Database user (default: aegisgate)
#   -h, --host       Database host (default: localhost)
#   -p, --port       Database port (default: 5432)
#   -o, --output     Backup directory (default: /var/backups/aegisgate)
#   -r, --retention  Retention days (default: 30)
#   -c, --compress   Compress backup (gzip) [optional]
#   -v, --verbose    Verbose output [optional]
#   -h, --help       Show this help
#
# EXAMPLES:
#   # Basic backup (uses defaults)
#   ./backup-postgres.sh
#
#   # Backup with custom database and retention
#   ./backup-postgres.sh -d aegisgate_prod -r 60
#
#   # Compressed backup with verbose output
#   ./backup-postgres.sh -c -v
#
# CRONJOB EXAMPLE (daily at 2 AM, 30-day retention):
#   0 2 * * * /opt/aegisgate/scripts/backup-postgres.sh -c >> /var/log/aegisgate-backup.log 2>&1
#
# CRONJOB EXAMPLE (hourly, 7-day retention for high-traffic):
#   0 * * * * /opt/aegisgate/scripts/backup-postgres.sh -r 7 -c >> /var/log/aegisgate-backup.log 2>&1
#
# CRONJOB EXAMPLE (weekly on Sunday at 3 AM, 90-day retention):
#   0 3 * * 0 /opt/aegisgate/scripts/backup-postgres.sh -r 90 -c >> /var/log/aegisgate-backup.log 2>&1
#
# RESTORE:
#   See restore-postgres.sh
#
# =========================================================================

set -euo pipefail

# Defaults
DATABASE="aegisgate"
USER="aegisgate"
HOST="localhost"
PORT="5432"
OUTPUT_DIR="/var/backups/aegisgate"
RETENTION_DAYS=30
COMPRESS=false
VERBOSE=false

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

# Parse arguments
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
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -r|--retention)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        -c|--compress)
            COMPRESS=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            ;;
    esac
done

# Validate prerequisites
command -v pg_dump >/dev/null 2>&1 || { log_error "pg_dump not found. Install postgresql-client."; exit 1; }

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate backup filename
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
BACKUP_FILE="${OUTPUT_DIR}/aegisgate_backup_${TIMESTAMP}.sql"

log_info "Starting PostgreSQL backup"
log "Database: $DATABASE"
log "Host: $HOST:$PORT"
log "User: $USER"
log "Output: $BACKUP_FILE"
log "Retention: $RETENTION_DAYS days"

# Perform backup
if PGPASSWORD="${POSTGRES_PASSWORD:-}" pg_dump \
    -h "$HOST" \
    -p "$PORT" \
    -U "$USER" \
    -d "$DATABASE" \
    --format=plain \
    --no-owner \
    --no-privileges \
    -f "$BACKUP_FILE" 2>/dev/null; then
    
    log_info "Backup completed successfully"
    
    # Compress if requested
    if [[ "$COMPRESS" == true ]]; then
        log "Compressing backup..."
        gzip "$BACKUP_FILE"
        BACKUP_FILE="${BACKUP_FILE}.gz"
        log_info "Compression completed: $BACKUP_FILE"
    fi
    
    # Show backup size
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    log_info "Backup size: $BACKUP_SIZE"
    
else
    log_error "Backup failed!"
    exit 1
fi

# Cleanup old backups
log "Cleaning up backups older than $RETENTION_DAYS days..."
find "$OUTPUT_DIR" -name "aegisgate_backup_*.sql*" -type f -mtime +$RETENTION_DAYS -delete
REMAINING=$(find "$OUTPUT_DIR" -name "aegisgate_backup_*.sql*" -type f | wc -l)
log_info "Remaining backups: $REMAINING"

log_info "Backup process completed"
exit 0
