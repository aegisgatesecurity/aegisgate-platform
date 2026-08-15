# AegisGate Platform — Backup Cronjob Examples

## Prerequisites

1. Install scripts:
   ```bash
   sudo mkdir -p /opt/aegisgate/scripts
   sudo cp backup-postgres.sh restore-postgres.sh /opt/aegisgate/scripts/
   sudo chmod +x /opt/aegisgate/scripts/*.sh
   ```

2. Set PostgreSQL credentials (securely):
   ```bash
   # Option 1: Environment variable (recommended for cron)
   echo "export POSTGRES_PASSWORD='your_secure_password'" | sudo tee -a /etc/environment
   
   # Option 2: .pgpass file (more secure)
   echo "localhost:5432:aegisgate:aegisgate:your_secure_password" | sudo tee -a /var/lib/postgresql/.pgpass
   sudo chmod 600 /var/lib/postgresql/.pgpass
   sudo chown postgres:postgres /var/lib/postgresql/.pgpass
   ```

3. Create backup directory:
   ```bash
   sudo mkdir -p /var/backups/aegisgate
   sudo chown aegisgate:aegisgate /var/backups/aegisgate
   ```

---

## Cronjob Examples

### Example 1: Daily Backup (Recommended for Most SOHO/SMB)

**Schedule:** Daily at 2:00 AM  
**Retention:** 30 days  
**Compression:** Yes

```bash
# Edit crontab
sudo crontab -e

# Add this line:
0 2 * * * POSTGRES_PASSWORD='your_secure_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 30 >> /var/log/aegisgate-backup.log 2>&1
```

**What this does:**
- Runs every day at 2 AM
- Compresses backup (saves ~70% disk space)
- Keeps 30 days of backups
- Logs to `/var/log/aegisgate-backup.log`

---

### Example 2: Hourly Backup (High-Traffic/Critical Systems)

**Schedule:** Every hour  
**Retention:** 7 days  
**Compression:** Yes

```bash
0 * * * * POSTGRES_PASSWORD='your_secure_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 7 >> /var/log/aegisgate-backup.log 2>&1
```

**What this does:**
- Runs every hour
- Compresses backup
- Keeps 7 days (168 backups total)
- Good for high-traffic systems with frequent changes

**Disk space estimate:** ~50MB per compressed backup × 168 = ~8.4GB

---

### Example 3: Weekly Backup (Low-Traffic/Dev Environments)

**Schedule:** Every Sunday at 3:00 AM  
**Retention:** 90 days  
**Compression:** Yes

```bash
0 3 * * 0 POSTGRES_PASSWORD='your_secure_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 90 >> /var/log/aegisgate-backup.log 2>&1
```

**What this does:**
- Runs every Sunday at 3 AM
- Compresses backup
- Keeps 90 days (~3 months)
- Good for low-traffic or development environments

---

### Example 4: Daily + Weekly (Hybrid Approach)

**Schedule:** Daily at 2 AM + Weekly on Sunday at 3 AM  
**Retention:** 14 days (daily) + 365 days (weekly)  
**Compression:** Yes

```bash
# Daily backup (14-day retention)
0 2 * * * POSTGRES_PASSWORD='your_secure_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 14 -o /var/backups/aegisgate/daily >> /var/log/aegisgate-backup.log 2>&1

# Weekly backup (365-day retention for compliance)
0 3 * * 0 POSTGRES_PASSWORD='your_secure_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 365 -o /var/backups/aegisgate/weekly >> /var/log/aegisgate-backup.log 2>&1
```

**What this does:**
- Daily backups for recent restores (2 weeks)
- Weekly backups for long-term compliance (1 year)
- Separate directories for easy management

---

### Example 5: Kubernetes CronJob (For Helm Deployments)

**File:** `backup-cronjob.yaml`

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: aegisgate-backup
  namespace: aegisgate
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15-alpine
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h aegisgate-postgres -U aegisgate -d aegisgate | gzip > /backups/aegisgate_backup_$(date +\%Y\%m\%d_\%H\%M\%S).sql.gz
              find /backups -name "aegisgate_backup_*.sql.gz" -mtime +30 -delete
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: aegisgate-secrets
                  key: postgres-password
            volumeMounts:
            - name: backup-storage
              mountPath: /backups
          restartPolicy: OnFailure
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: aegisgate-backup-pvc
```

**Apply:**
```bash
kubectl apply -f backup-cronjob.yaml
```

---

## Monitoring & Alerts

### Check Backup Status

```bash
# List recent backups
ls -lht /var/backups/aegisgate/aegisgate_backup_*.sql.gz | head -10

# Check backup log
tail -50 /var/log/aegisgate-backup.log

# Verify latest backup is recent (within 24 hours)
find /var/backups/aegisgate -name "aegisgate_backup_*.sql.gz" -mtime -1 | wc -l
# Should return: 1 or more
```

### Simple Monitoring Script

```bash
#!/bin/bash
# backup-monitor.sh - Check if backup is recent

BACKUP_DIR="/var/backups/aegisgate"
MAX_AGE_HOURS=26  # Allow 2-hour buffer

LATEST=$(find "$BACKUP_DIR" -name "aegisgate_backup_*.sql.gz" -mmin -$((MAX_AGE_HOURS * 60)) | wc -l)

if [[ $LATEST -eq 0 ]]; then
    echo "CRITICAL: No recent backup found in last $MAX_AGE_HOURS hours"
    exit 2
else
    echo "OK: Recent backup found"
    exit 0
fi
```

**Add to cron for hourly check:**
```bash
0 * * * * /opt/aegisgate/scripts/backup-monitor.sh | mail -s "Backup Status" admin@example.com
```

---

## Restore Instructions

### Test Restore (Dry Run)

```bash
# Find latest backup
LATEST=$(ls -t /var/backups/aegisgate/aegisgate_backup_*.sql.gz | head -1)

# Test restore (no changes made)
sudo /opt/aegisgate/scripts/restore-postgres.sh -t "$LATEST"
```

### Actual Restore

```bash
# WARNING: This will DROP and REPLACE the existing database
sudo /opt/aegisgate/scripts/restore-postgres.sh -f "$LATEST"
```

### Restore to Test Database

```bash
# Restore to a test database (safe, doesn't affect production)
sudo /opt/aegisgate/scripts/restore-postgres.sh -d aegisgate_test "$LATEST"
```

---

## Best Practices

1. **Test restores regularly** — At least quarterly, verify you can restore from backups
2. **Offsite backups** — Copy backups to a different location (S3, another server, etc.)
3. **Encrypt backups** — For sensitive data, consider encrypting backup files
4. **Monitor disk space** — Ensure `/var/backups` has sufficient space
5. **Rotate logs** — Logrotate for `/var/log/aegisgate-backup.log`
6. **Document procedures** — Ensure team knows how to restore in emergency

---

## Troubleshooting

### Backup Fails with "permission denied"

```bash
# Ensure script is executable
sudo chmod +x /opt/aegisgate/scripts/backup-postgres.sh

# Ensure backup directory is writable
sudo chown aegisgate:aegisgate /var/backups/aegisgate
```

### pg_dump Not Found

```bash
# Install PostgreSQL client
sudo apt-get install postgresql-client  # Debian/Ubuntu
sudo yum install postgresql             # RHEL/CentOS
```

### Backup Too Large

- Enable compression: `-c` flag
- Reduce retention: `-r 7` (7 days instead of 30)
- Consider incremental backups (pg_basebackup for large databases)

### Cronjob Not Running

```bash
# Check cron service
sudo systemctl status cron

# Check cron logs
grep CRON /var/log/syslog | tail -20

# Test cronjob manually
sudo /opt/aegisgate/scripts/backup-postgres.sh -c
```
