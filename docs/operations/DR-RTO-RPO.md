# Disaster Recovery, RTO, and RPO

**Version:** 4.3.1  
**Last Tested:** 2026-08-23  
**Status:** ✅ VALIDATED

---

## Executive Summary

AegisGate Platform is designed for rapid recovery from infrastructure failures with:

- **Recovery Time Objective (RTO):** 15 minutes
- **Recovery Point Objective (RPO):** 1 hour (with hourly backups)
- **Recovery Point Objective (RPO):** 5 minutes (with continuous replication)

These objectives are achievable with the documented backup and recovery procedures.

---

## RTO/RPO Definitions

| Metric | Target | Definition |
|--------|--------|------------|
| **RTO (Recovery Time Objective)** | 15 minutes | Maximum acceptable time from disaster declaration to full service restoration |
| **RPO (Recovery Point Objective)** | 1 hour | Maximum acceptable data loss measured in time (with hourly backups) |
| **MTTR (Mean Time to Recovery)** | <15 minutes | Average time to restore service (validated in DR tests) |
| **Backup Frequency** | Hourly | Automated PostgreSQL backups every hour |
| **Backup Retention** | 30 days | All backups retained for 30 days |

---

## Disaster Scenarios

### Scenario 1: Single Node Failure (Most Common)

**Impact:** Platform unavailable on affected node  
**Detection:** Health check failure, monitoring alert  
**Recovery:** Automated failover to standby node (if configured) or manual restart  
**RTO:** 5-15 minutes  
**RPO:** 0 (no data loss with PostgreSQL WAL archiving)

**Recovery Steps:**
1. Identify failed node via monitoring dashboard
2. If standby available: verify automatic failover
3. If no standby: restart platform container
4. Verify health check passes
5. Resume normal operations

### Scenario 2: Database Corruption

**Impact:** Data integrity compromised  
**Detection:** PostgreSQL errors, application failures  
**Recovery:** Restore from most recent backup  
**RTO:** 15-30 minutes  
**RPO:** 1 hour (time since last backup)

**Recovery Steps:**
1. Stop platform to prevent further corruption
2. Identify most recent valid backup
3. Restore PostgreSQL from backup
4. Restart platform
5. Verify data integrity
6. Resume normal operations

### Scenario 3: Complete Infrastructure Loss (Worst Case)

**Impact:** Total platform loss  
**Detection:** Complete outage, no health checks  
**Recovery:** Rebuild infrastructure from backups  
**RTO:** 30-60 minutes  
**RPO:** 1 hour (time since last backup)

**Recovery Steps:**
1. Provision new infrastructure (VM, K8s cluster)
2. Install Docker/container runtime
3. Deploy platform from Docker image
4. Restore PostgreSQL from backup
5. Restore configuration from backup
6. Verify all services healthy
7. Resume normal operations

---

## Backup Procedures

### Automated Backups

**Frequency:** Hourly  
**Retention:** 30 days  
**Storage:** Local disk (recommended: mounted volume or S3-compatible object storage)

**Setup:**
```bash
# Install backup script
sudo mkdir -p /opt/aegisgate/scripts
sudo cp backup-postgres.sh /opt/aegisgate/scripts/
sudo chmod +x /opt/aegisgate/scripts/backup-postgres.sh

# Create backup directory
sudo mkdir -p /var/backups/aegisgate
sudo chown aegisgate:aegisgate /var/backups/aegisgate

# Configure hourly cronjob
sudo crontab -e
# Add: 0 * * * * POSTGRES_PASSWORD='secure_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 30 >> /var/log/aegisgate-backup.log 2>&1
```

### Manual Backups

```bash
# Full backup with compression
./scripts/backup-postgres.sh -c -v

# Backup to custom location
./scripts/backup-postgres.sh -o /mnt/external-drive/backups -c

# Verify backup integrity
pg_restore --list /var/backups/aegisgate/aegisgate_20260823_1400.backup
```

### Backup Verification

**Weekly:** Test restore to staging environment  
**Monthly:** Full DR drill (see below)

```bash
# Verify backup is valid
pg_restore --list backup_file.backup

# Test restore to staging
./scripts/restore-postgres.sh -d aegisgate_staging backup_file.backup
```

---

## Recovery Procedures

### Quick Start Recovery (RTO <15 minutes)

**Prerequisites:**
- Recent backup available
- Infrastructure intact
- Docker/container runtime operational

**Steps:**
```bash
# 1. Stop existing platform (if running)
docker compose -f docker-compose.yml down

# 2. Restore PostgreSQL from backup
./scripts/restore-postgres.sh /var/backups/aegisgate/latest.backup

# 3. Start platform
docker compose -f docker-compose.yml up -d

# 4. Verify health
curl -s http://localhost:8443/health | jq

# Expected: {"status":"healthy", ...}
```

**Time:** 10-15 minutes  
**Data Loss:** 0-60 minutes (depending on backup frequency)

### Full Infrastructure Recovery (RTO 30-60 minutes)

**Prerequisites:**
- Recent backup available
- New infrastructure provisioned
- Network connectivity established

**Steps:**
```bash
# 1. Provision new infrastructure
# (VM with 4 CPU, 8GB RAM, 50GB disk for SMB; adjust for enterprise)

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo systemctl enable docker
sudo systemctl start docker

# 3. Deploy platform
git clone https://github.com/aegisgatesecurity/aegisgate-platform.git
cd aegisgate-platform
docker compose up -d

# 4. Restore PostgreSQL
./scripts/restore-postgres.sh /path/to/backup.backup

# 5. Restore configuration
cp /path/to/backup/config.yaml /data/config.yaml

# 6. Restart platform to apply config
docker compose restart

# 7. Verify all services
curl -s http://localhost:8443/health | jq
curl -s http://localhost:8443/api/v1/sla | jq

# 8. Update DNS/load balancer to point to new infrastructure
# (TTL-dependent, typically 5-15 minutes)
```

**Time:** 30-60 minutes  
**Data Loss:** 0-60 minutes (depending on backup frequency)

---

## DR Testing Schedule

### Monthly DR Drill (Required)

**Objective:** Validate RTO <15 minutes  
**Scope:** Single node failure recovery  
**Frequency:** Monthly  
**Duration:** 30 minutes

**Test Procedure:**
1. Schedule maintenance window
2. Take full backup
3. Stop platform container
4. Execute recovery procedure
5. Measure time from stop to healthy
6. Verify data integrity
7. Document results
8. Resume normal operations

**Success Criteria:**
- Platform healthy within 15 minutes
- No data corruption detected
- All services functional
- Health check passes

### Quarterly Full DR Test (Recommended)

**Objective:** Validate full infrastructure recovery  
**Scope:** Complete rebuild from backup  
**Frequency:** Quarterly  
**Duration:** 2 hours

**Test Procedure:**
1. Schedule maintenance window
2. Take full backup
3. Provision new test infrastructure
4. Deploy platform from scratch
5. Restore from backup
6. Verify all services
7. Run integration tests
8. Document results
9. Decommission test infrastructure

**Success Criteria:**
- Platform healthy within 60 minutes
- No data corruption detected
- All integration tests pass
- RPO within 1 hour

---

## DR Test Results

### Test 1: 2026-08-23 (Initial Validation)

**Scenario:** Single node failure  
**RTO Achieved:** 12 minutes  
**RPO Achieved:** 0 minutes (no data loss)  
**Status:** ✅ PASS

**Details:**
- Backup taken: 2026-08-23 14:00 UTC
- Platform stopped: 2026-08-23 14:30 UTC
- Recovery initiated: 2026-08-23 14:31 UTC
- Platform healthy: 2026-08-23 14:43 UTC
- **Total recovery time: 12 minutes**
- Data integrity: ✅ Verified (all records present)
- Service health: ✅ All endpoints responding

**Lessons Learned:**
- Recovery script execution: 3 minutes
- PostgreSQL restore: 6 minutes
- Platform startup: 2 minutes
- Health verification: 1 minute

### Test 2: Scheduled 2026-09-23

**Scenario:** Full infrastructure rebuild  
**RTO Target:** 60 minutes  
**RPO Target:** 1 hour  
**Status:** ⏳ SCHEDULED

---

## Monitoring & Alerting

### Critical Alerts (Page Immediately)

| Alert | Condition | Action |
|-------|-----------|--------|
| Platform Unhealthy | Health check fails for 2 minutes | Investigate, prepare for DR |
| Backup Failed | Hourly backup fails | Manual backup, investigate |
| Disk Space <20% | Backup volume low on space | Expand storage, clean old backups |
| PostgreSQL Down | Database unavailable | Execute DR procedure |

### Warning Alerts (Investigate During Business Hours)

| Alert | Condition | Action |
|-------|-----------|--------|
| Backup Age >2 hours | No recent backup | Investigate backup system |
| Recovery Time >10 min | Slow restore | Optimize backup/restore |
| Replication Lag >5 min | WAL archiving delayed | Investigate replication |

### Monitoring Commands

```bash
# Check platform health
curl -s http://localhost:8443/health | jq '.status'

# Check backup status
ls -lht /var/backups/aegisgate/ | head -5

# Verify latest backup integrity
pg_restore --list /var/backups/aegisgate/latest.backup | head -10

# Check PostgreSQL status
docker exec postgres pg_isready
```

---

## Responsibilities

### Platform Team (You)

- Execute monthly DR drills
- Investigate backup failures
- Maintain DR documentation
- Report DR test results

### Infrastructure Team (Customer/Partner)

- Provision infrastructure
- Configure monitoring
- Manage backups (if outsourced)
- Execute DR procedures (if delegated)

### Security Team

- Review DR procedures annually
- Validate RTO/RPO meet compliance requirements
- Participate in quarterly DR tests

---

## Compliance Mapping

| Framework | Requirement | AegisGate Control |
|-----------|-------------|-------------------|
| **SOC 2** | CC7.4 System recovery | DR procedures, monthly testing |
| **HIPAA** | 164.308(a)(7) Contingency plan | RTO/RPO documentation, backups |
| **PCI-DSS** | 12.10 Incident response | DR procedures, testing schedule |
| **ISO 27001** | A.17.1.3 Continuity | DR documentation, testing |
| **FedRAMP** | CP-10 Contingency Plan | RTO/RPO, quarterly testing |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-08-23 | AegisGate Team | Initial DR documentation |
| | | | - RTO/RPO targets defined |
| | | | - Backup procedures documented |
| | | | - Recovery procedures validated |
| | | | - Monthly DR test schedule established |

---

## Related Documents

- **RUNBOOK-010:** Incident Response
- **scripts/backup-postgres.sh:** Automated backup script
- **scripts/restore-postgres.sh:** Recovery script
- **docs/operations/posture-check.md:** Platform health verification
- **docs/troubleshooting.md:** Common issues and resolutions

---

**Approved By:** AegisGate Security Team  
**Next Review:** 2026-11-23 (Quarterly)  
**DR Test Schedule:** Monthly (last Saturday of each month)
