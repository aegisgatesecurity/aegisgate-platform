# AegisGate Platform — Helm Chart Enhancements (v4.1.0)

## Overview

This Helm chart has been enhanced with production-ready monitoring, backup, and scaling capabilities for SOC teams deploying AegisGate Platform in Kubernetes environments.

## What's New

### 1. Horizontal Pod Autoscaler (HPA)

**Purpose:** Automatically scale AegisGate replicas based on CPU/memory utilization.

**Status:** DISABLED by default (opt-in)

**Enable:**
```yaml
# values.yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
  targetMemoryUtilizationPercentage: 80
```

**Requirements:**
- Kubernetes metrics-server installed
- Professional+ tier (for multi-replica clustering)

**Why Disabled by Default:**
- Air-gapped environments may not have metrics-server
- Some SOCs prefer manual scaling for compliance
- Customer-specific scaling policies vary widely

---

### 2. Backup & Restore Scripts

**Purpose:** Simple, reliable PostgreSQL backup/restore for SOHO/SMB customers.

**Location:** `scripts/backup-postgres.sh`, `scripts/restore-postgres.sh`

**Quick Start:**
```bash
# Install scripts
sudo mkdir -p /opt/aegisgate/scripts
sudo cp scripts/*.sh /opt/aegisgate/scripts/
sudo chmod +x /opt/aegisgate/scripts/*.sh

# Create backup directory
sudo mkdir -p /var/backups/aegisgate
sudo chown aegisgate:aegisgate /var/backups/aegisgate

# Run backup
export POSTGRES_PASSWORD='your_password'
/opt/aegisgate/scripts/backup-postgres.sh -c  # -c = compress
```

**Cronjob Example (Daily at 2 AM):**
```bash
# Edit crontab
sudo crontab -e

# Add this line:
0 2 * * * POSTGRES_PASSWORD='your_password' /opt/aegisgate/scripts/backup-postgres.sh -c -r 30 >> /var/log/aegisgate-backup.log 2>&1
```

**See:** `scripts/backup-cronjob-examples.md` for detailed examples (hourly, weekly, hybrid, Kubernetes CronJob).

---

### 3. Grafana Dashboard

**Purpose:** Pre-built SOC dashboard for AegisGate metrics.

**Status:** DISABLED by default (opt-in)

**Enable:**
```yaml
# values.yaml
grafanaDashboard:
  enabled: true
  # sidecarLabel: "grafana_dashboard"  # Optional: change if your Grafana uses different label
```

**Requirements:**
- Grafana with sidecar for dashboards enabled
- Prometheus datasource configured

**Dashboard Panels:**
- Request Rate (req/s)
- Error Rate (%)
- Active Connections
- Security Scans (Total)
- Requests by Method (timeseries)
- Request Latency (p50, p95, p99)
- Rate Limit Hits by Tier
- MCP Connections
- HTTP Status Distribution (pie chart)
- Audit Events (Total)

**Import Manually:**
```bash
# Dashboard JSON is at:
deploy/helm/aegisgate-platform/dashboards/aegisgate-overview.json

# Import via Grafana UI:
# Dashboard → Import → Upload JSON file
```

---

### 4. Prometheus Alert Rules

**Purpose:** Pre-configured alerts for AegisGate monitoring.

**Status:** DISABLED by default (opt-in)

**Enable:**
```yaml
# values.yaml
prometheusRules:
  enabled: true
  additionalLabels:
    release: prometheus  # Match your Prometheus Operator label
```

**Requirements:**
- Prometheus Operator installed
- ServiceMonitor enabled

**Alerts Included:**

| Alert | Severity | Condition |
|-------|----------|-----------|
| AegisGateHighErrorRate | Critical | Error rate > 10% for 5m |
| AegisGatePodDown | Critical | Pod down for 2m |
| AegisGateHighRateLimitHits | Critical | Rate limits > 100/s for 5m |
| AegisGateHighLatency | Warning | p95 latency > 2s for 10m |
| AegisGateLowDiskSpace | Warning | PVC < 20% free for 15m |
| AegisGateHighMemoryUsage | Warning | Memory > 85% for 10m |
| AegisGateHighCPUUsage | Warning | CPU > 85% for 10m |
| AegisGateNoActiveConnections | Warning | No connections for 5m |
| AegisGateSecurityScanSpike | Info | Scan rate 2x normal for 5m |
| AegisGateMCPConnectionDrop | Info | MCP connections drop > 10 for 5m |
| AegisGateCertificateExpiringSoon | Info | Cert expires < 30 days |

**Runbook URLs:** All alerts include `runbook_url` annotation linking to troubleshooting docs.

---

## Installation

### Standard Installation (No Enhancements)

```bash
helm install aegisgate ./deploy/helm/aegisgate-platform
```

### Production Installation (All Enhancements)

```bash
helm install aegisgate ./deploy/helm/aegisgate-platform \
  --values values-production.yaml
```

**Example values-production.yaml:**
```yaml
# Production values for AegisGate Platform
replicaCount: 3

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 75

metrics:
  enabled: true
  serviceMonitor:
    enabled: true
    labels:
      release: prometheus

grafanaDashboard:
  enabled: true

prometheusRules:
  enabled: true
  additionalLabels:
    release: prometheus

persistence:
  size: 10Gi
  storageClassName: gp3

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: "2"
    memory: 2Gi
```

---

## Backup Strategy Recommendations

### SOHO (1-10 users)
- **Frequency:** Daily
- **Retention:** 30 days
- **Storage:** Local disk
- **Cronjob:** `0 2 * * *` (2 AM daily)

### SMB (10-100 users)
- **Frequency:** Daily + Weekly
- **Retention:** 14 days (daily) + 90 days (weekly)
- **Storage:** Local + offsite (S3, another server)
- **Cronjob:** Hybrid approach (see `backup-cronjob-examples.md`)

### Enterprise (100+ users)
- **Frequency:** Hourly (critical) or Daily
- **Retention:** 7 days (hourly) + 365 days (weekly)
- **Storage:** Enterprise backup system (Veeam, Commvault, etc.)
- **Method:** Use your existing backup infrastructure + AegisGate scripts for application-consistent backups

---

## Monitoring Stack Integration

### Prometheus + Grafana (Recommended)

```bash
# Install Prometheus Operator
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace

# Enable AegisGate monitoring
helm upgrade aegisgate ./deploy/helm/aegisgate-platform \
  --set metrics.serviceMonitor.enabled=true \
  --set grafanaDashboard.enabled=true \
  --set prometheusRules.enabled=true
```

### Standalone Prometheus

```yaml
# values.yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: false  # No Prometheus Operator

# Manually scrape /metrics endpoint
# Prometheus config:
# scrape_configs:
#   - job_name: 'aegisgate'
#     static_configs:
#       - targets: ['aegisgate-platform:8443']
#     metrics_path: '/metrics'
#     scheme: https
```

---

## Troubleshooting

### HPA Not Scaling

```bash
# Check if metrics-server is running
kubectl get pods -n kube-system | grep metrics-server

# Check HPA status
kubectl get hpa -n aegisgate

# Check metrics availability
kubectl top pods -n aegisgate
```

### Backup Fails

```bash
# Check PostgreSQL connectivity
pg_dump -h <host> -U aegisgate -d aegisgate --version

# Check disk space
df -h /var/backups

# Check backup logs
tail -50 /var/log/aegisgate-backup.log
```

### Dashboard Not Showing

```bash
# Check if ConfigMap was created
kubectl get configmap -n aegisgate | grep grafana

# Check Grafana sidecar logs
kubectl logs -n grafana <grafana-pod> | grep sidecar

# Verify dashboard label
kubectl get configmap aegisgate-grafana-dashboard -o yaml | grep -A 5 labels
```

### Alerts Not Firing

```bash
# Check if PrometheusRule was created
kubectl get prometheusrule -n aegisgate

# Verify Prometheus can see the rules
kubectl port-forward -n prometheus svc/prometheus-k8s 9090:9090
# Visit: http://localhost:9090/rules

# Check alert status
kubectl port-forward -n prometheus svc/prometheus-k8s 9090:9090
# Visit: http://localhost:9090/alerts
```

---

## Security Considerations

### Backup Security

1. **Encrypt backups** for sensitive data:
   ```bash
   /opt/aegisgate/scripts/backup-postgres.sh -c | gpg --encrypt --recipient admin@example.com > backup.sql.gz.gpg
   ```

2. **Secure credentials**:
   - Use `.pgpass` file instead of environment variables
   - Restrict file permissions: `chmod 600 /var/lib/postgresql/.pgpass`

3. **Offsite backups**:
   - Copy to S3: `aws s3 cp /var/backups/aegisgate/ s3://your-bucket/aegisgate-backups/ --recursive`
   - Copy to another server: `rsync -avz /var/backups/aegisgate/ backup-server:/backups/aegisgate/`

### Dashboard Security

1. **Restrict access** to Grafana:
   - Enable authentication
   - Use RBAC for dashboard access
   - Don't expose Grafana publicly

2. **Mask sensitive data**:
   - Dashboard doesn't show API keys, credentials
   - Metrics are aggregated (no PII exposed)

### Alert Security

1. **Secure alerting channels**:
   - Use encrypted webhooks (HTTPS)
   - Don't include sensitive data in alert annotations
   - Restrict Alertmanager access

---

## Contributing

Found a bug or want to add a panel to the dashboard?

1. **Dashboard:** Edit `dashboards/aegisgate-overview.json` in Grafana UI → Export JSON → Replace file
2. **Alerts:** Edit `templates/prometheusrule.yaml` → Test with `helm lint` → Submit PR
3. **Scripts:** Edit `scripts/*.sh` → Test locally → Submit PR

---

## Support

- **Documentation:** https://docs.aegisgatesecurity.io
- **GitHub Issues:** https://github.com/aegisgatesecurity/aegisgate-platform/issues
- **Community:** https://discord.gg/aegisgate (Professional+ tier)
- **Enterprise Support:** support@aegisgatesecurity.io (Enterprise tier)
