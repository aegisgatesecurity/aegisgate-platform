# AegisGate Security Platform — Deployment Artifacts

## Quick Reference

| Method | Command |
|--------|---------|
| **Docker Compose** | `docker compose up` |
| **Docker Compose + Monitoring** | `docker compose --profile monitoring up` |
| **Docker Compose + Redis** | `docker compose --profile redis up` |
| **Helm** | `helm install aegisgate ./deploy/helm/aegisgate-platform` |
| **K8s Manifests** | `kubectl apply -f deploy/k8s/manifests/` |

## Directory Layout

```
deploy/
├── docker/
│   └── prometheus.yml        # Prometheus scrape config for Docker Compose
├── helm/
│   └── aegisgate-platform/
│       ├── Chart.yaml         # Helm chart metadata (v1.3.1)
│       ├── values.yaml        # Default values (Community tier)
│       └── templates/
│           ├── _helpers.tpl   # Label helpers
│           ├── deployment.yaml
│           ├── service.yaml
│           ├── ingress.yaml
│           ├── pvc.yaml
│           ├── serviceaccount.yaml
│           ├── servicemonitor.yaml
│           └── secret.yaml
└── k8s/
    └── manifests/
        ├── 00-namespace.yaml
        ├── 01-serviceaccount.yaml
        ├── 02-pvc.yaml
        ├── 03-deployment.yaml
        ├── 04-service.yaml
        ├── 05-hpa.yaml
        └── 06-networkpolicy.yaml
```

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 8080 | Proxy | AI API security gateway |
| 8081 | MCP | Model Context Protocol server |
| 8443 | Dashboard | Admin UI, REST API, Prometheus `/metrics` |

## Tier Configuration

- **Community** (default): Single replica, file persistence, no Redis
- **Developer+**: Enable Redis profile, increase replicas, raise resource limits
- **Professional/Enterprise**: Scale horizontally, enable HPA, add ingress

## Monitoring

The platform exposes Prometheus metrics at `:8443/metrics`:

```yaml
# Docker Compose
docker compose --profile monitoring up

# Helm with ServiceMonitor
helm install aegisgate ./deploy/helm/aegisgate-platform \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.labels.release=prometheus

# K8s manifest (annotations embedded in pod template)
kubectl apply -f deploy/k8s/manifests/
```

## Persistence

The `/data` volume stores audit logs, certificates, and configuration:

- **Docker Compose**: Named volume `aegisgate-data`
- **Helm**: PVC (`persistence.enabled=true`, 1Gi default)
- **K8s Manifests**: PVC `aegisgate-data` (1Gi, `ReadWriteOnce`)