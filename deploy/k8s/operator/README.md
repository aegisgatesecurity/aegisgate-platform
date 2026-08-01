# AegisGate Kubernetes Operator

A Kubernetes operator that manages AegisGate Security Platform deployments via a custom resource definition (CRD). The operator watches `AegisGateDeployment` resources and automatically creates, updates, and manages the underlying Kubernetes Deployment, Service, and (optionally) HPA resources.

## What the Operator Does

The AegisGate Operator extends Kubernetes with a custom resource (`AegisGateDeployment`) that declaratively manages the full lifecycle of an AegisGate security proxy deployment:

- **Creates and manages** a Kubernetes `Deployment` with the specified container image, replicas, tier, ports, and resource requirements
- **Creates and manages** a Kubernetes `Service` exposing the proxy, MCP, and dashboard ports
- **Injects configuration** via environment variables derived from the CRD spec (tier, ports, ML settings, compliance)
- **References secrets** for license key injection
- **Updates status** subresource with available replicas, readiness, and conditions
- **Watches for changes** and reconciles the desired state continuously

## Installation

### 1. Install the CRD

```bash
kubectl apply -f deploy/k8s/operator/crd.yaml
```

### 2. Install RBAC

```bash
kubectl apply -f deploy/k8s/operator/rbac.yaml
```

### 3. Deploy the Operator

Build and push the operator image, then deploy it (example manifest):

```bash
# Build the operator
cd cmd/aegisgate-operator
go build -o aegisgate-operator .

# Containerize and push (adjust for your registry)
docker build -t your-registry/aegisgate-operator:latest .
docker push your-registry/aegisgate-operator:latest
```

Create a `Deployment` for the operator itself in the `aegisgate-system` namespace:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aegisgate-operator
  namespace: aegisgate-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: aegisgate-operator
  template:
    metadata:
      labels:
        app: aegisgate-operator
    spec:
      serviceAccountName: aegisgate-operator
      containers:
        - name: operator
          image: your-registry/aegisgate-operator:latest
          env:
            - name: WATCH_NAMESPACE
              value: ""  # Watch all namespaces
```

### 4. Create an AegisGateDeployment

```bash
kubectl apply -f example-aegisgate.yaml
```

## Example AegisGateDeployment CR

```yaml
apiVersion: aegisgate.io/v1alpha1
kind: AegisGateDeployment
metadata:
  name: aegisgate-prod
  namespace: production
spec:
  replicas: 3
  image: aegisgate/aegisgate:latest
  tier: enterprise
  proxyPort: 8080
  mcpPort: 8081
  dashboardPort: 8443
  mlEnabled: true
  mlShadowMode: false
  mlThreshold: 0.90
  resources:
    requests:
      cpu: "500m"
      memory: "512Mi"
    limits:
      cpu: "2000m"
      memory: "2Gi"
  licenseKeySecret: aegisgate-license
  persistence:
    enabled: true
    size: "50Gi"
  compliance:
    frameworks:
      - owasp-top-10
      - soc2
      - pci-dss
    regressionGate: true
```

## Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spec.replicas` | integer | `1` | Number of AegisGate replicas (1–100) |
| `spec.image` | string | *(required)* | Container image for the AegisGate deployment |
| `spec.tier` | enum | `community` | Tier: `community`, `professional`, or `enterprise` |
| `spec.proxyPort` | integer | `8080` | Proxy server port |
| `spec.mcpPort` | integer | `8081` | MCP (Model Context Protocol) server port |
| `spec.dashboardPort` | integer | `8443` | Dashboard HTTPS port |
| `spec.mlEnabled` | boolean | `false` | Enable ML-based anomaly detection |
| `spec.mlShadowMode` | boolean | `true` | Run ML in shadow mode (log, don't block) |
| `spec.mlThreshold` | number | `0.85` | ML anomaly detection threshold (0.0–1.0) |
| `spec.resources.requests.cpu` | string | — | CPU request (e.g., `"500m"`) |
| `spec.resources.requests.memory` | string | — | Memory request (e.g., `"512Mi"`) |
| `spec.resources.limits.cpu` | string | — | CPU limit (e.g., `"2000m"`) |
| `spec.resources.limits.memory` | string | — | Memory limit (e.g., `"2Gi"`) |
| `spec.licenseKeySecret` | string | — | Name of K8s Secret containing the license key |
| `spec.persistence.enabled` | boolean | `false` | Enable persistent storage |
| `spec.persistence.size` | string | `"10Gi"` | PVC size |
| `spec.compliance.frameworks` | string[] | `["owasp-top-10"]` | Compliance frameworks to enforce |
| `spec.compliance.regressionGate` | boolean | `false` | Enable compliance regression gate |

## Architecture

The operator follows a standard Kubernetes reconciliation loop pattern:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AegisGate Operator                               │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   Watcher     │───▶│  Work Queue   │───▶│    Reconciler        │  │
│  │              │    │              │    │                      │  │
│  │ Watches CRD  │    │ Buffered     │    │ 1. Read CRD spec     │  │
│  │ events:      │    │ events for   │    │ 2. Apply defaults    │  │
│  │  - ADD       │    │ processing   │    │ 3. Create/Update     │  │
│  │  - UPDATE    │    │              │    │    - Deployment      │  │
│  │  - DELETE    │    │              │    │    - Service         │  │
│  └──────────────┘    └──────────────┘    │ 4. Update status     │  │
│                                          │    - availableReplicas │  │
│                                          │    - ready             │  │
│                                          │    - conditions        │  │
│                                          └──────────┬───────────┘  │
│                                                     │              │
└─────────────────────────────────────────────────────┼──────────────┘
                                                      │
                                                      ▼
                              ┌──────────────────────────────────────┐
                              │          Kubernetes API              │
                              │                                      │
                              │  ┌────────────────────────────┐     │
                              │  │  AegisGateDeployment CRD   │     │
                              │  └────────────────────────────┘     │
                              │  ┌────────────────────────────┐     │
                              │  │  Deployment (apps/v1)      │     │
                              │  └────────────────────────────┘     │
                              │  ┌────────────────────────────┐     │
                              │  │  Service (v1)               │     │
                              │  └────────────────────────────┘     │
                              └──────────────────────────────────────┘
```

### Reconciliation Flow

1. **Watch**: The operator watches `AegisGateDeployment` resources for ADD, UPDATE, and DELETE events.
2. **Reconcile**: For each event, the reconciler:
   - Reads the CRD spec and applies defaults
   - Constructs the desired Deployment and Service manifests
   - Checks if the resources already exist:
     - If not → **Create** them
     - If yes → **Update** them to match the desired state
   - Updates the CRD status subresource with availability and condition information
3. **Status**: The status reflects the actual state, enabling other controllers or humans to observe the deployment health.

### Short Names

The CRD registers short names for convenience:
- `agd` — `aegisgatedeployments`
- `aegisgate` — `aegisgatedeployments`

```bash
kubectl get agd
kubectl get aegisgate -n production
```

## Cleanup

```bash
kubectl delete -f deploy/k8s/operator/rbac.yaml
kubectl delete -f deploy/k8s/operator/crd.yaml
```

> **Warning**: Deleting the CRD will remove all `AegisGateDeployment` resources and their managed Deployment/Service objects.