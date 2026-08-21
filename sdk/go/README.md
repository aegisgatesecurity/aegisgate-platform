# AegisGate Platform Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/aegisgatesecurity/aegisgate-platform/sdk/go.svg)](https://pkg.go.dev/github.com/aegisgatesecurity/aegisgate-platform/sdk/go)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The official Go SDK for the **AegisGate v4.3.1** platform API.

## Installation

```bash
go get github.com/aegisgatesecurity/aegisgate-platform/sdk/go
```

Requires **Go 1.26** or later.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    aegisgate "github.com/aegisgatesecurity/aegisgate-platform/sdk/go"
)

func main() {
    // Create client from configuration
    cfg := aegisgate.NewConfig(
        aegisgate.WithBaseURL("https://aegisgate.example.com"),
        aegisgate.WithAPIKey("your-api-key"),
    )

    client, err := aegisgate.NewClient(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Check platform health
    health, err := client.Health.Get(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Health: %s\n", health.Status)

    // Get version
    version, err := client.Version.Get(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Version: %s\n", version.Version)
}
```

## Configuration

### Using Environment Variables

```go
// Reads AEGISGATE_BASE_URL and AEGISGATE_API_KEY
client, err := aegisgate.NewClientFromEnv()
```

### Functional Options

```go
cfg := aegisgate.NewConfig(
    aegisgate.WithBaseURL("https://aegisgate.example.com"),
    aegisgate.WithAPIKey("your-api-key"),
    aegisgate.WithTimeout(60*time.Second),
    aegisgate.WithMaxRetries(5),
)
client, err := aegisgate.NewClient(cfg)
```

### Custom HTTP Client & TLS

```go
import "crypto/tls"

cfg := aegisgate.NewConfig(
    aegisgate.WithBaseURL("https://aegisgate.example.com"),
    aegisgate.WithAPIKey("your-api-key"),
    aegisgate.WithTLS(&tls.Config{
        InsecureSkipVerify: false,
    }),
)
```

### Bearer Token Authentication

```go
cfg := aegisgate.NewConfig(
    aegisgate.WithBaseURL("https://aegisgate.example.com"),
    aegisgate.WithToken("your-bearer-token"),
)
```

> **Note:** When both `Token` and `APIKey` are set, `Token` takes precedence.

### Configuration Reference

| Option | Description | Default |
|--------|-------------|---------|
| `WithBaseURL(url)` | Platform base URL | `http://localhost:8080` |
| `WithAPIKey(key)` | API key for `X-API-Key` header | — |
| `WithToken(token)` | Bearer token for `Authorization` header | — |
| `WithTimeout(d)` | HTTP request timeout | `30s` |
| `WithMaxRetries(n)` | Max retry attempts for 5xx/network errors | `3` |
| `WithHTTPClient(hc)` | Pre-configured `*http.Client` | — |
| `WithTLS(tlsCfg)` | TLS config for default transport | — |

## Services

The SDK provides typed service methods for every AegisGate v3.6.0 API endpoint. All methods accept `context.Context` as the first parameter.

### Auth

```go
// Login
loginResp, err := client.Auth.Login(ctx, &aegisgate.LoginRequest{
    Username: "admin",
    Password: "secret",
})

// Logout
err = client.Auth.Logout(ctx)

// List users
users, err := client.Auth.ListUsers(ctx)

// Create user
user, err := client.Auth.CreateUser(ctx, &aegisgate.CreateUserRequest{
    Username: "newuser",
    Password: "password123",
    Role:     "analyst",
})
```

### Compliance

```go
// Scan
report, err := client.Compliance.Scan(ctx)

// Report with framework filter
report, err := client.Compliance.Report(ctx, "SOC2")

// Integrity check
result, err := client.Compliance.Integrity(ctx)

// Evidence
evidence, err := client.Compliance.Evidence(ctx)
```

### Trust

```go
dashboard, err := client.Trust.Dashboard(ctx)
scores, err := client.Trust.Scores(ctx)
anomalies, err := client.Trust.Anomalies(ctx)
compliance, err := client.Trust.ComplianceCheck(ctx)
```

### Scan

```go
result, err := client.Scan.Scan(ctx, &aegisgate.ScanRequest{
    Target: "my-app",
    Type:   "full",
})
```

### Guardrails

```go
result, err := client.Guardrails.Check(ctx)
```

### Analytics

```go
usage, err := client.Analytics.Usage(ctx)
cost, err := client.Analytics.Cost(ctx)
anomalies, err := client.Analytics.Anomalies(ctx)
dashboard, err := client.Analytics.Dashboard(ctx)
```

### IOC (Indicator of Compromise)

```go
manifest, err := client.IOC.Manifest(ctx)
health, err := client.IOC.Health(ctx)
status, err := client.IOC.AdminStatus(ctx)
```

### SIEM

```go
status, err := client.SIEM.Status(ctx)
```

### ML Metrics

```go
metrics, err := client.ML.Metrics(ctx)
// metrics.TruePositives, metrics.Precision, metrics.Recall, etc.
```

### Audit

```go
result, err := client.Audit.Query(ctx)
```

### Policy

```go
policies, err := client.Policy.List(ctx)
policy, err := client.Policy.Get(ctx, "policy-123")
```

### Cluster

```go
health, err := client.Cluster.Health(ctx)
```

### Bridge

```go
status, err := client.Bridge.Status(ctx)
```

### Attestation

```go
// Offline verification
result, err := client.Attestation.Verify(ctx, &aegisgate.AttestationRequest{
    Artifact: "my-model.onnx",
})

// Online verification
result, err := client.Attestation.VerifyOnline(ctx, &aegisgate.AttestationRequest{
    Artifact: "my-model.onnx",
})
```

### AI-BOM (AI Bill of Materials)

```go
bom, err := client.AIBOM.Generate(ctx, &aegisgate.AIBOMRequest{
    ModelName:    "threat-detector",
    ModelVersion: "2.1.0",
})

verified, err := client.AIBOM.Verify(ctx, &aegisgate.AIBOMRequest{
    ModelName: "threat-detector",
})
```

### A2A (Agent-to-Agent)

```go
// Sign intent
signed, err := client.A2A.SignIntent(ctx, &aegisgate.A2AIntentSignRequest{
    Intent:  "deploy-model",
    AgentID: "agent-1",
})

// Verify intent
result, err := client.A2A.VerifyIntent(ctx, &aegisgate.A2AIntentVerifyRequest{
    Intent:    "deploy-model",
    Signature: signed.Signature,
    AgentID:   "agent-1",
})
```

### Digest

```go
// Generate
digest, err := client.Digest.Generate(ctx, &aegisgate.DigestGenerateRequest{
    Data:      "payload content",
    Algorithm: "sha256",
})

// Verify
result, err := client.Digest.Verify(ctx, &aegisgate.DigestVerifyRequest{
    Data:      "payload content",
    Digest:    digest.Digest,
    Algorithm: "sha256",
})
```

### Incident

```go
// Create
incident, err := client.Incident.Create(ctx, &aegisgate.IncidentCreate{
    Title:       "Anomaly detected",
    Description: "Trust score dropped below threshold",
    Severity:    "high",
})

// Get
incident, err := client.Incident.Get(ctx, "incident-123")

// Triage
incident, err := client.Incident.Triage(ctx, "incident-123", &aegisgate.IncidentTriage{
    Priority: "P1",
    Assignee: "oncall-engineer",
})

// Resolve
incident, err := client.Incident.Resolve(ctx, "incident-123", &aegisgate.IncidentResolve{
    Resolution: "False alarm - score recovered",
})
```

### Evaluator

```go
// Run evaluation
result, err := client.Evaluator.Run(ctx, &aegisgate.EvaluatorRunRequest{
    Target:   "my-app",
    PolicyID: "policy-123",
})

// Verify result
verified, err := client.Evaluator.Verify(ctx, &aegisgate.EvaluatorVerifyRequest{
    Target:   "my-app",
    ResultID: result.ID,
})
```

### Persistence

```go
result, err := client.Persistence.Get(ctx)
```

### Certificates

```go
cert, err := client.Certs.Get(ctx)
```

### License

```go
status, err := client.License.Status(ctx)
```

### SLA

```go
sla, err := client.SLA.Get(ctx)
```

### TSA (Time Stamping Authority)

```go
status, err := client.TSA.Status(ctx)
```

### DSAR (GDPR Data Subject Access Requests)

```go
// Export all data for an entity (GDPR Article 15)
bundle, err := client.DSAR.Export(ctx, "user-123")

// Erase all data for an entity (GDPR Article 17)
// Returns EraseResult with BlockedBy="legal_hold" if under hold
result, err := client.DSAR.Erase(ctx, "user-123")
```

### Legal Hold (E-Discovery)

```go
// Create a legal hold
hold, err := client.LegalHold.CreateHold(ctx, &aegisgate.LegalHoldCreateRequest{
    EntityID:   "user-123",
    EntityType: "user",
    Reason:     "Case #2026-001",
    IssuedBy:   "admin@company.com",
})

// Check if entity is under hold
underHold, _ := client.LegalHold.CheckUnderHold(ctx, "user-123")

// List all holds
holds, _ := client.LegalHold.ListHolds(ctx)

// Release a hold
err = client.LegalHold.ReleaseHold(ctx, hold.ID)
```

### A/B Testing v4.3.0 (Variant-based)

```go
// Create a test with named variants
test, err := client.ABTestV4.CreateTest(ctx, &aegisgate.ABTestV4CreateRequest{
    Name:        "model-comparison",
    Description: "Compare v4.2 vs v4.3",
    Variants: []aegisgate.ABTestV4Variant{
        {Name: "champion", Weight: 50, ModelRef: "model-v4.2"},
        {Name: "challenger", Weight: 50, ModelRef: "model-v4.3"},
    },
})

// Start the test
err = client.ABTestV4.StartTest(ctx, test.ID)

// Assign a request to a variant (deterministic FNV hashing)
variant, _ := client.ABTestV4.AssignVariant(ctx, test.ID, "req-123")

// Record a result
err = client.ABTestV4.RecordResult(ctx, test.ID, &aegisgate.ABTestV4ResultRequest{
    VariantName:   variant,
    Detected:      true,
    FalsePositive: false,
    LatencyMs:     38.7,
})

// Get metrics
metrics, _ := client.ABTestV4.GetMetrics(ctx, test.ID)

// Stop the test
err = client.ABTestV4.StopTest(ctx, test.ID)
```

## Error Handling

The SDK returns `*ErrorResponse` for API errors:

```go
import "github.com/aegisgatesecurity/aegisgate-platform/sdk/go"

result, err := client.Health.Get(ctx)
if err != nil {
    var apiErr *aegisgate.ErrorResponse
    if errors.As(err, &apiErr) {
        fmt.Printf("API error %d: %s\n", apiErr.StatusCode, apiErr.Message)
    } else {
        fmt.Printf("Network/other error: %v\n", err)
    }
}
```

`ErrorResponse` fields:
- `StatusCode` — HTTP status code (e.g., 404, 500)
- `Error` — Short error label (e.g., "Not Found")
- `Message` — Detailed error message from the server

### Retry Behaviour

The SDK automatically retries on:
- Network connectivity errors
- HTTP 5xx (server) responses

Retries use exponential backoff (500ms → 1s → 2s → 4s, capped at 8s). The number of retries is configurable via `WithMaxRetries(n)` (default: 3).

## Testing

```go
import (
    "net/http"
    "net/http/httptest"
    aegisgate "github.com/aegisgatesecurity/aegisgate-platform/sdk/go"
)

func TestHealth(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/health" {
            w.WriteHeader(http.StatusOK)
            fmt.Fprintln(w, `{"status":"ok"}`)
        }
    }))
    defer server.Close()

    cfg := aegisgate.NewConfig(
        aegisgate.WithBaseURL(server.URL),
        aegisgate.WithAPIKey("test-key"),
    )
    client, _ := aegisgate.NewClient(cfg)
    defer client.Close()

    health, err := client.Health.Get(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    if health.Status != "ok" {
        t.Errorf("expected ok, got %s", health.Status)
    }
}
```

## License

Licensed under the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0).

```
SPDX-License-Identifier: Apache-2.0
```