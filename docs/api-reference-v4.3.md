# AegisGate Platform API Reference — v4.3.0+

This document covers the REST API endpoints added in v4.3.0+ for the
three new compliance and testing pipelines: **DSAR** (GDPR data subject
access requests), **Legal Hold** (e-discovery), and **A/B Testing**
(ML model evaluation).

## Authentication

All endpoints require authentication. Most endpoints require admin role,
enforced by the platform's auth middleware. Authentication is via:

- **Bearer token**: `Authorization: Bearer <token>`
- **API key**: `X-API-Key: <key>`

## DSAR — Data Subject Access Request

Implements GDPR Articles 15–20: right to access, right to erasure,
right to data portability.

### POST /api/v1/dsar/export

Export all data associated with an entity across all registered data
providers. Returns a structured JSON bundle.

**Required role**: Admin

**Request body**:
```json
{
  "entity_id": "user-123"
}
```

**Response** (200 OK):
```json
{
  "entity_id": "user-123",
  "exported_at": "2026-08-21T18:00:00Z",
  "providers": {
    "rbac": { ... },
    "audit": { ... },
    "ioc": { ... }
  }
}
```

The response includes a `Content-Disposition` header suggesting a
filename for download.

### POST /api/v1/dsar/erase

Erase all data for an entity. If the entity is under legal hold, the
erasure is blocked and a 409 Conflict response is returned.

**Required role**: Admin

**Request body**:
```json
{
  "entity_id": "user-123"
}
```

**Response** (200 OK):
```json
{
  "entity_id": "user-123",
  "erased_at": "2026-08-21T18:00:00Z",
  "records_affected": 42,
  "providers": {
    "rbac": 5,
    "audit": 37
  }
}
```

**Response** (409 Conflict — blocked by legal hold):
```json
{
  "entity_id": "user-123",
  "blocked_by": "legal_hold"
}
```

## Legal Hold — E-Discovery Compliance

Manages legal holds that freeze data deletion for entities under
litigation. When a hold is active, DSAR erasure requests and retention
pruning must skip the held entity's data.

### POST /api/v1/legal-holds

Create a new legal hold on an entity.

**Required role**: Authenticated (admin for tier-gated features)

**Request body**:
```json
{
  "entity_id": "user-123",
  "entity_type": "user",
  "reason": "Case #2026-001 — pending litigation",
  "issued_by": "admin@company.com"
}
```

**Response** (201 Created):
```json
{
  "id": "hold_1724272800000000000",
  "entity_id": "user-123",
  "entity_type": "user",
  "reason": "Case #2026-001 — pending litigation",
  "issued_by": "admin@company.com",
  "created_at": "2026-08-21T18:00:00Z"
}
```

### GET /api/v1/legal-holds

List all legal holds (active and released).

**Required role**: Authenticated

**Response** (200 OK):
```json
[
  {
    "id": "hold_1724272800000000000",
    "entity_id": "user-123",
    "entity_type": "user",
    "reason": "Case #2026-001",
    "issued_by": "admin@company.com",
    "created_at": "2026-08-21T18:00:00Z"
  }
]
```

### GET /api/v1/legal-holds/{id}

Retrieve a single legal hold by ID.

**Required role**: Authenticated

**Response** (200 OK): Single `Hold` object (same as create response).

**Response** (404 Not Found): `{"error": "hold <id> not found"}`

### DELETE /api/v1/legal-holds/{id}

Release (deactivate) a legal hold. The hold record is retained for
audit trail but `released_at` is set to the current time.

**Required role**: Authenticated

**Response** (200 OK): `{"status": "released"}`

**Response** (404 Not Found): `{"error": "hold <id> not found"}`

### GET /api/v1/legal-holds/check/{entityID}

Check if an entity is currently under any active legal hold.

**Required role**: Authenticated

**Response** (200 OK):
```json
{
  "under_hold": true
}
```

## A/B Testing — ML Model Evaluation

Manages A/B tests for comparing ML model variants. Uses FNV hashing
for deterministic variant assignment.

### POST /api/v1/abtest/tests

Create a new A/B test with named variants.

**Required role**: Admin

**Request body**:
```json
{
  "name": "v4.3-detection-comparison",
  "description": "Compare v4.2 vs v4.3 detection model",
  "variants": [
    {"name": "champion", "weight": 50, "model_ref": "model-v4.2"},
    {"name": "challenger", "weight": 50, "model_ref": "model-v4.3"}
  ]
}
```

**Response** (201 Created):
```json
{
  "id": "test-abc123",
  "name": "v4.3-detection-comparison",
  "description": "Compare v4.2 vs v4.3 detection model",
  "variants": [...],
  "status": "created",
  "created_at": "2026-08-21T18:00:00Z"
}
```

### GET /api/v1/abtest/tests

List all A/B tests.

**Required role**: Admin

**Response** (200 OK):
```json
{
  "tests": [...],
  "count": 3,
  "time": "2026-08-21T18:00:00Z"
}
```

### POST /api/v1/abtest/tests/{id}/start

Start a test (transition from `created` to `running`).

**Required role**: Admin

**Response** (200 OK): `{"status": "started", "test_id": "test-abc123"}`

### POST /api/v1/abtest/tests/{id}/stop

Stop a test (transition from `running` to `stopped`).

**Required role**: Admin

**Response** (200 OK): `{"status": "stopped", "test_id": "test-abc123"}`

### GET /api/v1/abtest/tests/{id}/metrics

Get per-variant metrics for a test.

**Required role**: Admin

**Response** (200 OK):
```json
[
  {
    "variant_name": "champion",
    "total_requests": 500,
    "detections": 120,
    "false_positives": 15,
    "avg_latency_ms": 45.2
  },
  {
    "variant_name": "challenger",
    "total_requests": 500,
    "detections": 135,
    "false_positives": 10,
    "avg_latency_ms": 38.7
  }
]
```

### POST /api/v1/abtest/tests/{id}/assign

Assign a request to a variant using deterministic FNV hashing.
The same `request_id` always maps to the same variant.

**Required role**: Admin

**Request body**:
```json
{
  "request_id": "req-unique-123"
}
```

**Response** (200 OK):
```json
{
  "variant": "challenger",
  "test_id": "test-abc123"
}
```

### POST /api/v1/abtest/tests/{id}/result

Record a detection result for a variant.

**Required role**: Admin

**Request body**:
```json
{
  "variant_name": "challenger",
  "detected": true,
  "false_positive": false,
  "latency_ms": 38.7
}
```

**Response** (200 OK): `{"status": "recorded"}`

## Error Responses

All endpoints use standard HTTP status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad request (validation error) |
| 401 | Unauthorized |
| 403 | Forbidden (insufficient role) |
| 404 | Not found |
| 405 | Method not allowed |
| 409 | Conflict (e.g., erasure blocked by legal hold) |
| 500 | Internal server error |

Error response body format:
```json
{"error": "descriptive error message"}
```

## SDK Usage

The AegisGate Go SDK provides typed access to all these endpoints:

```go
import aegisgate "github.com/aegisgatesecurity/aegisgate-platform/sdk/go"

// DSAR
bundle, err := client.DSAR.Export(ctx, "user-123")
result, err := client.DSAR.Erase(ctx, "user-123")

// Legal Hold
hold, err := client.LegalHold.CreateHold(ctx, &aegisgate.LegalHoldCreateRequest{
    EntityID:   "user-123",
    EntityType: "user",
    Reason:     "Case #2026-001",
    IssuedBy:   "admin@company.com",
})
underHold, err := client.LegalHold.CheckUnderHold(ctx, "user-123")
err = client.LegalHold.ReleaseHold(ctx, hold.ID)

// A/B Testing v4
test, err := client.ABTestV4.CreateTest(ctx, &aegisgate.ABTestV4CreateRequest{
    Name:        "v4.3-comparison",
    Description: "Compare models",
    Variants: []aegisgate.ABTestV4Variant{
        {Name: "champion", Weight: 50, ModelRef: "model-v4.2"},
        {Name: "challenger", Weight: 50, ModelRef: "model-v4.3"},
    },
})
err = client.ABTestV4.StartTest(ctx, test.ID)
variant, err := client.ABTestV4.AssignVariant(ctx, test.ID, "req-123")
err = client.ABTestV4.RecordResult(ctx, test.ID, &aegisgate.ABTestV4ResultRequest{
    VariantName:   variant,
    Detected:      true,
    FalsePositive: false,
    LatencyMs:     38.7,
})
metrics, err := client.ABTestV4.GetMetrics(ctx, test.ID)
```