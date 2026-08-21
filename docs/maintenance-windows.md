## Maintenance Windows

Maintenance windows (v4.2.0+) allow you to put AegisGate into a maintenance state for planned downtime — security patches, config changes, or upstream provider maintenance — without taking the process offline. During maintenance, the platform returns HTTP 503 to all proxy requests while keeping health, version, and maintenance API endpoints accessible for monitoring and load balancer health checks.

### How It Works

The maintenance state uses an `atomic.Bool` for lock-free reads on the hot path — every proxy request checks this flag with zero overhead. When maintenance is active:

1. **Proxy requests** return `HTTP 503 Service Unavailable` with a `Retry-After` header (default: 300 seconds)
2. **Health endpoint** (`/health`) remains accessible — load balancers can detect the maintenance state and drain traffic
3. **Version endpoint** (`/version`) remains accessible
4. **Maintenance API** (`/api/v1/maintenance`) remains accessible for status checks and toggling
5. **Dashboard** (`/ui/`) shows a maintenance banner

### CLI Usage

#### Check Status

```bash
./aegisgate-platform maintenance status
```

Output:
```
Maintenance mode: inactive
No scheduled windows.
```

#### Enable Immediately

```bash
./aegisgate-platform maintenance enable --message "Security update in progress"
```

This activates maintenance mode right away. All proxy requests will return 503 until you disable it.

#### Schedule a Future Window

```bash
./aegisgate-platform maintenance schedule \
  --start "2026-09-01T02:00:00Z" \
  --end "2026-09-01T04:00:00Z" \
  --reason "Quarterly security patch"
```

The platform will automatically enter maintenance mode at the scheduled start time and exit at the end time. Times are in RFC 3339 format (ISO 8601 with timezone).

#### Disable

```bash
./aegisgate-platform maintenance disable
```

Deactivates maintenance mode immediately, regardless of whether it was manually enabled or scheduled.

### REST API

Maintenance windows can also be managed via the REST API at `/api/v1/maintenance`.

#### Get Status

```bash
curl http://localhost:8443/api/v1/maintenance
```

Response:
```json
{
  "active": false,
  "message": "",
  "scheduled_start": "2026-09-01T02:00:00Z",
  "scheduled_end": "2026-09-01T04:00:00Z",
  "reason": "Quarterly security patch"
}
```

#### Enable Maintenance Mode

```bash
curl -X POST http://localhost:8443/api/v1/maintenance \
  -H "Content-Type: application/json" \
  -d '{"action": "enable", "message": "Security update in progress"}'
```

#### Disable Maintenance Mode

```bash
curl -X POST http://localhost:8443/api/v1/maintenance \
  -H "Content-Type: application/json" \
  -d '{"action": "disable"}'
```

### Use Cases

#### Scheduled Patch Windows

For organizations with defined maintenance windows (e.g., "2 AM – 4 AM every Sunday"):

```bash
# Schedule the next window
./aegisgate-platform maintenance schedule \
  --start "2026-08-24T02:00:00Z" \
  --end "2026-08-24T04:00:00Z" \
  --reason "Weekly security patch window"
```

#### Emergency Maintenance

For unplanned emergency patches:

```bash
# Enable immediately
./aegisgate-platform maintenance enable --message "Emergency security patch — ETA 30 minutes"

# After patching is complete
./aegisgate-platform maintenance disable
```

#### Load Balancer Integration

Configure your load balancer to check `/health` during the maintenance window:

- **Active maintenance**: `/health` returns 200 with `"status": "maintenance"` — drain traffic to other instances
- **Normal operation**: `/health` returns 200 with `"status": "healthy"` — resume traffic

### What Stays Accessible During Maintenance

| Endpoint | Accessible? | Purpose |
|----------|:-----------:|---------|
| `/health` | ✅ | Load balancer health checks, monitoring |
| `/version` | ✅ | Version verification |
| `/api/v1/maintenance` | ✅ | Maintenance status and control |
| `/ready` | ✅ | Readiness probe |
| `/api/v1/scan` (proxy) | ❌ | Returns 503 with `Retry-After` |
| `/ui/` (dashboard) | ❌ | Shows maintenance banner |
| All other API endpoints | ❌ | Returns 503 |

### Client Behavior

Clients receiving a 503 should:

1. Check the `Retry-After` header (seconds until retry recommended)
2. Honor the retry-after value before retrying
3. Implement exponential backoff for repeated 503s
4. Optionally check `/health` to detect when maintenance ends

Example client retry logic:
```python
import requests
import time

def call_aegisgate(url, payload):
    for attempt in range(5):
        r = requests.post(url, json=payload)
        if r.status_code == 503:
            retry_after = int(r.headers.get("Retry-After", 300))
            time.sleep(retry_after)
            continue
        return r
    raise Exception("AegisGate in maintenance after 5 retries")
```

_See also: [CLI Reference](cli-reference.md), [Deployment Guide](deployment guide on the website), [Configuration Reference](configuration.md)._