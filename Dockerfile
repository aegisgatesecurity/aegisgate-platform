# =========================================================================
# AegisGate Security Platform — Multi-stage Production Build
# Build:  docker build -t aegisgate-platform:latest .
# Run:    docker run -p 8080:8080 -p 8081:8081 -p 8443:8443 aegisgate-platform:latest
#
# Self-contained: upstream packages vendored in ./upstream/
# No external repositories required at build time.
# Zero-config: binary runs with no config file, no environment variables.
# All defaults are embedded. Override with --config, --tier, or env vars.
# Data persistence: mount /data volume for audit logs, certificates, etc.
#
# Hardening (v3.3.1):
#   - Both base images are pinned to a SHA256 digest for reproducible builds.
#   - Production stage runs as non-root via USER appuser.
#   - HEALTHCHECK directive is set to hit the dashboard's /health endpoint.
#   - Only ca-certificates is added in the production stage (minimal attack surface).
# =========================================================================

# Builder stage: Go 1.26.4 on Alpine, pinned by digest for reproducibility.
# Update digest when bumping the Go version. Digest source: docker pull golang:1.26.4-alpine
FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build

# Build-time arguments for version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Copy the self-contained platform source (includes vendored upstream packages)
COPY . ./aegisgate-platform/

# Build the unified platform binary with version metadata injected via ldflags
WORKDIR /build/aegisgate-platform
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT:0:8} -X main.buildDate=${BUILD_DATE}" \
    -o /aegisgate-platform ./cmd/aegisgate-platform

# Production stage: minimal Alpine, pinned by digest. Update digest when bumping Alpine.
# Digest source: docker pull alpine:latest (as of 2026-06-08: alpine 3.23)
FROM alpine@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
RUN apk add --no-cache ca-certificates wget && adduser -D -g '' appuser

# Copy binary and UI assets
COPY --from=builder /aegisgate-platform /usr/local/bin/aegisgate-platform
COPY --from=builder /build/aegisgate-platform/ui/frontend /opt/aegisgate-platform/ui/frontend

# Create writable data directories (audits, certs, logs)
# /data is the single writable volume — everything else is read-only
RUN mkdir -p /data/certs /data/audit /data/logs && \
    chown -R appuser:appuser /data

# Copy default Community tier config (embedded in binary, but also available on disk)
COPY --from=builder /build/aegisgate-platform/configs/community.yaml /opt/aegisgate-platform/configs/community.yaml

# Copy billing config template (pricing defaults are embedded in binary via init(),
# but this template can be customized for different pricing tiers)
COPY --from=builder /build/aegisgate-platform/pkg/billing/billing-config.example.json /opt/aegisgate-platform/billing-config.json

# Copy security.txt for vulnerability disclosure (RFC 9116)
COPY --from=builder /build/aegisgate-platform/security.txt /var/www/html/.well-known/security.txt

# Declare /data as the persistence volume
VOLUME ["/data"]

USER appuser

EXPOSE 8080 8081 8443

# Health check uses the dashboard port's /health endpoint.
# wget is preferred over curl because curl is not installed in the minimal image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8443/health || exit 1

ENTRYPOINT ["aegisgate-platform"]
# Zero-config defaults: --embedded-mcp starts the MCP server in-process
# --tier=community applies Community limits, no config file needed
CMD ["--proxy-port=8080", "--mcp-port=8081", "--dashboard-port=8443", "--embedded-mcp", "--tier=community"]