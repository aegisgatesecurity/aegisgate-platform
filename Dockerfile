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
# v4.2.0: Community edition build (CGO_ENABLED=0, no ONNX Runtime).
# ML threat detection (ONNX inference) is an enterprise-only feature.
# The community edition uses regex-only scanning via the !cgo build path.
# Enterprise builds use a separate Dockerfile.enterprise with CGO_ENABLED=1
# and ONNX Runtime v1.27.0 bundled from Microsoft's official release.
#
# Hardening:
#   - Production stage runs as non-root via USER appuser.
#   - HEALTHCHECK directive is set to hit the dashboard's /health endpoint.
#   - Only ca-certificates added (minimal attack surface).
# =========================================================================

# Builder stage: Go 1.26.6 on Alpine.
FROM golang:1.26.6-alpine AS builder

# CGO dependencies: gcc + musl (needed for some stdlib packages).
RUN apk add --no-cache git ca-certificates gcc musl-dev

WORKDIR /build

# Build-time arguments for version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Copy the self-contained platform source (includes vendored upstream packages)
COPY . ./aegisgate-platform/

# Build the unified platform binary with version metadata injected via ldflags.
# CGO_ENABLED=0: community edition uses pure-Go build (no ONNX Runtime).
# The !cgo build path in pkg/ml/ provides regex-only threat detection.
WORKDIR /build/aegisgate-platform
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT:0:8} -X main.buildDate=${BUILD_DATE}" \
    -o /aegisgate-platform ./cmd/aegisgate-platform

# Production stage: minimal Alpine.
FROM alpine:3.24

# Install runtime dependencies: ca-certificates (TLS), wget (healthcheck).
RUN apk add --no-cache ca-certificates wget && \
    apk upgrade --no-cache libssl3 libcrypto3 && \
    adduser -D -g '' appuser

# Copy binary and UI assets
COPY --from=builder /aegisgate-platform /usr/local/bin/aegisgate-platform
COPY --from=builder /build/aegisgate-platform/ui/frontend /opt/aegisgate-platform/ui/frontend

# NOTE: ONNX threat detection model (threat_cnn_bilstm.onnx) is proprietary
# and not included in the community/open-source build. Enterprise builds
# inject the model via a separate build stage or volume mount. The
# ThreatDetector gracefully falls back to regex-only scanning when no
# model file is present.

# Create writable data directories (audits, certs, logs)
# /data is the single writable volume — everything else is read-only
RUN mkdir -p /data/certs /data/audit /data/logs /app/certs && \
    chown -R appuser:appuser /data /app/certs

# Copy default Community tier config (embedded in binary, but also available on disk)
COPY --from=builder /build/aegisgate-platform/configs/community.yaml /opt/aegisgate-platform/configs/community.yaml

# Run as non-root user
USER appuser

# Expose ports: 8080 (HTTP), 8081 (dashboard), 8443 (HTTPS)
EXPOSE 8080 8081 8443

# Health check hits the dashboard health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8081/health || exit 1

# Single writable volume for audit logs, certificates, etc.
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/aegisgate-platform"]