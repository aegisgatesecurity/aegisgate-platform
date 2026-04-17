# AegisGate Security Platform - Multi-stage Production Build
# Build:  docker build -t aegisgate-platform:latest ..
# Run:    docker run -p 8080:8080 -p 8081:8081 -p 8443:8443 aegisgate-platform:latest
# Note:   Build context must be the parent directory containing all three source trees
#
# Zero-config: binary runs with no config file, no environment variables.
# All defaults are embedded. Override with --config, --tier, or env vars.
# Data persistence: mount /data volume for audit logs, certificates, etc.

FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build

# Copy all source trees (go.mod uses relative replace directives)
COPY aegisgate-platform/ ./aegisgate-platform/
COPY aegisgate-source/  ./aegisgate-source/
COPY aegisguard-source/  ./aegisguard-source/

# Build the unified platform binary
WORKDIR /build/aegisgate-platform
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /aegisgate-platform ./cmd/aegisgate-platform

# Production stage — minimal, immutable, zero-config
FROM alpine:latest
RUN apk add --no-cache ca-certificates && adduser -D -g '' appuser

# Copy binary and UI assets
COPY --from=builder /aegisgate-platform /usr/local/bin/aegisgate-platform
COPY --from=builder /build/aegisgate-platform/ui/frontend /opt/aegisgate-platform/ui/frontend

# Create writable data directories (audits, certs, logs)
# /data is the single writable volume — everything else is read-only
RUN mkdir -p /data/certs /data/audit /data/logs && \
    chown -R appuser:appuser /data

# Copy default Community tier config (embedded in binary, but also available on disk)
COPY --from=builder /build/aegisgate-platform/configs/community.yaml /opt/aegisgate-platform/configs/community.yaml

# Declare /data as the persistence volume
VOLUME ["/data"]

USER appuser

EXPOSE 8080 8081 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8443/health || exit 1

ENTRYPOINT ["aegisgate-platform"]
# Zero-config defaults: --embedded-mcp starts the MCP server in-process
# --tier=community applies Community limits, no config file needed
CMD ["--proxy-port=8080", "--mcp-port=8081", "--dashboard-port=8443", "--embedded-mcp", "--tier=community"]