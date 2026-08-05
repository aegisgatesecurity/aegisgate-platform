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
# v4.0.0: CGO_ENABLED=1 build with ONNX Runtime for neural threat detection.
# The Char CNN-BiLSTM model (6.2MB) ships inside the container at
# /opt/aegisgate-platform/models/threat_cnn_bilstm.onnx and is auto-discovered
# by the ThreatDetector at startup. The onnxruntime shared library is installed
# via Alpine package manager for reproducibility.
#
# Hardening (v3.3.1+):
#   - Both base images are pinned to a SHA256 digest for reproducible builds.
#   - Production stage runs as non-root via USER appuser.
#   - HEALTHCHECK directive is set to hit the dashboard's /health endpoint.
#   - Only ca-certificates and libonnxruntime are added (minimal attack surface).
# =========================================================================

# Builder stage: Go 1.26.5 on Alpine, pinned by digest for reproducibility.
# Update digest when bumping the Go version. Digest source: docker pull golang:1.26.5-alpine
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

# CGO dependencies: gcc + musl for static linking, onnxruntime-dev for headers
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Install ONNX Runtime shared library + headers in builder stage.
# onnxruntime-dev provides the C header (onnxruntime_c_api.h) needed by
# onnxruntime_go's CGO bindings. The shared library is also needed at
# build time for linking, and at runtime for dlopen.
#
# We install from the onnxruntime Alpine package. If a newer version is
# needed, download the release from https://github.com/microsoft/onnxruntime/releases
# and COPY it in instead.
RUN apk add --no-cache onnxruntime-dev

WORKDIR /build

# Build-time arguments for version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Copy the self-contained platform source (includes vendored upstream packages)
COPY . ./aegisgate-platform/

# Build the unified platform binary with version metadata injected via ldflags.
# CGO_ENABLED=1 is required for onnxruntime_go (which uses cgo to call the
# ONNX Runtime C API). The binary dynamically links against libonnxruntime.so.
WORKDIR /build/aegisgate-platform
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT:0:8} -X main.buildDate=${BUILD_DATE}" \
    -o /aegisgate-platform ./cmd/aegisgate-platform

# Production stage: minimal Alpine, pinned by digest. Update digest when bumping Alpine.
# Digest source: docker pull alpine:latest (as of 2026-07-19: alpine 3.23)
FROM alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Install runtime dependencies: ca-certificates (TLS), wget (healthcheck),
# and onnxruntime (ML inference for threat detection).
# Alpine's onnxruntime package installs libonnxruntime.so.1 → libonnxruntime.so.1.23.0.
# The onnxruntime_go library looks for "onnxruntime.so" by default via dlopen, so we
# create a symlink at /usr/lib/libonnxruntime.so for auto-discovery.
RUN apk add --no-cache ca-certificates wget onnxruntime && \
    ln -sf /usr/lib/libonnxruntime.so.1 /usr/lib/libonnxruntime.so && \
    apk upgrade --no-cache libssl3 libcrypto3 && \
    adduser -D -g '' appuser

# Copy binary and UI assets
COPY --from=builder /aegisgate-platform /usr/local/bin/aegisgate-platform
COPY --from=builder /build/aegisgate-platform/ui/frontend /opt/aegisgate-platform/ui/frontend

# Copy ONNX threat detection model (6.2MB, opset 18, Char CNN-BiLSTM).
# Auto-discovered by ThreatDetector via ModelPath config or
# AEGISGATE_ML_MODEL_PATH env var. Default: /opt/aegisgate-platform/models/
COPY --from=builder /build/aegisgate-platform/pkg/ml/models/threat_cnn_bilstm.onnx /opt/aegisgate-platform/models/threat_cnn_bilstm.onnx
COPY --from=builder /build/aegisgate-platform/pkg/ml/models/threat_cnn_bilstm_model_card.json /opt/aegisgate-platform/models/threat_cnn_bilstm_model_card.json

# Create writable data directories (audits, certs, logs)
# /data is the single writable volume — everything else is read-only
RUN mkdir -p /data/certs /data/audit /data/logs /app/certs && \
    chown -R appuser:appuser /data /app/certs

# Copy default Community tier config (embedded in binary, but also available on disk)
COPY --from=builder /build/aegisgate-platform/configs/community.yaml /opt/aegisgate-platform/configs/community.yaml

# Copy billing config template (pricing defaults are embedded in binary via init(),
# but this template can be customized for different pricing tiers)
COPY --from=builder /build/aegisgate-platform/pkg/billing/billing-config.example.json /opt/aegisgate-platform/billing-config.json

# Copy security.txt for vulnerability disclosure (RFC 9116)
COPY --from=builder /build/aegisgate-platform/security.txt /var/www/html/.well-known/security.txt

# Declare /data as the persistence volume
VOLUME ["/data"]

# Set working directory so ./certs resolves to a writable location
WORKDIR /app

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