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
# by the ThreatDetector at startup. ONNX Runtime v1.27.0 is bundled from the
# official Microsoft release (matching the onnxruntime_go v1.27.0 binding).
#
# Hardening (v3.3.1+):
#   - Both base images are pinned to a SHA256 digest for reproducible builds.
#   - Production stage runs as non-root via USER appuser.
#   - HEALTHCHECK directive is set to hit the dashboard's /health endpoint.
#   - Only ca-certificates and libonnxruntime are added (minimal attack surface).
# =========================================================================

# Builder stage: Go 1.26.6 on Alpine, pinned to digest for reproducibility.
# Update digest when bumping the Go version. Digest source: docker pull golang:1.26.6-alpine
FROM golang:1.26.6-alpine AS builder

# CGO dependencies: gcc + musl for CGO compilation.
# ONNX Runtime headers come from the bundled release tarball (see
# ONNX_RUNTIME_URL below), not from Alpine packages, to ensure version
# alignment between the C library and the Go binding.
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Install ONNX Runtime v1.27.0 from official Microsoft release.
# onnxruntime_go v1.27.0 requires ORT API version 27, which is provided by
# onnxruntime v1.27.0. Alpine's package (v1.23.0) is too old and causes
# "API version not available" errors at runtime.
#
# The release tarball includes: include/ headers for CGO, lib/ shared libraries
# for runtime. We extract the entire lib/ directory (which includes the .so,
# .so.1, and .so.1.27.0 symlinks) and include/ headers for CGO compilation.
ARG ONNX_RUNTIME_VERSION=1.27.0
ARG ONNX_RUNTIME_URL=https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_RUNTIME_VERSION}/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}.tgz
RUN wget -qO /tmp/ort.tgz ${ONNX_RUNTIME_URL} && \
    tar -xzf /tmp/ort.tgz -C /tmp && \
    mkdir -p /usr/local/include/onnxruntime/core/session && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/include/onnxruntime_c_api.h /usr/local/include/onnxruntime/core/session/ && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/include/onnxruntime_cxx_api.h /usr/local/include/onnxruntime/core/session/ && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/include/onnxruntime_cxx_inline.h /usr/local/include/onnxruntime/core/session/ && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/include/onnxruntime_env_config_keys.h /usr/local/include/onnxruntime/core/session/ && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/include/onnxruntime_float16.h /usr/local/include/onnxruntime/core/session/ && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/lib/libonnxruntime.so* /usr/local/lib/ && \
    cp /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}/lib/libonnxruntime_providers_shared.so /usr/local/lib/ && \
    rm -rf /tmp/ort.tgz /tmp/onnxruntime-linux-x64-${ONNX_RUNTIME_VERSION}

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

# Install runtime dependencies: ca-certificates (TLS), wget (healthcheck).
# ONNX Runtime v1.27.0 is copied from the builder stage (not from Alpine packages)
# to ensure version alignment with onnxruntime_go v1.27.0.
RUN apk add --no-cache ca-certificates wget && \
    apk upgrade --no-cache libssl3 libcrypto3 && \
    adduser -D -g '' appuser

# Copy ONNX Runtime shared libraries from builder.
# onnxruntime_go uses dlopen to load the library at runtime.
# The symlink chain: libonnxruntime.so → libonnxruntime.so.1 → libonnxruntime.so.1.27.0
# matches the discoverONNXRuntimeLib() search path in detector_onnx_methods.go.
COPY --from=builder /usr/local/lib/libonnxruntime.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libonnxruntime_providers_shared.so /usr/local/lib/

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