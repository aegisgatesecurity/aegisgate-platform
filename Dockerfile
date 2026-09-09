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
# v9.0: ML-enabled build (CGO_ENABLED=1, ONNX Runtime v1.29.0 included).
# Includes CNN-BiLSTM threat detector (v9 model) for Professional+ tiers.
# Community tier falls back to heuristic detection when model not loaded.
#
# Uses Debian bookworm-slim base (not Alpine) because onnxruntime prebuilt
# Linux shared libraries require glibc (ld-linux-x86-64.so.2). Alpine's musl
# libc cannot load them. The ~67MB size increase over Alpine is acceptable
# for a production security platform.
#
# Hardening:
#   - Production stage runs as non-root via USER appuser.
#   - HEALTHCHECK directive is set to hit the dashboard's /health endpoint.
#   - Only ca-certificates and wget added (minimal attack surface).
# =========================================================================

# Builder stage: Go 1.27.0 on Debian bookworm with ONNX Runtime v1.29.0.
FROM golang:1.27.1-bookworm AS builder

# Install build tools + download ONNX Runtime v1.29.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates gcc wget && \
    rm -rf /var/lib/apt/lists/* && \
    wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.29.0/onnxruntime-linux-x64-1.29.0.tgz && \
    tar -xzf onnxruntime-linux-x64-1.29.0.tgz && \
    cp onnxruntime-linux-x64-1.29.0/lib/*.so /usr/lib/ && \
    cp -r onnxruntime-linux-x64-1.29.0/include/* /usr/include/ && \
    rm -rf onnxruntime-linux-x64-1.29.0.tgz onnxruntime-linux-x64-1.29.0

WORKDIR /build

# Build-time arguments for version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Copy the self-contained platform source (includes vendored upstream packages)
COPY . ./aegisgate-platform/

# Build with CGO enabled for ONNX Runtime support
WORKDIR /build/aegisgate-platform
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/usr/include"
ENV CGO_LDFLAGS="-L/usr/lib -lonnxruntime"
RUN go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /aegisgate-platform ./cmd/aegisgate-platform

# Production stage: minimal Debian bookworm-slim with ONNX Runtime.
FROM debian:bookworm-slim

# Install runtime dependencies: ca-certificates (TLS), wget (healthcheck), libstdc++ (for ONNX).
# apt-get upgrade pulls in security patches for base image packages (e.g. libpcre2 CVE fixes).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
        ca-certificates wget libstdc++6 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /usr/sbin/nologin appuser

# Copy binary, UI assets, and ONNX Runtime library
COPY --from=builder /aegisgate-platform /usr/local/bin/aegisgate-platform
COPY --from=builder /build/aegisgate-platform/ui/frontend /opt/aegisgate-platform/ui/frontend
COPY --from=builder /usr/lib/libonnxruntime.so* /usr/lib/

# Create ML model directory. The ONNX model file is proprietary and not
# included in the public repository. It should be provided at deploy time
# via a volume mount or downloaded from a secure artifact store.
# If the model is absent, the platform falls back to heuristic detection.
RUN mkdir -p /opt/aegisgate-platform/pkg/ml/models
RUN ln -sf /usr/lib/libonnxruntime.so /usr/lib/onnxruntime.so

# Create writable data directories (audits, certs, logs)
# /data is the single writable volume — everything else is read-only
RUN mkdir -p /data/certs /data/audit /data/logs /app/certs && \
    chown -R appuser:appuser /data /app/certs

# Copy default Community tier config (embedded in binary, but also available on disk)
COPY --from=builder /build/aegisgate-platform/configs/community.yaml /opt/aegisgate-platform/configs/community.yaml

# Security hardening: purge non-essential packages to reduce attack surface.
# Removes bash and perl-base — not needed at runtime (appuser shell is nologin,
# Go binary has no perl dependencies). Reduces image by ~15MB and eliminates
# two common local privilege escalation vectors.
RUN apt-get update && \
    apt-get purge -y --allow-remove-essential bash perl-base && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/log/*

# Run as non-root user (shell disabled via /usr/sbin/nologin)
USER appuser

# Expose ports: 8080 (HTTP), 8081 (dashboard), 8443 (HTTPS)
EXPOSE 8080 8081 8443

# Health check hits the dashboard health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://localhost:8081/health || exit 1

# Single writable volume for audit logs, certificates, etc.
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/aegisgate-platform"]