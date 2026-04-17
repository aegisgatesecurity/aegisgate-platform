# AegisGate Security Platform - Multi-stage Production Build
# Build:  docker build -t aegisgate-platform:latest ..
# Run:    docker run -p 8080:8080 -p 8081:8081 -p 8443:8443 aegisgate-platform:latest
# Note:   Build context must be the parent directory containing all three source trees

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

# Production stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates && adduser -D -g '' appuser

# Copy binary
COPY --from=builder /aegisgate-platform /usr/local/bin/aegisgate-platform

# Copy UI assets
COPY --from=builder /build/aegisgate-platform/ui/frontend /opt/aegisgate-platform/ui/frontend

USER appuser

EXPOSE 8080 8081 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8443/health || exit 1

ENTRYPOINT ["aegisgate-platform"]
CMD ["--proxy-port=8080", "--mcp-port=8081", "--dashboard-port=8443"]