# =========================================================================
# AegisGate Security Platform — K8s Operator Dockerfile
# =========================================================================
# Multi-stage build for the AegisGate Kubernetes Operator.
# Build: docker build -t aegisgate-operator:latest -f deploy/k8s/operator/Dockerfile .
# =========================================================================

# Stage 1: Build
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Copy go.mod/go.sum first for dependency caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the operator binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=v3.6.1" \
    -o /aegisgate-operator \
    ./cmd/aegisgate-operator/

# Stage 2: Runtime
FROM alpine:3.21

RUN apk --no-cache add ca-certificates && \
    adduser -D -u 1000 appuser

COPY --from=builder /aegisgate-operator /usr/local/bin/aegisgate-operator

USER appuser

EXPOSE 9443

ENTRYPOINT ["aegisgate-operator"]