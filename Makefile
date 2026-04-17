.PHONY: build test lint clean docker run-community run-developer help

# =========================================================================
# AegisGate Security Platform — Makefile
# =========================================================================

VERSION  := $(shell cat VERSION 2>/dev/null || echo "1.2.0")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
DATE     := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)"
BINARY   := aegisgate-platform
IMAGE    := aegisgate-platform

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the platform binary
	go build $(LDFLAGS) -o $(BINARY) ./cmd/aegisgate-platform/

test: ## Run all tests
	go test -v -race ./...

test-short: ## Run tests without verbose output
	go test -race ./...

lint: ## Run linters
	go vet ./...
	gofmt -l . | grep -q . && echo "Files need formatting:" && gofmt -l . && exit 1 || true

docker: ## Build Docker image
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest -f Dockerfile ../

docker-test: ## Test Docker image
	docker run --rm -p 8080:8080 -p 8081:8081 -p 8443:8443 \
		$(IMAGE):latest --embedded-mcp --target https://httpbin.org

run-community: build ## Run with Community tier config
	./$(BINARY) --config configs/community.yaml --embedded-mcp

run-developer: build ## Run with Developer tier config (requires LICENSE_KEY)
	./$(BINARY) --config configs/developer.yaml --embedded-mcp

run-quick: build ## Quick start with defaults (no config file)
	./$(BINARY) --embedded-mcp

clean: ## Remove build artifacts
	rm -f $(BINARY)
	go clean -testcache

version: ## Print version info
	@echo "AegisGate Security Platform v$(VERSION) (commit: $(COMMIT), built: $(DATE))"

deps: ## Download dependencies
	go mod download
	go mod tidy

coverage: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1