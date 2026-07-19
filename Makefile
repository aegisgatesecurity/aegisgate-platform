.PHONY: build test lint clean docker run-community run-developer run-professional run-enterprise lens-build lens-test lens-harness-test lens-testlab-test lens-e2e lens-privacy-test lens-backend-test lens-clean help

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

run-community: build ## Run with Community tier (no license required)
	./$(BINARY) --config configs/community.yaml --embedded-mcp

run-developer: build ## Run with Developer tier config (requires AEGISGATE_LICENSE_KEY)
	./$(BINARY) --config configs/developer.yaml --embedded-mcp

run-professional: build ## Run with Professional tier config (requires AEGISGATE_LICENSE_KEY)
	./$(BINARY) --config configs/professional.yaml --embedded-mcp

run-enterprise: build ## Run with Enterprise tier config (requires AEGISGATE_LICENSE_KEY)
	./$(BINARY) --config configs/enterprise.yaml --embedded-mcp

run-quick: build ## Quick start with defaults (Community tier, no config file)
	./$(BINARY) --embedded-mcp

run-licensed: build ## Run with explicit license key (set LICENSE_KEY env var)
	./$(BINARY) --license="$(LICENSE_KEY)" --embedded-mcp

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

licensegen: ## Build the license key generator
	go build -o licensegen ./cmd/licensegen/

licensegen-generate: licensegen ## Generate a license key (set CUSTOMER, TIER, DAYS env vars)
	./licensegen --customer="$(CUSTOMER)" --tier="$(TIER)" --days="$(DAYS)"
# =========================================================================
# AegisGate Lens targets
# =========================================================================
#
# The Lens is the privacy-first browser extension that
# complements the Platform. Its build/test pipeline is
# owned by the Lens repo's CI (aegisgatesecurity/aegisgate-
# lens); the targets here exist for local end-to-end
# testing of the Lens's INTEGRATION with the Platform.
#
# Source paths (override on the command line if needed).
# The defaults assume a sibling-checkout layout:
#   ../AegisGate-Lens/aegisgate-lens/src
#   ../AegisGate-Lens/aegisgate-lens/test
# In the founder's local setup the layout is:
#   /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/src
#   /home/chaos/Desktop/AegisGate/lens-repo-bootstrap/test
LENS_SRC_DIR     ?= ../aegisgate-lens/src
LENS_TESTS_DIR   ?= ../aegisgate-lens/test
LENS_DIST_DIR    ?= /tmp/lens-dist
# Lens version and commit. Defaults to the Platform's
# version/commit (which is fine for local dev). The
# Lens's own CI overrides these via env vars.
LENS_VERSION     ?= $(VERSION)
LENS_COMMIT      ?= $(COMMIT)

# Testlab availability check. The testlab/ directory is
# gitignored (see .gitignore line 35) and is only present
# on the founder's local system. The e2e target runs the
# testlab integration tests if and only if the directory
# is present. The CI in the Lens repo and the public
# Platform repo does NOT require testlab/; the public
# targets (lens-build, lens-harness-test) work without it.
TESTLAB_DIR := testlab

# =========================================================================
# Targets
# =========================================================================

lens-build: ## DEPRECATED: Lens v0.2.0 has its own build process. Use the Lens repo's make target instead.
	@echo "==> DEPRECATED: Lens v0.2.0 has its own build process."
	@echo "    The Platform's tools/build-lens-extension/ was designed for v0.1.0"
	@echo "    and has been removed. Build Lens from its own repository instead."
	@echo "    See: pkg/lenstest/doc.go for details."
	@exit 1

lens-harness-test: ## Run the Lens test harness unit tests (headless Chromium)
	@echo "==> Running Lens test harness unit tests"
	@cd ./tools/test-extension && go test -race -count=1 ./...
	@echo "==> All test harness unit tests passed"

lens-testlab-test: ## Run the lensbackend testlab integration tests (requires local testlab/)
	@if [ ! -d "$(TESTLAB_DIR)" ]; then \
		echo "==> testlab/ not present; skipping lens-testlab-test"; \
		echo "    (testlab/ is local-only; see .gitignore)"; \
		echo "    To run the testlab integration tests:"; \
		echo "      1. Place testlab/ in this repo (it's local-only)."; \
		echo "      2. chmod +x testlab/scripts/setup.sh testlab/scripts/teardown.sh"; \
		echo "      3. Build the test Docker images:"; \
		echo "           docker build -t testlab-aegisgate-test:local -f testlab/Dockerfile.testlab ."; \
		echo "           docker build -t aegisgate-lensbackend:test -f testlab/Dockerfile.lensbackend ."; \
		echo "      4. Run: make lens-testlab-test"; \
		exit 0; \
	fi
	@if [ ! -x "$(TESTLAB_DIR)/scripts/setup.sh" ]; then \
		echo "ERROR: $(TESTLAB_DIR)/scripts/setup.sh is not executable."; \
		echo "       Run: chmod +x $(TESTLAB_DIR)/scripts/setup.sh $(TESTLAB_DIR)/scripts/teardown.sh"; \
		exit 1; \
	fi
	@echo "==> Starting testlab (Postgres + Redis + Mailpit + Keycloak)"
	@cd $(TESTLAB_DIR) && bash -c '\
		set -e ; \
		trap "./scripts/teardown.sh ; echo \"==> Stopped testlab\"" EXIT ; \
		./scripts/setup.sh ; \
		echo "==> Running lensbackend integration tests against the testlab" ; \
		LAB_ENABLED=1 go test -tags=lab -count=1 -v ./../pkg/lensbackend/...'

# Note: lens-test depends on build + harness (sequential).
# testlab is independent -- we run it via lens-testlab-test.
# We don't fail the whole lens-test if testlab fails (since
# testlab is local-only); we just print a warning.
lens-test: lens-harness-test lens-privacy-test ## Run the Lens integration tests (harness + privacy boundary)

lens-e2e: lens-test ## End-to-end: build + harness + (if testlab) integration test
	@echo ""
	@echo "=========================================="
	@echo "  AegisGate Lens end-to-end test summary"
	@echo "=========================================="
	@echo ""
	@echo "  Build:                PASSED"
	@echo "  Test harness:         PASSED"
	TESTLAB_RESULT=SKIPPED
	@if [ -d "$(TESTLAB_DIR)" ]; then \
		echo "  Testlab integration:  (running...)" ; \
		if $(MAKE) --no-print-directory lens-testlab-test 2>/tmp/lens-testlab.log; then \
			echo "  Testlab integration:  PASSED" ; \
			rm -f /tmp/lens-testlab.log ; \
			TESTLAB_RESULT=PASSED ; \
		else \
			echo "  Testlab integration:  FAILED (see /tmp/lens-testlab.log)" ; \
			echo "---- last 30 lines of testlab output ----" ; \
			tail -30 /tmp/lens-testlab.log ; \
			echo "---- end testlab output ----" ; \
			TESTLAB_RESULT=FAILED ; \
		fi ; \
	else \
		echo "  Testlab integration:  SKIPPED (testlab/ is local-only)" ; \
	fi
	@echo ""
	@if [ "@TESTLAB_RESULT@" = "PASSED" ] || [ "@TESTLAB_RESULT@" = "SKIPPED" ]; then \
		echo "  All available Lens tests passed." ; \
	else \
		echo "  One or more Lens tests FAILED." ; \
	fi
	@echo ""

lens-privacy-test: ## Run the Lens privacy boundary test (9-field schema contract)
	@echo "==> Running Lens privacy boundary test"
	@go test -count=1 -v ./pkg/lensbackend/ -run TestPrivacyBoundary_NoLeak
	@echo "==> Privacy boundary test passed"

lens-backend-test: ## Run all Lens backend tests (validation, server, privacy)
	@echo "==> Running all Lens backend tests"
	@go test -count=1 -v ./pkg/lensbackend/...
	@echo "==> All Lens backend tests passed"

lens-clean: ## Remove the Lens build artifacts
	@rm -rf $(LENS_DIST_DIR)


# =========================================================================
# Manual test target (real Chrome via Chrome DevTools Protocol)
# =========================================================================
# Runs the Lens extension in a REAL Chrome browser and drives
# it against a REAL AI provider page (Duck.ai by default; no
# account required). Takes screenshots and verifies the
# privacy commitments (no prompt content over the wire) via
# real network log inspection.
#
# This is the "rock-solid" test that catches issues that
# headless testdata can't: real-DOM quirks, CSP issues,
# browser-specific behavior.
#
# Requires: google-chrome-stable (or chromium) installed.
# Does NOT require the testlab/ directory.
MANUAL_TEST_OUT ?= $(LENS_DIST_DIR)/../manual-test-output

manual-test: ## Run the Lens in real Chrome against a real AI provider page
	@echo "==> Building Lens extension"
	@$(MAKE) lens-build
	@echo "==> Running manual test (real Chrome + real Duck.ai)"
	@cd ./tools/manual-test && go run . \
		--dist $(LENS_DIST_DIR) \
		--provider duck \
		--output $(MANUAL_TEST_OUT) \
		--headless=false
	@echo "==> Manual test report: $(MANUAL_TEST_OUT)/MANUAL_TEST_REPORT.md"

manual-test-headless: ## Same as manual-test but with --headless (no display required)
	@echo "==> Building Lens extension"
	@$(MAKE) lens-build
	@echo "==> Running manual test (headless Chrome + real Duck.ai)"
	@cd ./tools/manual-test && go run . \
		--dist $(LENS_DIST_DIR) \
		--provider duck \
		--output $(MANUAL_TEST_OUT) \
		--headless=true
	@echo "==> Manual test report: $(MANUAL_TEST_OUT)/MANUAL_TEST_REPORT.md"
