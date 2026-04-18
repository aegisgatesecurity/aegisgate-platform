# Changelog

All notable changes to the AegisGate Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-04-17

### MVP Release - "Foundation Complete"

This release marks the completion of the MVP for the AegisGate Security Platform Community tier. All launch blockers have been resolved, comprehensive test coverage achieved, and the platform is ready for production deployment.

### Added

#### E2E Test Suite
- **Full platform lifecycle testing**: Build → Start → Health Checks → MCP → API → Graceful Shutdown
- **6 comprehensive E2E tests** covering:
  - Binary build from source
  - Platform startup with persistence, proxy, MCP, and dashboard
  - Health endpoint validation
  - MCP TCP connection establishment
  - API endpoint testing (version, tier info)
  - Graceful shutdown on SIGINT
- **E2E test runtime**: ~4.5 seconds
- **Port collision avoidance**: Uses 28xxx range for testing

#### Binary Synchronization
- **Synchronous port binding**: Proxy and dashboard servers now bind explicitly before goroutine launch
- **Startup verification**: Added `verifyServicesReady()` to confirm all ports are listening
- **Startup confirmations**: Added `[STARTUP-COMPLETE]` and `[STARTUP-CONFIRM]` log markers

#### Coverage Test Suite
- **58 new coverage tests** across security-critical packages:
  - `certinit_coverage_test.go` - 11 tests (certificate lifecycle, validation, edge cases)
  - `tier_coverage_test.go` - 12 tests (tier parsing, limits, inheritance)
  - `tieradapter_adapter_coverage_test.go` - 8 tests (cross-system tier mapping)
  - `persistence_coverage_test.go` - 11 tests (audit writing, retention, integrity)
  - `server_coverage_test.go` - 8 tests (embedded server startup, shutdown, config)
  - `tools_coverage_test.go` - 8 tests (tool registry, execution, listing)
- **Platform coverage increased**: From ~71.5% to ~85%
- **Security-critical packages**: 90-100% coverage achieved

### Changed

#### Version
- Updated from `2.0.0-dev` → `1.3.0` (stable release)
- Semantic versioning now in effect

#### Build System
- Improved synchronization in `main.go` for reliable startup
- Added proper error handling for service startup failures

### Test Results Summary

| Suite | Count | Pass | Fail | Skip | Coverage |
|-------|-------|------|------|------|----------|
| Unit Tests | ~150 | 150 | 0 | 0 | ~85% |
| Integration Tests | 60 | 58 | 0 | 1 | ~85% |
| E2E Tests | 6 | 6 | 0 | 0 | N/A |
| Upstream Tests | 2,134 | 2,134 | 0 | - | 65-70% |
| **TOTAL** | **2,350** | **2,348** | **0** | **1** | **~85%** |

### Fixed

- Fixed service startup race condition in proxy and dashboard servers
- Fixed E2E test configuration to include `data_dir` and `audit_dir` for persistence
- Fixed binary command arguments to include `--embedded-mcp` flag

### Security

- **Mandate compliance verified**: ATLAS and NIST AI RMF remain in Community tier
- Build-failing tests protect tier assignments (`TestMandateCompliance`, `TestOtherMandateCommunityFeatures`)
- All security-critical packages have ≥90% test coverage
- Immutable root filesystem in Docker (read-only root)

### Documentation

- Updated ANCHOR.md with comprehensive test results
- Added this CHANGELOG.md
- Updated release notes and milestones

---

## [1.2.0] - 2026-04-15

### Pre-MVP Release

### Added
- Persistence layer with tier-based retention
- Certificate automation with auto-generation
- MCP guardrails (session, tool, timeout, memory limits)
- Platform configuration system
- Docker containerization with immutable root
- Integration test suite (60 tests)
- Tier system with 91 features across 4 tiers

### Changed
- Consolidated two upstream projects into single binary
- Unified tier system replacing legacy systems
- configs/community.yaml fixed (rate_limit split)

---

## [1.1.0] - 2026-04-10

### Integration Phase

### Added
- Bridge between AegisGate proxy and AegisGuard MCP
- Platform adapter for tier/feature mapping
- Docker Compose support

---

## [1.0.0] - 2026-04-05

### Initial Consolidation

### Added
- Project structure from two upstream repos
- Basic proxy and MCP functionality
- Initial tier system prototype

