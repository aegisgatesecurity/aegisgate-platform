# AegisGate Test Lab

A Docker-based testing environment for the AegisGate Security Platform that provides a complete test infrastructure including a real OIDC/SAML Identity Provider (Keycloak), PostgreSQL, Redis, and the AegisGate application itself.

## Purpose

This lab environment enables:

- **Integration Testing**: Real OIDC/SAML flows with a production-quality IdP
- **End-to-End Testing**: Complete authentication flows across all components
- **Coverage Testing**: Testing code paths that require real HTTP calls and XML signatures
- **MCP Server Testing**: Using a second AegisGate instance as an MCP server
- **CI/CD Validation**: Ensuring changes work in a realistic environment

## Quick Start

```bash
# 1. Start the lab environment
cd testlab
docker-compose up -d

# 2. Wait for services to be ready
./scripts/setup.sh

# 3. Run standard unit tests
cd .. && go test -cover ./pkg/sso/...

# 4. Run lab integration tests (requires running lab)
LAB_ENABLED=1 go test -tags=lab -v ./pkg/sso/...

# 5. Stop the lab
cd testlab && docker-compose down
```

## Services

| Service | Port | Purpose |
|---------|------|---------|
| **Keycloak** | 8080 | Real OIDC + SAML Identity Provider |
| **PostgreSQL** | 5432 | Test database |
| **Redis** | 6379 | Session store |
| **AegisGate Test** | 8443 | Application under test |
| **MCP Server** | 9090 | MCP protocol server |

## Test Users

| Username | Password | Role |
|----------|----------|------|
| admin | admin | Administrator |
| operator | operator | Operator |
| developer | developer | Developer |
| viewer | viewer | Viewer |

## Test Categories

### Unit Tests (Default)
```bash
go test ./pkg/sso/...
```
- No external dependencies
- Uses mocks for external services
- Fast execution (~2 seconds)

### Coverage Tests
```bash
go test -cover ./pkg/sso/...
```
- Measures code coverage
- Currently at ~77% for pkg/sso
- Target: 80%+

### Lab Integration Tests
```bash
LAB_ENABLED=1 go test -tags=lab -v ./pkg/sso/...
```
- Requires running lab environment
- Tests with real OIDC/SAML flows
- Tests XML signature validation
- Longer execution time (~30 seconds)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LAB_ENABLED` | 0 | Set to 1 to enable lab tests |
| `KEYCLOAK_URL` | http://localhost:8080 | Keycloak server URL |
| `KEYCLOAK_REALM` | aegisgate | Keycloak realm name |
| `KEYCLOAK_ADMIN` | admin | Keycloak admin username |
| `KEYCLOAK_ADMIN_PASSWORD` | admin | Keycloak admin password |
| `OIDC_CLIENT_ID` | aegisgate-platform | OIDC client ID |
| `OIDC_CLIENT_SECRET` | aegisgate-oidc-secret | OIDC client secret |
| `DATABASE_URL` | postgres://... | PostgreSQL connection string |
| `REDIS_URL` | redis://localhost:6379/0 | Redis connection string |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Test Lab Network                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────┐   │
│  │  Keycloak  │────▶│  PostgreSQL │     │  AegisGate Test  │   │
│  │   (IdP)    │     │  (Storage)  │     │   (App Under    │   │
│  │             │     │             │     │     Test)       │   │
│  │ OIDC + SAML │     │             │     │                 │   │
│  │  Port 8080  │     │  Port 5432  │     │   Port 8443     │   │
│  └─────────────┘     └─────────────┘     └─────────────────┘   │
│         │                                         │              │
│         │           ┌─────────────┐                │              │
│         └──────────▶│    Redis    │◀───────────────┘              │
│                     │  (Sessions) │                              │
│                     │  Port 6379  │                              │
│                     └─────────────┘                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Future Expansion

### Phase 1: Coverage Improvement
- [x] Docker Compose setup
- [x] Keycloak realm configuration
- [x] Basic integration tests
- [ ] SAML signature validation tests
- [ ] OIDC token refresh tests

### Phase 2: RBAC Testing
- [ ] Role mapping tests
- [ ] Permission enforcement tests
- [ ] Cross-provider role synchronization

### Phase 3: ToolAuth Testing
- [ ] Tool authorization tests
- [ ] Risk matrix validation
- [ ] MCP session management

### Phase 4: E2E Testing
- [ ] Complete login flows
- [ ] Session lifecycle tests
- [ ] Logout and SLO tests

## Troubleshooting

### Keycloak not starting
```bash
docker logs aegisgate-keycloak
docker-compose logs keycloak
```

### Tests failing with connection errors
```bash
# Verify services are running
docker-compose ps

# Check Keycloak health
curl http://localhost:8080/health/ready
```

### Realm not imported
```bash
# Re-import realm
docker exec aegisgate-keycloak bash -c \
  '/opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/aegisgate-realm.json'
```

## Contributing

When adding new tests:
1. Add unit tests to `pkg/sso/*_test.go`
2. Add integration tests to `pkg/sso/*_integration_test.go`
3. Add lab tests to `pkg/sso/sso_lab_test.go`
4. Update coverage targets in CI configuration

## License

Apache-2.0
