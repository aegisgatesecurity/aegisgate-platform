<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2024-2026 AegisGate Security, LLC -->

# Contributing to AegisGate Platform

## Thank You

Thank you for your interest in contributing to AegisGate Platform! We welcome contributions from everyone — whether you're fixing a bug, adding a feature, improving documentation, or suggesting ideas. Your help makes this project better for the entire community.

## Code of Conduct

This project and everyone participating in it is governed by the [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [conduct@aegisgatesecurity.io](mailto:conduct@aegisgatesecurity.io).

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/aegisgate-platform.git
   cd aegisgate-platform
   ```
3. **Add the upstream** remote:
   ```bash
   git remote add upstream https://github.com/aegisgate/aegisgate-platform.git
   ```
4. **Create a branch** with a descriptive name using one of the following prefixes:
   - `feature/` — for new features (e.g., `feature/add-rate-limiting`)
   - `fix/` — for bug fixes (e.g., `fix/auth-token-expiry`)
   - `docs/` — for documentation changes (e.g., `docs/update-api-reference`)

   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- **Go 1.25.9** or later

### Building

```bash
go build ./...
```

### Testing

Run the full test suite with race detection:

```bash
go test -race ./...
```

### Linting & Security

Before submitting a pull request, ensure all of the following pass:

```bash
# Format check
gofmt -s -d .

# Vet
go vet ./...

# Vulnerability check
govulncheck ./...
```

All checks must pass with zero errors or warnings before a PR will be reviewed.

## Making Changes

- **One feature per PR** — keep pull requests focused on a single concern. This makes review faster and reduces the risk of regressions.
- **Write tests** — every change should include appropriate test coverage. Bug fixes should include a test that reproduces the original issue.
- **Maintain 75%+ coverage** — we require a minimum of 75% test coverage across the codebase. Use `go test -cover ./...` to check.
- **Run all checks locally** — verify that `go build`, `go test -race`, `gofmt`, `go vet`, and `govulncheck` all pass before pushing.

## Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>: <description>

[optional body]

[optional footer]
```

Common types:

| Type     | Usage                        |
|----------|------------------------------|
| `feat:`  | A new feature                |
| `fix:`   | A bug fix                    |
| `docs:`  | Documentation changes        |
| `style:` | Code style changes (format)  |
| `refactor:` | Code refactoring          |
| `test:`  | Adding or updating tests     |
| `chore:` | Build/tooling changes        |

Examples:

```
feat: add rate-limiting middleware to gateway
fix: resolve token expiry calculation in auth service
docs: update contributing guide with coverage requirements
```

## Pull Request Process

1. **Fill out the PR template** — provide a clear description of changes, motivation, and testing performed.
2. **Link related issues** — reference issues in the PR description (e.g., `Closes #42` or `Fixes #123`).
3. **CI must pass** — all continuous integration checks (build, test, lint, security scan) must pass before review begins.
4. **At least one review** — pull requests require at least one approving review from a maintainer before merging.
5. **Keep your branch up to date** — rebase on `main` before final review if needed:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

## Reporting Security Vulnerabilities

**Do not file public issues for security vulnerabilities.**

If you discover a security vulnerability, please report it responsibly by emailing [security@aegisgatesecurity.io](mailto:security@aegisgatesecurity.io) in accordance with our [SECURITY.md](SECURITY.md). We ask that you give us a reasonable amount of time to address the issue before any public disclosure.

## License

By contributing to AegisGate Platform, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE). No additional contributor license agreement (CLA) is required.

## Questions?

If you have questions or need help, feel free to start a discussion on [GitHub Discussions](https://github.com/aegisgate/aegisgate-platform/discussions).