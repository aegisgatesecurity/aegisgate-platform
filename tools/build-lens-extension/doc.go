// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool (v0.1.0+ Lens Phase 1 plain-JS)
// =========================================================================
//
// Package main implements the build tool for the AegisGate Lens
// browser extension. The build tool is a single Go program that:
//
//  1. Reads the plain JavaScript source files from the Lens repo
//     (github.com/aegisgatesecurity/aegisgate-lens/src/).
//  2. Validates the schema (the JSDoc `@typedef {Object} LensEvent`
//     block in api/client.js MUST match the Go Event struct in
//     pkg/lensbackend/validation.go).
//  3. Lints the source for forbidden patterns (eval, Function,
//     innerHTML, fetch outside the allowlist, prompt content
//     in log lines, etc. — see the §10.1 Privacy Policy CI check).
//  4. Copies the source files into dist/ preserving the
//     directory structure (util/, detectors/, privacy/, api/,
//     etc.). No transpilation, no bundling, no minification —
//     the source is already valid ES2020 plain JavaScript.
//  5. Generates the four Chrome Web Store icon sizes (16, 32,
//     48, 128) from the source PNG (lens-icon-source.png,
//     byte-identical to websites/aegisgate-site/public/logo.png).
//     Auto-crops transparent/white padding; nearest-neighbor
//     resize for crisp pixel rendering.
//  6. Packages the dist/ directory into a single ZIP.
//  7. Computes the SHA-256 of every file and emits
//     INVENTORY.txt for the release notes.
//
// The build tool has zero third-party dependencies. The
// Platform's go.mod is unchanged; the tool is built with the
// existing toolchain. Per the no-`npm` rule, there is no
// `package.json`, no `node_modules`, no bundler library.
//
// Usage:
//
//	go run ./tools/build-lens-extension/ \
//	  --src ../../aegisgate-lens/src \
//	  --dist ./dist \
//	  --version 0.1.0 \
//	  --commit $(git rev-parse HEAD)
//
// Output:
//
//	dist/
//	├── manifest.json
//	├── content.js
//	├── service-worker.js
//	├── popup.html
//	├── popup.js
//	├── welcome.html
//	├── welcome.js
//	├── util/logger.js
//	├── storage.js
//	├── privacy/domain_hash.js
//	├── privacy/schema.js
//	├── detectors/regex.js
//	├── detectors/luhn.js
//	├── detectors/index.js
//	├── detectors/from_platform.js
//	├── api/client.js
//	├── icons/icon-16.png
//	├── icons/icon-32.png
//	├── icons/icon-48.png
//	├── icons/icon-128.png
//	├── schema.json
//	└── INVENTORY.txt
//	lens-0.1.0-<short-sha>.zip   (the final artifact)
//
// Exit codes:
//
//	0  success
//	1  bad arguments
//	2  source not found or unreadable
//	3  schema validation failed
//	4  lint check failed
//	5  bundle failed
//	6  package failed
//	7  icon generation failed
//
// The build is deterministic. Given the same inputs (src/,
// version, commit), the output is byte-for-byte identical.
// This is required for the release artifact identity.
//
// v0.1.0+ Lens Phase 1 (plain-JS pivot, 2026-06-19).
// =========================================================================
package main
