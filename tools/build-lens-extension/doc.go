// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool (v3.5.0+ Lens Phase 2)
// =========================================================================
//
// Package main implements the build tool for the AegisGate Lens
// browser extension. The build tool is a single Go program that:
//
//   1. Reads the TypeScript source files from the Lens repo
//      (github.com/aegisgatesecurity/aegisgate-lens/src/).
//   2. Validates the schema (the TS types MUST match the Go
//      Event struct in pkg/lensbackend/validation.go).
//   3. Lints the source for forbidden patterns (eval, Function,
//      innerHTML, fetch outside the allowlist, prompt content
//      in log lines, etc. — see the §10.1 Privacy Policy CI check).
//   4. Bundles the source into a single dist/content.js,
//      dist/service-worker.js, and dist/popup/welcome JS+HTML
//      (no transpilation; the source is hand-written ES2020).
//   5. Minifies the JS (strips leading whitespace, blank lines,
//      comments) — ~30% size reduction.
//   6. Copies the manifest, assets, and the four icon PNGs.
//   7. Packages the dist/ directory into a single ZIP.
//   8. Computes the SHA-256 of every file and emits
//      INVENTORY.txt for the release notes.
//
// The build tool has zero third-party dependencies. The
// Platform's go.mod is unchanged; the tool is built with the
// existing toolchain. Per the no-`npm` rule, there is no
// `package.json`, no `node_modules`, no bundler library.
//
// Usage:
//
//   go run ./tools/build-lens-extension/ \
//     --src ../../aegisgate-lens/src \
//     --dist ./dist \
//     --version 0.1.0 \
//     --commit $(git rev-parse HEAD)
//
// Output:
//
//   dist/
//   ├── manifest.json
//   ├── content.js
//   ├── service-worker.js
//   ├── popup/popup.html
//   ├── popup/popup.js
//   ├── welcome.html
//   ├── welcome.js
//   ├── icons/icon-16.png
//   ├── icons/icon-32.png
//   ├── icons/icon-48.png
//   ├── icons/icon-128.png
//   ├── schema.json
//   └── INVENTORY.txt
//   lens-0.1.0-<short-sha>.zip   (the final artifact)
//
// Exit codes:
//
//   0  success
//   1  bad arguments
//   2  source not found or unreadable
//   3  schema validation failed
//   4  lint check failed
//   5  bundle or minify failed
//   6  package failed
//
// The build is deterministic. Given the same inputs (src/,
// version, commit), the output is byte-for-byte identical.
// This is required for the release artifact identity.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================
package main
