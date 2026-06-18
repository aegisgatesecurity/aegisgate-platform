// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Test Harness (v3.5.0+ Lens Phase 2)
// =========================================================================
//
// Package main implements the end-to-end test harness for the
// AegisGate Lens browser extension. The harness drives a
// headless Chromium via the Chrome DevTools Protocol (CDP) and
// runs the extension's content script against a mock AI
// provider page. It asserts that the extension detects the
// expected sensitive-data categories and does NOT send prompt
// content over the wire.
//
// IMPORTANT: This module depends on `gorilla/websocket` for
// CDP communication. The Platform's main go.mod is UNCHANGED;
// this dependency lives ONLY in tools/test-extension/go.mod,
// which is a separate Go module (test tooling, not runtime).
//
// The build/run flow:
//
//  1. Spawn headless Chromium with --remote-debugging-port=9222
//     --disable-gpu --no-sandbox.
//  2. GET http://localhost:9222/json/version to get the
//     WebSocket URL.
//  3. Open a WebSocket to that URL using gorilla/websocket.
//  4. Send CDP commands (Page.navigate, Runtime.evaluate,
//     Page.loadEventFired) using a JSON-RPC frame format.
//  5. Load the extension's content script into a mock AI
//     provider page (testdata/<provider>.html).
//  6. Run the test cases (regex detection tests) and assert
//     the expected outputs.
//  7. Write a JSON report and exit 0 on success, 1 on failure.
//
// Usage:
//
//	# Build the extension first:
//	go run ./tools/build-lens-extension/ \
//	  --src <lens-repo>/src --dist /tmp/lens-dist \
//	  --version 0.1.0 --commit <sha>
//
//	# Run the tests:
//	go run ./tools/test-extension/ \
//	  --dist /tmp/lens-dist \
//	  --tests <lens-repo>/test \
//	  --provider chatgpt
//
// Output:
//
//	test-report.json   {passes: N, fails: M, errors: K, ...}
//
// Exit codes:
//
//	0  all tests passed
//	1  one or more tests failed
//	2  chromium failed to start
//	3  CDP connection failed
//	4  test data missing
//
// Why a separate go.mod?
//
//	The Platform's runtime code is intentionally closed-dep
//	(stdlib + vendored upstream + a grandfathered set of
//	3rd-party packages). Adding gorilla/websocket to the
//	main go.mod would violate this.
//
//	The test harness is a developer tool, not a runtime
//	dependency. It is invoked during development and CI,
//	not shipped to users. A separate go.mod in tools/test-extension/
//	scopes the new dep to this tool only.
//
//	The Platform's prior art: tools/build-lens-extension/ is a
//	Go program with no third-party deps. It does NOT need a
//	separate go.mod (no deps). tools/test-extension/ DOES
//	need a separate go.mod (one dep: gorilla/websocket).
//
// v3.5.0+ Lens Phase 2.
// =========================================================================
package main
