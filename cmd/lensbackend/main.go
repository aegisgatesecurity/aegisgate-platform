// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens Backend - Standalone Server Binary (Pen-Test Target)
// =========================================================================
//
// Day 11: This binary is a thin wrapper around pkg/lensbackend.NewServer
// so the Lens backend can run as a standalone process for security
// testing. It is NOT the production entry point — in production, the
// Lens backend runs embedded in cmd/aegisgate-platform. This binary
// exists so penetration tests can attack the real Go binary (not the
// httptest in-process server) over the wire.
//
// Usage:
//
//	LENS_PORT=9999 \
//	LENS_BEARER_TOKEN=pentest-token \
//	LENS_IOC_STORE_PATH=/tmp/lens-pentest-ioc \
//	LENS_HMAC_KEY=/tmp/lens-pentest-hmac.bin \
//	go run ./cmd/lensbackend/
//
// Then attack it from the host or from a Kali container:
//
//	curl -s http://127.0.0.1:9999/api/v1/lens/healthz
//	# -> {"status":"ok","version":"..."}
//
// =========================================================================

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aegisgatesecurity/aegisgate-platform/pkg/lensbackend"
)

func main() {
	cfg, err := lensbackend.LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	// In pen-test mode, refuse to run without an explicit bearer
	// token. The default config has BearerToken="" which makes the
	// server return 503 for everything except /healthz.
	if cfg.BearerToken == "" {
		fmt.Fprintln(os.Stderr,
			"WARNING: LENS_BEARER_TOKEN is empty; only /healthz will be reachable.")
		fmt.Fprintln(os.Stderr,
			"Set LENS_BEARER_TOKEN=<token> to enable the other endpoints.")
	}

	srv, err := lensbackend.NewServer(cfg, "lensbackend-pentest")
	if err != nil {
		log.Fatalf("NewServer: %v", err)
	}
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("lensbackend listening on %s (ioc=%s, rate=%d/min)",
		addr, cfg.IOCStorePath, cfg.RateLimitPerMin)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
