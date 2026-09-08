// SPDX-License-Identifier: Apache-2.0
//go:build cgo
// +build cgo

package ml

import (
	"os"
	"path/filepath"
)

// onnxRuntimeSearchPaths lists common locations for the onnxruntime shared library.
// Searched in order; first match wins. Overridden by ONNXRuntimeLibPath config
// or ONNXRUNTIME_SHARED_LIBRARY_PATH env var.
var onnxRuntimeSearchPaths = []string{
	"/usr/local/lib/libonnxruntime.so",            // Docker container
	"/usr/lib/libonnxruntime.so",                  // Alpine package
	"/usr/lib/x86_64-linux-gnu/libonnxruntime.so", // Debian/Ubuntu
}

// discoverONNXRuntimeLib finds the onnxruntime shared library by searching:
//  1. Explicit config path (ONNXRuntimeLibPath in config)
//  2. Environment variable (ONNXRUNTIME_SHARED_LIBRARY_PATH)
//  3. User-local install (~/.local/lib)
//  4. System library paths
//
// Returns empty string if not found (onnxruntime will use its default search).
func discoverONNXRuntimeLib(configPath string) string {
	// 1. Explicit config path takes priority
	if configPath != "" {
		cleanPath := filepath.Clean(configPath)
		if _, err := os.Stat(cleanPath); err == nil {
			return cleanPath
		}
	}

	// 2. Environment variable
	if envPath := os.Getenv("ONNXRUNTIME_SHARED_LIBRARY_PATH"); envPath != "" {
		cleanEnvPath := filepath.Clean(envPath)
		if _, err := os.Stat(cleanEnvPath); err == nil {
			return cleanEnvPath
		}
	}

	// 3. User-local install
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		userLocalPath := filepath.Join(homeDir, ".local", "lib", "libonnxruntime.so")
		if _, err := os.Stat(userLocalPath); err == nil {
			return userLocalPath
		}
	}

	// 4. System library paths
	for _, p := range onnxRuntimeSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "" // Let onnxruntime use its default search
}
