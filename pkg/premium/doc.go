// SPDX-License-Identifier: Apache-2.0
// Package premium provides interface contracts for enterprise-tier features.
//
// This package defines Go interfaces that decouple the open-source platform
// core from proprietary enterprise implementations. The open-source build
// uses no-op defaults; the enterprise build registers real implementations
// at init() time.
//
// See interfaces.go for the full API surface.
package premium
