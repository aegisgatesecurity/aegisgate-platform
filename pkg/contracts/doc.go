// SPDX-License-Identifier: Apache-2.0
// AegisGate Security Platform — Canonical Contracts
//
// Package contracts defines the canonical data formats exchanged across all
// AegisGate products (Platform, Scanner, Rampart, Lens, MCP).
//
// These are the shared contracts that make full-mesh interoperability possible
// without point-to-point mapping spaghetti. Every product that exchanges
// pattern definitions or detection telemetry uses these types at the
// interop boundary.
//
// See MIGRATION.md for mapping from existing product structs to canonical format.
package contracts