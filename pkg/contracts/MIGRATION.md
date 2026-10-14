# AegisGate Canonical Contracts — Migration Guide

## Overview

This package (`pkg/contracts/`) defines the canonical data formats exchanged
across all AegisGate products. These are the shared contracts that make
full-mesh interoperability possible without point-to-point mapping spaghetti.

## Files

| File | Purpose |
|------|---------|
| `pattern.go` | Canonical pattern format (Go struct) |
| `event.go` | Canonical event schema (Go struct) |
| `pattern_v1.json` | JSON Schema for pattern format (for non-Go products like Lens) |
| `event_v1.json` | JSON Schema for event format (for non-Go products like Lens) |
| `MIGRATION.md` | This file — maps existing product structs to canonical format |

## Design Decisions

### 1. Severity as String (not int)
Platform uses `Severity int` (iota 0-4). Scanner/Rampart use `Severity string`.
**Canonical: string.** Strings are self-documenting in JSON, portable to JS (Lens),
and don't require a lookup table to interpret.

### 2. Raw Regex String (not compiled *regexp.Regexp)
Platform's `Pattern` stores `Regex *regexp.Regexp` (compiled). Scanner's `PatternDef`
stores `Regex string` (raw). **Canonical: raw string.** Compiled regex cannot be
serialized over HTTP. Each product compiles locally after receiving the raw string.

### 3. Metadata-Only Events (no PII values, no prompt text)
Following Rampart's proven privacy model (12 non-negotiables). Events contain
detection metadata (what was found, where, severity) but NEVER the matched text,
prompt content, or PII values. This is critical for:
- Air-gap trust: users know we're not exfiltrating their data
- Legal compliance: GDPR, CCPA, HIPAA
- Enterprise sales: security teams approve metadata-only telemetry

### 4. Source Field for Routing
Every event includes a `source` field ("lens", "rampart", "scanner", "mcp").
This lets the unified receiver route events to appropriate aggregation logic
without parsing the event structure to guess the origin.

### 5. CorrelationID for Cross-Product Tracing
Optional field that links related events across products. E.g., Scanner finds
a dangerous function in an MCP tool → MCP blocks that tool → both events share
a CorrelationID. Enables full-mesh observability without distributed tracing.

## Existing Struct → Canonical Mapping

### Pattern Format

| Field | Platform `scanner.Pattern` | Scanner `detectors.PatternDef` | Canonical `contracts.Pattern` |
|-------|---------------------------|-------------------------------|-------------------------------|
| ID | (uses Name) | (uses Name) | `ID` (new, unique key) |
| Name | `Name` | `Name` | `Name` |
| Regex | `Regex *regexp.Regexp` | `Regex string` | `Regex string` (raw) |
| Severity | `Severity int` (iota) | `Severity string` | `Severity PatternSeverity` (string) |
| Category | `Category string` | `Category Category` (string) | `Category PatternCategory` (string) |
| Description | `Description` | `Description` | `Description` |
| Languages | (n/a) | `Languages []Language` | `Languages []PatternLanguage` |
| Confidence | (n/a, implicit 1.0) | (n/a, implicit 1.0) | `Confidence float64` |
| Keywords | (n/a) | (extracted from regex) | `Keywords []string` |
| Version | (n/a) | (n/a) | `Version string` ("v1") |

### Event Format

| Field | Rampart `PlatformEvent` | Scanner `Finding` (metadata-only) | Lens FP Report | Canonical `contracts.Event` |
|-------|------------------------|-----------------------------------|----------------|------------------------------|
| ID | (n/a) | (n/a) | (n/a) | `ID` (UUID v4, new) |
| Source | `Source` ("rampart") | (implicit "scanner") | (implicit "lens") | `Source EventSource` |
| Timestamp | `Timestamp` | (scan time) | (report time) | `Timestamp time.Time` |
| Direction | `Direction` | (n/a) | (n/a) | `Direction EventDirection` |
| Host | `Host` | (n/a) | (hashed) | `Host` or `HashedDomain` |
| Path | `Path` | (n/a) | (n/a) | `Path` |
| Artifact | (n/a) | `Artifact` | (n/a) | `Artifact` |
| TotalDets | `TotalDets` | (count) | (1) | `TotalDetections` |
| Blocked | `Blocked` | (n/a) | (n/a) | `Blocked` |
| Action | (n/a) | (n/a) | `action` | `Action` |
| Findings | (n/a) | (per-finding) | (n/a) | `Findings []EventFinding` |
| Categories | `Categories` | `Category` | `category` | `Categories []string` |
| Severities | `Severities` | `Severity` | `severity` | `Severities []string` |
| Rules | `Rules` | `RuleID` | (n/a) | `Rules []string` |
| PIICategories | `PIICategories` | (n/a) | (n/a) | `PIICategories []string` |
| SecretTypes | `SecretTypes` | (n/a) | (n/a) | `SecretTypes []string` |
| MLScore | `MLScore` | (ML confidence) | (n/a) | `MLScore float64` |
| CorrelationID | (n/a) | (n/a) | (n/a) | `CorrelationID` (new) |
| InstallationID | (n/a) | (n/a) | (n/a) | `InstallationID` (new) |

## Migration Path

Products do NOT need to change their internal structs immediately. The canonical
format is used at the interop boundary (HTTP serialization). Each product can
add a converter function:

```go
// Platform: scanner.Pattern → contracts.Pattern
func (p *Pattern) ToCanonical() contracts.Pattern { ... }

// Scanner: detectors.PatternDef → contracts.Pattern
func (p *PatternDef) ToCanonical() contracts.Pattern { ... }

// Rampart: PlatformEvent → contracts.Event
func (e *PlatformEvent) ToCanonical() contracts.Event { ... }
```

Products keep their internal types. The canonical format is only used when
exchanging data across product boundaries (HTTP, shared modules).

## Versioning

- Schema version "v1" is the current version.
- When the format changes, bump to "v2" and keep "v1" endpoints alive.
- Pull endpoints: `/api/v1/patterns/latest` (v1), `/api/v2/patterns/latest` (v2)
- Push endpoints: `/api/v1/telemetry` (v1), `/api/v2/telemetry` (v2)
- Clients send their supported version; server responds with that version or
  a 400 with the latest supported version in the error body.