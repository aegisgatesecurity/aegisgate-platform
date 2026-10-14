// SPDX-License-Identifier: Apache-2.0
// Package sarifoutput produces SARIF (Static Analysis Results Interchange
// Format) 2.1.0 output for Platform detection results.
//
// Unlike the Scanner's SARIF output (which targets source files with
// line/column locations), Platform's SARIF output represents detections
// from HTTP request/response content scanning. Locations use the API
// endpoint (host + path + direction) as the artifact URI, and the
// character offset within the content as the region.
//
// The output is compatible with GitHub Code Scanning, SIEM ingestion,
// and any SARIF 2.1.0 consumer. Rule definitions include CWE, OWASP LLM
// Top 10, NIST AI RMF, NIST CSF 2.0, and EU AI Act references from the
// pkg/remediation/ metadata database.
//
// SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package sarifoutput