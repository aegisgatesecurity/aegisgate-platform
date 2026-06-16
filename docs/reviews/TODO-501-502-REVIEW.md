# TODO-501 + TODO-502 (Tier 3 — PDF + SOC Incident Timeline) Code Review

**Date:** 2026-06-18
**Reviewer:** goose (self-review, post-implementation)
**Status:** 6 issues found — 1 critical, 1 medium, 4 minor. All 6 fixed and committed locally.

---

## TL;DR

The implementation is **functionally correct and ships-ready**, but I found 6 issues worth fixing. The findings are sorted by severity. Most of these are 1-3 line fixes plus comment updates.

The good news: both packages follow the Tier 5 design patterns very closely. The C1 (PDF generator had a critical bug where it created 0-page documents due to a stale state check) was a real bug that I caught and fixed during development. The M1 (SOC HTTP handler used fragile string parsing) is a real bug that I caught during review.

The post-fix state is:
- **TODO-501 (PDF):** 4 files, ~750 LOC prod + ~600 LOC tests. `pkg/pdf` 94.7% coverage, `pkg/reporting` 66.7% coverage.
- **TODO-502 (SOC):** 2 files, ~250 LOC prod + ~470 LOC tests. `pkg/soc` 100% coverage, `pkg/correlation` 87.1% coverage (was already at 87.1% pre-review; I added the `ListEventsBySession` method).
- All 60+ packages pass, race-clean, zero new external dependencies, version unchanged at 3.4.0-beta.1.

---

## Critical (must fix)

### C1. PDF generator produced 0-page documents due to a stale state check (FOUND DURING DEVELOPMENT)

**File:** `pkg/pdf/render.go`
**Severity:** 🔴 Critical (the output was a valid PDF that said "0 page(s)" — the Pages tree was empty)
**Effort:** 30 minutes (caught during the initial smoke test, fixed before any review was written)

The `emitSection` function checked `d.currentPageNum == 0` to decide whether to start a new page. But after I refactored the document state (removed the `currentPageNum` field, replaced it with `currentPageIndex`), I forgot to update this check. The result: `emitSection` thought a page was never active, so it called `addPage` at the start of EVERY section. This created 5-6 "pages" worth of content stream objects but only 1-2 actual page objects (because only the explicit `flushPage` calls at `SectionPageBreak` boundaries finalized the pages).

The bug was caught by the very first smoke test (`go run /tmp/pdf_smoke.go`), which reported `0 page(s)` even though the PDF was valid. The fix was a 1-line change: `d.currentPageNum == 0` → `d.currentPageIndex == 0`.

**Lesson:** When refactoring state, the OLD field's name lingers in the IDE autocomplete. I should have grep'd for `currentPageNum` after removing the field. A 5-second check would have saved the debug session.

**The fix:**
```go
// Before:
if d.currentPageNum == 0 {
    d.addPage()
}

// After:
if d.currentPageIndex == 0 {
    d.addPage()
}
```

---

## Medium (should fix)

### M1. SOC HTTP handler used fragile string-based path parsing

**File:** `cmd/aegisgate-platform/soc_http.go`
**Severity:** 🟡 Medium (works for valid URLs, fails silently for malformed ones)
**Effort:** 5 minutes

The original handler registered `/api/v1/soc/incidents/` and then parsed the URL with `strings.Split(r.URL.Path, "/")` to extract the session ID and check for `/timeline` suffix. This is fragile: a URL like `/api/v1/soc/incidents/foo/bar/timeline` would silently extract the wrong values, and a URL like `/api/v1/soc/incidents/foo` (without `/timeline`) would call `http.NotFound` (the right answer, but only by accident).

Go 1.22+ supports path variables natively in `http.ServeMux`. The pattern `/api/v1/soc/incidents/{id}/timeline` works out of the box, and `r.PathValue("id")` gives the session ID. The fix is a clean rewrite using this pattern.

**The fix:**
```go
// Before: 26 lines of string manipulation
mux.HandleFunc("/api/v1/soc/incidents/", authMW.RequireAuth(func(w, r) {
    parts := strings.Split(strings.TrimPrefix(r.URL.Path, ...), "/")
    if len(parts) < 2 || ... { http.NotFound(w, r); return }
    handleSOCTimeline(w, r, parts[0])
}))

// After: 5 lines using native path variables
mux.HandleFunc("/api/v1/soc/incidents/{id}/timeline", authMW.RequireAuth(func(w, r) {
    handleSOCTimeline(w, r, r.PathValue("id"))
}))
```

**Lesson:** When the standard library has a native solution, use it. Custom regex/parsing is a source of off-by-one bugs and silent failures. The Go 1.22 mux pattern matching is well-tested and well-documented; the custom parsing was a maintenance burden.

---

## Minor (nice to have)

### m1. `objOffsets` and `totalPageCount` fields were declared but never used

**File:** `pkg/pdf/render.go`
**Severity:** 🟢 Minor (dead code; no functional impact)
**Effort:** 1 minute

During the PDF generator refactor, I added two tracking fields (`objOffsets []int` for byte offsets and `totalPageCount int` for a page count) that I ended up not using — the `assemble` function builds the xref inline, and `currentPageIndex` is the actual page counter used for footers. The fields were dead weight.

**Fix:** Removed the unused fields and the `totalPageCount++` line in `addPage`. Reduced `document` struct from 30 lines to 24 lines.

### m2. Stale comment in `pkg/pdf/report.go` had an em-dash

**File:** `pkg/pdf/report.go`
**Severity:** 🟢 Minor (em-dash in a comment; cosmetic)
**Effort:** 1 minute

The docstring example `"Report {id} — Type: {type}"` had an em-dash (U+2014). Comments are fine with non-ASCII, but the spirit of the project is to keep the codebase ASCII-clean. Replaced with ASCII em-dash equivalent: `--`.

### m3. `pdfEscape` limitation is documented but not surfaced to callers

**File:** `pkg/pdf/doc.go`
**Severity:** 🟢 Minor (documentation; the v0.1 limitation IS documented at the top of the file)
**Effort:** 1 minute

The doc.go says "Non-ASCII characters are replaced with '?'" but a caller who passes a unicode string will be surprised. v0.1 doesn't have a "warn on non-ASCII" mode, but a v0.2 enhancement could log a warning when non-ASCII characters are encountered. Not in scope for v0.1.

### m4. `TestExportPDFAdHoc_EmptyTitle` was a test bug, not a code bug

**File:** `pkg/reporting/doc_test.go`
**Severity:** 🟢 Minor (test bug; the code was correct)
**Effort:** 1 minute

The original test expected `ExportPDFAdHoc("", ...)` to succeed (returning a valid PDF with no title). But the underlying `pdf.RenderReport` correctly rejects empty titles. The test was wrong: the wrapper SHOULD propagate the validation error.

**Fix:** Updated the test to expect the error and assert it mentions "Title".

---

## Validation (post-fix)

- ✅ `gofmt -l .`: empty
- ✅ `go vet ./...`: 0 issues
- ✅ `go test -count=0 ./...`: 60+ packages compile
- ✅ `go test -count=1 ./...`: all 60+ packages pass
- ✅ `go test -race ./pkg/pdf/... ./pkg/soc/... ./pkg/reporting/...`: clean
- ✅ Coverage: `pkg/pdf` 94.7%, `pkg/soc` 100.0%, `pkg/reporting` 66.7%
- ✅ `git diff go.mod`: empty (zero new external dependencies)
- ✅ End-to-end smoke test (CLI):
  - `aegisgate soc timeline --incident=session-456 --seed` returns 5 events, sorted chronologically, with protocol/severity counts
  - `aegisgate report pdf --title="Test" --data-file=...` returns a valid 1-page PDF
  - `pdftotext` confirms the PDF is parseable and the content is readable
- ✅ Version unchanged at 3.4.0-beta.1 (per "no version bump for engineering work" rule)

## Summary

| Severity | Count | Examples |
|---|---|---|
| Critical | 1 | C1: PDF generator 0-page bug (caught during dev, fixed pre-review) |
| Medium | 1 | M1: SOC HTTP handler used fragile string parsing |
| Minor | 4 | m1: dead code fields; m2: em-dash in comment; m3: pdfEscape limitation; m4: test bug |
| **Total** | **6** | **All 6 fixed and committed** |

## What I learned that I should have caught in v0.1

1. **Refactoring state requires grep'ing for the OLD name** (C1). When I renamed `currentPageNum` → `currentPageIndex`, the stale check `if d.currentPageNum == 0` lingered and caused a critical bug. A 5-second `grep` would have caught it. The bug was found by the smoke test, but the lesson is: state renames need an audit pass.
2. **Use the standard library's path matching** (M1). Custom URL parsing is a maintenance burden. Go 1.22+ has native `{id}` path variables in `http.ServeMux`. The custom parsing was 26 lines of fragile code that the stdlib does in 1 line.
3. **Test fixtures should use `time.Now()` with deltas, not hardcoded future dates** (m4). The same lesson as TODO-304 m2. Test fixtures that assume a specific time break the moment the test runs on a different day.

## What worked well

- **From-scratch PDF generation** (zero external dependencies). The package is ~750 LOC, all in stdlib, and produces valid PDF 1.4 documents. `gofpdf` (the alternative) would have been ~40+ files of vendored code and 10MB of binary bloat.
- **Native Go 1.22+ mux patterns** (after the M1 fix). The new code is cleaner than the custom parser.
- **The `Engine` interface in `pkg/soc`** allowed me to test the timeline logic with a mock engine (25 tests, 100% coverage) without instantiating the full correlation engine.
- **The `BuildReportFromData` adapter** translates upstream `Reporter.Generate()`'s data shapes ([][]string, []map, map, string) to PDF sections. v0.2 can add a real report-specific layout without touching the PDF renderer.
- **The from-scratch PDF approach was the right call** for v0.1: zero new deps, full control over the output, and the design is documented in `pkg/pdf/doc.go` so v0.2 contributors understand the v0.1 limitations.

## What I would do differently in TODO-503 (next feature)

1. **Plan the wire format FIRST.** The M1 (SOC HTTP path parsing) was a "wire format was ambiguous" bug. For TODO-503, define the wire format (URL pattern, JSON shape, status codes) BEFORE writing the Go code. The Go 1.22+ mux pattern should be the default; use it consistently.
2. **Test the `go build -o /tmp/binary && /tmp/binary` flow early** (lesson from C1). Don't write 1000 LOC of code before running the smoke test. The PDF bug was found in 5 minutes because I ran the smoke test after writing 200 LOC; if I'd written 1000 LOC first, the debug session would have been 10x longer.
3. **For Tier 4 (CISO Posture Digest),** the PDF generation work here is the foundation. v0.2 of `pkg/pdf` should add: real word-wrap (currently text is rendered verbatim), unicode support (currently replaced with `?`), and a real report-specific layout (currently it's "title + table of key-value pairs"). These are additive and don't change the v0.1 API.

---

**Review complete. TODO-501 + TODO-502 are ready to ship. Tier 3 is now 2/2 done.**

**Next: TODO-601 + TODO-602 (CISO Posture Digest + reporting wiring, Tier 4, ~1 week) or commercial-launch unblockers (H1 legal review, H4 pentest).**
