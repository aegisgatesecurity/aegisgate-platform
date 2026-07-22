// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Security Platform - Trust Portal: HTML page
// =========================================================================
//
// The trust portal HTML is a single self-contained file embedded
// in the binary as a string constant. It has:
//
//   - Inline CSS (no external CDN, no build step)
//   - Inline JS (no framework, no external CDN)
//   - Semantic HTML (header, main, footer, nav, table, etc.)
//   - ARIA labels + skip-link for accessibility
//   - CSP-compatible (no inline scripts from external sources,
//     all from same origin)
//
// The page polls the 3 JSON endpoints every 60 seconds and re-renders.
// It is intentionally simple: no SPA, no router, no state management.
// A marketing/operational page doesn't need that complexity.
//
// Decisions locked in plans/TRUST-PORTAL-DESIGN.md:
//   - Path: aegisgatesecurity.io/trust (not subdomain)
//   - Refresh: 60s
//   - No customer count display (deferred to v3.5.0)
//   - Contact: support@aegisgatesecurity.io (already configured)
// =========================================================================

package trustportal

// indexHTML is the trust portal HTML page. It is served at /trust
// and /trust/index. The page is intentionally a single file with
// inline CSS and JS to keep deployment simple (no static file server,
// no CDN, no build step). CSP-compatible.
const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'">
<title>AegisGate Trust Portal - Live Compliance Posture</title>
<style>
:root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8; --green: #10b981; --yellow: #eab308; --red: #ef4444; --blue: #3b82f6; --border: #334155; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: var(--text); background: var(--bg); }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }
header { text-align: center; padding: 2rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
h1 { font-size: 2.5rem; font-weight: 700; }
h2 { font-size: 1.5rem; margin: 2rem 0 1rem; }
.subtitle { color: var(--muted); margin-top: 0.5rem; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
.status-pill { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: 600; font-size: 0.875rem; }
.status-healthy { background: var(--green); color: white; }
.status-degraded { background: var(--yellow); color: black; }
.status-unhealthy { background: var(--red); color: white; }
.status-unknown { background: var(--muted); color: white; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: 0.875rem; }
tr:last-child td { border-bottom: none; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
.metric { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; }
.metric-value { font-size: 2rem; font-weight: 700; color: var(--blue); }
.metric-label { color: var(--muted); font-size: 0.875rem; margin-top: 0.5rem; }
footer { text-align: center; color: var(--muted); margin-top: 3rem; padding-top: 2rem; border-top: 1px solid var(--border); }
a { color: var(--blue); }
.skip-link { position: absolute; left: -9999px; }
.skip-link:focus { left: 1rem; top: 1rem; background: var(--blue); color: white; padding: 0.5rem 1rem; border-radius: 4px; z-index: 100; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); border: 0; }
</style>
</head>
<body>
<a href="#main-content" class="skip-link">Skip to main content</a>
<div id="live-region" class="sr-only" aria-live="polite"></div>

<header role="banner">
<h1>AegisGate Trust Portal</h1>
<p class="subtitle">Live compliance posture - last updated <span id="last-updated">loading...</span></p>
</header>

<div class="container">
<main id="main-content" role="main">

<section class="card" aria-labelledby="overall-heading">
<h2 id="overall-heading">Overall Posture</h2>
<p>Status: <span id="overall-status" class="status-pill status-unknown">loading</span></p>
<p>Version: <span id="version">-</span> | Uptime: <span id="uptime">-</span></p>
</section>

<section aria-labelledby="metrics-heading">
<h2 id="metrics-heading" class="sr-only">Key Metrics</h2>
<div class="metric-grid">
<div class="metric">
<div class="metric-value" id="metric-tier1">-</div>
<div class="metric-label">Frameworks at Tier 1</div>
</div>
<div class="metric">
<div class="metric-value" id="metric-total">-</div>
<div class="metric-label">Total Frameworks</div>
</div>
<div class="metric">
<div class="metric-value" id="metric-uptime">-</div>
<div class="metric-label">Uptime Badge</div>
</div>
</div>
</section>

<section class="card" aria-labelledby="frameworks-heading">
<h2 id="frameworks-heading">Compliance Frameworks</h2>
<table>
<thead>
<tr><th>Framework</th><th>Tier 1</th><th>Enforced</th><th>Implementation</th></tr>
</thead>
<tbody id="frameworks-table">
<tr><td colspan="4">Loading...</td></tr>
</tbody>
</table>
</section>

<section class="card" aria-labelledby="disclaimer-heading">
<h2 id="disclaimer-heading">Uptime Note</h2>
<p id="uptime-disclaimer" class="subtitle">-</p>
</section>

</main>

<footer role="contentinfo">
<p>Questions? Contact <a href="mailto:support@aegisgatesecurity.io">support@aegisgatesecurity.io</a></p>
<p><small>Auto-refreshes every 60 seconds. Data is cached server-side for the same interval.</small></p>
</footer>
</div>

<script>
(function() {
"use strict";

var REFRESH_MS = 60000;
var liveRegion = document.getElementById("live-region");

function announce(msg) {
  if (liveRegion) liveRegion.textContent = msg;
}

function fmtTime(iso) {
  if (!iso) return "-";
  try {
    var d = new Date(iso);
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  } catch (e) { return iso; }
}

function statusPill(status) {
  var cls = "status-" + (status || "unknown");
  return '<span class="status-pill ' + cls + '">' + (status || "unknown") + '</span>';
}

async function fetchJSON(url) {
  var r = await fetch(url, { credentials: "omit", cache: "no-store" });
  if (!r.ok) throw new Error("HTTP " + r.status);
  return await r.json();
}

async function refreshPosture() {
  try {
    var p = await fetchJSON("/trust/api/posture");
    document.getElementById("overall-status").className = "status-pill status-" + (p.overall || "unknown");
    document.getElementById("overall-status").innerHTML = p.overall || "unknown";
    document.getElementById("version").textContent = p.version || "-";
    document.getElementById("uptime").textContent = p.uptime || "-";
    document.getElementById("last-updated").textContent = fmtTime(p.generated_at);
    if (p.license && p.license.tier) {
      announce("Posture refreshed: " + p.overall + " (tier " + p.license.tier + ")");
    }
  } catch (e) {
    console.error("posture fetch failed:", e);
    document.getElementById("overall-status").className = "status-pill status-unknown";
    document.getElementById("overall-status").innerHTML = "unavailable";
  }
}

async function refreshFrameworks() {
  try {
    var f = await fetchJSON("/trust/api/frameworks");
    document.getElementById("metric-tier1").textContent = f.tier1_count;
    document.getElementById("metric-total").textContent = f.total_count;
    var tbody = document.getElementById("frameworks-table");
    if (f.frameworks && f.frameworks.length > 0) {
      tbody.innerHTML = f.frameworks.map(function(fw) {
        return "<tr>" +
          "<td>" + fw.display_name + "</td>" +
          "<td>" + (fw.tier1 ? statusPill("healthy") : statusPill("degraded")) + "</td>" +
          "<td>" + (fw.enforced ? "Yes" : "No") + "</td>" +
          "<td>" + (fw.has_implementation ? "Yes" : "Pending") + "</td>" +
        "</tr>";
      }).join("");
    } else {
      tbody.innerHTML = "<tr><td colspan='4'>No frameworks registered.</td></tr>";
    }
  } catch (e) {
    console.error("frameworks fetch failed:", e);
    document.getElementById("frameworks-table").innerHTML = "<tr><td colspan='4'>Unable to load frameworks.</td></tr>";
  }
}

async function refreshUptime() {
  try {
    var u = await fetchJSON("/trust/api/uptime");
    document.getElementById("metric-uptime").textContent = u.uptime_badge || "-";
    document.getElementById("uptime-disclaimer").textContent = u.badge_disclaimer || "";
  } catch (e) {
    console.error("uptime fetch failed:", e);
    document.getElementById("metric-uptime").textContent = "unavailable";
  }
}

async function refreshAll() {
  await Promise.all([refreshPosture(), refreshFrameworks(), refreshUptime()]);
}

// Initial load
refreshAll();
// Poll every 60s
setInterval(refreshAll, REFRESH_MS);
})();
</script>
</body>
</html>
`
