// AegisGate Dashboard JavaScript — v4.1.0 API-aligned
// All endpoints use the canonical /api/v1/* routes
class AegisGateDashboard {
    constructor() {
        this.apiBase = "/api/v1";
        this.refreshInterval = 5000; // 5 seconds
        this.updateTimers = [];
        this.lastStats = null;
        this.lastHealth = null;
        this.lastTier = null;
    }

    async init() {
        console.log("AegisGate Dashboard v4.1.0 initialized");
        await this.fetchAggregatedStats();
        await this.fetchHealth();
        await this.fetchTier();
        await this.fetchGuardrails();
        this.updateGettingStarted();
        this.startAutomaticUpdates();
        this.setupEventListeners();
    }

    // ── API Fetch Methods ────────────────────────────────────────

    async fetchAggregatedStats() {
        try {
            const response = await fetch(`${this.apiBase}/stats`);
            if (response.ok) {
                const data = await response.json();
                this.lastStats = data;
                this.updateMetricsDisplay(data);
            }
        } catch (error) {
            console.error("Error fetching stats:", error);
            this.showError("stats", "Unable to load statistics");
        }
    }

    async fetchStats() {
        // Legacy persistence endpoint — kept for backward compat
        try {
            const response = await fetch(`${this.apiBase}/persistence`);
            if (response.ok) {
                const data = await response.json();
                this.lastStats = data;
            }
        } catch (error) {
            console.error("Error fetching persistence stats:", error);
        }
    }

    async fetchHealth() {
        try {
            const response = await fetch("/health");
            if (response.ok) {
                const data = await response.json();
                this.lastHealth = data;
                this.updateHealthDisplay(data);
                this.updateGettingStarted();
            }
        } catch (error) {
            console.error("Error fetching health:", error);
            this.showError("health", "Health check unavailable");
        }
    }

    async fetchTier() {
        try {
            const response = await fetch(`${this.apiBase}/tier`);
            if (response.ok) {
                const data = await response.json();
                this.updateTierDisplay(data);
                this.updateGettingStarted();
            }
        } catch (error) {
            console.error("Error fetching tier:", error);
        }
    }

    async fetchGuardrails() {
        try {
            const response = await fetch(`${this.apiBase}/guardrails`);
            if (response.ok) {
                const data = await response.json();
                this.updateGuardrailsDisplay(data);
            }
        } catch (error) {
            console.error("Error fetching guardrails:", error);
        }
    }

    // ── Display Update Methods ───────────────────────────────────

    updateMetricsDisplay(payload) {
        const d = payload?.data || payload;
        if (!d) return;

        // Total Requests — from persistence total_entries
        const totalReqs = d.persistence?.total_entries ?? d.total_entries ?? "—";
        this.setText("metric-requests-value", this.formatNumber(totalReqs));

        // Threats Blocked — from guardrails rejected_calls
        const g = d.guardrails;
        const rejected = g?.rejected_calls ?? g?.RejectedCalls ?? "—";
        this.setText("metric-threats-value", this.formatNumber(rejected));

        // Active Sessions — from guardrails active_sessions
        const sessions = g?.active_sessions ?? g?.ActiveSessions ?? "—";
        this.setText("metric-sessions-value", this.formatNumber(sessions));

        // System Health — from health data (fetched separately)
        // Uptime is set by updateHealthDisplay
        if (d.uptime_seconds != null) {
            this.setText("metric-health-detail", "Uptime: " + this.formatUptime(d.uptime_seconds));
        }
    }

    updateHealthDisplay(health) {
        // System Health card
        const healthValue = health.status === "healthy" ? "Healthy" :
                           health.status === "degraded" ? "Degraded" :
                           health.status ? health.status : "—";
        this.setText("metric-health-value", healthValue);

        // Update health card color based on status
        const healthCard = document.querySelector(".metric-card-info");
        if (healthCard) {
            if (health.status === "healthy") {
                healthCard.classList.remove("metric-card-warning", "metric-card-danger");
                healthCard.classList.add("metric-card-success");
            } else if (health.status === "degraded") {
                healthCard.classList.remove("metric-card-success", "metric-card-danger");
                healthCard.classList.add("metric-card-warning");
            } else {
                healthCard.classList.remove("metric-card-success", "metric-card-warning");
                healthCard.classList.add("metric-card-danger");
            }
        }

        // Uptime detail
        if (health.uptime) {
            this.setText("metric-health-detail", "Uptime: " + this.formatUptime(health.uptime));
        }

        // Legacy health status element (if present)
        const statusEl = document.getElementById("last-scan");
        if (statusEl) {
            statusEl.textContent = health.status || "Unknown";
            statusEl.className = "health-status " + (health.status === "healthy" ? "status-healthy" : "status-unhealthy");
        }

        // Version display (if element exists)
        if (health.version) {
            this.setText("version-display", "v" + health.version);
        }
    }

    updateTierDisplay(tier) {
        if (!tier) return;
        this.lastTier = tier;

        // Tier badge
        this.setText("tier-name", tier.name || tier.tier || "Community");
        this.setText("tier-proxy-rpm", tier.proxy_rpm != null ? tier.proxy_rpm : "—");
        this.setText("tier-mcp-rpm", tier.mcp_rpm != null ? tier.mcp_rpm : "—");

        // Feature count
        if (tier.features != null) {
            this.setText("tier-features", tier.features + " features");
        }
    }

    updateGuardrailsDisplay(data) {
        if (!data || !data.data) return;
        const g = data.data;

        this.setText("guardrails-status", g.guardrails_enabled ? "Active" : "Inactive");
        this.setText("guardrails-sessions", g.active_sessions != null ? g.active_sessions : "0");
        this.setText("guardrails-tool-calls", g.total_tool_calls != null ? g.total_tool_calls : "0");
        this.setText("guardrails-rejected", g.rejected_calls != null ? g.rejected_calls : "0");
    }

    // ── Getting Started ──────────────────────────────────────────

    updateGettingStarted() {
        // Populate checklist from health data
        const checks = this.lastHealth?.checks;
        if (checks) {
            this.updateCheckItem("gs-check-proxy", true, "Running");
            this.updateCheckItem("gs-check-scanner", checks.scanner?.healthy, checks.scanner?.healthy ? "Healthy" : "Unhealthy");
            this.updateCheckItem("gs-check-persistence", checks.persistence?.healthy, checks.persistence?.started ? "Active" : "Inactive");
            this.updateCheckItem("gs-check-license", checks.license?.valid, checks.license?.valid ? "Valid" : "Invalid");
            this.updateCheckItem("gs-check-tls", checks.certificates?.valid, checks.certificates?.valid ? "Configured" : "Missing");
        } else {
            this.updateCheckItem("gs-check-proxy", false, "Not reachable");
        }

        // Guardrails check (from last fetchGuardrails result)
        const guardrailsActive = document.getElementById("guardrails-status")?.textContent === "Active";
        this.updateCheckItem("gs-check-guardrails", guardrailsActive, guardrailsActive ? "Active" : "Inactive");

        // Populate config from tier data
        if (this.lastTier) {
            this.setText("gs-tier", this.lastTier.name || this.lastTier.tier || "Community");
            this.setText("gs-proxy-rpm", this.lastTier.proxy_rpm != null ? this.lastTier.proxy_rpm + " RPM" : "—");
            this.setText("gs-mcp-rpm", this.lastTier.mcp_rpm != null ? this.lastTier.mcp_rpm + " RPM" : "—");
            this.setText("gs-features", this.lastTier.features != null ? this.lastTier.features + " features" : "—");
        }
    }

    updateCheckItem(itemId, passed, statusText) {
        const item = document.getElementById(itemId);
        if (!item) return;
        const icon = item.querySelector(".gs-check-icon");
        const status = item.querySelector(".gs-check-status");

        if (passed === true) {
            item.classList.add("gs-pass");
            item.classList.remove("gs-fail");
            if (icon) icon.textContent = "✅";
        } else if (passed === false) {
            item.classList.add("gs-fail");
            item.classList.remove("gs-pass");
            if (icon) icon.textContent = "❌";
        }

        if (status && statusText) status.textContent = statusText;
    }

    // ── Utility Methods ──────────────────────────────────────────

    setText(elementId, text) {
        const el = document.getElementById(elementId);
        if (el) el.textContent = this.sanitizeHTML(String(text));
    }

    formatUptime(seconds) {
        if (seconds < 60) return Math.round(seconds) + "s";
        if (seconds < 3600) return Math.round(seconds / 60) + "m";
        if (seconds < 86400) return Math.round(seconds / 3600) + "h";
        return Math.round(seconds / 86400) + "d";
    }

    formatNumber(n) {
        if (n === null || n === undefined || n === "—") return "—";
        const num = Number(n);
        if (isNaN(num)) return String(n);
        if (num >= 1_000_000) return (num / 1_000_000).toFixed(1) + "M";
        if (num >= 1_000) return (num / 1_000).toFixed(1) + "K";
        return String(num);
    }

    showError(section, message) {
        console.warn(`[${section}] ${message}`);
    }

    // Sanitize HTML to prevent XSS attacks
    sanitizeHTML(str) {
        if (str === null || str === undefined) return '';
        str = String(str);
        return str.replace(/[&<>"'/]/g, function (char) {
            const escapeMap = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#x27;',
                '/': '&#x2F;'
            };
            return escapeMap[char];
        });
    }

    // Sanitize for safe use in HTML attributes
    sanitizeAttribute(str) {
        if (str === null || str === undefined) return '';
        str = String(str);
        return str.replace(/["'<>&]/g, function(char) {
            const escapeMap = {
                '"': '&quot;',
                "'": '&#x27;',
                '<': '&lt;',
                '>': '&gt;',
                '&': '&amp;'
            };
            return escapeMap[char];
        });
    }

    // ── Auto-refresh ─────────────────────────────────────────────

    startAutomaticUpdates() {
        this.updateTimers.push(setInterval(() => {
            this.fetchAggregatedStats();
            this.fetchHealth();
        }, this.refreshInterval));
    }

    stopAutomaticUpdates() {
        this.updateTimers.forEach(timer => clearInterval(timer));
        this.updateTimers = [];
    }

    // ── Event Listeners ──────────────────────────────────────────

    setupEventListeners() {
        // Navigation buttons
        const navButtons = document.querySelectorAll(".nav-btn");
        navButtons.forEach(button => {
            button.addEventListener("click", (e) => {
                navButtons.forEach(btn => btn.classList.remove("active"));
                e.target.classList.add("active");
                const buttonName = e.target.textContent.toLowerCase();
                this.handleNavigation(buttonName);
            });
        });

        // Nav links (tab navigation)
        const navLinks = document.querySelectorAll(".nav-link");
        navLinks.forEach(link => {
            link.addEventListener("click", (e) => {
                e.preventDefault();
                navLinks.forEach(l => {
                    l.classList.remove("active");
                    l.setAttribute("aria-selected", "false");
                });
                link.classList.add("active");
                link.setAttribute("aria-selected", "true");

                // Show/hide tab panels
                const targetPanel = link.getAttribute("aria-controls");
                document.querySelectorAll("[role=tabpanel]").forEach(panel => {
                    panel.hidden = true;
                });
                const panel = document.getElementById(targetPanel);
                if (panel) panel.hidden = false;

                this.handleNavigation(link.textContent.trim().toLowerCase());
            });
        });

        // Manual refresh button
        const refreshBtn = document.getElementById("refresh-btn");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => this.refreshNow());
        }

        // Auto-refresh toggle
        const autoRefreshToggle = document.getElementById("auto-refresh");
        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener("change", (e) => {
                if (e.target.checked) {
                    this.startAutomaticUpdates();
                } else {
                    this.stopAutomaticUpdates();
                }
            });
        }

        // Refresh interval selector
        const refreshInterval = document.getElementById("refresh-interval");
        if (refreshInterval) {
            refreshInterval.addEventListener("change", (e) => {
                this.refreshInterval = parseInt(e.target.value, 10);
                this.stopAutomaticUpdates();
                this.startAutomaticUpdates();
            });
        }

        // Copy buttons for Getting Started commands
        document.querySelectorAll(".gs-copy-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const text = e.target.getAttribute("data-copy");
                if (text) {
                    navigator.clipboard.writeText(text).then(() => {
                        const original = e.target.textContent;
                        e.target.textContent = "Copied!";
                        setTimeout(() => { e.target.textContent = original; }, 1500);
                    }).catch(() => {
                        // Fallback for older browsers
                        const textarea = document.createElement("textarea");
                        textarea.value = text;
                        document.body.appendChild(textarea);
                        textarea.select();
                        try { document.execCommand("copy"); } catch (err) { /* ignore */ }
                        document.body.removeChild(textarea);
                        e.target.textContent = "Copied!";
                        setTimeout(() => { e.target.textContent = "Copy"; }, 1500);
                    });
                }
            });
        });
    }

    handleNavigation(page) {
        // Refresh data for the active tab
        switch(page) {
            case "getting started":
                this.fetchHealth();
                this.updateGettingStarted();
                break;
            case "dashboard":
                this.fetchAggregatedStats();
                this.fetchHealth();
                break;
            case "audit logs":
                this.fetchAggregatedStats();
                break;
            case "compliance":
                this.fetchGuardrails();
                break;
            case "settings":
                // No data refresh needed for settings
                break;
        }
    }

    refreshNow() {
        this.fetchAggregatedStats();
        this.fetchHealth();
        this.fetchTier();
        this.fetchGuardrails();
    }

    // ── CSRF Protection ──────────────────────────────────────────

    getCSRFToken() {
        const name = "csrf_token";
        const cookies = document.cookie.split(";");
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.startsWith(name + "=")) {
                return cookie.substring(name.length + 1);
            }
        }
        return null;
    }

    async safePost(endpoint, data) {
        const csrfToken = this.getCSRFToken();
        const headers = { "Content-Type": "application/json" };
        if (csrfToken) {
            headers["X-CSRF-Token"] = csrfToken;
        }
        const response = await fetch(endpoint, {
            method: "POST",
            headers: headers,
            body: JSON.stringify(data)
        });
        return response;
    }
}

// Helper function to safely escape HTML entities
function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

// Initialize dashboard when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    const dashboard = new AegisGateDashboard();
    dashboard.init();
});

// Export for potential external usage
window.AegisGateDashboard = AegisGateDashboard;