// AegisGate Dashboard JavaScript — v1.2.0 API-aligned
// All endpoints use the canonical /api/v1/* routes
class AegisGateDashboard {
    constructor() {
        this.apiBase = "/api/v1";
        this.refreshInterval = 5000; // 5 seconds
        this.updateTimers = [];
        this.lastStats = null;
        this.lastHealth = null;
    }

    async init() {
        console.log("AegisGate Dashboard v1.3.0 initialized");
        await this.fetchStats();
        await this.fetchHealth();
        await this.fetchTier();
        await this.fetchGuardrails();
        this.startAutomaticUpdates();
        this.setupEventListeners();
    }

    // ── API Fetch Methods ────────────────────────────────────────

    async fetchStats() {
        try {
            const response = await fetch(`${this.apiBase}/persistence`);
            if (response.ok) {
                const data = await response.json();
                this.lastStats = data;
                this.updateStatsDisplay(data);
            }
        } catch (error) {
            console.error("Error fetching stats:", error);
            this.showError("stats", "Unable to load statistics");
        }
    }

    async fetchHealth() {
        try {
            const response = await fetch("/health");
            if (response.ok) {
                const data = await response.json();
                this.lastHealth = data;
                this.updateHealthDisplay(data);
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

    updateStatsDisplay(stats) {
        // Metrics cards — Dashboard panel
        this.setText("metric-requests-value", stats.total_entries != null ? stats.total_entries : "—");
        this.setText("metric-blocked-value", stats.disabled ? "Disabled" : "Active");
        this.setText("metric-threats-value", stats.pruned_count != null ? stats.pruned_count : "0");
        this.setText("metric-uptime-value", stats.audit_dir != null ? stats.audit_dir : "—");
    }

    updateHealthDisplay(health) {
        // Health status
        const statusEl = document.getElementById("last-scan");
        if (statusEl) {
            statusEl.textContent = health.status || "Unknown";
            statusEl.className = "health-status " + (health.status === "healthy" ? "status-healthy" : "status-unhealthy");
        }

        // Uptime
        if (health.uptime) {
            this.setText("uptime-value", this.formatUptime(health.uptime));
        }

        // Version
        if (health.version) {
            this.setText("version-display", "v" + health.version);
        }
    }

    updateTierDisplay(tier) {
        if (!tier) return;

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
            this.fetchStats();
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
    }

    handleNavigation(page) {
        // Refresh data for the active tab
        switch(page) {
            case "dashboard":
                this.fetchStats();
                this.fetchHealth();
                break;
            case "audit logs":
                this.fetchStats();
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
        this.fetchStats();
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