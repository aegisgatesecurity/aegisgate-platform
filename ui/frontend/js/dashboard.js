// AegisGate Dashboard JavaScript — v4.2.0 API-aligned
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
        console.log("AegisGate Dashboard v4.2.0 initialized");
        await this.fetchAggregatedStats();
        await this.fetchHealth();
        await this.fetchTier();
        await this.fetchGuardrails();
        this.renderComplianceFrameworks();
        this.setupComplianceFilters();
        this.fetchMaintenanceStatus();
        this.setupMaintenanceControls();
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
                this.updateSystemInfo();
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
                this.renderComplianceFrameworks(this.getActiveCompFilter());
            }
        } catch (error) {
            console.error("Error fetching tier:", error);
        }
    }

    getActiveCompFilter() {
        const active = document.querySelector(".comp-filter-btn.active");
        return active ? active.getAttribute("data-tier") : "all";
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

    // ── Compliance Dashboard ─────────────────────────────────────

    static FRAMEWORKS = [
        // Community tier (4)
        { name: "OWASP LLM Top 10", tier: "community", desc: "Vulnerabilities specific to LLM applications", controls: 42, automated: 38 },
        { name: "OWASP Web Top 10", tier: "community", desc: "Web application security risks", controls: 87, automated: 72 },
        { name: "MITRE ATLAS", tier: "community", desc: "Adversarial threat landscape for AI systems", controls: 78, automated: 56 },
        { name: "NIST AI RMF 1.0", tier: "community", desc: "AI Risk Management Framework", controls: 65, automated: 48 },
        // Developer tier (6)
        { name: "HIPAA", tier: "developer", desc: "Healthcare data privacy and security", controls: 54, automated: 42 },
        { name: "PCI-DSS", tier: "developer", desc: "Payment card industry data security", controls: 76, automated: 64 },
        { name: "SOC 2", tier: "developer", desc: "Service organization controls (Type II)", controls: 64, automated: 58 },
        { name: "ISO 27001", tier: "developer", desc: "Information security management systems", controls: 93, automated: 72 },
        { name: "CCPA/CPRA", tier: "developer", desc: "California consumer privacy regulations", controls: 45, automated: 31 },
        { name: "GDPR", tier: "developer", desc: "General Data Protection Regulation", controls: 99, automated: 68 },
        // Professional tier (16)
        { name: "ISO 42001", tier: "professional", desc: "AI management system standard", controls: 48, automated: 38 },
        { name: "EU AI Act", tier: "professional", desc: "European AI Act compliance requirements", controls: 81, automated: 57 },
        { name: "FIPS 140-2/140-3", tier: "professional", desc: "Federal cryptographic module standards", controls: 40, automated: 35 },
        { name: "CIS Critical Security Controls", tier: "professional", desc: "Critical security controls v8", controls: 153, automated: 121 },
        { name: "NIST Cybersecurity Framework", tier: "professional", desc: "NIST CSF 2.0 core functions", controls: 108, automated: 86 },
        { name: "CSA STAR", tier: "professional", desc: "Cloud Security Alliance STAR program", controls: 67, automated: 49 },
        { name: "NIST AI 600-1", tier: "professional", desc: "AI risk profile for generative AI", controls: 43, automated: 32 },
        { name: "SOX (Sarbanes-Oxley)", tier: "professional", desc: "Financial reporting security controls", controls: 49, automated: 37 },
        { name: "GLBA (Gramm-Leach-Bliley)", tier: "professional", desc: "Financial institutions data protection", controls: 39, automated: 28 },
        { name: "CJIS Security Policy", tier: "professional", desc: "Criminal Justice Information Services", controls: 71, automated: 54 },
        { name: "NERC CIP", tier: "professional", desc: "Critical infrastructure protection (energy)", controls: 57, automated: 44 },
        { name: "FERPA", tier: "professional", desc: "Educational records privacy", controls: 34, automated: 24 },
        { name: "HITECH Act", tier: "professional", desc: "Health information technology and security", controls: 46, automated: 35 },
        { name: "FFIEC Banking Guidance", tier: "professional", desc: "Federal financial institutions guidance", controls: 52, automated: 39 },
        { name: "TSA Security Directive", tier: "professional", desc: "Transportation security directives", controls: 31, automated: 23 },
        { name: "ISO 21434 (Automotive)", tier: "professional", desc: "Automotive cybersecurity engineering", controls: 44, automated: 31 },
        // Enterprise tier (5)
        { name: "FedRAMP", tier: "enterprise", desc: "Federal Risk and Authorization Management Program", controls: 325, automated: 234 },
        { name: "CMMC Level 2", tier: "enterprise", desc: "Cybersecurity Maturity Model Certification", controls: 156, automated: 117 },
        { name: "NIST 800-171", tier: "enterprise", desc: "Protecting controlled unclassified information", controls: 110, automated: 89 },
        { name: "HITRUST CSF", tier: "enterprise", desc: "Healthcare Trust Common Security Framework", controls: 135, automated: 98 },
        { name: "TISAX AL2", tier: "enterprise", desc: "Automotive industry information security", controls: 87, automated: 63 },
    ];

    static TIER_ORDER = { community: 0, developer: 1, professional: 2, enterprise: 3 };

    renderComplianceFrameworks(filterTier = "all") {
        const grid = document.getElementById("comp-framework-grid");
        if (!grid) return;

        const currentTier = this.lastTier?.tier || "community";
        const currentTierLevel = Dashboard.TIER_ORDER[currentTier] ?? 0;

        let frameworks = Dashboard.FRAMEWORKS;
        if (filterTier !== "all") {
            frameworks = frameworks.filter(f => f.tier === filterTier);
        }

        // Clear loading message
        grid.innerHTML = "";

        let availableCount = 0;
        for (const fw of frameworks) {
            const fwTierLevel = Dashboard.TIER_ORDER[fw.tier] ?? 0;
            const isAvailable = fwTierLevel <= currentTierLevel;
            if (isAvailable) availableCount++;

            const automationPct = Math.round((fw.automated / fw.controls) * 100);
            const progressClass = automationPct >= 70 ? "high" : automationPct >= 50 ? "medium" : "low";

            const card = document.createElement("article");
            card.className = "comp-card";
            card.innerHTML = `
                <div class="comp-card-header">
                    <h3>${fw.name}</h3>
                    <span class="comp-tier-badge tier-${fw.tier}">${fw.tier}</span>
                </div>
                <p class="comp-card-desc">${fw.desc}</p>
                <div class="comp-card-stats">
                    <div class="comp-stat">
                        <span class="comp-stat-value">${fw.controls}</span>
                        <span class="comp-stat-label">Controls</span>
                    </div>
                    <div class="comp-stat">
                        <span class="comp-stat-value">${fw.automated}</span>
                        <span class="comp-stat-label">Automated</span>
                    </div>
                    <div class="comp-stat">
                        <span class="comp-stat-value">${automationPct}%</span>
                        <span class="comp-stat-label">Automation</span>
                    </div>
                </div>
                <div class="comp-progress-bar" role="progressbar" aria-valuenow="${automationPct}" aria-valuemin="0" aria-valuemax="100" aria-label="${fw.name} automation rate">
                    <div class="comp-progress-fill ${progressClass}" style="width: ${automationPct}%"></div>
                </div>
                <span class="comp-status ${isAvailable ? "available" : "locked"}">
                    ${isAvailable ? "✅ Available" : "🔒 Requires " + fw.tier + " tier"}
                </span>
            `;
            grid.appendChild(card);
        }

        // Update summary
        this.setText("comp-available-frameworks", String(availableCount));

        // If no frameworks matched, show message
        if (frameworks.length === 0) {
            grid.innerHTML = '<p class="comp-loading">No frameworks in this tier.</p>';
        }
    }

    setupComplianceFilters() {
        document.querySelectorAll(".comp-filter-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                // Update active state
                document.querySelectorAll(".comp-filter-btn").forEach(b => {
                    b.classList.remove("active");
                    b.setAttribute("aria-pressed", "false");
                });
                e.target.classList.add("active");
                e.target.setAttribute("aria-pressed", "true");

                // Re-render with filter
                this.renderComplianceFrameworks(e.target.getAttribute("data-tier"));
            });
        });
    }

    // ── Maintenance & System Info ────────────────────────────────

    async fetchMaintenanceStatus() {
        try {
            const response = await fetch(`${this.apiBase}/maintenance`);
            if (response.ok) {
                const data = await response.json();
                this.updateMaintenanceDisplay(data);
            }
        } catch (error) {
            console.error("Error fetching maintenance status:", error);
        }
    }

    updateMaintenanceDisplay(status) {
        const badge = document.getElementById("cfg-maint-badge");
        const detail = document.getElementById("cfg-maint-detail");
        const enableBtn = document.getElementById("cfg-maint-enable");
        const disableBtn = document.getElementById("cfg-maint-disable");
        if (!badge) return;

        // Reset classes
        badge.classList.remove("cfg-status-active", "cfg-status-inactive", "cfg-status-scheduled");

        if (status.active) {
            badge.classList.add("cfg-status-active");
            badge.textContent = "Active";
            detail.textContent = status.message || "Maintenance in progress";
            if (enableBtn) enableBtn.disabled = true;
            if (disableBtn) disableBtn.disabled = false;
        } else if (status.scheduled) {
            badge.classList.add("cfg-status-scheduled");
            badge.textContent = "Scheduled";
            const start = status.start_time ? new Date(status.start_time).toLocaleString() : "—";
            const end = status.end_time ? new Date(status.end_time).toLocaleString() : "—";
            detail.textContent = `${start} → ${end}`;
            if (enableBtn) enableBtn.disabled = false;
            if (disableBtn) disableBtn.disabled = false;
        } else {
            badge.classList.add("cfg-status-inactive");
            badge.textContent = "Inactive";
            detail.textContent = "";
            if (enableBtn) enableBtn.disabled = false;
            if (disableBtn) disableBtn.disabled = true;
        }
    }

    setupMaintenanceControls() {
        const enableBtn = document.getElementById("cfg-maint-enable");
        if (enableBtn) {
            enableBtn.addEventListener("click", async () => {
                const msg = document.getElementById("cfg-maint-message")?.value || "";
                const retry = parseInt(document.getElementById("cfg-maint-retry")?.value || "300", 10);
                try {
                    const response = await fetch(`${this.apiBase}/maintenance`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ message: msg, retry_after_seconds: retry }),
                    });
                    if (response.ok) {
                        const data = await response.json();
                        this.updateMaintenanceDisplay(data);
                    }
                } catch (err) {
                    console.error("Error enabling maintenance:", err);
                }
            });
        }

        const disableBtn = document.getElementById("cfg-maint-disable");
        if (disableBtn) {
            disableBtn.addEventListener("click", async () => {
                try {
                    const response = await fetch(`${this.apiBase}/maintenance`, { method: "DELETE" });
                    if (response.ok) {
                        const data = await response.json();
                        this.updateMaintenanceDisplay(data);
                    }
                } catch (err) {
                    console.error("Error disabling maintenance:", err);
                }
            });
        }

        const scheduleBtn = document.getElementById("cfg-maint-schedule");
        if (scheduleBtn) {
            scheduleBtn.addEventListener("click", async () => {
                const startEl = document.getElementById("cfg-maint-start");
                const endEl = document.getElementById("cfg-maint-end");
                const reasonEl = document.getElementById("cfg-maint-reason");
                if (!startEl?.value || !endEl?.value) return;

                // Convert datetime-local to RFC3339
                const startTime = new Date(startEl.value).toISOString();
                const endTime = new Date(endEl.value).toISOString();
                const reason = reasonEl?.value || "";

                try {
                    const response = await fetch(`${this.apiBase}/maintenance`, {
                        method: "PUT",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ start_time: startTime, end_time: endTime, reason }),
                    });
                    if (response.ok) {
                        const data = await response.json();
                        this.updateMaintenanceDisplay(data);
                    }
                } catch (err) {
                    console.error("Error scheduling maintenance:", err);
                }
            });
        }
    }

    updateSystemInfo() {
        const h = this.lastHealth;
        if (!h) return;

        this.setText("cfg-sys-version", h.version ? "v" + h.version : "v4.2.0");
        this.setText("cfg-sys-tier", h.tier || "—");
        this.setText("cfg-sys-uptime", h.uptime ? this.formatUptime(h.uptime) : "—");

        const checks = h.checks || {};
        this.setText("cfg-sys-scanner", checks.scanner?.healthy ? "Healthy" : "Unhealthy");
        const persistText = checks.persistence?.started ? "Active" : "Inactive";
        this.setText("cfg-sys-persistence", persistText);
        this.setText("cfg-sys-tls", checks.certificates?.valid ? "Valid" : "Missing");

        if (this.lastTier) {
            this.setText("cfg-sys-tier", this.lastTier.display_name || this.lastTier.tier || "—");
        }
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
            this.fetchMaintenanceStatus();
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
                this.renderComplianceFrameworks(this.getActiveCompFilter());
                break;
            case "settings":
                this.fetchMaintenanceStatus();
                this.updateSystemInfo();
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