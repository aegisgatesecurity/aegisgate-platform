// AegisGate Dashboard JavaScript - Secure Version with XSS Protection
class AegisGateDashboard {
    constructor() {
        this.apiBase = "";
        this.refreshInterval = 5000; // 5 seconds
        this.updateTimers = [];
    }

    async init() {
        console.log("AegisGate Dashboard initialized");
        await this.fetchStats();
        await this.fetchHealth();
        await this.fetchViolations();
        this.startAutomaticUpdates();
        this.setupEventListeners();
    }

    async fetchStats() {
        try {
            const response = await fetch("/api/stats");
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.data) {
                    this.updateStatsDisplay(data.data);
                }
            }
        } catch (error) {
            console.error("Error fetching stats:", error);
        }
    }

    async fetchHealth() {
        try {
            const response = await fetch("/api/health");
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.data) {
                    this.updateHealthDisplay(data.data);
                }
            }
        } catch (error) {
            console.error("Error fetching health:", error);
        }
    }

    async fetchViolations() {
        try {
            const response = await fetch("/api/violations");
            if (response.ok) {
                const data = await response.json();
                if (data.success && Array.isArray(data.data)) {
                    this.updateViolationsDisplay(data.data);
                }
            }
        } catch (error) {
            console.error("Error fetching violations:", error);
        }
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

    // Sanitize for safe use in HTML attribute
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

    updateStatsDisplay(stats) {
        // Safe text content updates - no XSS risk
        if (stats.requests) {
            const el = document.getElementById("requests-per-min");
            if (el) el.textContent = this.sanitizeHTML(String(stats.requests));
        }

        if (stats.blocked) {
            const el = document.getElementById("violations");
            if (el) el.textContent = this.sanitizeHTML(String(stats.blocked));
        }

        if (stats.errors) {
            const el = document.getElementById("active-sessions");
            if (el) el.textContent = this.sanitizeHTML(String(stats.errors));
        }
    }

    updateHealthDisplay(health) {
        const statusEl = document.getElementById("last-scan");
        if (statusEl) {
            statusEl.textContent = health.status || "Unknown";
        }

        // Update uptime if available
        if (health.uptime) {
            const uptimeEl = document.getElementById("uptime");
            if (uptimeEl) uptimeEl.textContent = Math.round(health.uptime) + "s";
        }
    }

    updateViolationsDisplay(violations) {
        // violations is an array with severity counts
        if (violations.length > 0) {
            const counts = violations[0];
            const container = document.getElementById("violations-breakdown");
            if (container) {
                container.textContent = JSON.stringify(counts);
            }
        }
    }

    startAutomaticUpdates() {
        this.updateTimers.push(setInterval(() => {
            this.fetchStats();
            this.fetchHealth();
        }, this.refreshInterval));
    }

    setupEventListeners() {
        const navButtons = document.querySelectorAll(".nav-btn");
        navButtons.forEach(button => {
            button.addEventListener("click", (e) => {
                navButtons.forEach(btn => btn.classList.remove("active"));
                e.target.classList.add("active");

                const buttonName = e.target.textContent.toLowerCase();
                this.handleNavigation(buttonName);
            });
        });

        // Manual refresh button
        const refreshBtn = document.getElementById("refresh-btn");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                this.refreshNow();
            });
        }
    }

    handleNavigation(page) {
        console.log("Navigating to:", page);
        // Add page navigation logic here
    }

    refreshNow() {
        this.fetchStats();
        this.fetchHealth();
        this.fetchViolations();
    }

    // Get CSRF token from cookie
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

    // Make a CSRF-protected POST request
    async safePost(endpoint, data) {
        const csrfToken = this.getCSRFToken();
        const headers = {
            "Content-Type": "application/json"
        };

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
