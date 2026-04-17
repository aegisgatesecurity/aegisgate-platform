// ML Dashboard Widget
// ==================
// Real-time ML anomaly detection statistics widget for the admin UI

// MLStatsWidget configuration
const MLStatsWidget = {
    id: 'ml-stats-widget',
    title: 'ML Anomaly Detection',
    icon: 'shield-alt',
    refreshInterval: 5000, // 5 seconds

    // Default configuration
    defaults: {
        sensitivity: 'medium',
        showPromptInjection: true,
        showContentAnalysis: true,
        showBehavioral: true,
        chartType: 'line' // line, bar, donut
    },

    // Initialize widget
    init: function(containerId, config) {
        const container = document.getElementById(containerId);
        if (!container) {
            console.error('Container not found:', containerId);
            return;
        }

        this.config = { ...this.defaults, ...config };
        this.render(container);
        this.startPolling();
    },

    // Render the widget
    render: function(container) {
        container.innerHTML = `
            <div class="ml-stats-widget">
                <div class="ml-header">
                    <h3><i class="fas fa-shield-alt"></i> ML Anomaly Detection</h3>
                    <span class="ml-status" id="ml-status">
                        <span class="status-dot active"></span>
                        Active
                    </span>
                </div>

                <div class="ml-summary-cards">
                    <div class="ml-card">
                        <div class="ml-card-value" id="total-requests">0</div>
                        <div class="ml-card-label">Total Requests</div>
                    </div>
                    <div class="ml-card">
                        <div class="ml-card-value" id="analyzed-requests">0</div>
                        <div class="ml-card-label">Analyzed</div>
                    </div>
                    <div class="ml-card warning">
                        <div class="ml-card-value" id="anomalies-detected">0</div>
                        <div class="ml-card-label">Anomalies</div>
                    </div>
                    <div class="ml-card danger">
                        <div class="ml-card-value" id="blocked-requests">0</div>
                        <div class="ml-card-label">Blocked</div>
                    </div>
                </div>

                <div class="ml-charts">
                    <div class="ml-chart-section">
                        <h4>Detection Trend</h4>
                        <canvas id="ml-trend-chart" height="120"></canvas>
                    </div>

                    ${this.config.showPromptInjection ? `
                    <div class="ml-chart-section">
                        <h4>Prompt Injection</h4>
                        <canvas id="ml-pi-chart" height="80"></canvas>
                    </div>
                    ` : ''}

                    ${this.config.showContentAnalysis ? `
                    <div class="ml-chart-section">
                        <h4>Content Violations</h4>
                        <canvas id="ml-content-chart" height="80"></canvas>
                    </div>
                    ` : ''}
                </div>

                <div class="ml-details">
                    <div class="ml-detail-section">
                        <h4>Sensitivity</h4>
                        <div class="sensitivity-badge" id="sensitivity-badge">
                            <span class="badge medium">Medium</span>
                        </div>
                    </div>

                    <div class="ml-detail-section">
                        <h4>Recent Anomalies</h4>
                        <div class="anomaly-list" id="anomaly-list">
                            <div class="anomaly-item">No recent anomalies</div>
                        </div>
                    </div>
                </div>

                <div class="ml-controls">
                    <button class="btn btn-sm" onclick="MLStatsWidget.resetStats()">
                        <i class="fas fa-redo"></i> Reset Stats
                    </button>
                    <button class="btn btn-sm" onclick="MLStatsWidget.configure()">
                        <i class="fas fa-cog"></i> Configure
                    </button>
                </div>
            </div>
        `;

        this.initCharts();
    },

    // Initialize charts
    initCharts: function() {
        // Trend Chart
        this.trendChart = new Chart(document.getElementById('ml-trend-chart'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Requests',
                    data: [],
                    borderColor: '#4CAF50',
                    backgroundColor: 'rgba(76, 175, 80, 0.1)',
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Anomalies',
                    data: [],
                    borderColor: '#FF9800',
                    backgroundColor: 'rgba(255, 152, 0, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: true, position: 'bottom' }
                },
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true }
                }
            }
        });

        // Prompt Injection Chart
        if (document.getElementById('ml-pi-chart')) {
            this.piChart = new Chart(document.getElementById('ml-pi-chart'), {
                type: 'doughnut',
                data: {
                    labels: ['Blocked', 'Allowed'],
                    datasets: [{
                        data: [0, 100],
                        backgroundColor: ['#F44336', '#4CAF50']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: true, position: 'bottom' }
                    }
                }
            });
        }

        // Content Analysis Chart
        if (document.getElementById('ml-content-chart')) {
            this.contentChart = new Chart(document.getElementById('ml-content-chart'), {
                type: 'bar',
                data: {
                    labels: ['PII', 'Secrets', 'Policy'],
                    datasets: [{
                        label: 'Violations',
                        data: [0, 0, 0],
                        backgroundColor: ['#FF9800', '#F44336', '#9C27B0']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
    },

    // Start polling for stats
    startPolling: function() {
        this.fetchStats();
        this.pollInterval = setInterval(() => this.fetchStats(), this.refreshInterval);
    },

    // Stop polling
    stopPolling: function() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }
    },

    // Fetch stats from API
    fetchStats: async function() {
        try {
            const response = await fetch('/api/v1/ml/stats');
            if (!response.ok) throw new Error('Failed to fetch ML stats');

            const data = await response.json();
            this.updateDisplay(data);
        } catch (error) {
            console.error('Error fetching ML stats:', error);
        }
    },

    // Update display with new data
    updateDisplay: function(data) {
        // Update summary cards
        document.getElementById('total-requests').textContent =
            this.formatNumber(data.middleware?.total_requests || 0);
        document.getElementById('analyzed-requests').textContent =
            this.formatNumber(data.middleware?.analyzed_requests || 0);
        document.getElementById('anomalies-detected').textContent =
            this.formatNumber(data.middleware?.anomaly_counts?.total || 0);
        document.getElementById('blocked-requests').textContent =
            this.formatNumber(data.middleware?.blocked_requests || 0);

        // Update sensitivity badge
        const sensitivityEl = document.getElementById('sensitivity-badge');
        if (sensitivityEl) {
            const sensitivity = data.sensitivity || 'medium';
            sensitivityEl.innerHTML = `<span class="badge ${sensitivity}">${sensitivity.charAt(0).toUpperCase() + sensitivity.slice(1)}</span>`;
        }

        // Update trend chart
        if (this.trendChart) {
            const now = new Date().toLocaleTimeString();
            const requests = data.middleware?.total_requests || 0;
            const anomalies = data.middleware?.anomaly_counts?.total || 0;

            this.trendChart.data.labels.push(now);
            this.trendChart.data.datasets[0].data.push(requests);
            this.trendChart.data.datasets[1].data.push(anomalies);

            // Keep only last 20 data points
            if (this.trendChart.data.labels.length > 20) {
                this.trendChart.data.labels.shift();
                this.trendChart.data.datasets[0].data.shift();
                this.trendChart.data.datasets[1].data.shift();
            }

            this.trendChart.update();
        }

        // Update prompt injection chart
        if (this.piChart && data.prompt_injection) {
            const piData = data.prompt_injection;
            this.piChart.data.datasets[0].data = [
                piData.blocked_count || 0,
                (piData.threats_detected || 0) - (piData.blocked_count || 0)
            ];
            this.piChart.update();
        }

        // Update content analysis chart
        if (this.contentChart && data.content_analysis) {
            const caData = data.content_analysis;
            const byType = caData.by_type || {};
            this.contentChart.data.datasets[0].data = [
                (byType.ssn || 0) + (byType.email || 0) + (byType.phone || 0), // PII
                (byType.api_key || 0) + (byType.password || 0) + (byType.private_key || 0), // Secrets
                Object.keys(byType).length - 2 // Policy violations
            ];
            this.contentChart.update();
        }

        // Update anomaly list
        this.updateAnomalyList(data.recent_anomalies || []);
    },

    // Update anomaly list
    updateAnomalyList: function(anomalies) {
        const list = document.getElementById('anomaly-list');
        if (!list) return;

        if (anomalies.length === 0) {
            list.innerHTML = '<div class="anomaly-item">No recent anomalies</div>';
            return;
        }

        list.innerHTML = anomalies.slice(0, 5).map(a => `
            <div class="anomaly-item severity-${a.severity}">
                <span class="anomaly-type">${a.type}</span>
                <span class="anomaly-score">Score: ${a.score?.toFixed(1) || 'N/A'}</span>
                <span class="anomaly-time">${this.formatTime(a.timestamp)}</span>
            </div>
        `).join('');
    },

    // Reset stats
    resetStats: async function() {
        if (!confirm('Are you sure you want to reset ML statistics?')) return;

        try {
            const response = await fetch('/api/v1/ml/stats/reset', { method: 'POST' });
            if (!response.ok) throw new Error('Failed to reset stats');

            // Clear charts
            if (this.trendChart) {
                this.trendChart.data.labels = [];
                this.trendChart.data.datasets[0].data = [];
                this.trendChart.data.datasets[1].data = [];
                this.trendChart.update();
            }

            // Refresh
            this.fetchStats();
        } catch (error) {
            console.error('Error resetting stats:', error);
            alert('Failed to reset stats: ' + error.message);
        }
    },

    // Open configuration modal
    configure: function() {
        // Implementation would open a modal
        alert('Configuration modal - implement based on your UI framework');
    },

    // Format number with K/M suffix
    formatNumber: function(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    },

    // Format timestamp
    formatTime: function(timestamp) {
        if (!timestamp) return '';
        const date = new Date(timestamp);
        return date.toLocaleTimeString();
    },

    // Destroy widget
    destroy: function() {
        this.stopPolling();
        if (this.trendChart) this.trendChart.destroy();
        if (this.piChart) this.piChart.destroy();
        if (this.contentChart) this.contentChart.destroy();
    }
};

// Register widget
if (typeof window !== 'undefined') {
    window.MLStatsWidget = MLStatsWidget;
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MLStatsWidget;
}
