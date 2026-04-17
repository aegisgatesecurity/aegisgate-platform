class PolicyConsole {
    constructor() {
        this.policies = [];
        this.loadPolicies();
        this.setupEventListeners();
    }

    async loadPolicies() {
        try {
            const response = await fetch('/api/v1/policies');
            if (response.ok) {
                this.policies = await response.json();
                this.renderTable();
            }
        } catch (error) {
            console.error('Error loading policies:', error);
        }
    }

    renderTable() {
        const tbody = document.getElementById('policy-table-body');
        if (!tbody) return;

        tbody.innerHTML = this.policies.map(policy =>
            '<tr>' +
                '<td>' + policy.name + '</td>' +
                '<td><span class="compliance-badge ' + policy.framework + '">' + policy.framework + '</span></td>' +
                '<td><span class="severity-badge ' + policy.severity + '">' + policy.severity + '</span></td>' +
                '<td><span class="status-badge ' + (policy.enabled ? 'active' : 'inactive') + '">' + (policy.enabled ? 'Active' : 'Inactive') + '</span></td>' +
                '<td>' + (policy.violations || 0) + '</td>' +
                '<td>' + (policy.lastModified || 'N/A') + '</td>' +
                '<td>' +
                    '<button class="btn-icon edit">✏️</button>' +
                    '<button class="btn-icon delete">🗑️</button>' +
                '</td>' +
            '</tr>'
        ).join('');
    }

    filterPolicies(query) {
        console.log('Filtering by:', query);
    }

    filterByCompliance(framework) {
        console.log('Filtering by framework:', framework);
    }

    filterByStatus(status) {
        console.log('Filtering by status:', status);
    }

    setupEventListeners() {
        console.log('Policy console event listeners set up');
    }
}

const policyConsole = new PolicyConsole();

function navigateTo(page) {
    console.log('Navigating to:', page);
    // Add navigation logic
}

function openPolicyModal() {
    console.log('Opening policy modal');
    alert('Open policy creation modal');
}

function exportPolicies() {
    console.log('Exporting policies');
    alert('Export policies functionality');
}

function resetPolicies() {
    if (confirm('Reset all policies to default?')) {
        console.log('Resetting policies');
        alert('Policies reset to default');
    }
}
