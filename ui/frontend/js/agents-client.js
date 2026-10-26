// Agent Registry Dashboard Client — v5.0
// Communicates with /api/v1/agents/* and /api/v1/agent-policies/*
class AgentRegistryDashboard {
    constructor() {
        this.apiBase = '/api/v1';
        this.eventSource = null;
        this.refreshTimer = null;
        this.refreshInterval = 10000;
        this.init();
    }

    async init() {
        console.log('Agent Registry Dashboard v5.0 initialized');
        this.setupTabs();
        this.setupFilters();
        this.setupPolicies();
        this.setupFederation();
        await this.loadAgents();
        await this.loadDormancy();
        await this.loadDrift();
        await this.loadPolicies();
        this.checkFederation();
        this.connectSSE();
        this.startAutoRefresh();
    }

    // ── Tab Management ──────────────────────────────────────────

    setupTabs() {
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab + '-tab').classList.add('active');
            });
        });
    }

    // ── Filters ─────────────────────────────────────────────────

    setupFilters() {
        document.getElementById('filter-status').addEventListener('change', () => this.loadAgents());
        document.getElementById('filter-protocol').addEventListener('change', () => this.loadAgents());
        document.getElementById('filter-owner').addEventListener('input', this.debounce(() => this.loadAgents(), 300));
        document.getElementById('btn-refresh').addEventListener('click', () => {
            this.loadAgents();
            this.loadDormancy();
        });
    }

    getFilters() {
        const params = new URLSearchParams();
        const status = document.getElementById('filter-status').value;
        const protocol = document.getElementById('filter-protocol').value;
        const owner = document.getElementById('filter-owner').value.trim();
        if (status) params.set('status', status);
        if (protocol) params.set('protocol', protocol);
        if (owner) params.set('owner', owner);
        return params.toString();
    }

    // ── Agent List ──────────────────────────────────────────────

    async loadAgents() {
        try {
            const qs = this.getFilters();
            const url = `${this.apiBase}/agents${qs ? '?' + qs : ''}`;
            const res = await fetch(url);
            if (!res.ok) {
                this.renderAgentError(res.status);
                return;
            }
            const data = await res.json();
            const agents = data.agents || data || [];
            this.renderAgentTable(agents);
            this.updateOverview(agents);
        } catch (err) {
            document.getElementById('agent-table-body').innerHTML =
                `<tr><td colspan="8" class="empty-state">Error: ${this.escapeHtml(err.message)}</td></tr>`;
        }
    }

    renderAgentError(status) {
        const msg = status === 503
            ? 'Agent Registry requires Professional tier'
            : `HTTP ${status}`;
        document.getElementById('agent-table-body').innerHTML =
            `<tr><td colspan="8" class="empty-state">${this.escapeHtml(msg)}</td></tr>`;
    }

    renderAgentTable(agents) {
        const tbody = document.getElementById('agent-table-body');
        if (!agents || agents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No agents found</td></tr>';
            return;
        }
        tbody.innerHTML = agents.map(a => `
            <tr>
                <td><code>${this.escapeHtml(a.id)}</code></td>
                <td>${this.escapeHtml(a.name)}</td>
                <td><span class="status-badge ${a.status}">${a.status}</span></td>
                <td>${(a.protocols || []).map(p => `<span class="protocol-tag">${p}</span>`).join('')}</td>
                <td>${this.formatTime(a.last_activity)}</td>
                <td>${a.active_sessions || 0}</td>
                <td>${this.escapeHtml(a.owner || '—')}</td>
                <td>
                    <button class="action-btn small" onclick="dashboard.showAgentDetail('${this.escapeHtml(a.id)}')">Details</button>
                    ${this.lifecycleActions(a)}
                </td>
            </tr>
        `).join('');
    }

    lifecycleActions(agent) {
        if (agent.status === 'revoked') return '';
        const btns = [];
        if (agent.status === 'active' || agent.status === 'provisioned') {
            btns.push(`<button class="action-btn small" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','dormant')">Dormant</button>`);
            btns.push(`<button class="action-btn small" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','quarantined')">Quarantine</button>`);
        }
        if (agent.status === 'dormant') {
            btns.push(`<button class="action-btn small" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','quarantined')">Quarantine</button>`);
            btns.push(`<button class="action-btn small" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','active')">Activate</button>`);
        }
        if (agent.status === 'quarantined') {
            btns.push(`<button class="action-btn small danger" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','revoked')">Revoke</button>`);
            btns.push(`<button class="action-btn small" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','active')">Activate</button>`);
        }
        btns.push(`<button class="action-btn small danger" onclick="dashboard.transition('${this.escapeHtml(agent.id)}','revoked')">Revoke</button>`);
        return btns.join('');
    }

    async showAgentDetail(agentId) {
        try {
            const res = await fetch(`${this.apiBase}/agents/${encodeURIComponent(agentId)}`);
            if (!res.ok) return;
            const a = await res.json();
            alert(this.agentDetailText(a));
        } catch (err) {
            console.error('Error fetching agent detail:', err);
        }
    }

    agentDetailText(a) {
        const lines = [
            `Agent: ${a.name} (${a.id})`,
            `Status: ${a.status} (since ${this.formatTime(a.status_since)})`,
            `Role: ${a.role}`,
            `Enabled: ${a.enabled}`,
            `Protocols: ${(a.protocols || []).join(', ')}`,
            `Last Activity: ${this.formatTime(a.last_activity)}`,
            `Active Sessions: ${a.active_sessions}`,
            `Total Events: ${a.total_events}`,
            `Owner: ${a.owner || '—'}`,
            `In AIBOM: ${a.in_aibom}`,
            `AIBOM Drift: ${a.aibom_drift || 'none'}`,
            `Last Intent: ${a.last_intent || 'none'} (${this.formatTime(a.last_intent_at)})`,
            `Intent Count: ${a.intent_count}`,
            `Discovery Sources: ${(a.discovery_sources || []).join(', ')}`,
            `First Seen: ${this.formatTime(a.first_seen)}`,
            `Tags: ${Object.entries(a.tags || {}).map(([k,v]) => `${k}=${v}`).join(', ') || 'none'}`,
        ];
        return lines.join('\n');
    }

    async transition(agentId, newStatus) {
        if (!confirm(`Transition agent ${agentId} to ${newStatus}?`)) return;
        try {
            const res = await fetch(`${this.apiBase}/agents/${encodeURIComponent(agentId)}/lifecycle`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus }),
            });
            if (res.ok) {
                this.loadAgents();
                this.loadDormancy();
            } else {
                const body = await res.json().catch(() => ({}));
                alert(`Failed: ${body.error || res.statusText}`);
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    }

    // ── Overview Stats ──────────────────────────────────────────

    updateOverview(agents) {
        const counts = { active: 0, dormant: 0, quarantined: 0, revoked: 0, provisioned: 0 };
        agents.forEach(a => { if (counts[a.status] !== undefined) counts[a.status]++; });
        this.setText('stat-total', agents.length);
        this.setText('stat-active', counts.active);
        this.setText('stat-dormant', counts.dormant);
        this.setText('stat-quarantined', counts.quarantined);
        this.setText('stat-revoked', counts.revoked);
        this.setText('stat-provisioned', counts.provisioned);
    }

    // ── Dormancy Report ─────────────────────────────────────────

    async loadDormancy() {
        try {
            const res = await fetch(`${this.apiBase}/agents/dormancy`);
            if (!res.ok) {
                document.getElementById('dormancy-report').innerHTML =
                    '<p class="empty-state">Dormancy report unavailable</p>';
                return;
            }
            const report = await res.json();
            this.renderDormancy(report);
        } catch (err) {
            document.getElementById('dormancy-report').innerHTML =
                `<p class="empty-state">Error: ${this.escapeHtml(err.message)}</p>`;
        }
    }

    renderDormancy(report) {
        const container = document.getElementById('dormancy-report');
        const summary = `
            <div class="overview-grid">
                <div class="overview-card"><span class="overview-value">${report.total || 0}</span><span class="overview-label">Total</span></div>
                <div class="overview-card active-bg"><span class="overview-value">${report.active || 0}</span><span class="overview-label">Active</span></div>
                <div class="overview-card dormant-bg"><span class="overview-value">${report.dormant || 0}</span><span class="overview-label">Dormant</span></div>
                <div class="overview-card quarantine-bg"><span class="overview-value">${report.quarantined || 0}</span><span class="overview-label">Quarantined</span></div>
                <div class="overview-card revoked-bg"><span class="overview-value">${report.revoked || 0}</span><span class="overview-label">Revoked</span></div>
            </div>`;

        const agents = report.agents || [];
        const table = agents.length === 0
            ? '<p class="empty-state">No dormancy data</p>'
            : `<table><thead><tr><th>Agent</th><th>Status</th><th>Last Activity</th><th>Dormant For</th><th>Protocols</th><th>Sessions</th></tr></thead>
               <tbody>${agents.map(a => `
                   <tr>
                       <td>${this.escapeHtml(a.name || a.agent_id)}</td>
                       <td><span class="status-badge ${a.status}">${a.status}</span></td>
                       <td>${this.formatTime(a.last_activity)}</td>
                       <td>${this.formatDuration(a.dormant_for)}</td>
                       <td>${(a.protocols || []).map(p => `<span class="protocol-tag">${p}</span>`).join('')}</td>
                       <td>${a.active_sessions || 0}</td>
                   </tr>`).join('')}</tbody></table>`;

        container.innerHTML = summary + table;
    }

    // ── AIBOM Drift ─────────────────────────────────────────────

    async loadDrift() {
        try {
            const res = await fetch(`${this.apiBase}/agents/drift`);
            if (!res.ok) {
                document.getElementById('drift-report').innerHTML =
                    '<p class="empty-state">Drift report unavailable</p>';
                return;
            }
            const report = await res.json();
            this.renderDrift(report);
        } catch (err) {
            document.getElementById('drift-report').innerHTML =
                `<p class="empty-state">Error: ${this.escapeHtml(err.message)}</p>`;
        }
    }

    renderDrift(report) {
        const container = document.getElementById('drift-report');
        const summary = `
            <div class="overview-grid">
                <div class="overview-card active-bg"><span class="overview-value">${report.matched || 0}</span><span class="overview-label">Matched</span></div>
                <div class="overview-card dormant-bg"><span class="overview-value">${(report.in_aibom_not_active || []).length}</span><span class="overview-label">In AIBOM, Not Active</span></div>
                <div class="overview-card quarantine-bg"><span class="overview-value">${(report.active_not_in_aibom || []).length}</span><span class="overview-label">Active, Not In AIBOM</span></div>
            </div>`;

        const inNotActive = report.in_aibom_not_active || [];
        const activeNotIn = report.active_not_in_aibom || [];

        const sections = [];
        if (inNotActive.length > 0) {
            sections.push(`<h4>Declared in AIBOM but not running</h4>
                <table><thead><tr><th>Agent</th><th>Protocol</th><th>Note</th></tr></thead>
                <tbody>${inNotActive.map(d => `<tr><td>${this.escapeHtml(d.agent_name || d.agent_id)}</td><td>${d.protocol || '—'}</td><td>${this.escapeHtml(d.note || '')}</td></tr>`).join('')}</tbody></table>`);
        }
        if (activeNotIn.length > 0) {
            sections.push(`<h4>Running but not declared in AIBOM</h4>
                <table><thead><tr><th>Agent</th><th>Protocol</th><th>Last Seen</th></tr></thead>
                <tbody>${activeNotIn.map(d => `<tr><td>${this.escapeHtml(d.agent_name || d.agent_id)}</td><td>${d.protocol || '—'}</td><td>${this.formatTime(d.last_seen)}</td></tr>`).join('')}</tbody></table>`);
        }
        if (sections.length === 0 && (report.matched || 0) > 0) {
            sections.push('<p class="empty-state">✅ No drift detected — all agents match AIBOM</p>');
        }

        container.innerHTML = summary + sections.join('');
    }

    // ── Policies ────────────────────────────────────────────────

    setupPolicies() {
        document.getElementById('btn-new-policy').addEventListener('click', () => this.showPolicyEditor());
        document.getElementById('btn-cancel-policy').addEventListener('click', () => this.hidePolicyEditor());
        document.getElementById('policy-form').addEventListener('submit', (e) => this.savePolicy(e));
    }

    async loadPolicies() {
        try {
            const res = await fetch(`${this.apiBase}/agent-policies`);
            if (!res.ok) {
                document.getElementById('policy-list').innerHTML =
                    '<p class="empty-state">Policies unavailable</p>';
                return;
            }
            const data = await res.json();
            const policies = data.policies || data || [];
            this.renderPolicies(policies);
        } catch (err) {
            document.getElementById('policy-list').innerHTML =
                `<p class="empty-state">Error: ${this.escapeHtml(err.message)}</p>`;
        }
    }

    renderPolicies(policies) {
        const container = document.getElementById('policy-list');
        if (!policies || policies.length === 0) {
            container.innerHTML = '<p class="empty-state">No lifecycle policies configured</p>';
            return;
        }
        container.innerHTML = policies.map(p => `
            <div class="policy-card">
                <div class="policy-card-header">
                    <h4>${this.escapeHtml(p.name)} ${p.enabled ? '' : '<span style="color:#888">(disabled)</span>'}</h4>
                    <div>
                        <button class="action-btn small" onclick='dashboard.editPolicy(${JSON.stringify(p).replace(/'/g,"&#39;")})'>Edit</button>
                        <button class="action-btn small danger" onclick="dashboard.deletePolicy('${this.escapeHtml(p.id)}')">Delete</button>
                    </div>
                </div>
                <p style="color:#888;font-size:0.85rem">${this.escapeHtml(p.description || '')}</p>
                <div class="policy-thresholds">
                    <span>Dormant: ${p.dormancy_threshold || '—'}</span>
                    <span>Quarantine: ${p.quarantine_threshold || '—'}</span>
                    <span>Revoke: ${p.auto_revoke_threshold || '—'}</span>
                </div>
            </div>
        `).join('');
    }

    showPolicyEditor() {
        document.getElementById('policy-editor').classList.remove('hidden');
        document.getElementById('policy-editor-title').textContent = 'New Policy';
        document.getElementById('policy-form').reset();
        document.getElementById('policy-id').value = '';
    }

    editPolicy(p) {
        document.getElementById('policy-editor').classList.remove('hidden');
        document.getElementById('policy-editor-title').textContent = 'Edit Policy';
        document.getElementById('policy-id').value = p.id || '';
        document.getElementById('policy-name').value = p.name || '';
        document.getElementById('policy-desc').value = p.description || '';
        document.getElementById('policy-enabled').checked = p.enabled !== false;
        document.getElementById('policy-dormancy').value = p.dormancy_threshold || '';
        document.getElementById('policy-quarantine').value = p.quarantine_threshold || '';
        document.getElementById('policy-revoke').value = p.auto_revoke_threshold || '';
    }

    hidePolicyEditor() {
        document.getElementById('policy-editor').classList.add('hidden');
    }

    async savePolicy(e) {
        e.preventDefault();
        const policy = {
            id: document.getElementById('policy-id').value || 'policy-' + Date.now(),
            name: document.getElementById('policy-name').value,
            description: document.getElementById('policy-desc').value,
            enabled: document.getElementById('policy-enabled').checked,
            dormancy_threshold: document.getElementById('policy-dormancy').value || '24h',
            quarantine_threshold: document.getElementById('policy-quarantine').value || '168h',
            auto_revoke_threshold: document.getElementById('policy-revoke').value || '720h',
        };
        try {
            const res = await fetch(`${this.apiBase}/agent-policies`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(policy),
            });
            if (res.ok) {
                this.hidePolicyEditor();
                this.loadPolicies();
            } else {
                alert('Failed to save policy');
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    }

    async deletePolicy(id) {
        if (!confirm(`Delete policy ${id}?`)) return;
        try {
            const res = await fetch(`${this.apiBase}/agent-policies/${encodeURIComponent(id)}`, { method: 'DELETE' });
            if (res.ok) this.loadPolicies();
            else alert('Failed to delete policy');
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    }

    // ── Federation ──────────────────────────────────────────────

    setupFederation() {
        document.getElementById('btn-fed-export').addEventListener('click', () => this.exportBundle());
        document.getElementById('btn-fed-drift').addEventListener('click', () => this.loadFedDrift());
    }

    async checkFederation() {
        const container = document.getElementById('fed-status');
        try {
            const res = await fetch(`${this.apiBase}/agents/federation/bundle`);
            if (res.status === 503) {
                container.innerHTML = '<p class="fed-disabled">Federation is disabled (air-gap mode). Enable via <code>agent_registry.enable_federation</code> in config.</p>';
                document.getElementById('btn-fed-export').disabled = true;
                document.getElementById('btn-fed-drift').disabled = true;
                return;
            }
            if (res.ok) {
                const bundle = await res.json();
                container.innerHTML = `
                    <p class="fed-enabled">✅ Federation active</p>
                    <p>Instance: <code>${this.escapeHtml(bundle.instance_id || '—')}</code></p>
                    <p>Attestations: ${bundle.attestations?.length || 0} agents</p>
                    <p>Bundle ID: <code>${this.escapeHtml(bundle.bundle_id || '—')}</code></p>
                    <p>Signed: ${this.formatTime(bundle.signed_at)}</p>`;
            } else {
                container.innerHTML = `<p class="fed-disabled">Federation status: HTTP ${res.status}</p>`;
            }
        } catch {
            container.innerHTML = '<p class="fed-disabled">Federation status unavailable</p>';
        }
    }

    async exportBundle() {
        try {
            const res = await fetch(`${this.apiBase}/agents/federation/bundle`);
            if (!res.ok) { alert('Export failed'); return; }
            const bundle = await res.json();
            const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `agent-federation-bundle-${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    }

    async loadFedDrift() {
        const container = document.getElementById('fed-drift-report');
        try {
            const res = await fetch(`${this.apiBase}/agents/federation/drift`);
            if (!res.ok) { alert('Drift report unavailable'); return; }
            const report = await res.json();
            container.classList.remove('hidden');
            const local = report.local_only || [];
            const federated = report.federated_only || [];
            const discrepancies = report.status_discrepancies || [];
            container.innerHTML = `
                <div class="overview-grid">
                    <div class="overview-card"><span class="overview-value">${report.matched || 0}</span><span class="overview-label">Matched</span></div>
                    <div class="overview-card dormant-bg"><span class="overview-value">${local.length}</span><span class="overview-label">Local Only</span></div>
                    <div class="overview-card quarantine-bg"><span class="overview-value">${federated.length}</span><span class="overview-label">Federated Only</span></div>
                    <div class="overview-card revoked-bg"><span class="overview-value">${discrepancies.length}</span><span class="overview-label">Status Discrepancies</span></div>
                </div>
                ${discrepancies.length > 0 ? `<h4>Status Discrepancies</h4>
                    <table><thead><tr><th>Fingerprint</th><th>Local Status</th><th>Federated Status</th></tr></thead>
                    <tbody>${discrepancies.map(d => `<tr><td><code>${this.escapeHtml(d.fingerprint?.substring(0,16) || '—')}...</code></td><td><span class="status-badge ${d.local_status}">${d.local_status}</span></td><td><span class="status-badge ${d.federated_status}">${d.federated_status}</span></td></tr>`).join('')}</tbody></table>`
                    : '<p class="empty-state">✅ No cross-deployment discrepancies</p>'}`;
        } catch (err) {
            container.innerHTML = `<p class="empty-state">Error: ${this.escapeHtml(err.message)}</p>`;
        }
    }

    // ── SSE Event Stream ────────────────────────────────────────

    connectSSE() {
        const log = document.getElementById('event-log');
        try {
            this.eventSource = new EventSource(`${this.apiBase}/agents/stream`);
            this.eventSource.onopen = () => {
                document.getElementById('conn-status').classList.remove('disconnected', 'connecting');
                if (log.querySelector('.empty-state')) log.innerHTML = '';
                this.addEvent('system', 'Connected to event stream');
            };
            this.eventSource.onerror = () => {
                document.getElementById('conn-status').classList.add('disconnected');
                this.addEvent('system', 'Disconnected — reconnecting...');
            };
            this.eventSource.addEventListener('agent_lifecycle', (e) => this.handleSSE('agent_lifecycle', e));
            this.eventSource.addEventListener('agent_discovered', (e) => this.handleSSE('agent_discovered', e));
            this.eventSource.addEventListener('agent_dormant', (e) => this.handleSSE('agent_dormant', e));
            this.eventSource.addEventListener('agent_revoked', (e) => this.handleSSE('agent_revoked', e));
            this.eventSource.addEventListener('agent_drift', (e) => this.handleSSE('agent_drift', e));
        } catch {
            log.innerHTML = '<p class="empty-state">SSE not available</p>';
        }
    }

    handleSSE(type, event) {
        try {
            const data = JSON.parse(event.data);
            this.addEvent(type, `${data.agent_id || '—'}: ${data.message || data.status || ''}`);
            this.loadAgents();
        } catch {
            this.addEvent(type, event.data);
        }
    }

    addEvent(type, message) {
        const log = document.getElementById('event-log');
        const entry = document.createElement('div');
        entry.className = 'event-entry';
        entry.innerHTML = `<span class="event-time">${new Date().toLocaleTimeString()}</span><span class="event-type ${type}">${type}</span><span>${this.escapeHtml(message)}</span>`;
        log.insertBefore(entry, log.firstChild);
        while (log.children.length > 50) log.removeChild(log.lastChild);
    }

    // ── Auto Refresh ────────────────────────────────────────────

    startAutoRefresh() {
        this.refreshTimer = setInterval(() => {
            this.loadAgents();
            this.loadDormancy();
        }, this.refreshInterval);
    }

    // ── Utilities ───────────────────────────────────────────────

    setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    formatTime(t) {
        if (!t || t === '0001-01-01T00:00:00Z') return '—';
        const d = new Date(t);
        if (isNaN(d)) return '—';
        return d.toLocaleString();
    }

    formatDuration(d) {
        if (!d) return '—';
        if (typeof d === 'string') return d;
        const seconds = Math.floor(d / 1e9);
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        if (days > 0) return `${days}d ${hours}h`;
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }

    escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    debounce(fn, ms) {
        let timer;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), ms);
        };
    }
}

let dashboard;
document.addEventListener('DOMContentLoaded', () => { dashboard = new AgentRegistryDashboard(); });