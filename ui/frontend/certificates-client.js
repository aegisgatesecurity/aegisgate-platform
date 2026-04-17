class CertificateConsole {
    constructor() {
        this.certs = [];
        this.loadCertificates();
        this.setupEventListeners();
    }

    async loadCertificates() {
        try {
            const response = await fetch('/api/v1/certs');
            if (response.ok) {
                this.certs = await response.json();
                this.renderTable();
            }
        } catch (error) {
            console.error('Error loading certificates:', error);
        }
    }

    renderTable() {
        const tbody = document.getElementById('certificate-table-body');
        if (!tbody) return;

        tbody.innerHTML = this.certs.map(cert =>
            '<tr>' +
                '<td>' + cert.hostname + '</td>' +
                '<td>' + (cert.issuer || 'AegisGate CA') + '</td>' +
                '<td>' + (cert.validFrom || 'N/A') + '</td>' +
                '<td>' + (cert.validTo || 'N/A') + '</td>' +
                '<td><span class="status-badge ' + (cert.status || 'active') + '">' + (cert.status || 'Active') + '</span></td>' +
                '<td>' +
                    '<button class="btn-icon edit">✏️</button>' +
                    '<button class="btn-icon delete">🗑️</button>' +
                    '<button class="btn-icon refresh" onclick="certConsole.refreshCertificate('' + cert.hostname + '')">🔄</button>' +
                '</td>' +
            '</tr>'
        ).join('');
    }

    refreshCertificate(hostname) {
        console.log('Refreshing certificate for:', hostname);
        alert('Refresh certificate: ' + hostname);
    }

    setupEventListeners() {
        console.log('Certificate console event listeners set up');
    }
}

const certConsole = new CertificateConsole();

function navigateTo(page) {
    console.log('Navigating to:', page);
    // Add navigation logic
}

function generateCACert() {
    console.log('Generating CA certificate');
    alert('Generate CA certificate functionality');
}

function generateServerCert() {
    console.log('Generating server certificate');
    alert('Generate server certificate functionality');
}

function rotateSecrets() {
    console.log('Rotating secrets');
    alert('Rotate secrets functionality');
}
