// Demo Site JavaScript - AegisGate Platform

document.addEventListener('DOMContentLoaded', function() {
    initTerminal();
    initCopyButtons();
    initMermaid();
});

// Terminal Emulator
function initTerminal() {
    const terminalInput = document.getElementById('terminal-input');
    if (!terminalInput) return;
    
    const terminal = document.getElementById('terminal-body');
    let commandHistory = [];
    let historyIndex = -1;
    
    terminalInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            const command = this.value.trim();
            if (command) {
                executeCommand(command);
                commandHistory.push(command);
                historyIndex = commandHistory.length;
                this.value = '';
            }
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                this.value = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                this.value = commandHistory[historyIndex];
            } else {
                historyIndex = commandHistory.length;
                this.value = '';
            }
        }
    });
}

function executeCommand(command) {
    const terminal = document.getElementById('terminal-body');
    const output = document.createElement('div');
    
    // Echo command
    const cmdLine = document.createElement('div');
    cmdLine.innerHTML = `<span class="prompt">$</span> <span class="command">${escapeHtml(command)}</span>`;
    terminal.appendChild(cmdLine);
    
    // Simulate command output
    setTimeout(() => {
        const result = simulateCommand(command);
        output.className = 'output';
        output.innerHTML = result;
        terminal.appendChild(output);
        
        // Auto-scroll to bottom
        terminal.scrollTop = terminal.scrollHeight;
    }, 300);
}

function simulateCommand(command) {
    const cmd = command.toLowerCase().trim();
    
    // Docker commands
    if (cmd.startsWith('docker run')) {
        return `<span class="success">✓ Container started successfully</span>
Pulling image ghcr.io/aegisgatesecurity/aegisgate-platform:latest... done
Creating aegisgate-proxy ... done

🛡️ AegisGate Platform v1.3.7 is running!

Endpoints:
  HTTP Proxy:  http://localhost:8080
  MCP Server: http://localhost:8081
  Dashboard:  https://localhost:8443

<span class="success">✓ All systems operational</span>`;
    }
    
    if (cmd === 'docker ps') {
        return `<span class="success">✓ CONTAINER ID   IMAGE                                                      STATUS          PORTS</span>
a1b2c3d4e5f6   ghcr.io/aegisgatesecurity/aegisgate-platform:latest   Up 2 minutes   0.0.0.0:8080->8080/tcp`;
    }
    
    if (cmd === 'docker logs aegisgate' || cmd.startsWith('docker logs')) {
        return `[2026-04-27 10:23:45] 🛡️ AegisGate v1.3.7 starting...
[2026-04-27 10:23:45] ✓ Configuration loaded
[2026-04-27 10:23:45] ✓ License: Community Edition
[2026-04-27 10:23:46] ✓ MCP Guardrails initialized (8 rules)
[2026-04-27 10:23:46] ✓ Pattern Scanner loaded (144+ patterns)
[2026-04-27 10:23:46] ✓ Compliance frameworks: ATLAS, NIST, OWASP
[2026-04-27 10:23:46] ✓ HTTP Proxy listening on :8080
[2026-04-27 10:23:46] ✓ MCP Server listening on :8081
[2026-04-27 10:23:46] ✓ Dashboard listening on :8443
[2026-04-27 10:23:46] <span class="success">✓ All systems operational</span>`;
    }
    
    // Health checks
    if (cmd === 'curl localhost:8080/health' || cmd === 'curl http://localhost:8080/health') {
        return `<span class="success">✓ {"status":"healthy","version":"1.3.7","services":{"proxy":"up","mcp":"up","scanner":"up"}}</span>`;
    }
    
    if (cmd === 'curl localhost:8443/health' || cmd === 'curl https://localhost:8443/health') {
        return `<span class="success">✓ {"status":"healthy","tier":"community","features":["atlas","nist","owasp"]}</span>`;
    }
    
    if (cmd === 'curl localhost:8081/health' || cmd === 'curl http://localhost:8081/health') {
        return `<span class="success">✓ {"status":"healthy","mcp":"enabled","sessions":0,"tools_registered":0}</span>`;
    }
    
    // Status command
    if (cmd === 'status' || cmd === 'aegisgate status') {
        return `🛡️ AegisGate Platform™ v1.3.7
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
License:        Community Edition
Uptime:         2 minutes
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Services:
  HTTP Proxy    ✓ Running (0.0.0.0:8080)
  MCP Server    ✓ Running (0.0.0.0:8081)
  Dashboard     ✓ Running (0.0.0.0:8443)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security:
  Guardrails    8 active
  Patterns      144+ loaded
  Sessions      0 active
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Frameworks:
  MITRE ATLAS   ✓ Enabled
  NIST AI RMF   ✓ Enabled
  OWASP LLM     ✓ Enabled`;
    }
    
    // Stats command
    if (cmd === 'stats' || cmd === 'aegisgate stats') {
        return `📊 AegisGate Statistics (Last 24h)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requests:       <span style="color: var(--primary)">1,847,293</span>
Blocked:        <span style="color: var(--accent)">23,847</span> (1.3%)
Threats:        <span style="color: var(--accent)">1,293</span> (0.07%)
Latency (avg):  <span style="color: var(--secondary)">2.44ms</span>
Throughput:     <span style="color: var(--secondary)">11,681 RPS</span>
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Top Threats:
  1. Prompt Injection    892
  2. Credential Scan     234
  3. PII Exposure        167
  4. Rate Limit Hit     0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
    }
    
    // Version
    if (cmd === 'version' || cmd === 'aegisgate version') {
        return `🛡️ AegisGate Platform v1.3.7
Build:          2026-04-27
Go:             1.25.9
License:        Apache 2.0 (Community)
Git:            ${commitHash || 'a1b2c3d'}`;
    }
    
    // Config
    if (cmd === 'config' || cmd === 'aegisgate config show') {
        return `⚙️ AegisGate Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
General:
  Mode:         proxy
  Log Level:    info
  License:     community
  
HTTP Proxy:
  Listen:      :8080
  Timeout:     30s
  
MCP Server:
  Listen:      :8081
  Auth:        session
  Max Sessions: 100
  
Guardrails:
  Rate Limit:  1000 RPM
  Timeout:     60s
  Max Tools:   50/session
  
Compliance:
  ATLAS:       enabled
  NIST:        enabled
  OWASP:       enabled
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
    }
    
    // List tools (simulated)
    if (cmd === 'tools list' || cmd === 'aegisgate tools list') {
        return `🛠️ Registered MCP Tools (Sample)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. database_query     (read-only SQL)
  2. file_read          (sandboxed)
  3. web_search         (rate-limited)
  4. code_execute       (disabled)
  5. secret_manager     (restricted)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span style="color: var(--text-muted)">Run 'tools list --verbose' for details</span>`;
    }
    
    // Scan command
    if (cmd.startsWith('scan ') || cmd.startsWith('aegisgate scan')) {
        // Check for malicious content
        if (cmd.includes('password') || cmd.includes('secret') || cmd.includes('sk-')) {
            return `🔍 Scan Result
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span style="color: var(--accent)">⚠️ THREAT DETECTED</span>
  
Type:      API Key / Secret
Pattern:   aws_key
Location:  Content match
Severity:  <span style="color: var(--accent)">HIGH</span>
  
Action:    Blocked
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span class="success">✓ Request blocked by AegisGate guardrail</span>`;
        }
        
        if (cmd.includes('ssn') || cmd.includes('123-45-6789') || cmd.includes('social security')) {
            return `🔍 Scan Result
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span style="color: var(--accent)">⚠️ THREAT DETECTED</span>
  
Type:      PII / PHI
Pattern:   hipaa_ssn
Location:  Content match
Severity:  <span style="color: var(--accent)">HIGH</span>
  
Framework: HIPAA
Action:    Blocked
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span class="success">✓ PHI detected and blocked by HIPAA scanner</span>`;
        }
        
        if (cmd.includes('ignore previous') || cmd.includes('disregard') || cmd.includes('forget')) {
            return `🔍 Scan Result
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span style="color: var(--accent)">⚠️ THREAT DETECTED</span>
  
Type:      Prompt Injection
Pattern:   atlas_prompt_override
Location:  Content match
Severity:  <span style="color: var(--accent)">CRITICAL</span>
  
Framework: MITRE ATLAS
Action:    Blocked
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span class="success">✓ Prompt injection blocked by ATLAS guardrail</span>`;
        }
        
        return `🔍 Scan Result
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span class="success">✓ No threats detected</span>
  
Content Length:  ${cmd.length} chars
Patterns Matched: 0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
    }
    
    // Threat test
    if (cmd.startsWith('test ') || cmd.startsWith('threat ')) {
        return `🔐 Threat Simulation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type:      ${cmd.includes('injection') ? 'Prompt Injection' : 'Credential Scan'}
Severity:  HIGH
Source:    Simulated Attack
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span class="success">✓ AegisGate would BLOCK this request</span>
Guardrail: MITRE ATLAS / Credential Scanner
Reason:    Pattern match on prohibited content
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`;
    }
    
    // Help
    if (cmd === 'help' || cmd === '?') {
        return `Available commands:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span style="color: var(--primary)">docker run ...</span>    - Start AegisGate container
<span style="color: var(--primary)">status</span>            - Show system status
<span style="color: var(--primary)">stats</span>             - Show statistics
<span style="color: var(--primary)">version</span>          - Show version
<span style="color: var(--primary)">config</span>           - Show configuration
<span style="color: var(--primary)">tools list</span>       - List MCP tools
<span style="color: var(--primary)">scan [text]</span>       - Scan content for threats
<span style="color: var(--primary)">test [type]</span>      - Test threat detection
<span style="color: var(--primary)">clear</span>            - Clear terminal
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<span style="color: var(--text-muted)">Try: scan with 'sk-api-key-xxx' or '123-45-6789'</span>`;
    }
    
    // Clear
    if (cmd === 'clear' || cmd === 'cls') {
        const terminal = document.getElementById('terminal-body');
        terminal.innerHTML = '';
        return '';
    }
    
    // Exit
    if (cmd === 'exit' || cmd === 'quit') {
        return `<span style="color: var(--text-muted)">Session ended. Refresh page to restart.</span>`;
    }
    
    // Unknown command
    return `<span style="color: var(--accent)">Command not found: ${escapeHtml(cmd.split(' ')[0])}</span>
<span style="color: var(--text-muted)">Type 'help' for available commands</span>`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Copy Buttons
function initCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    
    copyButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const codeElement = this.parentElement.querySelector('pre');
            if (codeElement) {
                navigator.clipboard.writeText(codeElement.textContent).then(() => {
                    const originalText = this.textContent;
                    this.textContent = 'Copied!';
                    this.style.background = 'var(--secondary)';
                    
                    setTimeout(() => {
                        this.textContent = originalText;
                        this.style.background = '';
                    }, 2000);
                });
            }
        });
    });
}

// Fill Terminal Command (for index.html buttons)
function fillCommand(cmd) {
    const terminalInput = document.getElementById('terminal-input');
    if (terminalInput) {
        terminalInput.value = cmd;
        terminalInput.focus();
        // Scroll to terminal if not visible
        const terminal = document.querySelector('.terminal-container');
        if (terminal) {
            terminal.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    } else {
        // If on index page without terminal, redirect to demo page
        window.location.href = 'demo.html';
    }
}

// Mermaid Diagram Rendering
function initMermaid() {
    if (typeof mermaid !== 'undefined') {
        mermaid.initialize({
            startOnLoad: true,
            theme: 'dark',
            themeVariables: {
                primaryColor: '#00ADD8',
                primaryBorderColor: '#00ADD8',
                lineColor: '#F97583',
                secondaryColor: '#238636'
            }
        });
    }
}

// Smooth Scroll
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});

// Intersection Observer for Animations
const observerOptions = { threshold: 0.1, rootMargin: '0px 0px -50px 0px' };
const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
        }
    });
}, observerOptions);

document.querySelectorAll('section, .card, .stat').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    observer.observe(el);
});

const style = document.createElement('style');
style.textContent = `.visible { opacity: 1 !important; transform: translateY(0) !important; }`;
document.head.appendChild(style);
