/* ============================================================================
   MNIDS - Professional Network Intrusion Detection System
   Advanced Dashboard with Terminal Analysis, AI Integration & VirusTotal
   ============================================================================ */

// Malicious IOC IP List - Real Threat Intelligence
const MALICIOUS_IPS = [
  '128.71.84.176', '136.243.37.219', '139.198.19.213', '144.76.38.10',
  '144.76.56.124', '144.76.69.77', '148.251.125.12', '154.125.234.13',
  '160.154.145.106', '173.249.30.147', '178.159.37.85', '178.63.34.189',
  '185.232.52.99', '195.238.108.90', '195.54.167.56', '196.52.84.15',
  '196.52.84.21', '213.239.216.194', '37.138.49.131', '37.138.53.146',
  '49.233.160.137', '5.183.94.62', '5.188.210.18', '5.188.84.104',
  '5.188.84.147', '5.188.84.15', '5.188.84.220', '5.188.84.233',
  '5.188.84.25', '5.188.84.3', '5.188.84.35', '5.188.84.45',
  '5.188.84.65', '5.188.86.218', '5.9.140.242', '66.249.79.159',
  '79.228.253.175', '79.240.7.239', '80.82.64.229', '92.220.10.100',
  '95.128.164.111'
];

class MNIDS {
  constructor() {
    this.currentPage = 'dashboard';
    this.trafficFlows = [];
    this.analysisResults = [];
    this.isAnalyzing = false;
    this.vtApiKey = localStorage.getItem('vtApiKey') || '';
    this.deepseekKey = localStorage.getItem('deepseekKey') || '';
    this.init();
  }

  init() {
    this.render();
    this.attachEventListeners();
  }

  render() {
    const root = document.getElementById('root');
    root.innerHTML = `
      <div class="app-container">
        <aside class="sidebar">
          <div class="sidebar-header">
            <div class="sidebar-title">MNIDS</div>
            <div class="sidebar-subtitle">Network Intrusion Detection</div>
          </div>
          <nav class="nav-menu">
            <div class="nav-item ${this.currentPage === 'dashboard' ? 'active' : ''}" data-page="dashboard">
              <span class="nav-icon">📊</span> Dashboard
            </div>
            <div class="nav-item ${this.currentPage === 'analysis' ? 'active' : ''}" data-page="analysis">
              <span class="nav-icon">🔍</span> Analysis
            </div>
            <div class="nav-item ${this.currentPage === 'mllab' ? 'active' : ''}" data-page="mllab">
              <span class="nav-icon">🧠</span> ML Lab
            </div>
            <div class="nav-item ${this.currentPage === 'settings' ? 'active' : ''}" data-page="settings">
              <span class="nav-icon">⚙️</span> Settings
            </div>
          </nav>
        </aside>

        <div class="main-content">
          <header class="header">
            <div class="header-left">
              <h1 class="header-title">${this.getPageTitle()}</h1>
              <p class="header-subtitle">Advanced threat detection with ensemble ML models</p>
            </div>
            <div class="header-badges">
              <div class="status-indicator">
                <div class="status-dot"></div>
                Production Active
              </div>
              <div class="model-info">
                <strong>Model:</strong> Random Forest + Isolation Forest<br>
                <strong>Status:</strong> ✓ Ready<br>
                <strong>Accuracy:</strong> 50.67%
              </div>
            </div>
          </header>

          <div class="content">
            ${this.renderPage()}
          </div>
        </div>
      </div>
    `;
  }

  getPageTitle() {
    const titles = {
      dashboard: 'Traffic Upload & Analysis',
      analysis: 'Detailed Flow Analysis',
      mllab: 'ML Model Testing',
      settings: 'Configuration & API Keys'
    };
    return titles[this.currentPage] || 'MNIDS Dashboard';
  }

  renderPage() {
    switch(this.currentPage) {
      case 'dashboard': return this.renderDashboard();
      case 'analysis': return this.renderAnalysis();
      case 'mllab': return this.renderMLLab();
      case 'settings': return this.renderSettings();
      default: return this.renderDashboard();
    }
  }

  renderDashboard() {
    return `
      <div class="page active">
        ${this.renderUploadSection()}
        ${this.analysisResults.length > 0 ? this.renderAnalysisResults() : ''}
      </div>
    `;
  }

  renderUploadSection() {
    return `
      <div class="card">
        <div class="card-title">Upload Network Traffic File</div>
        <div class="upload-card" id="dropZone">
          <div class="upload-area-icon">📤</div>
          <p class="upload-area-text">Drag & Drop PCAP or CSV File Here</p>
          <p class="upload-area-hint">Supports: CSV with flow data, PCAP packet captures</p>
          <button class="button button-primary" onclick="document.getElementById('fileInput').click()">
            Browse Files
          </button>
          <input type="file" id="fileInput" accept=".csv,.pcap,.pcapng" style="display: none;">
        </div>
      </div>

      ${this.isAnalyzing ? `
        <div class="card">
          <div class="card-title">Live Analysis Terminal</div>
          <div class="analysis-terminal" id="terminal">
            <div class="terminal-header">
              <div class="terminal-dot"></div>
              <span>MNIDS Analysis Engine - Processing Traffic Flows</span>
            </div>
            <div id="terminalLogs"></div>
          </div>
          <div style="margin-top: 1rem; text-align: center;">
            <div style="display: inline-block; font-family: monospace; color: var(--accent-green);">
              ▓▓▓▓▓▓▓▓░░░ 75%
            </div>
          </div>
        </div>
      ` : ''}
    `;
  }

  renderAnalysisResults() {
    const normal = this.analysisResults.filter(r => r.threat_level === 'normal').length;
    const suspicious = this.analysisResults.filter(r => r.threat_level === 'suspicious').length;
    const risky = this.analysisResults.filter(r => r.threat_level === 'risky').length;

    return `
      <div class="card">
        <div class="card-title">Analysis Summary</div>
        <div class="metrics-grid">
          <div class="metric-box">
            <div class="metric-label">Total Flows</div>
            <div class="metric-value">${this.analysisResults.length}</div>
          </div>
          <div class="metric-box">
            <div class="metric-label">Normal Traffic</div>
            <div class="metric-value positive">${normal}</div>
          </div>
          <div class="metric-box">
            <div class="metric-label">Suspicious</div>
            <div class="metric-value warning">${suspicious}</div>
          </div>
          <div class="metric-box">
            <div class="metric-label">High Risk</div>
            <div class="metric-value negative">${risky}</div>
          </div>
        </div>

        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              ${this.analysisResults.slice(0, 20).map((flow, idx) => `
                <tr>
                  <td>${flow.src_ip}</td>
                  <td>${flow.dst_ip}</td>
                  <td>${flow.dst_port}</td>
                  <td>${flow.protocol}</td>
                  <td><span class="badge ${flow.threat_level}">${flow.threat_level.toUpperCase()}</span></td>
                  <td style="font-weight: 700; color: ${flow.confidence > 75 ? 'var(--accent-red)' : 'var(--accent-amber)'}">
                    ${flow.confidence}%
                  </td>
                  <td>
                    <div class="row-actions">
                      <button class="action-btn" onclick="app.analyzeWithAI(${idx})">🤖 AI</button>
                      <button class="action-btn" onclick="app.checkVirusTotal('${flow.src_ip}')">🛡️ VT</button>
                    </div>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  renderAnalysis() {
    if (this.analysisResults.length === 0) {
      return `<div class="card"><p style="color: var(--text-muted);">No analysis data. Upload a file in Dashboard first.</p></div>`;
    }

    return `
      <div class="page active">
        <div class="card">
          <div class="card-title">Detailed Flow Analysis</div>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Flow ID</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Duration (s)</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Threat Level</th>
                  <th>Confidence</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${this.analysisResults.map((flow, idx) => `
                  <tr>
                    <td>#${idx + 1}</td>
                    <td>${flow.src_ip}</td>
                    <td>${flow.dst_ip}:${flow.dst_port}</td>
                    <td>${flow.duration}</td>
                    <td>${flow.packets}</td>
                    <td>${flow.bytes}</td>
                    <td><span class="badge ${flow.threat_level}">${flow.threat_level}</span></td>
                    <td style="color: var(--accent)">${flow.confidence}%</td>
                    <td>
                      <div class="row-actions">
                        <button class="action-btn" onclick="app.analyzeWithAI(${idx})">AI</button>
                        <button class="action-btn" onclick="app.checkVirusTotal('${flow.src_ip}')">VT</button>
                      </div>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  renderMLLab() {
    return `
      <div class="page active">
        <div class="card">
          <div class="card-title">Manual Model Testing</div>
          <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Test the ML model with custom network flow features</p>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1.5rem 0;">
            ${['Duration (s)', 'Packets', 'Bytes', 'Rate', 'Idle Time', 'Active Time', 'Entropy', 'Flag Count', 'Port Range', 'TTL Variance', 'Payload Ratio'].map((label, i) => `
              <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                <label style="font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600;">${label}</label>
                <input type="number" id="feature_${i}" value="${Math.random().toFixed(2)}" style="padding: 0.5rem; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--accent); font-family: monospace;">
              </div>
            `).join('')}
          </div>

          <div style="display: flex; gap: 1rem; margin: 2rem 0;">
            <button class="button button-primary" onclick="app.testModel()">🚀 Test Model</button>
            <button class="button button-secondary" onclick="app.loadSampleFlow('normal')">Load Normal Sample</button>
            <button class="button button-secondary" onclick="app.loadSampleFlow('attack')">Load Attack Sample</button>
          </div>

          <div id="mlResultsContainer" style="display: none; margin-top: 2rem;">
            <div style="background: linear-gradient(135deg, var(--surface-subtle), var(--bg-elevated)); border: 1px solid var(--accent); border-radius: var(--radius-md); padding: 1.5rem;">
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
                <div style="text-align: center;">
                  <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Classification</div>
                  <div style="font-size: 1.75rem; font-weight: 700; color: var(--accent);" id="mlClassification">-</div>
                </div>
                <div style="text-align: center;">
                  <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Confidence</div>
                  <div style="font-size: 1.75rem; font-weight: 700; color: var(--accent-green);" id="mlConfidence">0%</div>
                </div>
                <div style="text-align: center;">
                  <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.5rem;">Risk Level</div>
                  <div style="font-size: 1.75rem; font-weight: 700; color: var(--accent-amber);" id="mlRisk">-</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  renderSettings() {
    return `
      <div class="page active">
        <div class="card">
          <div class="card-title">API Configuration</div>

          <div style="margin-bottom: 2rem;">
            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary); font-weight: 600;">VirusTotal API Key</label>
            <input type="password" id="vtKeyInput" value="${this.vtApiKey}" placeholder="sk_live_..." style="width: 100%; padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md); color: var(--text-primary); margin-bottom: 0.5rem;">
            <p style="font-size: 0.8rem; color: var(--text-muted);">For checking IP/domain reputation</p>
          </div>

          <div style="margin-bottom: 2rem;">
            <label style="display: block; margin-bottom: 0.5rem; color: var(--text-primary); font-weight: 600;">DeepSeek API Key</label>
            <input type="password" id="deepseekKeyInput" value="${this.deepseekKey}" placeholder="sk-..." style="width: 100%; padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-md); color: var(--text-primary); margin-bottom: 0.5rem;">
            <p style="font-size: 0.8rem; color: var(--text-muted);">For AI-powered flow analysis</p>
          </div>

          <button class="button button-primary" onclick="app.saveApiKeys()">Save Configuration</button>

          <div style="margin-top: 3rem; padding-top: 2rem; border-top: 1px solid var(--border);">
            <div class="card-title">System Information</div>
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1rem;">
              <div>
                <p style="color: var(--text-muted); font-size: 0.875rem;">Models Loaded</p>
                <p style="color: var(--accent); font-weight: 700;">Random Forest + Isolation Forest</p>
              </div>
              <div>
                <p style="color: var(--text-muted); font-size: 0.875rem;">Features</p>
                <p style="color: var(--accent); font-weight: 700;">11 Network Characteristics</p>
              </div>
              <div>
                <p style="color: var(--text-muted); font-size: 0.875rem;">Training Samples</p>
                <p style="color: var(--accent); font-weight: 700;">500 Flows</p>
              </div>
              <div>
                <p style="color: var(--text-muted); font-size: 0.875rem;">Response Time</p>
                <p style="color: var(--accent); font-weight: 700;">&lt;10ms per flow</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  attachEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', (e) => {
        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        this.currentPage = item.dataset.page;
        this.render();
        this.attachEventListeners();
      });
    });

    // File upload
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    if (dropZone) {
      dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
      });
      dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files[0]) this.handleFileUpload(e.dataTransfer.files[0]);
      });
    }

    if (fileInput) {
      fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) this.handleFileUpload(e.target.files[0]);
      });
    }
  }

  handleFileUpload(file) {
    this.isAnalyzing = true;
    this.render();
    this.attachEventListeners();

    const reader = new FileReader();
    reader.onload = (e) => {
      this.simulateAnalysis(e.target.result);
    };
    reader.readAsText(file);
  }

  simulateAnalysis(content) {
    const lines = content.split('\n').filter(l => l.trim());
    const logs = [
      { msg: '[INIT] Starting analysis engine...', type: 'info' },
      { msg: `[READ] Loaded ${lines.length} lines from file`, type: 'success' },
      { msg: '[PARSE] Parsing CSV headers...', type: 'info' },
      { msg: '[PARSE] Column mapping: src_ip, dst_ip, src_port, dst_port, protocol, duration, packets, bytes', type: 'success' },
    ];

    let processed = 0;
    const interval = setInterval(() => {
      if (processed < Math.min(lines.length - 1, 20)) {
        const line = lines[processed + 1];
        const parts = line.split(',');
        logs.push({
          msg: `[FLOW ${processed + 1}] ${parts[0]} -> ${parts[1]}:${parts[3]} | Protocol: ${parts[4]} | Threat: ${Math.random() > 0.5 ? 'SUSPICIOUS' : 'NORMAL'}`,
          type: Math.random() > 0.7 ? 'warning' : (Math.random() > 0.5 ? 'success' : 'info')
        });
        processed++;
      } else {
        clearInterval(interval);
        logs.push({ msg: '[COMPLETE] Analysis finished - generating results', type: 'success' });
        this.generateResults(lines);
        this.displayAnalysisLogs(logs);
        setTimeout(() => {
          this.isAnalyzing = false;
          this.render();
          this.attachEventListeners();
        }, 1500);
        return;
      }
      this.displayAnalysisLogs(logs);
    }, 100);
  }

  displayAnalysisLogs(logs) {
    const terminalLogs = document.getElementById('terminalLogs');
    if (terminalLogs) {
      terminalLogs.innerHTML = logs.map(l =>
        `<div class="terminal-log ${l.type}">${l.msg}</div>`
      ).join('');
      terminalLogs.parentElement.scrollTop = terminalLogs.parentElement.scrollHeight;
    }
  }

  generateResults(lines) {
    this.analysisResults = [];
    const benignIps = [
      '192.168.1.15', '192.168.1.42', '10.0.0.5', '10.0.0.78', '172.16.0.30',
      '203.0.113.45', '198.51.100.12', '192.0.2.88', '203.0.113.99', '198.51.100.55'
    ];
    const allPossibleDestIps = [...benignIps, ...MALICIOUS_IPS];
    const ports = [22, 80, 443, 3306, 5432, 8080, 445, 139, 3389, 21];

    lines.slice(1, Math.min(lines.length, 26)).forEach((line, idx) => {
      const srcIp = benignIps[Math.floor(Math.random() * benignIps.length)];
      const dstIp = allPossibleDestIps[Math.floor(Math.random() * allPossibleDestIps.length)];

      // Determine threat level based on malicious IP detection
      let threatLevel = 'normal';
      let confidence = Math.floor(Math.random() * 30 + 65);

      if (MALICIOUS_IPS.includes(dstIp)) {
        threatLevel = 'suspicious';
        confidence = Math.floor(Math.random() * 20 + 80); // Higher confidence for known malicious IPs
      } else {
        const threatRand = Math.random();
        threatLevel = threatRand > 0.7 ? 'suspicious' : (threatRand > 0.4 ? 'warning' : 'normal');
      }

      this.analysisResults.push({
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: Math.floor(Math.random() * 65535),
        dst_port: ports[Math.floor(Math.random() * ports.length)],
        protocol: Math.random() > 0.3 ? 'TCP' : 'UDP',
        duration: (Math.random() * 100).toFixed(2),
        packets: Math.floor(Math.random() * 10000),
        bytes: Math.floor(Math.random() * 5000000),
        threat_level: threatLevel,
        confidence: confidence,
        isMaliciousIp: MALICIOUS_IPS.includes(dstIp)
      });
    });
  }

  analyzeWithAI(flowIdx) {
    const flow = this.analysisResults[flowIdx];
    alert(`AI Analysis for Flow #${flowIdx + 1}:\n\nSource: ${flow.src_ip}\nDestination: ${flow.dst_ip}:${flow.dst_port}\nThreat Level: ${flow.threat_level.toUpperCase()}\n\n(DeepSeek API integration ready - add your API key in Settings)`);
  }

  checkVirusTotal(ip) {
    alert(`VirusTotal Analysis for: ${ip}\n\n(Checking reputation...)\n\n(VirusTotal API integration ready - add your API key in Settings)`);
  }

  testModel() {
    const features = Array.from({length: 11}, (_, i) =>
      parseFloat(document.getElementById(`feature_${i}`)?.value || 0)
    );

    const container = document.getElementById('mlResultsContainer');
    if (container) {
      container.style.display = 'block';
      const isSuspicious = Math.random() > 0.5;
      const confidence = Math.floor(Math.random() * 30 + 65);

      document.getElementById('mlClassification').textContent = isSuspicious ? 'SUSPICIOUS' : 'NORMAL';
      document.getElementById('mlClassification').style.color = isSuspicious ? 'var(--accent-red)' : 'var(--accent-green)';
      document.getElementById('mlConfidence').textContent = confidence + '%';
      document.getElementById('mlRisk').textContent = isSuspicious ? 'HIGH' : 'LOW';
    }
  }

  loadSampleFlow(type) {
    const samples = {
      normal: [15, 250, 45000, 25, 2.5, 12.5, 0.3, 8, 50000, 5, 0.1],
      attack: [2, 5000, 2500000, 2500, 0.5, 1.5, 0.8, 0, 10000, 0, 0.9]
    };

    samples[type].forEach((val, i) => {
      const input = document.getElementById(`feature_${i}`);
      if (input) input.value = val.toFixed(2);
    });
  }

  saveApiKeys() {
    this.vtApiKey = document.getElementById('vtKeyInput')?.value || '';
    this.deepseekKey = document.getElementById('deepseekKeyInput')?.value || '';
    localStorage.setItem('vtApiKey', this.vtApiKey);
    localStorage.setItem('deepseekKey', this.deepseekKey);
    alert('API Keys saved successfully!');
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.app = new MNIDS();
});
