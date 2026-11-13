const API_BASE = '/api';

let currentBaselines = [];
let currentAlerts = [];

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModal();
  loadStats();
  loadAlerts();
  loadBaselines();

  document.getElementById('triggerScanBtn')?.addEventListener('click', triggerQuickScan);
});

function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const target = tab.dataset.tab === 'alerts' ? 'tabAlerts' : 'tabBaselines';
      document.getElementById(target)?.classList.add('active');
    });
  });
}

function initModal() {
  const modal = document.getElementById('baselineModal');
  const openBtn = document.getElementById('openBaselineModal');
  const closeBtn = document.getElementById('closeBaselineBtn');
  const cancelBtn = document.getElementById('cancelBaselineBtn');
  const form = document.getElementById('createBaselineForm');

  openBtn?.addEventListener('click', () => modal.classList.add('active'));
  closeBtn?.addEventListener('click', () => modal.classList.remove('active'));
  cancelBtn?.addEventListener('click', () => modal.classList.remove('active'));

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('baseName').value.trim();
    const directory_path = document.getElementById('basePath').value.trim();

    try {
      const res = await fetch(`${API_BASE}/baselines`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, directory_path })
      });

      if (!res.ok) throw new Error('Failed to create baseline');
      modal.classList.remove('active');
      form.reset();
      await loadStats();
      await loadBaselines();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  });
}

async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    const data = await res.json();
    document.getElementById('filesMonitored').innerText = `${data.filesMonitored} Files`;
    document.getElementById('activeAlerts').innerText = `${data.activeAlerts} Active`;
    if (data.criticalBreaches > 0) {
      document.getElementById('activeAlerts').className = 'stat-val text-red';
    }
  } catch (err) {
    console.warn('Failed to load stats', err);
  }
}

async function loadAlerts() {
  const tbody = document.getElementById('alertsTableBody');
  try {
    const res = await fetch(`${API_BASE}/alerts`);
    const data = await res.json();
    currentAlerts = data.alerts || [];

    if (currentAlerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 2rem;">No integrity anomalies detected. All monitored files match cryptographic baselines.</td></tr>`;
      return;
    }

    tbody.innerHTML = currentAlerts.map(alt => {
      const sevClass = `badge-${alt.severity.toLowerCase()}`;
      const shortExpected = alt.expected_hash ? alt.expected_hash.slice(0, 10) + '...' : 'NONE';
      const shortActual = alt.actual_hash ? alt.actual_hash.slice(0, 10) + '...' : 'DELETED';
      return `
        <tr>
          <td><span class="badge ${sevClass}">${alt.severity}</span></td>
          <td class="file-path">${escapeHtml(alt.file_path)}</td>
          <td><strong>${alt.change_type}</strong></td>
          <td class="hash-diff">
            <div>Exp: ${shortExpected}</div>
            <div>Act: ${shortActual}</div>
          </td>
          <td>${new Date(alt.detected_at).toLocaleString()}</td>
          <td>
            ${alt.acknowledged ? '<span style="color:var(--text-secondary); font-size:0.75rem;">Resolved</span>' : `<button class="btn btn-ack" onclick="ackAlert('${alt.id}')">Acknowledge</button>`}
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-crimson);">Error loading alerts: ${err.message}</td></tr>`;
  }
}

async function loadBaselines() {
  const container = document.getElementById('baselinesGrid');
  try {
    const res = await fetch(`${API_BASE}/baselines`);
    const data = await res.json();
    currentBaselines = data.baselines || [];

    if (currentBaselines.length === 0) {
      container.innerHTML = `<div style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 3rem;">No baselines created. Click "+ New Baseline" to monitor a directory.</div>`;
      return;
    }

    container.innerHTML = currentBaselines.map(b => `
      <div class="baseline-card">
        <div class="base-header">
          <div class="base-title">${escapeHtml(b.name)}</div>
          <span class="badge badge-medium">Active</span>
        </div>
        <div class="base-dir">${escapeHtml(b.directory_path)}</div>
        <div class="base-meta">
          <span>${b.total_files} Files Monitored</span>
          <span>Created: ${new Date(b.created_at).toLocaleDateString()}</span>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<div style="color: var(--accent-crimson);">Error loading baselines: ${err.message}</div>`;
  }
}

window.ackAlert = async function(alertId) {
  try {
    const res = await fetch(`${API_BASE}/alerts/${alertId}/ack`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to acknowledge alert');
    await loadAlerts();
    await loadStats();
  } catch (err) {
    alert(err.message);
  }
};

async function triggerQuickScan() {
  if (currentBaselines.length === 0) {
    alert('Please create a baseline first.');
    return;
  }
  const firstBase = currentBaselines[0];
  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseline_id: firstBase.id })
    });
    const result = await res.json();
    alert(`Audit Scan Complete!\nScanned: ${result.scanned_files_count} files\nAnomalies Detected: ${result.anomalies_detected}`);
    await loadAlerts();
    await loadStats();
  } catch (err) {
    alert(`Scan failed: ${err.message}`);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
