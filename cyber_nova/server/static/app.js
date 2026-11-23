/**
 * Cyber-Nova SOC Command Center - Frontend Application
 * Real-time WebSocket streaming, interactive Kanban, and Multi-Agent Mesh
 */

// Application State
const state = {
  socket: null,
  currentSnapshot: null,
  activeFilter: 'all',
  activeRuleTab: 'waf',
  autoScroll: true,
  isRunning: false,
};

// DOM References
const elements = {
  incId: document.getElementById('inc-id-display'),
  incSeverity: document.getElementById('inc-severity-display'),
  incStatus: document.getElementById('inc-status-display'),
  scenarioSelect: document.getElementById('scenario-select'),
  btnRun: document.getElementById('btn-run'),
  btnStep: document.getElementById('btn-step'),
  btnStop: document.getElementById('btn-stop'),
  btnReset: document.getElementById('btn-reset'),
  btnCustomModal: document.getElementById('btn-custom-modal'),

  // Nodes & Mesh
  nodeSentinel: document.getElementById('node-sentinel'),
  nodeInvestigator: document.getElementById('node-investigator'),
  nodeRemediation: document.getElementById('node-remediation'),
  nodeAuditor: document.getElementById('node-auditor'),
  pulseDot: document.getElementById('pulse-dot'),

  // Telemetry & IOCs
  telemetryLogs: document.getElementById('telemetry-logs-list'),
  iocTableBody: document.getElementById('ioc-table-body'),
  iocCounter: document.getElementById('ioc-counter'),
  vulnCountBadge: document.getElementById('vuln-count-badge'),
  vulnCardsList: document.getElementById('vuln-cards-list'),

  // Kanban
  tasksTodo: document.getElementById('tasks-todo'),
  tasksProgress: document.getElementById('tasks-progress'),
  tasksVerifying: document.getElementById('tasks-verifying'),
  tasksDone: document.getElementById('tasks-done'),
  countTodo: document.getElementById('count-todo'),
  countProgress: document.getElementById('count-progress'),
  countVerifying: document.getElementById('count-verifying'),
  countDone: document.getElementById('count-done'),
  kanbanDoneCount: document.getElementById('kanban-done-count'),
  kanbanTotalCount: document.getElementById('kanban-total-count'),

  // Terminal
  terminalFeed: document.getElementById('terminal-feed'),
  terminalStats: document.getElementById('terminal-stats'),
  autoScrollToggle: document.getElementById('auto-scroll-toggle'),

  // Diff
  diffTargetFile: document.getElementById('diff-target-file'),
  diffAuthor: document.getElementById('diff-author'),
  diffExplanation: document.getElementById('diff-explanation'),
  diffCodeView: document.getElementById('diff-code-view'),

  // Sandbox
  sandboxVerdict: document.getElementById('sandbox-verdict'),
  valExploitBlocked: document.getElementById('val-exploit-blocked'),
  valRegressionPassed: document.getElementById('val-regression-passed'),
  valExecTime: document.getElementById('val-exec-time'),
  sandboxLogs: document.getElementById('sandbox-logs'),

  // Rules
  ruleContent: document.getElementById('rule-content'),
  btnCopyRule: document.getElementById('btn-copy-rule'),

  // Compliance
  execSummaryText: document.getElementById('exec-summary-text'),
  techPostmortemText: document.getElementById('tech-postmortem-text'),
  actionItemsList: document.getElementById('action-items-list'),
  complianceCards: document.getElementById('compliance-cards'),
  auditorSealHash: document.getElementById('auditor-seal-hash'),
  auditorSealTime: document.getElementById('auditor-seal-time'),

  // Modal
  customModal: document.getElementById('custom-modal'),
  modalClose: document.getElementById('modal-close'),
  modalCancel: document.getElementById('modal-cancel'),
  modalSubmit: document.getElementById('modal-submit'),
  customTitle: document.getElementById('custom-title'),
  customFileName: document.getElementById('custom-file-name'),
  customCode: document.getElementById('custom-code'),
  customLogs: document.getElementById('custom-logs'),
};

// WebSocket Connection
function connectWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  state.socket = new WebSocket(wsUrl);

  state.socket.onopen = () => {
    logTerminalEntry('SYSTEM', 'Connected to Cyber-Nova Event Stream via WebSocket', 'system');
  };

  state.socket.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'snapshot') {
        renderSnapshot(msg.payload);
      } else if (msg.type === 'event') {
        handleRealtimeEvent(msg.payload);
      }
    } catch (e) {
      console.error('WebSocket parse error:', e);
    }
  };

  state.socket.onclose = () => {
    logTerminalEntry('SYSTEM', 'WebSocket disconnected. Reconnecting in 2s...', 'system');
    setTimeout(connectWebSocket, 2000);
  };
}

// Handle Real-Time Event Stream
function handleRealtimeEvent(event) {
  const type = event.type;
  const data = event.data;

  // Refresh full state whenever status or task changes
  if (['task_created', 'task_updated', 'status_changed', 'scenario_loaded', 'reset', 'custom_loaded'].includes(type)) {
    fetchSnapshot();
  }

  if (type === 'message_posted') {
    appendTerminalMessage(data);
    if (data.msg_type === 'HANDOFF') {
      animateHandoffPulse(data.sender, data.recipient);
    }
  } else if (type === 'agent_state_changed') {
    updateAgentNodeState(data.role, data.status);
  } else if (type === 'tool_executed') {
    logTerminalEntry(data.agent_name, `[TOOL] Executed ${data.tool_name} in ${data.duration_ms}ms`, 'tool');
  } else if (type === 'status_changed') {
    elements.incStatus.textContent = data.to;
    elements.incStatus.className = `badge-status status-${data.to.toLowerCase()}`;
    if (['RESOLVED', 'FAILED'].includes(data.to)) {
      setRunningState(false);
    }
  }
}

// Fetch Full State Snapshot from REST API
async function fetchSnapshot() {
  try {
    const res = await fetch('/api/incident/state');
    const data = await res.json();
    renderSnapshot(data);
  } catch (e) {
    console.error('Failed to fetch snapshot:', e);
  }
}

// Render Full Snapshot to DOM
function renderSnapshot(snapshot) {
  state.currentSnapshot = snapshot;
  const inc = snapshot.incident;

  // 1. Header Info
  elements.incId.textContent = inc.id;
  elements.incSeverity.textContent = inc.severity;
  elements.incSeverity.className = `badge-severity severity-${inc.severity.toLowerCase()}`;
  elements.incStatus.textContent = inc.status;
  elements.incStatus.className = `badge-status status-${inc.status.toLowerCase()}`;

  // 2. Telemetry Logs
  elements.telemetryLogs.textContent = inc.telemetry_logs.join('\n');

  // 3. IOCs Table
  renderIOCTable(inc.iocs || []);

  // 4. Vulnerabilities
  renderVulnerabilities(inc.vulnerabilities || []);

  // 5. Kanban Tasks
  renderKanbanTasks(inc.tasks || {});

  // 6. Patch Diff
  renderPatchDiff(inc.patches || []);

  // 7. Sandbox Verification
  renderSandboxVerification(inc.verification);

  // 8. Defense Rules
  renderDefenseRules(inc.defense_rules || []);

  // 9. Compliance & Audit
  renderCompliance(inc.audit_report);

  // 10. Agent active states derived from tasks
  deriveAgentStatesFromTasks(inc.tasks || {});
}

// Render IOC Table
function renderIOCTable(iocs) {
  elements.iocCounter.textContent = `${iocs.length} IOCs`;
  if (iocs.length === 0) {
    elements.iocTableBody.innerHTML = '<tr><td colspan="4" class="empty-state">No IOCs extracted yet.</td></tr>';
    return;
  }
  elements.iocTableBody.innerHTML = iocs.map(ioc => `
    <tr>
      <td><span class="badge-mini">${escapeHtml(ioc.ioc_type)}</span></td>
      <td><code>${escapeHtml(ioc.value)}</code></td>
      <td><span style="color:${ioc.reputation_score >= 0.8 ? '#ff3366' : '#ffb800'}">${(ioc.reputation_score * 100).toFixed(0)}% Malicious</span></td>
      <td style="color:#94a3b8">${escapeHtml(ioc.context)}</td>
    </tr>
  `).join('');
}

// Render Vulnerabilities List
function renderVulnerabilities(vulns) {
  elements.vulnCountBadge.textContent = vulns.length;
  if (vulns.length === 0) {
    elements.vulnCardsList.innerHTML = '<div class="empty-state">Awaiting forensic code analysis...</div>';
    return;
  }
  elements.vulnCardsList.innerHTML = vulns.map(v => `
    <div class="vuln-item-card">
      <div class="vuln-item-header">
        <span class="vuln-item-title">${escapeHtml(v.name)} (${escapeHtml(v.cwe_id)})</span>
        <span class="vuln-item-score">CVSS ${v.cvss_score}</span>
      </div>
      <div style="font-size:0.65rem; color:#94a3b8; font-family:var(--font-mono)">
        ${escapeHtml(v.file_path)}:${v.line_number}
      </div>
    </div>
  `).join('');
}

// Render Kanban Tasks
function renderKanbanTasks(tasksMap) {
  const tasks = Object.values(tasksMap);
  const cols = {
    TODO: [],
    IN_PROGRESS: [],
    VERIFYING: [],
    DONE: []
  };

  tasks.forEach(t => {
    if (cols[t.status]) cols[t.status].push(t);
  });

  elements.countTodo.textContent = cols.TODO.length;
  elements.countProgress.textContent = cols.IN_PROGRESS.length;
  elements.countVerifying.textContent = cols.VERIFYING.length;
  elements.countDone.textContent = cols.DONE.length;

  elements.kanbanDoneCount.textContent = cols.DONE.length;
  elements.kanbanTotalCount.textContent = tasks.length;

  elements.tasksTodo.innerHTML = renderTaskCards(cols.TODO);
  elements.tasksProgress.innerHTML = renderTaskCards(cols.IN_PROGRESS);
  elements.tasksVerifying.innerHTML = renderTaskCards(cols.VERIFYING);
  elements.tasksDone.innerHTML = renderTaskCards(cols.DONE);
}

function renderTaskCards(tasks) {
  if (tasks.length === 0) return '<div class="empty-state" style="padding:10px 0">No tasks</div>';
  return tasks.map(t => `
    <div class="task-card">
      <div class="task-card-header">
        <span class="task-id">${escapeHtml(t.id)}</span>
        <span class="task-agent-badge">${escapeHtml(t.assigned_to)}</span>
      </div>
      <div class="task-title">${escapeHtml(t.title)}</div>
      ${t.result_summary ? `<div class="task-summary">${escapeHtml(t.result_summary)}</div>` : ''}
    </div>
  `).join('');
}

// Render Patch Diff
function renderPatchDiff(patches) {
  if (!patches || patches.length === 0) {
    elements.diffTargetFile.textContent = '--';
    elements.diffAuthor.textContent = '--';
    elements.diffExplanation.textContent = 'Awaiting patch synthesis by RemediationAgent...';
    elements.diffCodeView.innerHTML = '<code class="diff-code"># Patch diff will appear here.</code>';
    return;
  }

  const p = patches[patches.length - 1];
  elements.diffTargetFile.textContent = p.target_file;
  elements.diffAuthor.textContent = p.author_agent;
  elements.diffExplanation.textContent = p.explanation;

  // Format diff lines
  const lines = p.diff.split('\n');
  const formattedLines = lines.map(line => {
    const escaped = escapeHtml(line);
    if (line.startsWith('+') && !line.startsWith('+++')) {
      return `<div class="diff-line-add">${escaped}</div>`;
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      return `<div class="diff-line-del">${escaped}</div>`;
    }
    return `<div>${escaped}</div>`;
  }).join('');

  elements.diffCodeView.innerHTML = formattedLines;
}

// Render Sandbox Verification
function renderSandboxVerification(verif) {
  if (!verif) {
    elements.sandboxVerdict.textContent = 'PENDING EXECUTION';
    elements.sandboxVerdict.className = 'sandbox-verdict';
    elements.valExploitBlocked.textContent = '--';
    elements.valRegressionPassed.textContent = '--';
    elements.valExecTime.textContent = '-- ms';
    elements.sandboxLogs.textContent = 'Awaiting automated verification run in isolated sandbox...';
    return;
  }

  elements.sandboxVerdict.textContent = verif.success ? 'VERIFICATION PASSED (100% SECURE)' : 'VERIFICATION FAILED';
  elements.sandboxVerdict.className = `sandbox-verdict ${verif.success ? 'passed' : 'failed'}`;
  elements.valExploitBlocked.textContent = verif.exploit_blocked ? 'YES (Mitigated)' : 'NO (Vulnerable)';
  elements.valExploitBlocked.style.color = verif.exploit_blocked ? '#00ff88' : '#ff3366';
  elements.valRegressionPassed.textContent = verif.regression_tests_passed ? 'PASSED (Zero Regressions)' : 'FAILED';
  elements.valRegressionPassed.style.color = verif.regression_tests_passed ? '#00ff88' : '#ff3366';
  elements.valExecTime.textContent = `${verif.execution_time_ms} ms`;
  elements.sandboxLogs.textContent = verif.logs.join('\n');
}

// Render Defense Rules
function renderDefenseRules(rules) {
  if (!rules || rules.length === 0) {
    elements.ruleContent.textContent = 'Awaiting rule generation by RemediationAgent...';
    return;
  }

  const targetType = state.activeRuleTab.toUpperCase();
  const rule = rules.find(r => r.rule_type === targetType) || rules[0];
  elements.ruleContent.textContent = rule ? rule.rule_content : 'Rule not available';
}

// Render Compliance & Audit
function renderCompliance(auditReport) {
  if (!auditReport) {
    elements.execSummaryText.textContent = 'Awaiting formal audit completion by Auditor-04...';
    elements.techPostmortemText.textContent = '--';
    elements.actionItemsList.innerHTML = '<li>Awaiting auditor sign-off.</li>';
    elements.auditorSealHash.textContent = 'NOT SIGNED YET';
    elements.auditorSealTime.textContent = '--';
    return;
  }

  elements.execSummaryText.textContent = auditReport.executive_summary;
  elements.techPostmortemText.innerHTML = escapeHtml(auditReport.technical_postmortem).replace(/\n/g, '<br>');

  elements.actionItemsList.innerHTML = auditReport.recommended_actions.map(a => `<li>${escapeHtml(a)}</li>`).join('');

  elements.complianceCards.innerHTML = Object.entries(auditReport.compliance_status).map(([fw, status]) => `
    <div class="framework-card">
      <span class="fw-title">${escapeHtml(fw)}</span>
      <span class="fw-status compliant">${escapeHtml(status)}</span>
    </div>
  `).join('');

  elements.auditorSealHash.textContent = auditReport.auditor_signature;
  elements.auditorSealTime.textContent = new Date(auditReport.signoff_timestamp * 1000).toUTCString();
}

// Derive Agent States
function deriveAgentStatesFromTasks(tasksMap) {
  const tasks = Object.values(tasksMap);
  const roles = ['sentinel', 'investigator', 'remediation', 'auditor'];

  roles.forEach(role => {
    const roleTasks = tasks.filter(t => t.assigned_to === role);
    let st = 'IDLE';
    if (roleTasks.some(t => t.status === 'IN_PROGRESS' || t.status === 'VERIFYING')) {
      st = 'ANALYZING';
    } else if (roleTasks.length > 0 && roleTasks.every(t => t.status === 'DONE')) {
      st = 'COMPLETE';
    }
    updateAgentNodeState(role, st);
  });
}

function updateAgentNodeState(role, status) {
  const el = document.getElementById(`node-${role}`);
  const statusEl = document.getElementById(`${role}-status`);
  if (!el || !statusEl) return;

  statusEl.textContent = status;
  statusEl.className = `node-status status-${status.toLowerCase()}`;

  if (['ANALYZING', 'EXECUTING_TOOL', 'COLLABORATING'].includes(status)) {
    el.classList.add('active-agent');
  } else {
    el.classList.remove('active-agent');
  }
}

// Animate Handoff Pulse
function animateHandoffPulse(sender, recipient) {
  const dot = elements.pulseDot;
  if (!dot) return;

  dot.classList.remove('hidden');
  dot.style.animation = 'none';
  dot.offsetHeight; // trigger reflow
  dot.style.animation = 'pulse-travel 1s ease-in-out forwards';

  setTimeout(() => {
    dot.classList.add('hidden');
  }, 1000);
}

// Append Terminal Message
function appendTerminalMessage(msg) {
  const senderClass = `term-sender-${msg.sender.toLowerCase().split('-')[0]}`;
  const timeStr = new Date(msg.timestamp * 1000).toLocaleTimeString();

  const entry = document.createElement('div');
  entry.className = 'term-entry';
  entry.dataset.sender = msg.sender.toLowerCase();

  entry.innerHTML = `
    <span class="term-time">[${timeStr}]</span>
    <span class="term-sender ${senderClass}">${escapeHtml(msg.sender)}</span>
    <span class="term-type type-${msg.msg_type.toLowerCase()}">${escapeHtml(msg.msg_type)}</span>
    <span class="term-body">${escapeHtml(msg.content)}</span>
  `;

  elements.terminalFeed.appendChild(entry);
  applyTerminalFilter();

  if (elements.autoScrollToggle.checked) {
    elements.terminalFeed.scrollTop = elements.terminalFeed.scrollHeight;
  }

  const count = elements.terminalFeed.querySelectorAll('.term-entry').length;
  elements.terminalStats.textContent = `${count} log entries`;
}

function logTerminalEntry(sender, text, type = 'thought') {
  appendTerminalMessage({
    sender: sender,
    msg_type: type.toUpperCase(),
    content: text,
    timestamp: Date.now() / 1000
  });
}

function applyTerminalFilter() {
  const filter = state.activeFilter;
  const entries = elements.terminalFeed.querySelectorAll('.term-entry');
  entries.forEach(entry => {
    if (filter === 'all' || (entry.dataset.sender && entry.dataset.sender.includes(filter))) {
      entry.style.display = 'flex';
    } else {
      entry.style.display = 'none';
    }
  });
}

function setRunningState(running) {
  state.isRunning = running;
  elements.btnRun.disabled = running;
  elements.btnStep.disabled = running;
  elements.btnStop.disabled = !running;
  if (running) {
    elements.btnRun.innerHTML = '<span class="icon">⏳</span> Running Swarm...';
  } else {
    elements.btnRun.innerHTML = '<span class="icon">▶</span> Run Swarm';
  }
}

// Setup Event Listeners
function setupEventListeners() {
  // Scenario select
  elements.scenarioSelect.addEventListener('change', async (e) => {
    const key = e.target.value;
    try {
      await fetch('/api/incident/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_key: key })
      });
      elements.terminalFeed.innerHTML = '';
      logTerminalEntry('SYSTEM', `Loaded scenario '${key}'`, 'system');
    } catch (err) {
      console.error(err);
    }
  });

  // Run Swarm button
  elements.btnRun.addEventListener('click', async () => {
    setRunningState(true);
    try {
      await fetch('/api/incident/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ delay: 0.8 })
      });
    } catch (e) {
      setRunningState(false);
    }
  });

  // Step Next button
  elements.btnStep.addEventListener('click', async () => {
    try {
      await fetch('/api/incident/step', { method: 'POST' });
    } catch (e) {
      console.error(e);
    }
  });

  // Stop button
  elements.btnStop.addEventListener('click', async () => {
    try {
      await fetch('/api/incident/stop', { method: 'POST' });
      setRunningState(false);
    } catch (e) {
      console.error(e);
    }
  });

  // Reset button
  elements.btnReset.addEventListener('click', async () => {
    try {
      await fetch('/api/incident/reset', { method: 'POST' });
      elements.terminalFeed.innerHTML = '';
      setRunningState(false);
    } catch (e) {
      console.error(e);
    }
  });

  // Workspace Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const tabId = btn.dataset.tab;
      const pane = document.getElementById(`pane-${tabId}`);
      if (pane) pane.classList.add('active');
    });
  });

  // Telemetry Subtabs
  document.querySelectorAll('.subtab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.subtab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const subtabId = btn.dataset.subtab;
      const content = document.getElementById(`subtab-${subtabId}`);
      if (content) content.classList.add('active');
    });
  });

  // Defense Rule Subtabs
  document.querySelectorAll('.rule-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.rule-tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.activeRuleTab = btn.dataset.rule;
      if (state.currentSnapshot) {
        renderDefenseRules(state.currentSnapshot.incident.defense_rules);
      }
    });
  });

  // Copy Rule
  elements.btnCopyRule.addEventListener('click', () => {
    const text = elements.ruleContent.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const orig = elements.btnCopyRule.textContent;
      elements.btnCopyRule.textContent = 'Copied!';
      setTimeout(() => elements.btnCopyRule.textContent = orig, 1500);
    });
  });

  // Terminal Filters
  document.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      state.activeFilter = chip.dataset.filter;
      applyTerminalFilter();
    });
  });

  // Custom Target Modal
  elements.btnCustomModal.addEventListener('click', () => {
    elements.customModal.classList.remove('hidden');
  });

  elements.modalClose.addEventListener('click', () => {
    elements.customModal.classList.add('hidden');
  });

  elements.modalCancel.addEventListener('click', () => {
    elements.customModal.classList.add('hidden');
  });

  elements.modalSubmit.addEventListener('click', async () => {
    const title = elements.customTitle.value.trim();
    const fileName = elements.customFileName.value.trim();
    const code = elements.customCode.value;
    const logs = elements.customLogs.value.split('\n').filter(l => l.trim().length > 0);

    try {
      await fetch('/api/incident/custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: `INC-CUSTOM-${Date.now().toString().slice(-4)}`,
          title: title,
          file_name: fileName,
          code: code,
          logs: logs
        })
      });
      elements.customModal.classList.add('hidden');
      elements.terminalFeed.innerHTML = '';
      logTerminalEntry('SYSTEM', `Loaded custom target: ${title}`, 'system');
    } catch (e) {
      console.error('Failed to load custom target:', e);
    }
  });
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Initialize on Load
window.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  connectWebSocket();
  fetchSnapshot();
});
