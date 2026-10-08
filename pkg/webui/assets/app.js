
const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));
const el = (tag, attrs = {}, children = []) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) e.setAttribute(k, v);
  }
  for (const c of [].concat(children)) {
    if (c == null) continue;
    if (typeof c === 'string') e.appendChild(document.createTextNode(c));
    else e.appendChild(c);
  }
  return e;
};

const STATE = {
  findings: [],
  summary: null,
  metadata: null,
  graph: null,
  currentScanId: null,
  es: null,
  view: 'grouped', 
  config: { allowLiveExploit: false, allowSidecarInjection: false },
  capabilityCache: new Map(), 
  q: '',                
  _expandAll: false,    
};

fetch('/api/config').then(r => r.json()).then(c => {
  STATE.config = c || STATE.config;
}).catch(() => {});

const EXCLUSION_FILE_MAX_BYTES = 1024 * 1024;

async function readExclusionFile(file) {
  if (!file) return { ok: false, message: 'no file selected' };
  if (file.size === 0) return { ok: false, message: `"${file.name}" is empty` };
  if (file.size > EXCLUSION_FILE_MAX_BYTES) {
    return { ok: false, message: `"${file.name}" is ${Math.round(file.size / 1024)} KB — maximum is 1 MB` };
  }
  const text = await file.text();
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(text)) {
    return { ok: false, message: `"${file.name}" is not a text YAML/JSON file` };
  }
  if (!text.trim()) return { ok: false, message: `"${file.name}" contains no rules` };
  return { ok: true, text, message: `loaded ${file.name} (${text.length} bytes)` };
}

document.addEventListener('DOMContentLoaded', () => {
  const uploadBtn = document.getElementById('f-excl-upload');
  const filePicker = document.getElementById('f-excl-file');
  const status = document.getElementById('f-excl-status');
  const box = document.getElementById('f-exclusions');
  if (uploadBtn && filePicker) {
    uploadBtn.addEventListener('click', () => filePicker.click());
    filePicker.addEventListener('change', async () => {
      const result = await readExclusionFile(filePicker.files[0]);
      if (status) status.textContent = result.message;
      if (!result.ok) return;
      if (box) box.value = result.text;
      renderScanPlan();
    });
  }
});

function activateTab(btn) {
  $$('.tab').forEach(b => {
    b.classList.toggle('active', b === btn);
    if (b === btn) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  const tab = btn.dataset.tab;
  const subpage = btn.getAttribute('for');
  if (subpage) document.getElementById(subpage).checked = true;
  $$('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + tab));
  $$('.help-popover:popover-open').forEach(p => p.hidePopover());
  if (tab === 'history') loadHistory();
  if (tab === 'global') loadGlobal();
}

$$('.tab').forEach(btn => {
  btn.addEventListener('click', () => activateTab(btn));
});

function readScanPlan() {
  const mode = $('#f-mode').value;
  const level = $('#f-level').value;
  const modeLabels = { discover: 'Discover', scan: 'Scan', exploit: 'Exploit', chain: 'Chain' };
  const levelLabels = { safe: 'Safe', 'read-only': 'Read-only', intrusive: 'Intrusive (dry-run)' };
  const descriptions = {
    discover: 'Map the resources and actions reachable by the selected identity.',
    scan: 'Collect resources and identify configuration risks.',
    chain: 'Active escalation: may create test pods, inject debug containers and execute in pods.',
    exploit: level === 'safe' ? 'Verify findings with authorization checks only.' :
      level === 'intrusive' ? 'Verify findings, including server-side dry-run tests.' :
        'GET/LIST verification may read secrets and tokens.',
  };
  const modules = [
    ['#f-trivy', 'Trivy'], ['#f-nuclei', 'Nuclei'],
    ['#f-stealth', 'Stealth / Evasion'], ['#f-runtime', 'Runtime extras'],
    ['#f-cni', 'CNI intelligence'],
  ].filter(([selector]) => $(selector).checked).map(([, label]) => label);
  const guard = mode === 'chain' || !$('#f-no-guard').checked;
  return {
    context: $('#f-context').value || 'Not selected',
    namespace: $('#f-ns').value.trim() || 'All permitted namespaces',
    mode: modeLabels[mode] || mode,
    level: mode === 'chain' ? 'Active chain' : mode === 'exploit' ? levelLabels[level] || level : 'Not used',
    profile: $('#f-profile').value === 'internal' ? 'Internal trust' : 'External',
    guard,
    guardLabel: mode === 'chain' ? 'On (required)' : guard ? 'On' : 'Off',
    activity: descriptions[mode] || '',
    intrusive: mode === 'chain' || mode === 'exploit' && level === 'intrusive',
    modules: modules.length ? modules.join(', ') : 'None enabled',
    exclusions: $('#f-exclusions').value.trim()
      ? (mode === 'chain' ? 'Configured (not applied in chain mode)' : 'Configured')
      : 'None',
  };
}

function renderScanPlan() {
  const plan = readScanPlan();
  ['context', 'namespace', 'mode', 'level', 'profile', 'modules', 'exclusions'].forEach(key => {
    const node = $('#plan-' + key);
    if (node) node.textContent = plan[key];
  });
  const guard = $('#plan-guard');
  if (guard) {
    guard.textContent = plan.guardLabel;
    guard.classList.toggle('plan-guard-on', plan.guard);
    guard.classList.toggle('plan-guard-off', !plan.guard);
  }
  const activity = $('#plan-activity');
  if (activity) {
    activity.textContent = plan.activity;
    activity.classList.toggle('intrusive', plan.intrusive);
  }
  $('#f-guard').checked = plan.guard;
  const label = $('#guard-label');
  if (label) label.textContent = plan.guard ? 'Safety guard enabled' : 'Safety guard disabled';
}

function helpPopoverPosition(anchor, popup, width, height) {
  const gap = 10;
  const margin = 12;
  let left = anchor.right + gap;
  if (left + popup.width > width - margin) left = anchor.left - popup.width - gap;
  left = Math.max(margin, Math.min(left, width - popup.width - margin));
  const top = Math.max(margin, Math.min(anchor.top - 6, height - popup.height - margin));
  return { left, top };
}

function initFieldHelp() {
  let current = null;
  const position = () => {
    if (!current || !current.popup.matches(':popover-open')) return;
    const coords = helpPopoverPosition(current.button.getBoundingClientRect(),
      current.popup.getBoundingClientRect(), window.innerWidth, window.innerHeight);
    current.popup.style.left = coords.left + 'px';
    current.popup.style.top = coords.top + 'px';
  };
  $$('.field-help').forEach(button => {
    const popup = document.getElementById(button.getAttribute('popovertarget'));
    if (!popup) return;
    popup.addEventListener('beforetoggle', event => {
      const opening = event.newState === 'open';
      button.setAttribute('aria-expanded', String(opening));
      if (opening) {
        current = { button, popup };
        requestAnimationFrame(position);
      } else if (current?.popup === popup) {
        current = null;
      }
    });
  });
  window.addEventListener('resize', position);
  document.addEventListener('scroll', position, true);
}

['input', 'change'].forEach(event => {
  document.addEventListener(event, ev => {
    if (ev.target.id?.startsWith('f-')) renderScanPlan();
  });
});
initFieldHelp();
renderScanPlan();

document.addEventListener('click', ev => {
  if (!ev.target.classList.contains('view-btn')) return;
  $$('.view-btn').forEach(b => b.classList.toggle('active', b === ev.target));
  STATE.view = ev.target.dataset.view;
  renderFindings();
});

document.addEventListener('click', ev => {
  if (ev.target && ev.target.id === 'ns-expand-all') {
    STATE._expandAll = true;
    document.querySelectorAll('#findings .tree-group.level-ns').forEach(g => g.classList.add('open'));
  } else if (ev.target && ev.target.id === 'ns-collapse-all') {
    STATE._expandAll = false;
    document.querySelectorAll('#findings .tree-group.level-ns').forEach(g => g.classList.remove('open'));
  }
});

$('#f-no-guard').addEventListener('change', ev => {
  if (ev.target.checked) {
    if (!confirm('Disabling the safety guard means Kube-Dementor CAN issue DELETE / PATCH / UPDATE calls against this cluster.\n\nYou should only turn this off against a throw-away lab cluster.\n\nProceed?')) {
      ev.target.checked = false;
    }
  }
});

async function init() {
  try {
    const r = await fetch('/api/contexts');
    const d = await r.json();
    const sel = $('#f-context');
    sel.innerHTML = '';
    (d.contexts || []).forEach(c => {
      const opt = el('option', { value: c }, c);
      if (c === d.current) opt.selected = true;
      sel.appendChild(opt);
    });
    if (!d.contexts?.length) {
      sel.appendChild(el('option', { value: '' }, 'No contexts found — check your kubeconfig'));
    }
  } catch (e) {
    $('#run-status').textContent = 'failed to load contexts: ' + e.message;
  }
  renderScanPlan();
}
init();

$('#run-btn').addEventListener('click', async () => {
  const btn = $('#run-btn');
  const body = {
    context: $('#f-context').value,
    namespace: $('#f-ns').value.trim(),
    mode: $('#f-mode').value,
    level: $('#f-level').value,
    minSeverity: '',
    hideFalsePositives: $('#f-hide-fp').checked,
    enableTrivy: $('#f-trivy').checked,
    enableNuclei: $('#f-nuclei').checked,
    disableSafetyGuard: $('#f-no-guard').checked,
    enableStealth:       $('#f-stealth') ? $('#f-stealth').checked : false,
    enableRuntimeExtras: $('#f-runtime') ? $('#f-runtime').checked : false,
    enableCNIExtras:     $('#f-cni')     ? $('#f-cni').checked     : false,
    exclusionYaml:       ($('#f-exclusions') && $('#f-exclusions').value) || '',
    refreshThreatIntel:  $('#f-refresh-intel') ? $('#f-refresh-intel').checked : true,
    profile:             $('#f-profile') ? $('#f-profile').value : 'external',
  };
  if (!body.context) { alert('Please choose a context.'); return; }
  btn.disabled = true;
  $('#run-status').innerHTML = '<span class="spinner"></span>running…';
  $('#live-card').hidden = false;
  $('#live-log').textContent = '';
  $('#result-card').hidden = true;
  if ($('#graph-card')) $('#graph-card').hidden = true;
  if ($('#paths-card')) $('#paths-card').hidden = true;
  document.getElementById('chain-banner')?.remove();
  
  const pBody = document.getElementById('paths-body');
  if (pBody) {
    delete pBody.dataset.userInteracted;
    if (pBody.dataset && pBody.dataset.showAll) delete pBody.dataset.showAll;
  }

  try {
    const r = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'failed to start scan');
    STATE.currentScanId = d.id;
    openLogStream(d.id);
  } catch (e) {
    btn.disabled = false;
    $('#run-status').textContent = 'error: ' + e.message;
  }
});

function openLogStream(id) {
  if (STATE.es) STATE.es.close();
  const es = new EventSource(`/api/scans/${id}/events`);
  STATE.es = es;
  es.addEventListener('log', ev => {
    const log = $('#live-log');
    log.textContent += ev.data + '\n';
    log.scrollTop = log.scrollHeight;
  });
  es.addEventListener('done', async () => {
    es.close(); STATE.es = null;
    $('#run-status').textContent = 'scan finished.';
    $('#run-btn').disabled = false;
    await loadScanResult(id);
  });
  es.onerror = () => {
    es.close(); STATE.es = null; $('#run-btn').disabled = false;
    $('#run-status').textContent = 'log stream lost (server restarted or connection dropped) — check History for this scan.';
  };
}

async function loadScanResult(id) {
  try {
    const r = await fetch(`/api/scans/${id}`);
    const d = await r.json();
    if (d.status !== 'completed' || !d.report) {
      const reason = d.status === 'running'
        ? `scan ${id} is still running — reopen it from History when it finishes.`
        : `scan ended with status: ${d.status}${d.error ? ' (' + d.error + ')' : ''}`;
      $('#run-status').textContent = reason;
      return;
    }
    STATE.findings = (d.report.findings || []).map(finding => {
      if (finding.ruleId !== 'KH-CHAIN-SHELL' || finding.shell?.verified) return finding;
      return { ...finding, exploit: null,
        title: `Unverified legacy shell target: ${finding.resource?.name || 'unknown'}`,
        description: 'The older server advertised this target without pod-specific exec proof. Its shell and compromise claims are not trusted.' };
    });
    STATE.accepted = d.report.acceptedFindings || [];
    STATE.summary = d.report.summary;
    STATE.metadata = d.report.metadata;
    STATE.identity = d.report.identity || {};
    STATE.graph   = d.report.graph || legacyChainGraph(d.report);
    
    
    
    const initialSev = ($('#f-sev') && $('#f-sev').value) || '';
    if ($('#fi-sev')) {
      $('#fi-sev').value = initialSev;
    }
    renderSummary(d.report);
    renderSafetyChip(d.report.metadata);
    renderIdentityBanner(d.report.identity);
    populateCategoryFilter();
    renderFindings();
    renderAccepted();
    renderThreatIntelStatus(d.report.metadata);
    renderAttackGraph();
    renderVisualGraph();
    renderChainBanner(id, d.report);
    $('#result-card').hidden = false;
    const target = $('#result-card');
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (e) {
    $('#run-status').textContent = 'failed to load result: ' + e.message;
  }
}

function renderSummary(report) {
  const s = report.summary;
  const meta = report.metadata;
  const id = report.identity || {};
  const host = el('div');
  const row = el('div', { class: 'summary' });
  const stats = [
    ['CRITICAL', s.bySeverity?.CRITICAL || 0, 'Critical'],
    ['HIGH', s.bySeverity?.HIGH || 0, 'High'],
    ['MEDIUM', s.bySeverity?.MEDIUM || 0, 'Medium'],
    ['LOW', s.bySeverity?.LOW || 0, 'Low'],
    ['INFO', s.bySeverity?.INFO || 0, 'Info'],
    ['EXPLOIT', Math.max(0, (s.exploited || 0) -
      (report.findings || []).filter(f => f.ruleId === 'KH-CHAIN-SHELL' && !f.shell?.verified && f.exploit?.exploited).length), 'Exploited'],
    ['SCORE', (s.riskScore || 0) + '/100', 'Risk score'],
  ];
  for (const [cls, v, label] of stats) {
    row.appendChild(el('div', { class: 'stat ' + cls }, [
      el('div', { class: 'label' }, label),
      el('div', { class: 'value' }, String(v)),
    ]));
  }
  host.appendChild(row);

  const met = el('div', { class: 'kv', style: 'margin-bottom:8px;' });
  met.appendChild(el('b', {}, 'Cluster'));
  met.appendChild(el('div', {}, `${meta.clusterName || '-'}`));
  met.appendChild(el('b', {}, 'Context'));
  met.appendChild(el('div', {}, meta.contextName || '-'));
  met.appendChild(el('b', {}, 'Server / version'));
  met.appendChild(el('div', {}, `${meta.clusterServer || '-'} — ${meta.serverVersion || '?'}`));
  met.appendChild(el('b', {}, 'Identity'));
  met.appendChild(el('div', {}, (meta.user || '-') + (id.isClusterAdmin ? '  (cluster-admin)' : '')));
  met.appendChild(el('b', {}, 'Mode / duration'));
  met.appendChild(el('div', {}, `${meta.mode} — ${meta.durationMs} ms`));
  if (meta.externalScanners?.length) {
    met.appendChild(el('b', {}, 'External scanners'));
    met.appendChild(el('div', {}, meta.externalScanners.join(', ')));
  }
  host.appendChild(met);
  if (meta.incomplete) {
    const warning = el('div', { class: 'chip chip-warn', style: 'margin-bottom:12px;' },
      'Assessment incomplete. Missing resources or failed authorization checks are unknown, not a clean result.');
    warning.title = (meta.collectionIssues || []).map(issue =>
      `${issue.operation} ${issue.resource} ${issue.namespace || ''}: ${issue.error}`).join('\n');
    host.appendChild(warning);
  }
  if (meta.namespacesChecked?.length) {
    host.appendChild(el('div', {}, 'Namespaces checked: ' + meta.namespacesChecked.join(', ')));
  }

  $('#summary').replaceChildren(host);
}

function renderSafetyChip(meta) {
  const chip = $('#safety-chip');
  chip.hidden = false;
  const v = meta.safetyViolations || [];
  if (meta.safetyGuard === false || meta.safetyGuard === undefined && v.length === 0) {
    chip.textContent = 'safety-guard OFF';
    chip.className = 'chip chip-bad';
  } else if (v.length === 0) {
    chip.textContent = 'safety-guard on · 0 blocked';
    chip.className = 'chip chip-ok';
  } else {
    chip.textContent = `safety-guard on · ${v.length} mutation(s) blocked`;
    chip.className = 'chip chip-warn';
    chip.title = v.join('\n');
  }

  
  const evCnt = STATE.findings.filter(f => f.category === 'evasion').length;
  const rtCnt = STATE.findings.filter(f => f.category === 'runtime' || f.category === 'service-mesh').length;
  const cniCnt = STATE.findings.filter(f => f.category === 'cni').length;
  const toggle = (id, on, text) => {
    const el = $(id);
    if (!el) return;
    el.hidden = !on;
    if (on) el.textContent = text;
  };
  toggle('#stealth-chip', evCnt > 0, `stealth · ${evCnt} evasion finding${evCnt===1?'':'s'}`);
  toggle('#runtime-chip', rtCnt > 0, `runtime-extras · ${rtCnt} finding${rtCnt===1?'':'s'}`);
  toggle('#cni-chip',     cniCnt > 0, `cni-extras · ${cniCnt} finding${cniCnt===1?'':'s'}`);
  
  const md = STATE.metadata || {};
  const profileChip = $('#profile-chip');
  if (profileChip) {
    if (md.profile === 'internal') {
      profileChip.hidden = false;
      profileChip.textContent = 'profile · internal-trust (severities demoted)';
      profileChip.title = 'Selected severity baseline. Defence-in-depth, RBAC and KEV findings are unchanged.';
    } else {
      profileChip.hidden = false;
      profileChip.textContent = 'profile · external';
      profileChip.title = 'Default severity baseline; assume the API server may be reachable from untrusted networks.';
    }
  }
  const escChip = $('#escape-chip');
  if (escChip) {
    const verdict = md.escapePosture || '';
    const escCnt = STATE.findings.filter(f => f.category === 'escape' && f.ruleId !== 'KH-ESC-POSTURE').length;
    if (verdict) {
      escChip.hidden = false;
      escChip.classList.remove('chip-ok', 'chip-bad', 'chip-warn');
      let label;
      switch (verdict) {
        case 'no-known-escape':
          escChip.classList.add('chip-ok');
          label = 'escape posture · no known escape';
          break;
        case 'vulnerable':
          escChip.classList.add('chip-bad');
          label = `escape posture · vulnerable (${escCnt} finding${escCnt===1?'':'s'})`;
          break;
        case 'exploited':
          escChip.classList.add('chip-bad');
          label = `escape posture · EXPLOITED (${escCnt} finding${escCnt===1?'':'s'})`;
          break;
        default:
          escChip.classList.add('chip-warn');
          label = 'escape posture · ' + verdict;
      }
      escChip.textContent = label;
      escChip.title = 'Aggregated container-escape posture across CVE/technique catalogue (KH-ESC-*).';
    } else {
      escChip.hidden = true;
    }
  }
}

function populateCategoryFilter() {
  const set = new Set();
  STATE.findings.forEach(f => set.add(f.category));
  const sel = $('#fi-cat');
  const current = sel.value;
  sel.innerHTML = '<option value="">All categories</option>';
  Array.from(set).sort().forEach(c => {
    sel.appendChild(el('option', { value: c }, c));
  });
  if (current) sel.value = current;
}

function exploitPill(f) {
  if (!f.exploit) return { cls: 'UNVERIFIED', label: 'unverified' };
  if (f.exploit.exploited) return { cls: 'EXPLOITED', label: 'exploited' };
  if (f.exploit.falsePositive) return { cls: 'FP', label: 'false positive' };
  if (f.exploit.verified) return { cls: 'VERIFIED', label: 'verified' };
  return { cls: 'UNVERIFIED', label: 'unverified' };
}

function resourceStr(r) {
  if (!r) return '';
  if (r.namespace) return `${r.kind}/${r.namespace}/${r.name}`;
  return `${r.kind}/${r.name}`;
}

function filteredFindings() {
  const q = $('#q').value.trim().toLowerCase();
  STATE.q = q;
  const sev = $('#fi-sev').value;
  const cat = $('#fi-cat').value;
  const expStatus = $('#fi-exp').value;
  
  
  
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const floor = sev ? (sevRank[sev] ?? 99) : 99;
  return STATE.findings.filter(f => {
    if (sev && (sevRank[f.severity] ?? 99) > floor) return false;
    if (cat && f.category !== cat) return false;
    if (expStatus) {
      const pill = exploitPill(f).cls;
      if (expStatus === 'exploited' && pill !== 'EXPLOITED') return false;
      if (expStatus === 'verified' && pill !== 'VERIFIED') return false;
      if (expStatus === 'fp' && pill !== 'FP') return false;
      if (expStatus === 'unverified' && pill !== 'UNVERIFIED') return false;
    }
    if (q) {
      const hay = (f.title + ' ' + resourceStr(f.resource) + ' ' + (f.evidence || '') + ' ' + (f.description || '')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderFindings() {
  const host = $('#findings');
  host.innerHTML = '';
  const list = filteredFindings();
  if (!list.length) {
    host.appendChild(el('div', { class: 'empty' }, 'No findings match these filters.'));
    return;
  }
  if (STATE.view === 'flat') {
    list.forEach(f => host.appendChild(renderFinding(f)));
  } else {
    host.appendChild(renderGrouped(list));
  }
}

const CAT_MISCONFIG = new Set(['workload','rbac','secret','network','cluster',
                               'admission','attack-path','supply-chain','audit',
                               'cni','service-mesh','runtime']);
const CAT_CVE       = new Set(['image-cve']);
const CAT_EXPLOIT   = new Set(['external-scan','persistence','escape',
                               'cloud-credentials','kubelet']);
const CAT_STEALTH   = new Set(['evasion']);

function tabOf(f) {
  if (CAT_STEALTH.has(f.category)) return 'stealth';
  if (CAT_CVE.has(f.category)) return 'cve';
  if (CAT_EXPLOIT.has(f.category)) return 'exploit';
  if (f.exploit && f.exploit.exploited) return 'exploit';
  return 'misconfig';
}

function renderGrouped(findings) {
  const byNs = new Map();
  for (const f of findings) {
    const ns = f.resource?.namespace || '(cluster-scoped)';
    if (!byNs.has(ns)) byNs.set(ns, { misconfig: [], cve: [], exploit: [], stealth: [] });
    byNs.get(ns)[tabOf(f)].push(f);
  }

  const sevRank = f => ({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[f.severity] ?? 9);
  const allIn = b => [...b.misconfig, ...b.cve, ...b.exploit, ...b.stealth];
  const nsEntries = Array.from(byNs.entries()).sort((a, b) => {
    const allA = allIn(a[1]);
    const allB = allIn(b[1]);
    const wa = allA.length ? Math.min(...allA.map(sevRank)) : 9;
    const wb = allB.length ? Math.min(...allB.map(sevRank)) : 9;
    if (wa !== wb) return wa - wb;
    return a[0].localeCompare(b[0]);
  });

  const root = document.createDocumentFragment();
  for (const [ns, buckets] of nsEntries) {
    const allNs = allIn(buckets);
    const sevCounts = countSev(allNs);
    
    
    const wantOpen = STATE._expandAll === true ||
                     (STATE.q && STATE.q.length >= 2);
    const nsGroup = el('div', { class: 'tree-group level-ns' + (wantOpen ? ' open' : '') });
    const nsHead = el('div', { class: 'tree-head' }, [
      el('span', { class: 'chev' }, '›'),
      el('span', { class: 'ns-icon', title: 'Namespace' }, 'NS'),
      el('span', { class: 'label' }, ns),
      el('span', { class: 'count' }, `${allNs.length} findings`),
      el('span', { class: 'sevbar' }, sevBar(sevCounts)),
    ]);
    const nsBody = el('div', { class: 'tree-body' });
    nsHead.addEventListener('click', () => nsGroup.classList.toggle('open'));

    
    const tabBar = el('div', { class: 'nstabs' });
    const tabContent = el('div', { class: 'nstab-content' });

    
    const tabs = [
      ['misconfig', 'Misconfig',          buckets.misconfig],
      ['cve',       'CVEs (Trivy)',       buckets.cve],
      ['exploit',   'Exploit / External', buckets.exploit],
      ['stealth',   'Stealth / Evasion',  buckets.stealth],
    ].filter(t => t[2].length);  
    
    const initialTab = tabs.find(t => t[2].length)?.[0] || 'misconfig';

    tabs.forEach(([id, label, list]) => {
      const btn = el('button', {
        class: 'nstab' + (id === initialTab ? ' active' : ''),
        'data-tab': id,
      }, [
        document.createTextNode(label),
        el('span', { class: 'nstab-count' }, ' ' + list.length),
      ]);
      btn.addEventListener('click', ev => {
        ev.stopPropagation();
        tabBar.querySelectorAll('.nstab').forEach(b => b.classList.toggle('active', b === btn));
        tabContent.replaceChildren(renderTabContent(list));
      });
      tabBar.appendChild(btn);
    });

    tabContent.appendChild(renderTabContent(buckets[initialTab]));
    nsBody.appendChild(tabBar);
    nsBody.appendChild(tabContent);

    nsGroup.appendChild(nsHead);
    nsGroup.appendChild(nsBody);
    root.appendChild(nsGroup);
  }
  return root;
}

function renderTabContent(findings) {
  const frag = document.createDocumentFragment();
  if (!findings.length) {
    frag.appendChild(el('div', { class: 'empty' }, 'No findings in this category.'));
    return frag;
  }
  const sevRank = f => ({CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4}[f.severity] ?? 9);

  
  const byR = new Map();
  for (const f of findings) {
    const rKey = `${f.resource?.kind || '?'}/${f.resource?.name || '?'}`;
    if (!byR.has(rKey)) byR.set(rKey, []);
    byR.get(rKey).push(f);
  }
  const entries = Array.from(byR.entries()).sort((a, b) => {
    const wa = Math.min(...a[1].map(sevRank));
    const wb = Math.min(...b[1].map(sevRank));
    if (wa !== wb) return wa - wb;
    return a[0].localeCompare(b[0]);
  });

  for (const [rKey, rFindings] of entries) {
    const [kind, name] = rKey.split('/', 2);
    const rCounts = countSev(rFindings);
    const rGroup = el('div', { class: 'tree-group level-resource' });
    const rHead = el('div', { class: 'tree-head' }, [
      el('span', { class: 'chev' }, '›'),
      el('span', { class: 'kind-icon', title: 'Kind' }, kindShort(kind)),
      el('span', { class: 'label' }, name),
      el('span', { class: 'count' }, `${kind} · ${rFindings.length} finding${rFindings.length === 1 ? '' : 's'}`),
      el('span', { class: 'sevbar' }, sevBar(rCounts)),
    ]);
    const rBody = el('div', { class: 'tree-body' });
    rHead.addEventListener('click', () => rGroup.classList.toggle('open'));

    rFindings.sort((a, b) => sevRank(a) - sevRank(b));
    rFindings.forEach(f => rBody.appendChild(renderFinding(f)));

    rGroup.appendChild(rHead);
    rGroup.appendChild(rBody);
    frag.appendChild(rGroup);
  }
  return frag;
}

function countSev(list) {
  const c = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0, INFO:0 };
  for (const f of list) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}
function sevBar(c) {
  const out = [];
  for (const sev of ['CRITICAL','HIGH','MEDIUM','LOW','INFO']) {
    if (c[sev]) out.push(el('span', { class: 'sev-dot ' + sev, title: sev }, `${c[sev]}`));
  }
  return out;
}
function kindShort(k) {
  const map = { Pod:'P', Deployment:'D', StatefulSet:'SS', DaemonSet:'DS', Service:'SV',
                ServiceAccount:'SA', Secret:'SE', ConfigMap:'CM', Role:'R', ClusterRole:'CR',
                RoleBinding:'RB', ClusterRoleBinding:'CRB', Namespace:'NS',
                Node:'N', Cluster:'C', ExternalEndpoint:'EX' };
  return map[k] || (k ? k.slice(0,2).toUpperCase() : '?');
}

function extractScorePills(f) {
  
  const tags = f.tags || [];
  const pills = [];
  const s = tags.find(t => t.startsWith('stealth:'));
  const r = tags.find(t => t.startsWith('reliability:'));
  if (s) pills.push(el('span', { class: 'pill pill-stealth', title: 'Higher = noisier for Falco/Tetragon' }, s));
  if (r) pills.push(el('span', { class: 'pill pill-reliability', title: 'Higher = more reliable exploit' }, r));
  tags.filter(t => t.startsWith('mitre:')).forEach(t => {
    pills.push(el('span', { class: 'pill pill-mitre', title: 'MITRE ATT&CK for Containers' }, t));
  });
  return pills;
}

function renderFinding(f) {
  const pill = exploitPill(f);
  const titleParts = [
    document.createTextNode(f.title),
    el('span', { class: 'rid' }, ' ' + f.ruleId),
  ];
  const scorePills = extractScorePills(f);
  const headChildren = [
    el('span', { class: 'pill pill-' + f.severity }, f.severity),
    el('div', { class: 'title' }, titleParts),
    ...scorePills,
    el('span', { class: 'pill pill-' + pill.cls }, pill.label),
  ];
  
  if ((f.tags || []).some(t => t.startsWith('KEV:'))) {
    headChildren.push(el('span', { class: 'pill pill-kev', title: 'CISA Known Exploited Vulnerability' }, 'KEV'));
  }
  if (STATE.config.allowLiveExploit && (pill.cls === 'EXPLOITED' || pill.cls === 'VERIFIED')) {
    headChildren.push(exploitDropdown(f));
  }
  
  const acceptBtn = el('button', { class: 'btn-accept', title: 'Accept this finding (won\'t block future scans)' }, '✓ Accept');
  acceptBtn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    ev.stopImmediatePropagation();
    ev.preventDefault();
    openAcceptModal(f);
  }, true);
  headChildren.push(acceptBtn);
  headChildren.push(el('span', { class: 'chev' }, '›'));
  const head = el('div', { class: 'head' }, headChildren);
  const body = el('div', { class: 'body' });

  
  body.appendChild(kv([
    ['Target', resourceStr(f.resource)],
    ['Category', f.category],
  ]));
  
  if (f.description)       body.appendChild(section('Description', mdBlock(f.description)));
  if (f.evidence)          body.appendChild(section('Evidence',    mdBlock(f.evidence)));
  if (f.impact)            body.appendChild(section('Impact',      mdBlock(f.impact)));

  if (f.exploit) {
    body.appendChild(section('Exploitation result',
      kv([
        ['Status', pill.label + (f.exploit.safetyLevel ? ` (${f.exploit.safetyLevel})` : '')],
        f.exploit.evidence ? ['Proof', f.exploit.evidence] : null,
        f.exploit.error ? ['Error', f.exploit.error] : null,
      ].filter(Boolean))
    ));
    if (f.exploit.poc) body.appendChild(section('Proof-of-concept', codeBlock(f.exploit.poc)));
  }
  if (f.recommendation)  body.appendChild(section('Recommendation',     mdBlock(f.recommendation)));
  if (f.remediationYaml) body.appendChild(section('Suggested YAML',     codeBlock(f.remediationYaml)));
  if (f.remediationCmd)  body.appendChild(section('Remediation command', codeBlock(f.remediationCmd)));
  if ((f.references || []).length) body.appendChild(section('References', mdBlock(f.references.map(r => r.startsWith('http') ? `[${r}](${r})` : r).join('  ·  '))));

  const card = el('div', { class: 'finding sev-' + f.severity }, [head, body]);
  head.addEventListener('click', () => card.classList.toggle('open'));
  return card;
}

function kv(pairs) {
  const div = el('div', { class: 'kv' });
  for (const [k, v] of pairs) {
    div.appendChild(el('b', {}, k));
    div.appendChild(el('div', {}, v || ''));
  }
  return div;
}
function section(title, body) {
  return el('div', { class: 'section' }, [el('h4', {}, title), body]);
}
function codeBlock(text) {
  const pre = el('pre', {}, text);
  const btn = el('button', {
    class: 'copy-btn',
    onclick: async ev => {
      try { await navigator.clipboard.writeText(text); btn.textContent = 'copied';
            setTimeout(() => (btn.textContent = 'copy'), 1200); } catch {}
      ev.stopPropagation();
    },
  }, 'copy');
  pre.appendChild(btn);
  return pre;
}

['q', 'fi-sev', 'fi-cat', 'fi-exp'].forEach(id => {
  const node = document.getElementById(id);
  node.addEventListener('input', renderFindings);
  node.addEventListener('change', renderFindings);
});

$('#export-json').addEventListener('click', () => {
  if (!STATE.findings.length) return;
  const blob = new Blob(
    [JSON.stringify({ summary: STATE.summary, metadata: STATE.metadata, findings: STATE.findings, accepted: STATE.accepted || [] }, null, 2)],
    { type: 'application/json' }
  );
  const a = el('a', { href: URL.createObjectURL(blob), download: 'kube-dementor-' + (STATE.currentScanId || 'report') + '.json' });
  document.body.appendChild(a); a.click(); a.remove();
});

async function loadHistory() {
  const tbody = $('#history-table tbody');
  tbody.innerHTML = `<tr><td colspan="8" class="empty"><span class="spinner"></span>loading…</td></tr>`;
  try {
    const r = await fetch('/api/scans');
    const list = await r.json();
    tbody.innerHTML = '';
    if (!list.length) { tbody.innerHTML = `<tr><td colspan="8" class="empty">No scans yet.</td></tr>`; return; }
    list.forEach(s => {
      const tr = el('tr');
      tr.appendChild(el('td', {}, new Date(s.started).toLocaleString()));
      tr.appendChild(el('td', {}, s.cluster || '-'));
      tr.appendChild(el('td', {}, s.request?.context || '-'));
      tr.appendChild(el('td', {}, s.request?.mode || '-'));
      tr.appendChild(el('td', {}, String(s.summary?.bySeverity?.CRITICAL || 0)));
      tr.appendChild(el('td', {}, String(s.summary?.bySeverity?.HIGH || 0)));
      tr.appendChild(el('td', {}, String(s.summary?.exploited || 0)));
      const btn = el('button', { class: 'ghost', onclick: () => openScan(s.id) }, 'open');
      tr.appendChild(el('td', {}, btn));
      tbody.appendChild(tr);
    });
  } catch (e) {
    const row = el('tr');
    const cell = el('td', { colspan: '8', class: 'empty' }, 'error: ' + e.message);
    row.appendChild(cell);
    tbody.replaceChildren(row);
  }
}

async function openScan(id) {
  activateTab($('.tab[for="sp-main"]'));
  $('#live-card').hidden = true;
  $('#run-status').textContent = 'viewing historic scan ' + id;
  STATE.currentScanId = id;
  await loadScanResult(id);
}


const NODE_STYLE = {
  me:     { fill: '#f59e0b', stroke: '#fbbf24', r: 18 },
  hv:     { fill: '#ef4444', stroke: '#f87171', r: 16 },
  sa:     { fill: '#38bdf8', stroke: '#7dd3fc', r: 14 },
  user:   { fill: '#38bdf8', stroke: '#7dd3fc', r: 14 },
  group:  { fill: '#38bdf8', stroke: '#7dd3fc', r: 14 },
  role:   { fill: '#a78bfa', stroke: '#c4b5fd', r: 13 },
  pod:    { fill: '#475569', stroke: '#64748b', r: 12 },
  secret: { fill: '#475569', stroke: '#64748b', r: 12 },
  cm:     { fill: '#475569', stroke: '#64748b', r: 12 },
  node:   { fill: '#475569', stroke: '#64748b', r: 12 },
  ns:     { fill: '#475569', stroke: '#64748b', r: 11 },
  other:  { fill: '#475569', stroke: '#64748b', r: 12 },
};

function nodeStyle(n, meID) {
  if (n.id === meID) return NODE_STYLE.me;
  if (n.highValue)   return NODE_STYLE.hv;
  const k = (n.kind || '').toLowerCase();
  if (k.includes('serviceaccount')) return NODE_STYLE.sa;
  if (k === 'user' || k === 'group') return NODE_STYLE.user;
  if (k.includes('role')) return NODE_STYLE.role;
  if (k.includes('secret')) return NODE_STYLE.secret;
  if (k.includes('configmap')) return NODE_STYLE.cm;
  if (k === 'pod') return NODE_STYLE.pod;
  if (k === 'node') return NODE_STYLE.node;
  if (k === 'namespace') return NODE_STYLE.ns;
  return NODE_STYLE.other;
}

function labelFor(n) {
  if (n.namespace) return n.name + ' (' + n.namespace + ')';
  return n.name;
}

function filterGraph(graph, opts) {
  const { me, maxHops, onlyMe, onlyHV } = opts;
  if (!graph || !graph.nodes?.length) return { nodes: [], edges: [] };

  
  const outAdj = new Map();
  for (const e of graph.edges) {
    if (!outAdj.has(e.from)) outAdj.set(e.from, []);
    outAdj.get(e.from).push(e);
  }
  const nodeByID = new Map(graph.nodes.map(n => [n.id, n]));

  
  const fwdReach = new Set();
  if (onlyMe && me) {
    const depth = new Map();
    depth.set(me, 0);
    fwdReach.add(me);
    const q = [me];
    while (q.length) {
      const id = q.shift();
      const d = depth.get(id);
      if (d >= maxHops) continue;
      for (const e of (outAdj.get(id) || [])) {
        if (fwdReach.has(e.to)) continue;
        fwdReach.add(e.to);
        depth.set(e.to, d + 1);
        q.push(e.to);
      }
    }
  } else {
    
    for (const n of graph.nodes) fwdReach.add(n.id);
  }

  
  let keep = fwdReach;
  if (onlyHV) {
    const leads = new Set();
    
    const memo = new Map(); 
    const dfs = (id) => {
      if (memo.has(id)) return memo.get(id);
      memo.set(id, false); 
      const n = nodeByID.get(id);
      if (n?.highValue) { memo.set(id, true); return true; }
      for (const e of (outAdj.get(id) || [])) {
        if (dfs(e.to)) { memo.set(id, true); return true; }
      }
      return memo.get(id);
    };
    for (const id of fwdReach) {
      if (dfs(id)) leads.add(id);
    }
    
    if (me) leads.add(me);
    keep = leads;
  }

  const nodes = graph.nodes.filter(n => keep.has(n.id));
  const edges = graph.edges.filter(e => keep.has(e.from) && keep.has(e.to));
  return { nodes, edges };
}

function layoutGraph(nodes, edges, width, height, meID) {
  if (!nodes.length) return;
  const pos = new Map();
  nodes.forEach((n, i) => {
    if (pos.has(n.id)) return;
    if (n.id === meID) {
      pos.set(n.id, { x: width / 2, y: height / 2 });
    } else {
      const a = (i / nodes.length) * Math.PI * 2;
      pos.set(n.id, { x: width / 2 + Math.cos(a) * 150, y: height / 2 + Math.sin(a) * 150 });
    }
  });
  const vel = new Map();
  nodes.forEach(n => vel.set(n.id, { x: 0, y: 0 }));

  const K = 160;        
  const REPEL = 22000;  
  const SPRING = 0.04;  
  const DAMP = 0.82;

  
  const eset = edges.map(e => [e.from, e.to]);

  for (let it = 0; it < 200; it++) {
    
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const pa = pos.get(a.id), pb = pos.get(b.id);
        let dx = pa.x - pb.x, dy = pa.y - pb.y;
        let d2 = dx * dx + dy * dy + 0.01;
        const f = REPEL / d2;
        const d = Math.sqrt(d2);
        const fx = (dx / d) * f, fy = (dy / d) * f;
        vel.get(a.id).x += fx; vel.get(a.id).y += fy;
        vel.get(b.id).x -= fx; vel.get(b.id).y -= fy;
      }
    }
    
    for (const [fa, fb] of eset) {
      const pa = pos.get(fa), pb = pos.get(fb);
      if (!pa || !pb) continue;
      const dx = pb.x - pa.x, dy = pb.y - pa.y;
      const d = Math.sqrt(dx * dx + dy * dy) + 0.01;
      const f = (d - K) * SPRING;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      vel.get(fa).x += fx; vel.get(fa).y += fy;
      vel.get(fb).x -= fx; vel.get(fb).y -= fy;
    }
    
    for (const n of nodes) {
      const p = pos.get(n.id), v = vel.get(n.id);
      if (n.id === meID) { v.x = 0; v.y = 0; continue; } 
      p.x += v.x; p.y += v.y;
      v.x *= DAMP; v.y *= DAMP;
      
      p.x = Math.max(120, Math.min(width - 120, p.x));
      p.y = Math.max(50, Math.min(height - 50, p.y));
    }
  }
  return pos;
}

function renderAttackGraph() {
  
  
  const card = $('#paths-card');
  const body = $('#paths-table tbody');
  const empty = $('#paths-empty');
  if (!card || !body) return;
  if (STATE.metadata?.mode === 'chain') {
    card.hidden = true; 
    return;
  }
  const pathFindings = (STATE.findings || []).concat(STATE.accepted || [])
    .filter(f => f.ruleId && f.ruleId.startsWith('KH-PATH'));
  
  
  
  const pBody = document.getElementById('paths-body');
  if (pBody && !pBody.dataset.userInteracted) {
    pBody.classList.add('collapsed');
  }
  if (!pathFindings.length) {
    card.hidden = false;
    body.innerHTML = '';
    if (empty) empty.hidden = false;
    refreshPathsHeaderChip(0, 0, STATE.metadata?.incomplete ? 'UNKNOWN' : 'INFO', 0);
    return;
  }
  if (empty) empty.hidden = true;
  card.hidden = false;
  body.innerHTML = '';
  const onlyMe = $('#p-onlyme') ? $('#p-onlyme').checked : true;
  const onlyHV = $('#p-onlyhv') ? $('#p-onlyhv').checked : true;
  const id = STATE.identity || null;

  let totalShown = 0;
  let fromMeCount = 0;
  let worst = 'INFO';
  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const PATHS_RENDER_LIMIT = 50;

  
  
  const filteredRows = [];
  for (const f of pathFindings) {
    const nodes = f.attackPath?.nodes || [];
    const chain = nodes.length
      ? nodes.map(node => [node.kind, node.namespace, node.name].filter(Boolean).join('/'))
      : parsePathEvidence(f.evidence || '');
    if (!chain.length) continue;
    const startLabel = chain[0];
    const endLabel = chain[chain.length - 1];
    const startID = nodes[0]?.id || startLabel;
    const fromMe = isFromMeLabel(startID, id);
    
    
    const isHV = nodes.length ? nodes[nodes.length - 1].highValue === true : true;
    if (onlyMe && !fromMe) continue;
    if (onlyHV && !isHV) continue;
    filteredRows.push({ f, chain, startLabel, startID, endLabel, fromMe });
    if (fromMe) fromMeCount++;
    if ((sevOrder[f.severity] ?? 9) < (sevOrder[worst] ?? 9)) worst = f.severity;
  }

  const showAll = !!body.dataset.showAll;
  const renderRows = showAll ? filteredRows : filteredRows.slice(0, PATHS_RENDER_LIMIT);
  for (const r of renderRows) {
    const { f, chain, startLabel, startID, endLabel } = r;
    totalShown++;

    const row = document.createElement('tr');
    row.className = 'path-row sev-' + f.severity;
    const startCell = document.createElement('td');
    startCell.className = 'path-start';
    startCell.textContent = startLabel;
    const viaCell = document.createElement('td');
    viaCell.className = 'path-via';
    viaCell.textContent = whoViaLabel(startID, id);
    const hopsCell = document.createElement('td');
    hopsCell.textContent = String(chain.length - 1);
    const endCell = document.createElement('td');
    endCell.className = 'path-end';
    endCell.textContent = endLabel;
    const sevCell = document.createElement('td');
    sevCell.innerHTML = `<span class="pill pill-${f.severity}">${f.severity}</span>`;
    const expand = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'btn btn-compact';
    btn.textContent = '▾';
    btn.title = 'Show full path';
    btn.addEventListener('click', () => {
      const next = row.nextElementSibling;
      if (next && next.classList.contains('path-detail-row')) {
        next.remove();
        btn.textContent = '▾';
        return;
      }
      btn.textContent = '▴';
      const detail = document.createElement('tr');
      detail.className = 'path-detail-row';
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'path-detail';
      td.innerHTML = chain.map((h, i) =>
        `<span class="path-node">${mdEscape(h)}</span>${i < chain.length - 1 ? '<span class="path-arrow">→</span>' : ''}`
      ).join('');
      for (const edge of (f.attackPath?.edges || [])) {
        const note = document.createElement('div');
        note.textContent = `${edge.kind}: ${edge.note || ''}`;
        td.appendChild(note);
      }
      if (f.description) {
        const desc = document.createElement('div');
        desc.className = 'path-desc';
        desc.innerHTML = renderMarkdown(f.description);
        td.appendChild(desc);
      }
      detail.appendChild(td);
      row.parentNode.insertBefore(detail, row.nextSibling);
    });
    expand.appendChild(btn);
    row.append(startCell, viaCell, hopsCell, endCell, sevCell, expand);
    body.appendChild(row);
  }

  
  if (filteredRows.length > PATHS_RENDER_LIMIT) {
    const tr = document.createElement('tr');
    tr.className = 'path-show-all';
    const td = document.createElement('td');
    td.colSpan = 6;
    const a = document.createElement('button');
    a.className = 'btn ghost';
    a.textContent = showAll
      ? `Show only top ${PATHS_RENDER_LIMIT}`
      : `Show all ${filteredRows.length} paths`;
    a.addEventListener('click', () => {
      if (body.dataset.showAll) delete body.dataset.showAll;
      else body.dataset.showAll = '1';
      renderAttackGraph();
    });
    td.appendChild(a);
    tr.appendChild(td);
    body.appendChild(tr);
  }

  const countEl = document.getElementById('paths-count');
  if (countEl) {
    countEl.textContent = `${totalShown} of ${filteredRows.length} path(s) shown · ${pathFindings.length} total`;
  }
  refreshPathsHeaderChip(filteredRows.length, fromMeCount, worst, pathFindings.length);
  if (!body.children.length && empty) empty.hidden = false;
}

// refreshPathsHeaderChip writes a one-line summary into the collapsed
// header so the user knows what's hiding inside without opening the card.
function refreshPathsHeaderChip(filtered, fromMe, worst, total) {
  const head = document.getElementById('paths-toggle');
  if (!head) return;
  let chip = head.querySelector('.paths-summary');
  if (!chip) {
    chip = document.createElement('span');
    chip.className = 'paths-summary';
    head.insertBefore(chip, head.querySelector('.toggle-chev'));
  }
  if (!total) {
    chip.textContent = worst === 'UNKNOWN' ? 'paths unknown: incomplete assessment' : 'no paths found in assessed data';
    return;
  }
  const sev = worst || 'INFO';
  chip.innerHTML =
    `<span class="pill pill-${sev}">worst: ${sev}</span>` +
    `<span class="muted"> · ${filtered} matching · ${fromMe} from me · ${total} total</span>`;
}

function parsePathEvidence(ev) {
  if (!ev) return [];
  const parts = ev.split(/\s*(?:→|->|—|=>)\s*/).map(s => s.trim()).filter(Boolean);
  if (parts.length >= 2) return parts;
  return [];
}

function legacyChainGraph(report) {
  if (report.metadata?.mode !== 'chain') return null;
  const summary = (report.findings || []).find(finding => finding.ruleId === 'KH-CHAIN-SUMMARY');
  const text = summary?.description || '';
  const access = text.match(/Maximum Access Achieved:\s*([A-Z_]+)/)?.[1] || 'UNKNOWN';
  const me = 'Operator/current-credentials';
  const nodes = [{ id: me, kind: 'Operator', name: 'Current credentials' }];
  const edges = [];
  const phases = new Set();
  for (const line of text.split('\n')) {
    const match = line.match(/^\s*\d+\.\s+\[([✓✗○])\]\s+([^→]+)→\s+(.+)\s+\([^)]*\)\s*$/);
    if (!match) continue;
    const phase = match[2].trim();
    const id = `ChainStep/${nodes.length}`;
    const status = match[1] === '✓' ? 'success' : match[1] === '✗' ? 'failed' : 'skipped';
    phases.add(phase);
    nodes.push({ id, kind: 'ChainStep', name: match[3].trim(), phase, status,
      detail: 'Recorded by the older server. Detailed failure evidence is unavailable in this saved report.' });
    edges.push({ from: me, to: id, kind: 'Attempt', status, note: `${phase}: ${status}` });
  }
  for (const phase of ['container-escape', 'cred-harvest', 'cluster-recon', 'control-plane']) {
    if (phases.has(phase)) continue;
    const id = `ChainStep/${nodes.length}`;
    nodes.push({ id, kind: 'ChainStep', name: `${phase} (not recorded)`, phase, status: 'skipped',
      detail: 'No attempt is recorded for this phase. Absence of an attempt is not proof that the target is inaccessible.' });
    edges.push({ from: me, to: id, kind: 'NotRecorded', status: 'skipped' });
  }
  nodes.push({ id: `Access/${access}`, kind: 'AccessLevel', name: `Recorded access: ${access}`,
    status: 'success', detail: 'Legacy report, not a live shell or an exhaustive assessment.' });
  edges.push({ from: me, to: `Access/${access}`, kind: 'Result', status: 'success' });
  return { me, nodes, edges };
}

function graphStatusStyle(status) {
  const colors = { success: '#22c55e', failed: '#ef4444', skipped: '#94a3b8', potential: '#f59e0b' };
  return { color: colors[status] || colors.potential, dashed: status === 'failed' || status === 'skipped' };
}

function layoutChainGraph(nodes, width, height, me) {
  const positions = new Map([[me, { x: 130, y: height / 2 }]]);
  const steps = nodes.filter(node => node.id !== me);
  const rows = Math.ceil(steps.length / 2);
  steps.forEach((node, index) => positions.set(node.id, {
    x: index % 2 === 0 ? width * 0.43 : width * 0.78,
    y: (Math.floor(index / 2) + 1) * height / (rows + 1),
  }));
  return positions;
}

function renderVisualGraph() {
  const card = $('#graph-card');
  const svg = $('#graph-svg');
  const emptyMsg = $('#graph-empty');
  if (!card || !svg || !emptyMsg) return;
  const g = STATE.graph || { nodes: [], edges: [], me: '' };
  card.hidden = false;
  svg.replaceChildren();
  const detail = $('#graph-detail');
  if (detail) detail.hidden = true;
  const chain = STATE.metadata?.mode === 'chain';
  $('#graph-caption').textContent = chain
    ? 'Execution trace. Failed/skipped edges grant no access. Completed does not mean every attack was attempted. Drag nodes, pan, or scroll to zoom.'
    : 'Potential authorization/escape paths, not proof of compromise. Drag nodes, pan, or scroll to zoom.';
  const filtered = filterGraph(g, { me: g.me, maxHops: 15, onlyMe: $('#graph-onlyme')?.checked || false, onlyHV: false });
  const nodes = filtered.nodes.slice(0, 150);
  const ids = new Set(nodes.map(node => node.id));
  const edges = (g.edges || []).filter(edge => ids.has(edge.from) && ids.has(edge.to));
  $('#graph-count').textContent = `${nodes.length}/${(g.nodes || []).length} nodes · ${edges.length} edges`;
  emptyMsg.hidden = nodes.length > 0;
  if (!nodes.length) return;
  const width = 1200;
  const height = chain ? Math.max(620, Math.ceil((nodes.length - 1) / 2) * 85 + 100) : 620;
  const position = chain ? layoutChainGraph(nodes, width, height, g.me) : layoutGraph(nodes, edges, width, height, g.me);
  let view = { x: 0, y: 0, width, height };
  const setView = () => svg.setAttribute('viewBox', `${view.x} ${view.y} ${view.width} ${view.height}`);
  setView();
  $('#graph-reset').onclick = () => { view = { x: 0, y: 0, width, height }; setView(); };
  if ($('#graph-onlyme')) $('#graph-onlyme').onchange = renderVisualGraph;
  const svgEl = (tag, attrs, text) => {
    const element = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs || {})) element.setAttribute(key, value);
    if (text != null) element.textContent = text;
    return element;
  };
  const defs = svgEl('defs');
  const marker = svgEl('marker', { id: 'graph-arrow', viewBox: '0 -5 10 10', refX: 20, markerWidth: 6, markerHeight: 6, orient: 'auto' });
  marker.appendChild(svgEl('path', { d: 'M0,-5L10,0,L0,5', fill: '#94a3b8' }));
  defs.appendChild(marker);
  svg.appendChild(defs);
  const lineElements = edges.map(edge => {
    const style = graphStatusStyle(edge.status || 'potential');
    const line = svgEl('line', { stroke: style.color, 'stroke-width': 1.7, 'stroke-dasharray': style.dashed ? '6 4' : '', 'marker-end': 'url(#graph-arrow)' });
    line.appendChild(svgEl('title', {}, `${edge.kind}: ${edge.status || 'potential'}\n${edge.note || ''}`));
    svg.appendChild(line);
    return line;
  });
  const groups = new Map();
  for (const node of nodes) {
    const style = nodeStyle(node, g.me);
    const color = node.status ? graphStatusStyle(node.status).color : style.fill;
    const group = svgEl('g', { 'data-node-id': node.id, tabindex: 0, role: 'button', 'aria-label': `${labelFor(node)}: ${node.status || 'potential'}` });
    group.style.cursor = 'grab';
    group.appendChild(svgEl('circle', { r: style.r, fill: color, stroke: node.id === g.me ? '#fbbf24' : '#cbd5e1', 'stroke-width': node.id === g.me ? 3 : 1 }));
    group.appendChild(svgEl('text', { y: 4, fill: '#0f172a', 'font-size': 10, 'text-anchor': 'middle' }, shortKind(node.kind)));
    const label = labelFor(node);
    group.appendChild(svgEl('text', { y: style.r + 15, fill: '#e6edf6', 'font-size': 11, 'text-anchor': 'middle' }, label.length > 32 ? label.slice(0, 30) + '…' : label));
    group.appendChild(svgEl('title', {}, `${label}\n${node.phase || node.kind}: ${node.status || 'potential'}\n${node.detail || ''}`));
    const showDetail = () => {
      if (!detail) return;
      detail.hidden = false;
      detail.textContent = `${label}\nType/phase: ${node.phase || node.kind}\nStatus: ${node.status || 'potential / unverified'}\n${node.detail || ''}`;
    };
    group.addEventListener('click', showDetail);
    group.addEventListener('keydown', event => { if (event.key === 'Enter') showDetail(); });
    group.onpointerdown = event => {
      drag = { id: node.id, x: event.clientX, y: event.clientY, startX: event.clientX, startY: event.clientY, showDetail, moved: false };
      svg.setPointerCapture(event.pointerId);
      event.stopPropagation();
      event.preventDefault();
    };
    groups.set(node.id, group);
    svg.appendChild(group);
  }
  function redraw() {
    for (const [id, group] of groups) {
      const point = position.get(id);
      group.setAttribute('transform', `translate(${point.x},${point.y})`);
    }
    edges.forEach((edge, index) => {
      const from = position.get(edge.from), to = position.get(edge.to);
      for (const [key, value] of Object.entries({ x1: from.x, y1: from.y, x2: to.x, y2: to.y })) lineElements[index].setAttribute(key, value);
    });
  }
  let drag = null;
  svg.onpointerdown = event => { drag = { x: event.clientX, y: event.clientY }; svg.setPointerCapture(event.pointerId); };
  svg.onpointermove = event => {
    if (!drag) return;
    if (Math.hypot(event.clientX - (drag.startX ?? drag.x), event.clientY - (drag.startY ?? drag.y)) > 3) drag.moved = true;
    const rect = svg.getBoundingClientRect();
    const dx = (event.clientX - drag.x) * view.width / rect.width;
    const dy = (event.clientY - drag.y) * view.height / rect.height;
    if (drag.id) {
      const point = position.get(drag.id);
      point.x += dx; point.y += dy; redraw();
    } else {
      view.x -= dx; view.y -= dy; setView();
    }
    drag.x = event.clientX; drag.y = event.clientY;
  };
  svg.onpointerup = () => {
    if (drag?.id && !drag.moved) drag.showDetail();
    drag = null;
  };
  svg.onpointercancel = () => { drag = null; };
  svg.onwheel = event => {
    event.preventDefault();
    const rect = svg.getBoundingClientRect();
    const factor = event.deltaY > 0 ? 1.1 : 0.9;
    const nextWidth = Math.max(240, Math.min(6000, view.width * factor));
    const ratio = nextWidth / view.width;
    view.x += (event.clientX - rect.left) / rect.width * view.width * (1 - ratio);
    view.y += (event.clientY - rect.top) / rect.height * view.height * (1 - ratio);
    view.width = nextWidth; view.height *= ratio; setView();
  };
  redraw();
}

function shortKind(k) {
  if (!k) return '?';
  const m = {
    ServiceAccount: 'SA', User: 'U', Group: 'G',
    Role: 'R', ClusterRole: 'CR', ClusterAdmin: '★',
    Pod: 'P', Secret: 'SE', ConfigMap: 'CM', Node: 'N', Namespace: 'NS',
  };
  return m[k] || k.slice(0, 2).toUpperCase();
}

// Paths toolbar — re-render on change.
document.addEventListener('change', (ev) => {
  if (ev.target.id === 'p-onlyme' || ev.target.id === 'p-onlyhv') renderAttackGraph();
});
document.addEventListener('click', (ev) => {
  if (ev.target.closest && ev.target.closest('#paths-toggle')) {
    const body = document.getElementById('paths-body');
    if (body) {
      body.classList.toggle('collapsed');
      
      body.dataset.userInteracted = '1';
    }
  }
});


function exploitDropdown(f) {
  const btn = el('button', { class: 'btn-exploit', title: 'Actively exploit this finding' }, 'Exploit ▾');
  
  
  btn.addEventListener('click', (ev) => {
    ev.stopPropagation();
    ev.stopImmediatePropagation();
    ev.preventDefault();
    openExploitMenu(btn, f);
  }, true);
  return btn;
}

async function openExploitMenu(anchor, f) {
  
  $$('.exploit-menu').forEach(m => m.remove());

  let caps = STATE.capabilityCache.get(f.id);
  if (!caps) {
    try {
      const r = await fetch(`/api/scans/${STATE.currentScanId}/findings/${encodeURIComponent(f.id)}/capabilities`);
      if (!r.ok) {
        let message = 'HTTP ' + r.status;
        try { message = (await r.json()).error || message; } catch {}
        throw new Error(message);
      }
      const body = await r.json();
      caps = body.capabilities || [];
      STATE.capabilityCache.set(f.id, caps);
    } catch (e) {
      alert('Could not list capabilities: ' + e.message);
      return;
    }
  }
  if (!caps.length) {
    alert('No live-exploit capability is available for this finding.');
    return;
  }

  const menu = el('div', { class: 'exploit-menu' });
  
  
  menu.addEventListener('click', (ev) => ev.stopPropagation());
  for (const c of caps) {
    const item = el('div', { class: 'exploit-item danger-' + (c.danger || 'medium') }, [
      el('div', { class: 'ei-label' }, c.label),
      el('div', { class: 'ei-desc' }, c.purpose || ''),
    ]);
    item.addEventListener('click', (ev) => {
      ev.stopPropagation();
      ev.stopImmediatePropagation();
      menu.remove();
      document.removeEventListener('click', closer, true);
      openExploitModal(f, c);
    });
    menu.appendChild(item);
  }
  document.body.appendChild(menu);
  
  const rect = anchor.getBoundingClientRect();
  menu.style.position = 'fixed';
  menu.style.left = rect.left + 'px';
  menu.style.top = (rect.bottom + 4) + 'px';
  
  const closer = (e) => {
    if (menu.contains(e.target)) return;
    menu.remove();
    document.removeEventListener('click', closer, true);
  };
  setTimeout(() => document.addEventListener('click', closer, true), 50);
}

function openExploitModal(f, cap) {
  const cluster = (STATE.metadata && STATE.metadata.clusterName) || '';
  const liveEnabled = STATE.config?.allowLiveExploit === true;
  const overlay = el('div', { class: 'modal-overlay' });

  const form = el('div', { class: 'modal' });
  form.appendChild(el('h3', {}, cap.label));
  form.appendChild(el('p', { class: 'modal-purpose' }, cap.purpose || ''));
  form.appendChild(el('div', { class: 'modal-warn danger-' + (cap.danger || 'medium') },
    `Runs LIVE against cluster "${cluster}". Risk: ${cap.danger || 'medium'}.`));

  const inputs = {};
  const inputsBox = el('div', { class: 'modal-inputs' });
  for (const inp of (cap.inputs || [])) {
    const lab = el('label', {}, inp.label + (inp.name ? ` (${inp.name})` : ''));
    let field;
    if (inp.kind === 'textarea') {
      field = el('textarea', { rows: '3', placeholder: inp.placeholder || '' });
    } else if (inp.kind === 'select') {
      field = el('select', {});
      for (const o of (inp.options || [])) field.appendChild(el('option', { value: o }, o));
    } else {
      field = el('input', { type: 'text', placeholder: inp.placeholder || '' });
    }
    if (inp.default) field.value = inp.default;
    inputs[inp.name] = field;
    inputsBox.appendChild(lab);
    inputsBox.appendChild(field);
  }
  form.appendChild(inputsBox);

  form.appendChild(el('label', { class: 'modal-confirm' }, `Type "${cluster}" to confirm:`));
  const confirmEl = el('input', { type: 'text', placeholder: cluster });
  form.appendChild(confirmEl);

  const errBox = el('div', { class: 'modal-err' });
  if (!liveEnabled) {
    errBox.textContent = 'Live execution is disabled on this server. No command or shell will be started. Enabling it requires starting the server explicitly with --live-exploit.';
  }
  form.appendChild(errBox);

  const outBox = el('pre', { class: 'modal-output' });
  outBox.style.display = 'none';
  form.appendChild(outBox);

  const cancel = el('button', { class: 'btn' }, 'Cancel');
  const run = el('button', { class: 'btn btn-primary' }, cap.kind === 'shell' ? 'Open shell' : 'Run');
  run.disabled = !liveEnabled;
  const buttons = el('div', { class: 'modal-buttons' }, [cancel, run]);
  form.appendChild(buttons);

  overlay.appendChild(form);
  overlay.addEventListener('click', ev => { if (ev.target === overlay) overlay.remove(); });
  cancel.addEventListener('click', () => overlay.remove());

  run.addEventListener('click', async () => {
    if (!liveEnabled) return;
    if (confirmEl.value !== cluster) {
      errBox.textContent = 'Cluster name does not match.';
      return;
    }
    errBox.textContent = '';
    outBox.textContent = '';
    outBox.style.display = 'none';
    run.disabled = true;
    run.textContent = 'Running…';
    const inputValues = {};
    for (const [k, v] of Object.entries(inputs)) inputValues[k] = v.value;

    if (cap.kind === 'shell') {
      overlay.remove();
      openShellTerminal(f, cluster);
      return;
    }
    try {
      const r = await fetch(
        `/api/scans/${STATE.currentScanId}/findings/${encodeURIComponent(f.id)}/exploit`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ capability: cap.id, inputs: inputValues, confirmText: cluster }) });
      const res = await r.json();
      if (!r.ok) {
        errBox.textContent = res.error || ('HTTP ' + r.status);
        return;
      }
      outBox.style.display = 'block';
      outBox.textContent = formatExecResult(res);
    } catch (e) {
      errBox.textContent = e.message;
    } finally {
      run.disabled = false;
      run.textContent = 'Run again';
    }
  });

  document.body.appendChild(overlay);
  confirmEl.focus();
}

function formatExecResult(res) {
  const out = [];
  if (res.capabilityId) out.push(`capability: ${res.capabilityId}`);
  if (res.startedAt || res.finishedAt)
    out.push(`started: ${res.startedAt || 'not reported'}  finished: ${res.finishedAt || 'not reported'}`);
  if (res.command) out.push(`command: ${res.command}`);
  if (res.evidence) out.push(`evidence: ${res.evidence}`);
  if (res.error) out.push(`error: ${res.error}`);
  if (res.stdout) out.push('\n── stdout ──\n' + res.stdout);
  if (res.stderr) out.push('\n── stderr ──\n' + res.stderr);
  if (res.data !== undefined && res.data !== null)
    out.push('\n── data ──\n' + JSON.stringify(res.data, null, 2));
  return out.join('\n');
}

// ─── Minimal pod-shell terminal ─────────────────────────────────────────
async function openShellTerminal(f, cluster) {
  const scanId = STATE.currentScanId;
  const overlay = el('div', { class: 'modal-overlay term-overlay' });
  const wrap = el('div', { class: 'term-wrap' });
  let ws = null;
  let closed = false;
  const abort = new AbortController();
  const close = () => {
    closed = true;
    abort.abort();
    if (ws) ws.close();
    overlay.remove();
  };
  wrap.appendChild(el('div', { class: 'term-bar' }, [
    el('span', {}, `shell → ${f.resource.namespace}/${f.resource.name} on ${cluster}`),
    el('button', { class: 'btn', onclick: close }, 'Close'),
  ]));
  const out = el('pre', { class: 'term-out' });
  const inp = el('input', { class: 'term-input', type: 'text', placeholder: 'type here + Enter…', autofocus: true });
  wrap.appendChild(out);
  wrap.appendChild(inp);
  overlay.appendChild(wrap);
  document.body.appendChild(overlay);
  inp.disabled = true;
  out.textContent = '[checking shell availability]\n';
  overlay.addEventListener('click', ev => { if (ev.target === overlay) close(); });

  const target = `/api/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(f.id)}`;
  try {
    const response = await fetch(`${target}/shell-status?confirm=${encodeURIComponent(cluster)}`, { signal: abort.signal });
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || `HTTP ${response.status}`);
    if (closed) return;
    out.textContent += `[target running: ${status.container}, scope: ${status.scope}]\n`;
    if (status.rexecAvailable) out.textContent += '[rexec available: standard pods/exec is tried first; on failure the audited kubectl-rexec plugin is used automatically]\n';
  } catch (error) {
    if (!closed) out.textContent += `[shell not opened] ${error.message}\n`;
    return;
  }

  const wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url = `${wsProto}//${location.host}/ws/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(f.id)}/shell?confirm=${encodeURIComponent(cluster)}`;
  ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => { out.textContent += '[connected]\n'; inp.disabled = false; inp.focus(); };
  ws.onmessage = (ev) => {
    const chunk = typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(new Uint8Array(ev.data));
    out.textContent += chunk;
    out.scrollTop = out.scrollHeight;
  };
  ws.onerror = () => { out.textContent += '\n[connection error] WebSocket upgrade/transport failed. Check the server message and reverse-proxy WebSocket support.\n'; };
  ws.onclose = event => {
    out.textContent += `\n[disconnected] code=${event.code}${event.reason ? ': ' + event.reason : ''}\n`;
    inp.disabled = true;
  };
  inp.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      const txt = inp.value + '\n';
      if (ws.readyState === WebSocket.OPEN) ws.send(txt);
      inp.value = '';
    }
  });
}

// ─── Chain banner (cleanup + shell shortcuts) ───────────────────────────
function renderChainBanner(scanId, report) {
  
  const old = document.getElementById('chain-banner');
  if (old) old.remove();

  
  const shellFindings = (report.findings || []).filter(f => f.ruleId === 'KH-CHAIN-SHELL' && f.shell?.verified === true);
  if (!shellFindings.length) return;

  const banner = el('div', { class: 'chain-banner', id: 'chain-banner' });
  banner.appendChild(el('div', { class: 'chain-banner-title' }, [
    el('span', { class: 'chain-icon', html: '<svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M9.5 1 3 9h4l-1 6 6.5-8h-4z"/></svg>' }),
    el('strong', {}, `Chain run ended — ${shellFindings.length} previously verified exec target(s)`),
  ]));
  banner.appendChild(el('p', { class: 'muted' },
    STATE.config.allowLiveExploit
      ? 'Current pod state and attachment are rechecked. A completed run is not proof that every stage succeeded.'
      : 'Interactive shells are disabled on this server. Targets below are evidence from the run, not active sessions.'));

  const podList = el('div', { class: 'chain-pods' });
  for (const f of shellFindings) {
    const podName = f.resource?.name || 'unknown';
    const ns = f.resource?.namespace || 'default';
    const shellType = f.shell.scope || 'container';
    const labels = {
      'node-escape': 'Reconnect verified node exec',
      'control-plane': 'Reconnect verified control-plane exec',
      'hostpath-escape': 'Reconnect verified host filesystem exec',
      'container': 'Reconnect container exec',
    };

    const shellBtn = el('button', {
      class: 'btn btn-shell danger-high',
      disabled: STATE.config.allowLiveExploit ? null : 'disabled',
      onclick: () => openShellTerminal(f, (STATE.metadata && STATE.metadata.clusterName) || ''),
    }, labels[shellType] || 'Shell');

    const execBtn = el('button', {
      class: 'btn btn-exec',
      disabled: STATE.config.allowLiveExploit ? null : 'disabled',
      onclick: () => {
        
        STATE.capabilityCache.delete(f.id);
        openExploitMenu(execBtn, f);
      },
    }, 'Run command');

    podList.appendChild(el('div', { class: 'chain-pod-row' }, [
      el('span', { class: 'chain-pod-name' }, `${ns}/${podName}`),
      el('span', { class: 'chain-pod-type badge-' + shellType }, shellType.replace('-', ' ')),
      shellBtn,
      execBtn,
    ]));
  }
  banner.appendChild(podList);

  
  const cleanupBtn = el('button', {
    class: 'btn btn-cleanup',
    onclick: async () => {
      const cluster = (STATE.metadata && STATE.metadata.clusterName) || '';
      if (!confirm(`Delete all chain pods from cluster "${cluster}"?\n\nThis removes the escaped pods and closes any open shells.`)) return;
      cleanupBtn.disabled = true;
      cleanupBtn.textContent = 'Cleaning up…';
      try {
        const resp = await fetch(`/api/scans/${STATE.currentScanId}/chain/cleanup`, { method: 'POST' });
        if (!resp.ok) {
          let message = 'HTTP ' + resp.status;
          try { message = (await resp.json()).error || message; } catch {}
          alert('Cleanup failed: ' + message);
          cleanupBtn.disabled = false;
          cleanupBtn.textContent = '🧹 Cleanup all chain pods';
          return;
        }
        banner.innerHTML = '<div class="chain-banner-title"><span class="chain-icon"><svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 8.5l4 4 7-9"/></svg></span><strong>Chain pods cleaned up</strong></div>';
        banner.classList.add('chain-cleaned');
      } catch (e) {
        alert('Cleanup failed: ' + e.message);
        cleanupBtn.disabled = false;
        cleanupBtn.textContent = '🧹 Cleanup all chain pods';
      }
    },
  }, '🧹 Cleanup all chain pods');
  banner.appendChild(el('div', { class: 'chain-cleanup' }, [cleanupBtn]));

  
  const resultCard = document.getElementById('result-card');
  if (resultCard) resultCard.parentNode.insertBefore(banner, resultCard);
}

document.addEventListener('click', (ev) => {
  if (ev.target.id !== 'export-csv') return;
  if (!STATE.currentScanId) { alert('No scan loaded yet.'); return; }
  window.location = `/api/scans/${STATE.currentScanId}/csv`;
});

function mdEscape(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}
function mdBlock(src) {
  const d = document.createElement('div');
  d.className = 'md';
  d.innerHTML = renderMarkdown(src);
  return d;
}

function renderIdentityBanner(id) {
  const box = document.getElementById('identity-banner');
  if (!box) return;
  if (!id || !id.username) { box.textContent = ''; return; }
  const parts = [];
  parts.push(`user=${id.username}`);
  if (id.uid) parts.push(`uid=${id.uid}`);
  if (id.groups && id.groups.length) {
    const short = id.groups.slice(0, 5);
    const more = id.groups.length > 5 ? ` +${id.groups.length - 5}` : '';
    parts.push(`groups=[${short.join(', ')}${more}]`);
  }
  if (id.isClusterAdmin) parts.push('★ cluster-admin');
  if (id.canImpersonate) parts.push('impersonate=yes');
  if ((id.impersonatableUsers || []).length)           parts.push(`impUsers=${id.impersonatableUsers.join(',')}`);
  if ((id.impersonatableGroups || []).length)          parts.push(`impGroups=${id.impersonatableGroups.join(',')}`);
  if ((id.impersonatableServiceAccounts || []).length) parts.push(`impSAs=${id.impersonatableServiceAccounts.join(',')}`);
  if ((id.tokenRequestSAs || []).length)               parts.push(`tokenRequest=${id.tokenRequestSAs.join(',')}`);
  if (id.discoverySource) parts.push(`(via ${id.discoverySource})`);
  box.textContent = '';
  box.appendChild(document.createTextNode(parts.join('  ·  ')));

  
  if (id.namespacedRules && Object.keys(id.namespacedRules).length) {
    const detBox = document.createElement('details');
    detBox.className = 'identity-rules';
    const sum = document.createElement('summary');
    const nsCount = Object.keys(id.namespacedRules).length;
    const rCount  = Object.values(id.namespacedRules).reduce((a, r) => a + (r ? r.length : 0), 0);
    sum.textContent = `what I can do in ${nsCount} namespace(s) (${rCount} rule(s)) ▾`;
    detBox.appendChild(sum);
    for (const ns of Object.keys(id.namespacedRules).sort()) {
      const h = document.createElement('h4');
      h.textContent = `ns/${ns}`;
      detBox.appendChild(h);
      const pre = document.createElement('pre');
      pre.className = 'identity-rules-pre';
      const rows = id.namespacedRules[ns] || [];
      const text = rows.map(r => {
        const verbs = (r.verbs || []).join(',');
        if (r.resources && r.resources.length) {
          const ag = (r.apiGroups && r.apiGroups[0]) || 'core';
          return `  ${verbs}  ${r.resources.join(',')}  (${ag})`;
        }
        if (r.nonResourceURLs && r.nonResourceURLs.length) {
          return `  ${verbs}  ${r.nonResourceURLs.join(',')}`;
        }
        return `  ${verbs}`;
      }).join('\n');
      pre.textContent = text;
      detBox.appendChild(pre);
    }
    box.appendChild(detBox);
  }
}

function identityNodeID(username) {
  if (!username) return '';
  if (username.startsWith('system:serviceaccount:')) {
    const parts = username.slice('system:serviceaccount:'.length).split(':');
    if (parts.length === 2) return `ServiceAccount/${parts[0]}/${parts[1]}`;
  }
  return 'User/' + username;
}

function isFromMeLabel(startLabel, id) {
  if (!id) return false;
  const source = (startLabel || '').replace(/\s*🎯\s*$/, '').trim();
  if (source === identityNodeID(id.username)) return true;
  if (source === STATE.graph?.me) return true;
  for (const g of (id.groups || [])) {
    if (source === 'Group/' + g) return true;
  }
  for (const sa of (id.impersonatableServiceAccounts || [])) {
    if (sa === '*' && source.startsWith('ServiceAccount/')) return true;
    if (source === 'ServiceAccount/' + sa) return true;
  }
  for (const sa of (id.tokenRequestSAs || [])) {
    if (sa.endsWith('/*') && source.startsWith('ServiceAccount/' + sa.slice(0, -1))) return true;
    if (source === 'ServiceAccount/' + sa) return true;
  }
  return false;
}

function whoViaLabel(startLabel, id) {
  if (!id) return '—';
  const source = (startLabel || '').replace(/\s*🎯\s*$/, '').trim();
  if (source === identityNodeID(id.username) || source === STATE.graph?.me) return 'you';
  for (const g of (id.groups || [])) {
    if (source === 'Group/' + g) return 'group:' + g;
  }
  for (const sa of (id.impersonatableServiceAccounts || [])) {
    if (source === 'ServiceAccount/' + sa || (sa === '*' && source.startsWith('ServiceAccount/'))) return 'impersonate SA';
  }
  return isFromMeLabel(source, id) ? 'SA token request' : '—';
}

function renderThreatIntelStatus(meta) {
  const box = document.getElementById('intel-status');
  if (!box) return;
  const t = meta?.threatIntel;
  if (!t) { box.textContent = ''; return; }
  const parts = [];
  if (t.kevEntries) parts.push(`CISA KEV: ${t.kevEntries} CVEs (fetched ${new Date(t.kevFetched).toLocaleString()})`);
  if (t.trivyDbUpdated) parts.push(`Trivy DB refreshed ${new Date(t.trivyDbUpdated).toLocaleString()}`);
  if (t.nucleiTemplatesUpdated) parts.push(`Nuclei templates ${new Date(t.nucleiTemplatesUpdated).toLocaleString()}`);
  if (t.warnings && t.warnings.length) parts.push('warnings: ' + t.warnings.join(' · '));
  box.textContent = parts.join(' · ') || 'no threat-intel sources active';
}

function openAcceptModal(f) {
  const overlay = el('div', { class: 'modal-overlay' });
  const form = el('div', { class: 'modal' });
  form.appendChild(el('h3', {}, 'Accept finding'));
  form.appendChild(el('p', { class: 'modal-purpose' },
    `${f.title} — ${resourceStr(f.resource)}. Accepting removes it from the active list.`));
  form.appendChild(el('label', {}, 'Reason (optional but recommended)'));
  const reason = el('textarea', { rows: '3', placeholder: 'e.g. privileged container expected for CI runner' });
  form.appendChild(reason);
  const globalWrap = el('label', { class: 'check' });
  const globalBox = el('input', { type: 'checkbox' });
  globalWrap.append(globalBox, document.createTextNode(' Accept globally (applies to every future scan until removed)'));
  form.appendChild(globalWrap);
  const buttons = el('div', { class: 'modal-buttons' });
  const cancel = el('button', { class: 'btn' }, 'Cancel');
  const ok = el('button', { class: 'btn btn-primary' }, 'Accept');
  cancel.addEventListener('click', () => overlay.remove());
  ok.addEventListener('click', async () => {
    await acceptFinding(f, reason.value, globalBox.checked);
    overlay.remove();
  });
  buttons.append(cancel, ok);
  form.appendChild(buttons);
  overlay.appendChild(form);
  overlay.addEventListener('click', ev => { if (ev.target === overlay) overlay.remove(); });
  document.body.appendChild(overlay);
  reason.focus();
}

function renderMarkdown(src) {
  if (src == null) return '';
  let s = String(src);
  
  const codeBlocks = [];
  s = s.replace(/```([\s\S]*?)```/g, (m, code) => {
    codeBlocks.push(code);
    return `@@CODEBLOCK${codeBlocks.length - 1}@@`;
  });
  s = mdEscape(s);
  
  s = s.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
  
  s = s.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  s = s.replace(/\b_([^_]+)_\b/g, '<i>$1</i>');
  
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g,
    '<a href="$2" target="_blank" rel="noopener">$1</a>');
  
  s = s.replace(/^###\s+(.*)$/gm, '<h4>$1</h4>');
  s = s.replace(/^##\s+(.*)$/gm,  '<h3>$1</h3>');
  s = s.replace(/^#\s+(.*)$/gm,   '<h2>$1</h2>');
  
  s = s.replace(/^(?:\d+\.)\s+(.*)$/gm, '<li>$1</li>');
  
  s = s.replace(/^[-*]\s+(.*)$/gm, '<li>$1</li>');
  
  s = s.replace(/(?:<li>.*<\/li>\n?)+/g, m => `<ul>${m}</ul>`);
  
  s = s.replace(/^---+$/gm, '<hr>');
  
  s = s.replace(/\n\n+/g, '<br><br>');
  s = s.replace(/\n/g, '<br>');
  
  s = s.replace(/@@CODEBLOCK(\d+)@@/g, (_, i) => `<pre class="md-code">${mdEscape(codeBlocks[+i])}</pre>`);
  return s;
}

async function acceptFinding(f, reason, asGlobal) {
  const r = await fetch(`/api/scans/${STATE.currentScanId}/accept`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      findingId: f.id,
      reason: reason || '',
      by: 'local',
      global: !!asGlobal,
    }),
  });
  const res = await r.json();
  if (!r.ok) { alert(res.error || 'accept failed'); return; }
  if (res.globalError) { alert('Finding accepted in this scan, but the global accept was not saved: ' + res.globalError); }

  STATE.findings = STATE.findings.filter(x => x.id !== f.id);
  STATE.accepted = STATE.accepted || [];
  const acc = {...f, accepted: true, acceptedReason: reason || '', acceptedBy: 'local', acceptedScope: asGlobal ? 'global' : 'scan'};
  STATE.accepted.unshift(acc);
  if (res.summary) STATE.summary = res.summary;
  renderSummary({ summary: STATE.summary, metadata: STATE.metadata });
  renderFindings();
  renderAccepted();
}

async function unacceptFinding(f, removeGlobally) {
  const r = await fetch(`/api/scans/${STATE.currentScanId}/unaccept`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ findingId: f.id, global: !!removeGlobally }),
  });
  const res = await r.json();
  if (!r.ok) { alert(res.error || 'unaccept failed'); return; }
  STATE.accepted = (STATE.accepted || []).filter(x => x.id !== f.id);
  const back = {...f, accepted: false, acceptedReason: '', acceptedBy: '', acceptedScope: ''};
  STATE.findings.push(back);
  if (res.summary) STATE.summary = res.summary;
  renderSummary({ summary: STATE.summary, metadata: STATE.metadata });
  renderFindings();
  renderAccepted();
}

function renderAccepted() {
  const host = document.getElementById('accepted-list');
  const cnt = document.getElementById('accepted-count');
  if (!host) return;
  const list = STATE.accepted || [];
  cnt.textContent = list.length ? `(${list.length})` : '';
  host.innerHTML = '';
  if (!list.length) {
    host.appendChild(el('p', { class: 'muted' }, 'No accepted findings yet.'));
    return;
  }
  for (const f of list) {
    const card = el('div', { class: 'accepted-item' });
    card.appendChild(el('div', { class: 'head' }, [
      el('span', { class: 'pill pill-' + f.severity }, f.severity),
      el('span', { class: 'pill pill-' + (f.acceptedScope || 'scan') }, f.acceptedScope || 'scan'),
      el('div', { class: 'title' }, [document.createTextNode(f.title), el('span', { class: 'rid' }, ' ' + f.ruleId)]),
    ]));
    if (f.acceptedReason) card.appendChild(el('div', { class: 'accepted-reason' }, 'reason: ' + f.acceptedReason));
    if (f.resource) card.appendChild(el('div', { class: 'muted' }, resourceStr(f.resource)));
    const row = el('div', { class: 'accepted-actions' });
    const un = el('button', { class: 'btn' }, 'Un-accept');
    un.addEventListener('click', () => unacceptFinding(f, f.acceptedScope === 'global'));
    row.appendChild(un);
    card.appendChild(row);
    host.appendChild(card);
  }
}

async function loadGlobal() {
  const host = document.getElementById('global-list');
  if (!host) return;
  host.innerHTML = '<p class="muted">loading…</p>';
  try {
    const r = await fetch('/api/accepted');
    const d = await r.json();
    const path = d.path || '~/.kube-dementor/accepted.json';
    const gp = document.getElementById('global-path');
    if (gp) gp.textContent = path;
    host.innerHTML = '';
    const items = d.items || [];
    if (!items.length) {
      host.appendChild(el('p', { class: 'muted' }, 'No globally accepted findings.'));
      return;
    }
    for (const it of items) {
      const row = el('div', { class: 'accepted-item' });
      row.appendChild(el('div', { class: 'head' }, [
        el('span', { class: 'pill pill-global' }, 'global'),
        el('div', { class: 'title' }, [document.createTextNode(it.title || it.resource || it.ruleId), el('span', { class: 'rid' }, ' ' + it.ruleId)]),
      ]));
      if (it.reason) row.appendChild(el('div', { class: 'accepted-reason' }, 'reason: ' + it.reason));
      if (it.resource) row.appendChild(el('div', { class: 'muted' }, it.resource));
      const acts = el('div', { class: 'accepted-actions' });
      const rm = el('button', { class: 'btn' }, 'Remove from global');
      rm.addEventListener('click', async () => {
        if (!confirm('Remove this global accept? Subsequent scans will flag this finding again.')) return;
        const resp = await fetch('/api/accepted/' + encodeURIComponent(it.signature), { method: 'DELETE' });
        if (!resp.ok) {
          let message = 'HTTP ' + resp.status;
          try { message = (await resp.json()).error || message; } catch {}
          alert('Could not remove global accept: ' + message);
          return;
        }
        loadGlobal();
      });
      acts.appendChild(rm);
      row.appendChild(acts);
      host.appendChild(row);
    }
  } catch (e) {
    host.innerHTML = '<p class="muted">failed: ' + e.message + '</p>';
  }
}
