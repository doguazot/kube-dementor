const API = '';
let graphData = { nodes: [], edges: [] };
let canvas, ctx;
let camera = { x: 0, y: 0, zoom: 1 };
let dragging = null, panStart = null, hoveredNode = null, selectedNode = null;

const NODE_COLORS = { Identity:'#6366f1', PermissionSet:'#f59e0b', Pod:'#22c55e', Container:'#06b6d4', K8sNode:'#ef4444', Volume:'#a855f7', Action:'#a855f7' };
const EDGE_COLORS = { CONTAINS:'#334155', HAS_PERMISSION:'#475569', MEMBER_OF:'#64748b', ROLE_BIND:'#ef4444', POD_EXEC:'#f59e0b', TOKEN_STEAL:'#ec4899', IDENTITY_IMPERSONATE:'#a855f7', CE_PRIV_MOUNT:'#ef4444', CE_NSENTER:'#ef4444', POD_CREATE:'#f59e0b', POD_CREATE_ESCAPE:'#ef4444' };
const ATTACK_EDGES = ['ROLE_BIND','POD_EXEC','TOKEN_STEAL','IDENTITY_IMPERSONATE','CE_PRIV_MOUNT','CE_NSENTER','POD_CREATE','POD_CREATE_ESCAPE'];

async function apiResponse(response) {
  var data = await response.json();
  if (!response.ok) throw new Error(data.error || ('Request failed: HTTP ' + response.status));
  return data;
}
async function apiGet(p) { return apiResponse(await fetch(API+p)); }
async function apiPost(p, b) { return apiResponse(await fetch(API+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})); }
function esc(s) { if(s==null) return ''; var d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }

function switchView(name) {
  document.querySelectorAll('.view').forEach(function(v){v.classList.remove('active');});
  document.querySelectorAll('.nav-btn').forEach(function(b){b.classList.remove('active');});
  document.getElementById('view-'+name).classList.add('active');
  var btn = document.querySelector('[data-view="'+name+'"]');
  if(btn) btn.classList.add('active');
  var loaders = {graph:initGraph, critical:loadCritical, escapes:loadEscapes, paths:loadPaths, exec:loadExec, tokens:loadTokens, impersonate:loadImpersonate, chain:loadChainView, scans:loadScans};
  if(loaders[name]) loaders[name]();
}

async function loadOverview() {
  var stats, expData, critical, escapes, scans;
  try {
    var results = await Promise.all([
      apiGet('/api/v1/stats'),
      apiGet('/api/v1/exploitability'),
      apiGet('/api/v1/critical-assets'),
      apiGet('/api/v1/container-escapes'),
      apiGet('/api/v1/scans')
    ]);
    stats = results[0]; expData = results[1]; critical = results[2]; escapes = results[3]; scans = results[4];
  } catch(e) {
    document.getElementById('overview-content').innerHTML = '<p style="color:var(--red);">Failed to load overview.</p>';
    return;
  }

  var totalNodes = 0;
  for (var k in stats) totalNodes += stats[k];
  document.getElementById('stat-nodes').textContent = totalNodes;

  var critCount = critical ? critical.length : 0;
  var escCount = escapes ? escapes.length : 0;
  document.getElementById('badge-critical').textContent = critCount;
  document.getElementById('badge-escapes').textContent = escCount;

  var edgeCounts = {};
  var totalEdges = 0;
  for (var i = 0; i < ATTACK_EDGES.length; i++) {
    var et = ATTACK_EDGES[i];
    var d = await apiGet('/api/v1/attack-paths?type='+et);
    edgeCounts[et] = d ? d.length : 0;
    totalEdges += edgeCounts[et];
  }
  document.getElementById('stat-edges').textContent = totalEdges;
  document.getElementById('badge-exec').textContent = edgeCounts.POD_EXEC||0;
  document.getElementById('badge-tokens').textContent = edgeCounts.TOKEN_STEAL||0;
  document.getElementById('badge-impersonate').textContent = edgeCounts.IDENTITY_IMPERSONATE||0;
  document.getElementById('badge-paths').textContent = edgeCounts.ROLE_BIND||0;

  var expYes = expData.YES || 0;
  var expNo = expData.NO || 0;
  var expUnchecked = expData.UNCHECKED || 0;

  var el = document.getElementById('overview-content');
  el.innerHTML =
    '<h3>Security Overview</h3><p class="subtitle">Scan results at a glance. Click any card for details.</p>' +
    coverageWarning((scans || [])[0] || {}) +

    '<div class="card-grid" style="grid-template-columns:1fr 1fr 1fr;margin-bottom:16px;">' +
      '<div class="stat-card clickable" style="border-left:3px solid var(--green);cursor:pointer;" onclick="showExploitFindings(\'YES\')">' +
        '<div class="label">Authorized Steps</div>' +
        '<div class="value" style="color:var(--green);">' + expYes + '</div>' +
        '<div class="desc">Authorization is not runtime compromise</div>' +
      '</div>' +
      '<div class="stat-card clickable" style="border-left:3px solid #ef4444;cursor:pointer;" onclick="showExploitFindings(\'NO\')">' +
        '<div class="label">Authority Not Established</div>' +
        '<div class="value" style="color:var(--text-muted);">' + expNo + '</div>' +
        '<div class="desc">Review scope and coverage before concluding safety</div>' +
      '</div>' +
      '<div class="stat-card clickable" style="cursor:pointer;" onclick="showExploitFindings(\'UNCHECKED\')">' +
        '<div class="label">Conditional / Unchecked</div>' +
        '<div class="value">' + expUnchecked + '</div>' +
        '<div class="desc">Includes admitted specifications with untested runtime access</div>' +
      '</div>' +
    '</div>' +

    '<h3 style="margin-top:8px;">Cluster Resources</h3><p class="subtitle">Discovered Kubernetes objects. Click to list.</p>' +
    '<div class="card-grid">' +
      statCard('K8s Nodes', stats.K8sNode||0, '#ef4444', 'K8sNode') +
      statCard('Identities', stats.Identity||0, '#6366f1', 'Identity') +
      statCard('Pods', stats.Pod||0, '#22c55e', 'Pod') +
      statCard('Containers', stats.Container||0, '#06b6d4', 'Container') +
    '</div>' +

    '<h3 style="margin-top:8px;">Attack Vectors</h3><p class="subtitle">Detected attack paths by type. Click to list findings.</p>' +
    '<div class="card-grid">' +
      vecCard('Critical Assets', critCount, '#ef4444', 'critical') +
      vecCard('Container Escapes', escCount, '#ef4444', 'escapes') +
      vecCard('Pod Exec', edgeCounts.POD_EXEC||0, '#f59e0b', 'exec') +
      vecCard('Token Steal', edgeCounts.TOKEN_STEAL||0, '#ec4899', 'tokens') +
      vecCard('Impersonation', edgeCounts.IDENTITY_IMPERSONATE||0, '#a855f7', 'impersonate') +
      vecCard('Role Bindings', edgeCounts.ROLE_BIND||0, '#f59e0b', 'paths') +
      '<div class="stat-card clickable" onclick="showExploitFindings(\'UNCHECKED\')"><div class="label">Prospective Pod Creation</div><div class="value">' + (edgeCounts.POD_CREATE||0) + '</div><div class="desc">Conditional on admission and runtime</div></div>' +
    '</div>' +

    '<div id="overlay-panel" style="display:none;"></div>';
}

function statCard(t, v, c, nodeType) {
  return '<div class="stat-card clickable" style="cursor:pointer;" onclick="showNodeList(\'' + nodeType + '\',\'' + esc(t) + '\',\'' + c + '\')">' +
    '<div class="label">' + esc(t) + '</div><div class="value" style="color:' + c + ';">' + v + '</div>' +
    '<div style="font-size:10px;color:var(--text-muted);margin-top:4px;">click to list</div></div>';
}
function vecCard(t, v, c, viewName) {
  var badge = v > 0
    ? '<span class="tag" style="background:'+c+'22;color:'+c+';">'+v+'</span>'
    : '<span class="tag tag-green">0</span>';
  return '<div class="stat-card clickable" style="cursor:pointer;" onclick="switchView(\'' + viewName + '\')">' +
    '<div style="display:flex;justify-content:space-between;"><span class="label">' + esc(t) + '</span>' + badge + '</div>' +
    '<div class="value" style="color:' + c + ';">' + v + '</div>' +
    '<div style="font-size:10px;color:var(--text-muted);margin-top:4px;">click to view</div></div>';
}

async function showNodeList(nodeType, title, color) {
  var panel = document.getElementById('overlay-panel');
  if (!panel) return;
  panel.style.display = 'block';
  panel.innerHTML = '<div class="loading">Loading ' + esc(title) + '...</div>';

  try {
    var nodes = await apiGet('/api/v1/nodes?type=' + encodeURIComponent(nodeType));
    if (!nodes || !nodes.length) {
      panel.innerHTML = overlayHeader(title, color) + '<p style="color:var(--text-muted);padding:12px;">No ' + esc(title) + ' found in this scan.</p></div>';
      return;
    }

    var html = overlayHeader(title + ' (' + nodes.length + ')', color);
    html += '<table style="width:100%;font-size:12px;"><tr>';

    
    var cols = ['name'];
    if (nodeType === 'Pod') cols = ['name','namespace','nodeName','serviceAccountName'];
    else if (nodeType === 'Container') cols = ['name','image','privileged'];
    else if (nodeType === 'Identity') cols = ['name','namespace','kind'];
    else if (nodeType === 'K8sNode') cols = ['name','kubeletVersion','isControlPlane','internalIP'];
    else if (nodeType === 'Volume') cols = ['name','source'];

    for (var ci = 0; ci < cols.length; ci++) {
      html += '<th style="text-align:left;padding:6px;border-bottom:1px solid var(--border);">' + esc(cols[ci]) + '</th>';
    }
    html += '</tr>';

    for (var ni = 0; ni < nodes.length; ni++) {
      var n = nodes[ni];
      html += '<tr>';
      for (var ci2 = 0; ci2 < cols.length; ci2++) {
        var val = n[cols[ci2]];
        if (val !== null && typeof val === 'object') val = JSON.stringify(val);
        if (val === true) val = 'YES';
        if (val === false) val = 'no';
        html += '<td style="padding:6px;border-bottom:1px solid var(--border);">' + esc(val != null ? String(val) : '-') + '</td>';
      }
      html += '</tr>';
    }
    html += '</table></div>';
    panel.innerHTML = html;
  } catch(e) {
    panel.innerHTML = overlayHeader(title, color) + '<p style="color:var(--red);padding:12px;">Error: ' + esc(e.message) + '</p></div>';
  }
}

async function showExploitFindings(status) {
  var panel = document.getElementById('overlay-panel');
  if (!panel) return;
  panel.style.display = 'block';
  var label = status === 'YES' ? 'Authorized Steps' : status === 'NO' ? 'Authority Not Established' : 'Conditional / Unchecked Steps';
  var color = status === 'YES' ? '#22c55e' : '#ef4444';
  panel.innerHTML = '<div class="loading">Loading findings...</div>';

  try {
    var edges = await apiGet('/api/v1/exploitability-details?status=' + encodeURIComponent(status));

    var html = overlayHeader(label + ' (' + (edges ? edges.length : 0) + ')', color);
    if (!edges || !edges.length) {
      html += '<p style="padding:12px;color:var(--text-muted);">No ' + esc(label.toLowerCase()) + ' in this scan.</p>';
    } else {
      html += '<table style="width:100%;font-size:12px;"><tr><th style="text-align:left;padding:6px;">Type</th><th style="text-align:left;padding:6px;">Source</th><th style="text-align:left;padding:6px;">Target</th><th style="text-align:left;padding:6px;">Severity</th><th style="text-align:left;padding:6px;">Reason</th></tr>';
      for (var i = 0; i < edges.length; i++) {
        var e = edges[i];
        var ec = EDGE_COLORS[e.type] || '#64748b';
        html += '<tr>' +
          '<td style="padding:6px;border-bottom:1px solid var(--border);"><span class="tag" style="background:'+ec+'22;color:'+ec+';">' + esc(e.type) + '</span></td>' +
          '<td style="padding:6px;border-bottom:1px solid var(--border);font-weight:600;">' + esc(e.source) + '</td>' +
          '<td style="padding:6px;border-bottom:1px solid var(--border);">' + esc(e.target) + '</td>' +
          '<td style="padding:6px;border-bottom:1px solid var(--border);">' + esc(e.severity || '-') + '</td>' +
          '<td style="padding:6px;border-bottom:1px solid var(--border);font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(e.reason || e.exp_reason || '-') + '</td>' +
        '</tr>';
      }
      html += '</table>';
    }
    html += '</div>';
    panel.innerHTML = html;
  } catch(e) {
    panel.innerHTML = overlayHeader(label, color) + '<p style="color:var(--red);padding:12px;">Error: ' + esc(e.message) + '</p></div>';
  }
}

function overlayHeader(title, color) {
  return '<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-top:16px;max-height:60vh;overflow-y:auto;">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--surface);z-index:1;">' +
      '<span style="font-weight:700;color:' + color + ';">' + esc(title) + '</span>' +
      '<button onclick="closeOverlayPanel()" style="background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:18px;">&times;</button>' +
    '</div>';
}

function closeOverlayPanel() {
  var panel = document.getElementById('overlay-panel');
  if (panel) { panel.style.display = 'none'; panel.innerHTML = ''; }
}

async function loadChainView() {
  var el = document.getElementById('chain-content');
  var identities = [];
  try {
    identities = await apiGet('/api/v1/nodes?type=Identity');
  } catch(e) { el.innerHTML = '<p>Error loading identities: ' + esc(e.message) + '</p>'; return; }

  var options = (identities||[]).map(function(i){ return '<option value="'+esc(i.uid)+'" label="'+esc((i.namespace ? i.namespace+'/' : '')+i.name)+'">'; }).join('');

  el.innerHTML =
    '<h3>Attack Chain Explorer</h3>' +
    '<p class="subtitle">Select an identity to see where it can jump, what it can do, and the full attack chain.</p>' +
    '<div class="chain-search">' +
      '<input type="text" id="chain-input" placeholder="Type or select an identity..." list="chain-dl" />' +
      '<datalist id="chain-dl">' + options + '</datalist>' +
      '<button onclick="runChainSearch()">Analyze</button>' +
    '</div>' +
    '<div id="chain-results"></div>';
}

async function runChainSearch() {
  var name = document.getElementById('chain-input').value.trim();
  if (!name) return;
  var el = document.getElementById('chain-results');
  el.innerHTML = '<div class="loading">Analyzing attack chains...</div>';

  try {
    var data = await apiGet('/api/v1/attack-chain?identity=' + encodeURIComponent(name));
    if (!data) { el.innerHTML = '<p>No data returned.</p>'; return; }

    var reachable = data.reachable || [];
    var perms = data.directPerms || [];

    
    var byType = {};
    for (var i = 0; i < reachable.length; i++) {
      var r = reachable[i];
      var t = r.targetType || 'Unknown';
      if (!byType[t]) byType[t] = [];
      byType[t].push(r);
    }

    var html =
      '<div style="margin-bottom:16px;">' +
        '<div class="stat-card" style="border-left:3px solid var(--accent);">' +
          '<div class="label">Identity: ' + esc(name) + '</div>' +
          '<div style="margin-top:8px;font-size:13px;">' +
            '<b>Direct roles:</b> ' + (perms.length ? perms.map(function(p){ return '<span class="tag tag-orange">' + esc(p.role) + '</span> '; }).join('') : '<span style="color:var(--text-muted);">none</span>') +
          '</div>' +
          '<div style="margin-top:6px;font-size:13px;">' +
            '<b>Reachable targets:</b> ' + reachable.length +
          '</div>' +
        '</div>' +
      '</div>';

    var types = Object.keys(byType);
    for (var ti = 0; ti < types.length; ti++) {
      var type = types[ti];
      var items = byType[type];
      var color = NODE_COLORS[type] || '#64748b';
      html += '<h3 style="margin-top:16px;font-size:14px;">Can reach: ' + esc(type) + ' (' + items.length + ')</h3>';
      var limit = Math.min(items.length, 30);
      for (var ii = 0; ii < limit; ii++) {
        var item = items[ii];
        var chain = item.edgeType || (item.edgeTypes || []).join(' → ');
        html +=
          '<div class="chain-node" onclick="chainJump(\'' + esc(item.targetName) + '\')">' +
            '<div class="legend-dot" style="background:' + color + ';"></div>' +
            '<div style="flex:1;">' +
              '<div style="font-weight:600;">' + esc(item.targetName) + '</div>' +
              '<div style="font-size:11px;color:var(--text-muted);">via: ' + esc(chain) + ' (' + (item.hops||'?') + ' hops)</div>' +
            '</div>' +
            '<span style="font-size:10px;color:var(--text-muted);">click to explore →</span>' +
          '</div>';
      }
      if (items.length > 30) {
        html += '<div style="font-size:11px;color:var(--text-muted);padding:6px;">...and ' + (items.length - 30) + ' more</div>';
      }
    }

    if (reachable.length === 0) {
      html += '<div style="padding:20px;text-align:center;color:var(--text-muted);">This identity has no outgoing attack paths.</div>';
    }

    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = '<p style="color:var(--red);">Error: ' + esc(e.message) + '</p>';
  }
}

function chainJump(name) {
  document.getElementById('chain-input').value = name;
  runChainSearch();
}

async function loadCritical() {
  var data = await apiGet('/api/v1/critical-assets');
  var el = document.getElementById('critical-content');
  if (!data || !data.length) { el.innerHTML = '<p>No critical assets found.</p>'; return; }
  el.innerHTML = '<h3>Critical Assets</h3><p class="subtitle">Identities with path to cluster-admin</p>' +
    '<table><tr><th>Name</th><th>Namespace</th><th>Kind</th></tr>' +
    data.map(function(r){ return '<tr><td><b>'+esc(r.name)+'</b></td><td>'+esc(r.namespace||'-')+'</td><td><span class="tag tag-red">'+esc(r.kind)+'</span></td></tr>'; }).join('') +
    '</table>';
}

async function loadEscapes() {
  var data = await apiGet('/api/v1/container-escapes');
  var el = document.getElementById('escapes-content');
  if (!data || !data.length) { el.innerHTML = '<p>No container escapes found.</p>'; return; }
  el.innerHTML = '<h3>Container Escapes</h3><p class="subtitle">Containers that can escape to the node. Click for details.</p>' +
    data.map(function(r, i) {
      return findingCard('esc-'+i, r.escapeType, r.details?.severity||'CRITICAL',
        r.containerName+' → '+(r.nodeName||'?'),
        r.details?.reason||'', r.details?.impact||'', r.details?.exploit_cmd||'',
        r.details?.remediation||'',
        {container:r.containerName, node:r.nodeName, _exploitable:r.details?.exploitable, _exploitable_reason:r.details?.exploitable_reason});
    }).join('');
  bindFindingToggles();
}

async function loadPaths() { await loadEdgeFindings('paths', 'ROLE_BIND', 'Critical Role Bindings', 'Identities bound to critical roles'); }
async function loadExec() { await loadEdgeFindings('exec', 'POD_EXEC', 'Pod Exec Paths', 'Identities that can exec into pods'); }
async function loadTokens() { await loadEdgeFindings('tokens', 'TOKEN_STEAL', 'Token Steal', 'Pods mounting high-privilege SA tokens'); }
async function loadImpersonate() { await loadEdgeFindings('impersonate', 'IDENTITY_IMPERSONATE', 'Identity Impersonation', 'Identities that can impersonate others'); }

async function loadEdgeFindings(viewId, edgeType, title, subtitle) {
  var data = await apiGet('/api/v1/attack-paths?type='+edgeType);
  var el = document.getElementById(viewId+'-content');
  if (!data || !data.length) { el.innerHTML = '<p>No findings.</p>'; return; }
  el.innerHTML = '<h3>'+esc(title)+'</h3><p class="subtitle">'+esc(subtitle)+'. Click a finding for details.</p>' +
    data.map(function(r, i) {
      return findingCard(viewId+'-'+i, edgeType, r.properties?.severity||'HIGH',
        (r.sourceName||'?')+' → '+(r.targetName||'?'),
        r.properties?.reason||'', r.properties?.impact||'', r.properties?.exploit_cmd||'',
        r.properties?.remediation||'',
        {source:r.sourceName, target:r.targetName, _exploitable:r.properties?.exploitable, _exploitable_reason:r.properties?.exploitable_reason});
    }).join('');
  bindFindingToggles();
}

function findingCard(id, type, severity, title, reason, impact, exploitCmd, remediation, meta) {
  var sevColor = severity==='CRITICAL'?'#ef4444':'#f59e0b';
  var typeColor = EDGE_COLORS[type]||'#6366f1';
  var exp = (meta && meta._exploitable) || 'UNCHECKED';
  var expReason = (meta && meta._exploitable_reason) || '';
  var expColor, expLabel;
  if (exp === 'YES') { expColor = '#22c55e'; expLabel = 'AUTHORIZED STEP'; }
  else if (exp === 'NO') { expColor = '#ef4444'; expLabel = 'AUTHORITY NOT ESTABLISHED'; }
  else { expColor = '#8892b0'; expLabel = 'CONDITIONAL / UNCHECKED'; }

  var borderStyle = '';
  if (exp === 'YES') borderStyle = 'border-left:3px solid #22c55e;';
  else if (exp === 'NO') borderStyle = 'border-left:3px solid #334155;opacity:0.7;';

  var metaParts = [];
  if (meta) {
    var keys = Object.keys(meta);
    for (var i = 0; i < keys.length; i++) {
      if (!keys[i].startsWith('_') && meta[keys[i]]) {
        metaParts.push('<span style="font-size:11px;color:var(--text-muted);margin-right:10px;"><b>'+esc(keys[i])+':</b> '+esc(meta[keys[i]])+'</span>');
      }
    }
  }

  return '<div class="finding-card" style="'+borderStyle+'">' +
    '<div class="finding-header" data-finding="'+id+'">' +
      '<span class="arrow">&#9654;</span>' +
      '<span class="tag" style="background:'+sevColor+'22;color:'+sevColor+';">'+esc(severity)+'</span>' +
      '<span class="tag" style="background:'+typeColor+'22;color:'+typeColor+';">'+esc(type)+'</span>' +
      '<span class="tag" style="background:'+expColor+'22;color:'+expColor+';">'+expLabel+'</span>' +
      '<span style="font-size:12px;font-weight:600;">'+esc(title)+'</span>' +
    '</div>' +
    '<div class="finding-body" data-finding-body="'+id+'">' +
      '<div style="padding:8px 12px;margin-top:10px;background:'+expColor+'11;border:1px solid '+expColor+'33;border-radius:6px;display:flex;align-items:center;gap:8px;">' +
        '<span class="tag" style="background:'+expColor+'22;color:'+expColor+';">'+expLabel+'</span>' +
        '<span style="font-size:12px;">'+esc(expReason)+'</span>' +
      '</div>' +
      (metaParts.length ? '<div style="padding-top:10px;">'+metaParts.join('')+'</div>' : '') +
      (reason ? '<div class="finding-section"><div class="finding-section-title">Why detected?</div><div class="finding-text">'+esc(reason)+'</div></div>' : '') +
      (impact ? '<div class="finding-section"><div class="finding-section-title">Impact</div><div class="impact-box">'+esc(impact)+'</div></div>' : '') +
      (exploitCmd ? '<div class="finding-section"><div class="finding-section-title">Verification Commands</div><div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button>'+esc(exploitCmd)+'</div></div>' : '') +
      (remediation ? '<div class="finding-section"><div class="finding-section-title">Remediation</div><div class="remediation-box">'+esc(remediation)+'</div></div>' : '') +
    '</div></div>';
}

function bindFindingToggles() {
  document.querySelectorAll('.finding-header').forEach(function(h) {
    h.onclick = function() {
      var body = document.querySelector('[data-finding-body="'+this.dataset.finding+'"]');
      body.classList.toggle('open');
      this.classList.toggle('open');
    };
  });
}

function copyCode(btn) {
  var text = btn.parentElement.textContent.replace('Copy','').trim();
  navigator.clipboard.writeText(text).then(function(){ btn.textContent='Copied!'; setTimeout(function(){ btn.textContent='Copy'; }, 1500); });
}

async function loadScans() {
  graphInited = false;
  var el = document.getElementById('scans-content');
  var scans = [];
  try { scans = await apiGet('/api/v1/scans'); } catch(e) {   }

  el.innerHTML =
    '<h3>Scan Management</h3><p class="subtitle">Run new scans and view past results</p>' +
    '<div class="scan-form">' +
      '<label>Namespace (empty = visible scope / context namespace)</label>' +
      '<input type="text" id="scan-namespace" placeholder="e.g. kube-system" />' +
      '<label>Kubeconfig path (empty = default)</label>' +
      '<input type="text" id="scan-kubeconfig" placeholder="e.g. ~/.kube/config" />' +
      '<button class="btn-scan" onclick="triggerScan()">Start New Scan</button>' +
    '</div>' +
    '<div id="scan-status"></div>' +
    '<h3 style="margin-top:16px;">Scan History</h3>' +
    '<div id="scan-list">' + renderScanList(scans) + '</div>';
}

function renderScanList(scans) {
  if (!scans || !scans.length) return '<p style="color:var(--text-muted);font-size:13px;">No scans recorded yet.</p>';
  var html = '';
  for (var i = 0; i < scans.length; i++) {
    var s = scans[i];
    var statusColor = s.status==='completed'?'var(--green)':s.status==='running'?'var(--orange)':'var(--red)';
    var dur = '...';
    if (s.finishedAt && s.startedAt) {
      dur = Math.round((new Date(s.finishedAt) - new Date(s.startedAt)) / 1000);
    }
    var clickable = s.status === 'completed' ? ' style="cursor:pointer;" onclick="viewScanDetail(\'' + esc(s.id) + '\')"' : '';
    html += '<div class="scan-item"' + clickable + '>' +
      '<div style="display:flex;justify-content:space-between;align-items:center;">' +
        '<span style="font-weight:600;font-size:13px;">' + esc(s.id) + '</span>' +
        '<div>' +
          (s.status === 'completed' ? '<span style="font-size:10px;color:var(--accent);margin-right:8px;">click to view findings →</span>' : '') +
          '<span class="tag" style="color:'+statusColor+';">' + esc(s.status) + '</span>' +
        '</div>' +
      '</div>' +
      '<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">' +
        'Namespace: ' + esc(s.namespace || 'visible scope') + ' | Duration: ' + dur + 's | Nodes: ' + (s.nodeCount||0) + ' | Edges: ' + (s.edgeCount||0) +
      '</div>' +
      '<div style="font-size:11px;margin-top:4px;">' +
        '<span style="color:var(--green);">Authorized: ' + (s.exploitable||0) + '</span>' +
        ' | <span style="color:var(--text-muted);">Authority not established: ' + (s.notExploitable||0) + '</span>' +
        ' | Conditional / unchecked: ' + (s.unchecked||0) +
      '</div>' +
      (s.error ? '<div style="font-size:11px;color:var(--red);margin-top:4px;">' + esc(s.error) + '</div>' : '') +
      coverageWarning(s) +
    '</div>';
  }
  return html;
}

async function viewScanDetail(scanId) {
  var el = document.getElementById('scans-content');
  el.innerHTML = '<div class="loading">Loading scan results...</div>';

  try {
    var data = await apiGet('/api/v1/scans/' + encodeURIComponent(scanId));
    if (!data) { el.innerHTML = '<p>No data.</p>'; return; }

    var meta = data.meta || {};
    var nodes = data.nodes || {};
    var edges = data.edges || [];
    var note = data.note || '';

    var dur = '...';
    if (meta.finishedAt && meta.startedAt) {
      dur = Math.round((new Date(meta.finishedAt) - new Date(meta.startedAt)) / 1000);
    }

    
    var byType = {};
    for (var i = 0; i < edges.length; i++) {
      var e = edges[i];
      if (!byType[e.type]) byType[e.type] = [];
      byType[e.type].push(e);
    }

    var html = '<button class="nav-btn" style="margin-bottom:12px;" onclick="loadScans()">← Back to Scan List</button>';

    
    html += '<div class="stat-card" style="border-left:3px solid var(--accent);margin-bottom:16px;">' +
      '<div class="label" style="font-size:15px;font-weight:700;">' + esc(scanId) + '</div>' +
      '<div style="font-size:12px;color:var(--text-muted);margin-top:6px;">' +
        'Started: ' + esc(meta.startedAt ? new Date(meta.startedAt).toLocaleString() : '?') +
        ' | Duration: ' + dur + 's' +
        ' | Namespace: ' + esc(meta.namespace || 'cluster-wide') +
      '</div>' +
      '<div style="margin-top:10px;display:flex;gap:16px;">' +
        '<div><span style="font-weight:600;color:var(--green);font-size:18px;">' + (meta.exploitable||0) + '</span><div style="font-size:11px;color:var(--text-muted);">Authorized Steps</div></div>' +
        '<div><span style="font-weight:600;color:var(--red);font-size:18px;">' + (meta.notExploitable||0) + '</span><div style="font-size:11px;color:var(--text-muted);">Authority Not Established</div></div>' +
        '<div><span style="font-weight:600;font-size:18px;">' + (meta.unchecked||0) + '</span><div style="font-size:11px;color:var(--text-muted);">Conditional / Unchecked</div></div>' +
        '<div><span style="font-weight:600;font-size:18px;">' + (meta.edgeCount||0) + '</span><div style="font-size:11px;color:var(--text-muted);">Total Edges</div></div>' +
        '<div><span style="font-weight:600;font-size:18px;">' + (meta.nodeCount||0) + '</span><div style="font-size:11px;color:var(--text-muted);">Total Nodes</div></div>' +
      '</div>' +
    '</div>';

    html += coverageWarning(meta);

    
    if (nodes.pods || nodes.containers || nodes.identities || nodes.nodes) {
      html += '<h3>Discovered Resources</h3>' +
        '<div class="card-grid">' +
          statCard('Identities', nodes.identities||0, '#6366f1') +
          statCard('Pods', nodes.pods||0, '#22c55e') +
          statCard('Containers', nodes.containers||0, '#06b6d4') +
          statCard('K8s Nodes', nodes.nodes||0, '#ef4444') +
          statCard('Volumes', nodes.volumes||0, '#a855f7') +
        '</div>';
    }

    if (note) {
      html += '<div style="padding:10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text-muted);font-size:12px;margin-top:12px;">' + esc(note) + '</div>';
    }

    
    var edgeTypes = Object.keys(byType);
    if (edgeTypes.length > 0) {
      html += '<h3 style="margin-top:16px;">Findings by Type</h3>';

      
      html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">';
      for (var ti = 0; ti < edgeTypes.length; ti++) {
        var et = edgeTypes[ti];
        var color = EDGE_COLORS[et] || '#64748b';
        html += '<span class="tag" style="background:'+color+'22;color:'+color+';cursor:pointer;" onclick="document.getElementById(\'scan-type-'+et+'\').scrollIntoView({behavior:\'smooth\'})">' + esc(et) + ': ' + byType[et].length + '</span>';
      }
      html += '</div>';

      for (var ti2 = 0; ti2 < edgeTypes.length; ti2++) {
        var eType = edgeTypes[ti2];
        var typeEdges = byType[eType];
        
        if (eType === 'CONTAINS') continue;

        html += '<div id="scan-type-'+eType+'" style="margin-top:12px;">';
        html += '<h4 style="font-size:13px;color:var(--text);">' + esc(eType) + ' <span style="color:var(--text-muted);font-weight:400;">(' + typeEdges.length + ' findings)</span></h4>';

        var showCount = Math.min(typeEdges.length, 50);
        for (var fi = 0; fi < showCount; fi++) {
          var edge = typeEdges[fi];
          var props = edge.properties || {};
          html += findingCard(
            'scan-'+eType+'-'+fi,
            eType,
            props.severity || 'HIGH',
            (edge.sourceName||'?') + ' → ' + (edge.targetName||'?'),
            props.reason || '',
            props.impact || '',
            props.exploit_cmd || '',
            props.remediation || '',
            { source: edge.sourceName, target: edge.targetName, _exploitable: props.exploitable, _exploitable_reason: props.exploitable_reason }
          );
        }
        if (typeEdges.length > 50) {
          html += '<div style="font-size:11px;color:var(--text-muted);padding:8px;">...and ' + (typeEdges.length - 50) + ' more ' + eType + ' findings</div>';
        }
        html += '</div>';
      }
    } else {
      html += '<div style="padding:20px;text-align:center;color:var(--text-muted);margin-top:16px;">No findings recorded for this scan.</div>';
    }

    el.innerHTML = html;
    bindFindingToggles();
  } catch(e) {
    el.innerHTML = '<p style="color:var(--red);">Error loading scan: ' + esc(e.message) + '</p>' +
      '<button class="nav-btn" style="margin-top:8px;" onclick="loadScans()">← Back</button>';
  }
}

async function triggerScan() {
  var ns = document.getElementById('scan-namespace').value.trim();
  var kc = document.getElementById('scan-kubeconfig').value.trim();
  document.getElementById('scan-status').innerHTML =
    '<div style="padding:10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--orange);margin-bottom:8px;">Scan triggered. This may take a minute. The page will refresh data when complete.</div>';
  try {
    await apiPost('/api/v1/scans', { namespace: ns, kubeconfig: kc });
    
    setTimeout(function() { loadScans(); }, 5000);
    setTimeout(function() { loadScans(); }, 15000);
    setTimeout(function() { loadScans(); }, 30000);
    setTimeout(function() { loadScans(); loadOverview(); }, 60000);
    setTimeout(function() { loadScans(); loadOverview(); }, 120000);
  } catch(e) {
    document.getElementById('scan-status').innerHTML = '<div style="color:var(--red);">Error: ' + esc(e.message) + '</div>';
  }
}

async function runCustomQuery() {
  var cypher = document.getElementById('cypher-input').value.trim();
  if (!cypher) return;
  switchView('paths');
  var el = document.getElementById('paths-content');
  el.innerHTML = '<div class="loading">Running query...</div>';
  try {
    var data = await apiPost('/api/v1/query', { cypher: cypher });
    if (!data || !data.length) { el.innerHTML = '<p>No results.</p>'; return; }
    var keys = Object.keys(data[0]);
    el.innerHTML = '<h3>Query Results</h3><p class="subtitle">' + data.length + ' rows</p>' +
      '<table><tr>' + keys.map(function(k){return '<th>'+esc(k)+'</th>';}).join('') + '</tr>' +
      data.map(function(r){return '<tr>'+keys.map(function(k){return '<td style="font-size:12px;">'+esc(String(r[k]!=null?r[k]:''))+'</td>';}).join('')+'</tr>';}).join('') +
      '</table>';
  } catch(e) {
    el.innerHTML = '<p style="color:var(--red);">Error: ' + esc(e.message) + '</p>';
  }
}

var graphInited = false;
function coverageWarning(meta) {
  if (!meta.incomplete) return '';
  return '<div style="color:var(--orange);padding:8px;">Incomplete coverage. Missing data is not evidence of safety.' +
    (meta.warnings || []).map(function(w){ return '<div>' + esc(w) + '</div>'; }).join('') + '</div>';
}
function graphMessage(message) {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#8892b0'; ctx.font = '14px sans-serif'; ctx.textAlign = 'center';
  ctx.fillText(message, canvas.width/2, canvas.height/2);
}
async function initGraph() {
  canvas = document.getElementById('graph-canvas');
  ctx = canvas.getContext('2d');
  resizeCanvas();
  window.removeEventListener('resize', resizeCanvas);
  window.addEventListener('resize', resizeCanvas);

  if (graphInited) return;
  
  var edgesData;
  try {
    edgesData = await apiGet('/api/v1/graph');
  } catch(e) { graphMessage('Graph unavailable: ' + e.message); return; }
  graphInited = true;

  if (!edgesData || !edgesData.length) {
    graphMessage('No graph edges in the collected data. Review scan coverage; this is not a safety guarantee.');
    return;
  }

  
  var nodeMap = {};
  for (var i = 0; i < edgesData.length; i++) {
    var e = edgesData[i];
    if (!nodeMap[e.source]) nodeMap[e.source] = {id:e.source, name:e.sname||e.source, label:e.slabel};
    if (!nodeMap[e.target]) nodeMap[e.target] = {id:e.target, name:e.tname||e.target, label:e.tlabel};
  }

  var nodeArr = Object.values(nodeMap);
  for (var ni = 0; ni < nodeArr.length; ni++) {
    var n = nodeArr[ni];
    var angle = (2 * Math.PI * ni) / nodeArr.length;
    var rad = Math.min(canvas.width, canvas.height) * 0.35;
    n.x = canvas.width/2 + rad * Math.cos(angle) + (Math.random()-0.5)*40;
    n.y = canvas.height/2 + rad * Math.sin(angle) + (Math.random()-0.5)*40;
    n.vx = 0; n.vy = 0;
    n.radius = n.label==='K8sNode'?14 : n.label==='Identity'?10 : 7;
  }

  graphData.nodes = nodeArr;
  graphData.edges = [];
  for (var ei = 0; ei < edgesData.length; ei++) {
    var ed = edgesData[ei];
    if (nodeMap[ed.source] && nodeMap[ed.target]) {
      graphData.edges.push({source: nodeMap[ed.source], target: nodeMap[ed.target], type: ed.type});
    }
  }

  
  var legendHtml = '<div style="font-weight:600;margin-bottom:4px;">Nodes</div>';
  var nodeTypes = Object.keys(NODE_COLORS);
  for (var li = 0; li < nodeTypes.length; li++) {
    if (nodeTypes[li] === 'Volume') continue;
    legendHtml += '<div class="legend-item"><div class="legend-dot" style="background:'+NODE_COLORS[nodeTypes[li]]+';"></div>'+nodeTypes[li]+'</div>';
  }
  legendHtml += '<div style="font-weight:600;margin-top:6px;margin-bottom:4px;">Attack Edges</div>';
  for (var ai = 0; ai < ATTACK_EDGES.length; ai++) {
    legendHtml += '<div class="legend-item"><div class="legend-dot" style="background:'+(EDGE_COLORS[ATTACK_EDGES[ai]]||'#334155')+';"></div>'+ATTACK_EDGES[ai]+'</div>';
  }
  document.getElementById('graph-legend').innerHTML = legendHtml;

  canvas.onmousedown = onMouseDown;
  canvas.onmousemove = onMouseMove;
  canvas.onmouseup = function() { dragging = null; panStart = null; };
  canvas.onwheel = onWheel;
  canvas.ondblclick = onDblClick;

  runSimulation();
}

function resizeCanvas() {
  if (!canvas) return;
  var r = canvas.parentElement.getBoundingClientRect();
  canvas.width = r.width; canvas.height = r.height;
}

function runSimulation() {
  var nodes = graphData.nodes, edges = graphData.edges, alpha = 1;
  function tick() {
    alpha *= 0.995;
    if (alpha < 0.001) alpha = 0.001;

    
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i+1; j < nodes.length; j++) {
        var dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
        var dist = Math.hypot(dx, dy) || 1;
        var force = 1000 / (dist * dist) * alpha;
        var fx = dx/dist*force, fy = dy/dist*force;
        nodes[i].vx -= fx; nodes[i].vy -= fy;
        nodes[j].vx += fx; nodes[j].vy += fy;
      }
    }
    
    for (var ei = 0; ei < edges.length; ei++) {
      var e = edges[ei];
      var dx = e.target.x - e.source.x, dy = e.target.y - e.source.y;
      var dist = Math.hypot(dx, dy) || 1;
      var force = (dist - 100) * 0.004 * alpha;
      var fx = dx/dist*force, fy = dy/dist*force;
      e.source.vx += fx; e.source.vy += fy;
      e.target.vx -= fx; e.target.vy -= fy;
    }
    
    for (var ni = 0; ni < nodes.length; ni++) {
      var n = nodes[ni];
      n.vx += (canvas.width/2 - n.x) * 0.0005 * alpha;
      n.vy += (canvas.height/2 - n.y) * 0.0005 * alpha;
      if (n !== dragging) {
        n.vx *= 0.9; n.vy *= 0.9;
        n.x += n.vx; n.y += n.vy;
      }
    }
    draw();
    requestAnimationFrame(tick);
  }
  tick();
}

function draw() {
  if (!ctx) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.save();
  ctx.translate(camera.x, camera.y);
  ctx.scale(camera.zoom, camera.zoom);

  
  for (var ei = 0; ei < graphData.edges.length; ei++) {
    var e = graphData.edges[ei];
    ctx.beginPath();
    ctx.moveTo(e.source.x, e.source.y);
    ctx.lineTo(e.target.x, e.target.y);
    ctx.strokeStyle = EDGE_COLORS[e.type] || '#334155';
    ctx.lineWidth = 1.5;
    ctx.globalAlpha = 0.6;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  
  for (var ni = 0; ni < graphData.nodes.length; ni++) {
    var n = graphData.nodes[ni];
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI*2);
    ctx.fillStyle = NODE_COLORS[n.label] || '#64748b';
    if (n === hoveredNode || n === selectedNode) {
      ctx.shadowColor = NODE_COLORS[n.label] || '#64748b';
      ctx.shadowBlur = 15;
    }
    ctx.fill();
    ctx.shadowBlur = 0;

    if (n.radius >= 8 || n === hoveredNode) {
      ctx.fillStyle = '#e2e8f0';
      ctx.font = '10px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(n.name || '', n.x, n.y - n.radius - 4);
    }
  }
  ctx.restore();
}

function screenToWorld(sx, sy) {
  return { x: (sx - camera.x) / camera.zoom, y: (sy - camera.y) / camera.zoom };
}
function findNode(sx, sy) {
  var w = screenToWorld(sx, sy);
  for (var i = graphData.nodes.length - 1; i >= 0; i--) {
    var n = graphData.nodes[i];
    var dx = n.x - w.x, dy = n.y - w.y;
    if (dx*dx + dy*dy < (n.radius+4)*(n.radius+4)) return n;
  }
  return null;
}
function onMouseDown(e) {
  var rect = canvas.getBoundingClientRect();
  var mx = e.clientX - rect.left, my = e.clientY - rect.top;
  var node = findNode(mx, my);
  if (node) { dragging = node; }
  else { panStart = { x: mx - camera.x, y: my - camera.y }; }
}
function onMouseMove(e) {
  var rect = canvas.getBoundingClientRect();
  var mx = e.clientX - rect.left, my = e.clientY - rect.top;
  if (dragging) {
    var w = screenToWorld(mx, my);
    dragging.x = w.x; dragging.y = w.y;
    dragging.vx = 0; dragging.vy = 0;
  } else if (panStart) {
    camera.x = mx - panStart.x; camera.y = my - panStart.y;
  } else {
    hoveredNode = findNode(mx, my);
    canvas.style.cursor = hoveredNode ? 'pointer' : 'grab';
  }
}
function onWheel(e) {
  e.preventDefault();
  var rect = canvas.getBoundingClientRect();
  var mx = e.clientX - rect.left, my = e.clientY - rect.top;
  var delta = e.deltaY > 0 ? 0.9 : 1.1;
  var wx = (mx - camera.x) / camera.zoom;
  var wy = (my - camera.y) / camera.zoom;
  camera.zoom *= delta;
  camera.zoom = Math.max(0.1, Math.min(5, camera.zoom));
  camera.x = mx - wx * camera.zoom;
  camera.y = my - wy * camera.zoom;
}
function onDblClick(e) {
  var rect = canvas.getBoundingClientRect();
  var mx = e.clientX - rect.left, my = e.clientY - rect.top;
  var node = findNode(mx, my);
  if (node) { selectedNode = node; showDetail(node); }
}

function showDetail(node) {
  var panel = document.getElementById('detail-panel');
  var content = document.getElementById('detail-content');
  var color = NODE_COLORS[node.label] || '#64748b';
  var edges = graphData.edges.filter(function(e){ return e.source === node || e.target === node; });

  var edgesHtml = '';
  var limit = Math.min(edges.length, 20);
  for (var i = 0; i < limit; i++) {
    var e = edges[i];
    var other = e.source === node ? e.target : e.source;
    var dir = e.source === node ? '→' : '←';
    edgesHtml += '<div style="font-size:12px;padding:4px 0;border-bottom:1px solid var(--border);">' +
      '<span class="tag" style="background:'+(EDGE_COLORS[e.type]||'#334155')+'33;color:'+(EDGE_COLORS[e.type]||'#334155')+';">'+e.type+'</span> ' +
      dir + ' ' + esc(other.name) + '</div>';
  }
  if (edges.length > 20) edgesHtml += '<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">...and '+(edges.length-20)+' more</div>';

  content.innerHTML =
    '<h3 style="color:'+color+';">'+esc(node.label)+'</h3>' +
    '<div class="field"><div class="field-label">Name</div><div class="field-value">'+esc(node.name)+'</div></div>' +
    '<div class="field"><div class="field-label">UID</div><div class="field-value" style="font-size:11px;">'+esc(node.id)+'</div></div>' +
    '<div class="field"><div class="field-label">Connections</div><div class="field-value">'+edges.length+' edges</div></div>' +
    '<div style="margin-top:12px;">'+edgesHtml+'</div>' +
    '<button class="nav-btn" style="margin-top:12px;justify-content:center;" onclick="document.getElementById(\'chain-input\')&&(document.getElementById(\'chain-input\').value=\''+esc(node.name)+'\');switchView(\'chain\');runChainSearch();">Explore attack chain →</button>';
  panel.classList.add('open');
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
  selectedNode = null;
}

loadOverview();
