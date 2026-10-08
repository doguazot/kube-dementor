const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'assets', 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, 'assets', 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, 'assets', 'style.css'), 'utf8');
const navigation = source.slice(source.indexOf('function activateTab('), source.indexOf("$$('.tab').forEach(btn =>"));
const planFunctions = source.slice(source.indexOf('function readScanPlan('), source.indexOf('function helpPopoverPosition('));
const helpFunctions = source.slice(source.indexOf('function helpPopoverPosition('), source.indexOf("['input', 'change'].forEach"));
const historyFunction = source.slice(source.indexOf('async function openScan('), source.indexOf('const NODE_STYLE ='));

function node(attrs = {}) {
  const classes = new Set();
  return {
    ...attrs,
    textContent: '',
    attributes: {},
    classList: {
      toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
    setAttribute(key, value) { this.attributes[key] = value; },
    removeAttribute(key) { delete this.attributes[key]; },
    getAttribute(key) { return this.attributes[key] || null; },
  };
}

function navigationContext() {
  const tabs = [
    ['run', 'sp-main'], ['run', 'sp-extras'], ['run', 'sp-redteam'],
    ['run', 'sp-exclusions'], ['accepted'], ['global'], ['history'],
  ].map(([tab, subpage]) => {
    const button = node({ dataset: { tab } });
    if (subpage) button.setAttribute('for', subpage);
    return button;
  });
  const panels = ['run', 'accepted', 'global', 'history'].map(tab => node({ id: 'tab-' + tab }));
  const radios = Object.fromEntries(['main', 'extras', 'redteam', 'exclusions'].map(name => ['sp-' + name, node({ checked: false })]));
  const status = node();
  let historyLoads = 0;
  let globalLoads = 0;
  let popoverClosed = false;
  let reportLoaded = '';
  const context = {
    STATE: {},
    document: { getElementById: id => radios[id] },
    $$: selector => selector === '.tab' ? tabs : selector === '.tab-panel' ? panels :
      [{ hidePopover() { popoverClosed = true; } }],
    $: selector => selector === '.tab[for="sp-main"]' ? tabs[0] : selector === '#run-status' ? status : node(),
    loadHistory() { historyLoads++; },
    loadGlobal() { globalLoads++; },
    async loadScanResult(id) { reportLoaded = id; },
  };
  vm.runInNewContext(navigation + historyFunction, context);
  return {
    context, tabs, panels, radios,
    state: () => ({ historyLoads, globalLoads, popoverClosed, reportLoaded }),
  };
}

function planContext(values = {}) {
  const controls = {
    '#f-context': node({ value: 'demo-context' }),
    '#f-ns': node({ value: '' }),
    '#f-mode': node({ value: 'exploit' }),
    '#f-level': node({ value: 'read-only' }),
    '#f-profile': node({ value: 'external' }),
    '#f-no-guard': node({ checked: false }),
    '#f-guard': node({ checked: true }),
    '#f-exclusions': node({ value: '' }),
    ...Object.fromEntries(['trivy', 'nuclei', 'stealth', 'runtime', 'cni'].map(id => ['#f-' + id, node({ checked: false })])),
  };
  Object.entries(values).forEach(([key, value]) => Object.assign(controls[key], value));
  const output = Object.fromEntries([
    'context', 'namespace', 'mode', 'level', 'profile', 'guard', 'activity', 'modules', 'exclusions',
  ].map(key => ['#plan-' + key, node()]));
  output['#guard-label'] = node();
  const context = { $: selector => controls[selector] || output[selector] };
  vm.runInNewContext(planFunctions, context);
  return { context, controls, output };
}

test('every sidebar destination selects exactly one item and loads its own panel', () => {
  const { context, tabs, panels, radios, state } = navigationContext();
  for (const selected of tabs) {
    context.activateTab(selected);
    assert.deepEqual(tabs.filter(tab => tab.classList.contains('active')), [selected]);
    assert.deepEqual(tabs.filter(tab => tab.attributes['aria-current'] === 'page'), [selected]);
    assert.deepEqual(panels.filter(panel => panel.classList.contains('active')).map(panel => panel.id),
      ['tab-' + selected.dataset.tab]);
    const radio = selected.getAttribute('for');
    if (radio) assert.equal(radios[radio].checked, true);
  }
  assert.equal(state().historyLoads, 1);
  assert.equal(state().globalLoads, 1);
  assert.equal(state().popoverClosed, true);
  assert.doesNotMatch(css, /\.tabs:has\(\.subtab\.active\)\s+\.tab\[data-tab=["']run["']\]/);
});

test('opening a historical report resets subnavigation to the main scan page', async () => {
  const { context, tabs, radios, state } = navigationContext();
  context.activateTab(tabs[3]);
  await context.openScan('historic-report');
  assert.deepEqual(tabs.filter(tab => tab.classList.contains('active')), [tabs[0]]);
  assert.equal(radios['sp-main'].checked, true);
  assert.equal(context.STATE.currentScanId, 'historic-report');
  assert.equal(state().reportLoaded, 'historic-report');
});

test('default scan plan is a selection preview with no optional modules', () => {
  const { context, output } = planContext();
  context.renderScanPlan();
  assert.equal(output['#plan-context'].textContent, 'demo-context');
  assert.equal(output['#plan-namespace'].textContent, 'All permitted namespaces');
  assert.equal(output['#plan-modules'].textContent, 'None enabled');
  assert.equal(output['#plan-exclusions'].textContent, 'None');
  assert.match(output['#plan-activity'].textContent, /may read secrets and tokens/);
});

test('chain preview never claims read-only execution or a disabled mandatory guard', () => {
  const { context, output, controls } = planContext({
    '#f-mode': { value: 'chain' },
    '#f-no-guard': { checked: true },
  });
  context.renderScanPlan();
  assert.equal(output['#plan-level'].textContent, 'Active chain');
  assert.equal(output['#plan-guard'].textContent, 'On (required)');
  assert.match(output['#plan-activity'].textContent, /create test pods.*inject debug containers.*execute in pods/);
  assert.equal(output['#plan-activity'].classList.contains('intrusive'), true);
  assert.equal(controls['#f-guard'].checked, true);
});

test('changed scope, modules and exclusions remain visible in the plan without HTML interpolation', () => {
  const { context, output } = planContext({
    '#f-context': { value: '<script>not-markup</script>' },
    '#f-ns': { value: ' team ' },
    '#f-trivy': { checked: true },
    '#f-cni': { checked: true },
    '#f-exclusions': { value: 'version: 1\nrules: []' },
    '#f-no-guard': { checked: true },
  });
  context.renderScanPlan();
  assert.equal(output['#plan-context'].textContent, '<script>not-markup</script>');
  assert.equal(output['#plan-namespace'].textContent, 'team');
  assert.equal(output['#plan-modules'].textContent, 'Trivy, CNI intelligence');
  assert.equal(output['#plan-exclusions'].textContent, 'Configured');
  assert.equal(output['#plan-guard'].textContent, 'Off');
  assert.equal(output['#plan-guard'].classList.contains('plan-guard-off'), true);
});

test('scan and discover preview do not advertise the unused exploit level', () => {
  for (const mode of ['scan', 'discover']) {
    const { context } = planContext({ '#f-mode': { value: mode } });
    assert.equal(context.readScanPlan().level, 'Not used');
    assert.equal(context.readScanPlan().intrusive, false);
  }
});

test('chain preview reports exclusions as configured but not applied', () => {
  const { context, output } = planContext({
    '#f-mode': { value: 'chain' },
    '#f-exclusions': { value: 'version: 1\nrules: []' },
  });
  context.renderScanPlan();
  assert.equal(output['#plan-exclusions'].textContent, 'Configured (not applied in chain mode)');
  const nonChain = planContext({ '#f-exclusions': { value: 'version: 1\nrules: []' } });
  nonChain.context.renderScanPlan();
  assert.equal(nonChain.output['#plan-exclusions'].textContent, 'Configured');
});

test('exclusion file loading rejects empty, oversized and binary files', async () => {
  const context = {};
  vm.runInNewContext(source.slice(
    source.indexOf('const EXCLUSION_FILE_MAX_BYTES'),
    source.indexOf("document.addEventListener('DOMContentLoaded'"),
  ), context);
  const file = (name, text, size) => ({ name, size: size ?? text.length, text: async () => text });

  assert.equal((await context.readExclusionFile(file('empty.yaml', ''))).ok, false);
  const tooBig = await context.readExclusionFile(file('big.yaml', 'rules: []', 1024 * 1024 + 1));
  assert.equal(tooBig.ok, false);
  assert.match(tooBig.message, /maximum is 1 MB/);
  const binary = await context.readExclusionFile(file('image.png', 'rules: [\u0000\u001B]'));
  assert.equal(binary.ok, false);
  assert.match(binary.message, /not a text/);
  const valid = await context.readExclusionFile(file('ok.yaml', 'version: 1\nrules:\n  - ruleId: KH-WRK-001\n'));
  assert.equal(valid.ok, true);
  assert.match(valid.message, /loaded ok\.yaml/);
  assert.equal((await context.readExclusionFile(null)).ok, false);
});

test('help controls point to unique native popovers with accessible names and explicit field labels', () => {
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(ids).size, ids.length);
  const buttons = [...html.matchAll(/<button\b[^>]*class="field-help"[^>]*>/g)];
  assert.equal(buttons.length, 10);
  for (const [button] of buttons) {
    const popup = button.match(/popovertarget="([^"]+)"/)[1];
    assert.match(button, /type="button"/);
    assert.match(button, /aria-label="Help for [^"]+"/);
    assert.match(button, /aria-expanded="false"/);
    assert.ok(html.includes(`id="${popup}" class="help-popover" popover role="note"`));
  }
  for (const id of ['f-context', 'f-ns', 'f-mode', 'f-level', 'f-sev', 'f-profile']) {
    assert.ok(html.includes(`label for="${id}"`));
  }
  assert.doesNotMatch(html, /class="(?:hero|modules-hint|muted hint)"/);
});

test('help popovers fit the viewport at both desktop and mobile edges', () => {
  const context = {};
  vm.runInNewContext(helpFunctions, context);
  const anchor = { left: 900, right: 932, top: 690 };
  const popup = { width: 304, height: 170 };
  const result = context.helpPopoverPosition(anchor, popup, 1024, 768);
  assert.equal(result.left, 586);
  assert.equal(result.top, 586);
  const mobile = context.helpPopoverPosition({ left: 10, right: 54, top: 0 }, { width: 351, height: 220 }, 375, 667);
  assert.equal(mobile.left, 12);
  assert.equal(mobile.top, 12);
});

test('native help state synchronizes aria-expanded and positions only the open popup', () => {
  const button = node();
  button.setAttribute('popovertarget', 'help-demo');
  button.getBoundingClientRect = () => ({ left: 90, right: 122, top: 100 });
  const handlers = {};
  const popup = {
    style: {},
    open: true,
    matches: () => popup.open,
    getBoundingClientRect: () => ({ width: 304, height: 150 }),
    addEventListener(name, handler) { handlers[name] = handler; },
  };
  const context = {
    $$: () => [button],
    document: { getElementById: () => popup, addEventListener() {} },
    window: { innerWidth: 1440, innerHeight: 900, addEventListener() {} },
    requestAnimationFrame: callback => callback(),
  };
  vm.runInNewContext(helpFunctions, context);
  context.initFieldHelp();
  handlers.beforetoggle({ newState: 'open' });
  assert.equal(button.attributes['aria-expanded'], 'true');
  assert.equal(popup.style.left, '132px');
  assert.equal(popup.style.top, '94px');
  handlers.beforetoggle({ newState: 'closed' });
  assert.equal(button.attributes['aria-expanded'], 'false');
});

async function submittedScan(values = {}) {
  const { controls } = planContext(values);
  controls['#f-hide-fp'] = node({ checked: true });
  controls['#f-refresh-intel'] = node({ checked: true });
  let onRun;
  let payload;
  controls['#run-btn'] = {
    addEventListener(event, callback) { onRun = callback; },
  };
  const context = {
    $: selector => controls[selector] || node(),
    STATE: {},
    document: { getElementById: () => null },
    alert(message) { throw new Error(message); },
    openLogStream() {},
    async fetch(url, options) {
      assert.equal(url, '/api/scans');
      assert.equal(options.method, 'POST');
      payload = JSON.parse(options.body);
      return { ok: true, json: async () => ({ id: 'test-scan' }) };
    },
  };
  vm.runInNewContext(source.slice(source.indexOf("$('#run-btn').addEventListener("),
    source.indexOf('function openLogStream(')), context);
  await onRun();
  return payload;
}

test('default scan submission keeps optional modules off and collects all severities', async () => {
  const payload = await submittedScan();
  assert.equal(payload.context, 'demo-context');
  assert.equal(payload.mode, 'exploit');
  assert.equal(payload.level, 'read-only');
  assert.equal(payload.minSeverity, '');
  assert.equal(payload.disableSafetyGuard, false);
  assert.equal(payload.enableTrivy, false);
  assert.equal(payload.enableNuclei, false);
  assert.equal(payload.enableStealth, false);
  assert.equal(payload.enableRuntimeExtras, false);
  assert.equal(payload.enableCNIExtras, false);
  assert.equal(payload.exclusionYaml, '');
});

test('scan submission includes settings from hidden optional pages without changing the request contract', async () => {
  const exclusions = 'version: 1\nrules: []';
  const payload = await submittedScan({
    '#f-ns': { value: ' team ' },
    '#f-trivy': { checked: true },
    '#f-runtime': { checked: true },
    '#f-exclusions': { value: exclusions },
  });
  assert.equal(payload.namespace, 'team');
  assert.equal(payload.enableTrivy, true);
  assert.equal(payload.enableRuntimeExtras, true);
  assert.equal(payload.enableNuclei, false);
  assert.equal(payload.exclusionYaml, exclusions);
  assert.equal(payload.refreshThreatIntel, true);
  assert.equal(payload.profile, 'external');
  assert.equal(payload.hideFalsePositives, true);
});
