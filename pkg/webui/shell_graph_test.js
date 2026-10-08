const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'assets', 'app.js'), 'utf8');
const shellFunction = source.slice(source.indexOf('async function openShellTerminal('), source.indexOf('// ─── Chain banner'));
const modalFunctions = source.slice(source.indexOf('function openExploitModal('), source.indexOf('// ─── Minimal pod-shell terminal'));
const graphFunctions = source.slice(source.indexOf('const NODE_STYLE ='), source.indexOf('function renderAttackGraph()')) +
  source.slice(source.indexOf('function graphStatusStyle('), source.indexOf('// Paths toolbar'));
const legacyGraphFunction = source.slice(source.indexOf('function legacyChainGraph('), source.indexOf('function graphStatusStyle('));

function element() {
  return {
    children: [], attributes: {}, listeners: {}, style: {}, textContent: '', hidden: false,
    appendChild(child) { this.children.push(child); return child; },
    setAttribute(key, value) { this.attributes[key] = String(value); },
    addEventListener(event, callback) { this.listeners[event] = callback; },
    replaceChildren(...children) { this.children = children; },
    remove() { this.removed = true; },
    focus() {},
    setPointerCapture() {},
    getBoundingClientRect() { return { width: 1200, height: 620, left: 0, top: 0 }; },
  };
}

function terminalContext(fetch, WebSocket) {
  const body = element();
  const context = {
    STATE: { currentScanId: 'scan' }, fetch, WebSocket,
    AbortController, TextDecoder, Uint8Array,
    location: { protocol: 'http:', host: 'fixture.test' },
    document: { body },
    el(tag, attrs = {}, children = []) {
      const node = element();
      node.tag = tag;
      for (const [key, value] of Object.entries(attrs)) {
        if (key.startsWith('on')) node.listeners[key.slice(2)] = value;
        else node[key] = value;
      }
      for (const child of [].concat(children)) node.children.push(child);
      return node;
    },
  };
  vm.runInNewContext(shellFunction, context);
  return { context, body };
}

function modalContext(enabled, fetch) {
  const { context, body } = terminalContext(fetch, class {});
  context.STATE.config = { allowLiveExploit: enabled };
  context.STATE.metadata = { clusterName: 'fixture' };
  vm.runInNewContext(modalFunctions, context);
  context.openExploitModal({ id: 'finding' }, { id: 'host-exec', label: 'Run command on host' });
  const form = body.children[0].children[0];
  return {
    context,
    confirm: form.children.find(child => child.tag === 'input'),
    error: form.children.find(child => child.class === 'modal-err'),
    output: form.children.find(child => child.class === 'modal-output'),
    run: form.children.find(child => child.class === 'modal-buttons').children[1],
  };
}

test('disabled live mode blocks command modal locally without sending a request', async () => {
  let calls = 0;
  const { confirm, error, output, run } = modalContext(false, async () => { calls++; });
  assert.equal(run.disabled, true);
  assert.match(error.textContent, /Live execution is disabled.*No command or shell/);
  confirm.value = 'fixture';
  await run.listeners.click();
  assert.equal(calls, 0);
  assert.equal(output.style.display, 'none');
});

test('rejected command requests display the server error, not a fabricated execution result', async () => {
  const { confirm, error, output, run } = modalContext(true, async () => ({
    ok: false, status: 403, json: async () => ({ error: 'live-exploit disabled on this server' }),
  }));
  confirm.value = 'fixture';
  await run.listeners.click();
  assert.equal(error.textContent, 'live-exploit disabled on this server');
  assert.equal(output.textContent, '');
  assert.equal(output.style.display, 'none');
  assert.equal(run.disabled, false);
});

test('execution result formatting preserves real fields without undefined placeholders', async () => {
  const { context, confirm, output, run } = modalContext(true, async () => ({
    ok: true, json: async () => ({ capabilityId: 'host-exec', startedAt: 'start', finishedAt: 'finish', stdout: 'fixture output' }),
  }));
  confirm.value = 'fixture';
  await run.listeners.click();
  assert.match(output.textContent, /capability: host-exec/);
  assert.match(output.textContent, /started: start.*finished: finish/);
  assert.match(output.textContent, /fixture output/);
  assert.equal(output.style.display, 'block');
  assert.equal(context.formatExecResult({ error: 'disabled' }), 'error: disabled');
});

test('disabled shells show the actual server reason without opening WebSocket', async () => {
  let opened = 0;
  const { context, body } = terminalContext(
    async () => ({ ok: false, json: async () => ({ error: 'interactive shells are disabled' }) }),
    class { constructor() { opened++; } },
  );
  await context.openShellTerminal({ id: 'finding', resource: { namespace: 'team', name: 'target' } }, 'fixture');
  const output = body.children[0].children[0].children[1];
  assert.match(output.textContent, /shell not opened.*interactive shells are disabled/);
  assert.equal(opened, 0);
});

test('terminal close stops its socket and disconnect messages include the close code', async () => {
  let socket;
  class FakeSocket {
    constructor() { socket = this; }
    close() { this.closed = true; }
  }
  const { context, body } = terminalContext(
    async () => ({ ok: true, json: async () => ({ container: 'app', scope: 'container' }) }),
    FakeSocket,
  );
  await context.openShellTerminal({ id: 'finding', resource: { namespace: 'team', name: 'target' } }, 'fixture');
  socket.onclose({ code: 1008, reason: 'denied' });
  const wrap = body.children[0].children[0];
  assert.match(wrap.children[1].textContent, /code=1008: denied/);
  wrap.children[0].children[1].listeners.click();
  assert.equal(socket.closed, true);
  assert.equal(body.children[0].removed, true);
});

test('closing during preflight cannot open a later socket', async () => {
  let complete;
  let opened = 0;
  const response = new Promise(resolve => { complete = resolve; });
  const { context, body } = terminalContext(() => response, class { constructor() { opened++; } });
  const opening = context.openShellTerminal({ id: 'finding', resource: { namespace: 'team', name: 'target' } }, 'fixture');
  body.children[0].children[0].children[0].children[1].listeners.click();
  complete({ ok: true, json: async () => ({ container: 'app', scope: 'container' }) });
  await opening;
  assert.equal(opened, 0);
});

test('visual graph displays failed/skipped/potential states, supports drag/zoom, and keeps labels as text', () => {
  const selectors = Object.fromEntries([
    '#graph-card', '#graph-svg', '#graph-empty', '#graph-detail',
    '#graph-caption', '#graph-count', '#graph-reset', '#graph-onlyme',
  ].map(selector => [selector, element()]));
  const context = {
    $: selector => selectors[selector],
    document: { createElementNS: () => element() },
    STATE: {
      metadata: { mode: 'chain' },
      graph: {
        me: 'operator',
        nodes: [
          { id: 'operator', kind: 'Operator', name: 'Current credentials' },
          { id: 'attempt', kind: 'ChainStep', name: '<script>failed attempt</script>', status: 'failed', detail: 'exec denied' },
          { id: 'cp', kind: 'ChainStep', name: 'Control-plane', status: 'skipped', detail: 'No credentials' },
          { id: 'debug', kind: 'EphemeralCandidate', name: 'Potential debug container', status: 'potential', detail: 'Authorization only; admission and host access unverified' },
        ],
        edges: [
          { from: 'operator', to: 'attempt', kind: 'Attempt', status: 'failed' },
          { from: 'operator', to: 'cp', kind: 'Attempt', status: 'skipped' },
          { from: 'operator', to: 'debug', kind: 'CanInjectEphemeral', status: 'potential' },
        ],
      },
    },
  };
  vm.runInNewContext(graphFunctions, context);
  context.renderVisualGraph();
  const svg = selectors['#graph-svg'];
  const lines = svg.children.filter(child => child.attributes['marker-end']);
  assert.equal(lines[0].attributes.stroke, '#ef4444');
  assert.equal(lines[1].attributes['stroke-dasharray'], '6 4');
  assert.equal(lines[2].attributes.stroke, '#f59e0b', 'authorization-only debug path must remain amber, not successful');
  const target = svg.children.find(child => child.attributes['data-node-id'] === 'attempt');
  target.listeners.click();
  assert.match(selectors['#graph-detail'].textContent, /<script>failed attempt<\/script>/);
  assert.match(selectors['#graph-detail'].textContent, /Status: failed/);
  selectors['#graph-detail'].hidden = true;
  target.onpointerdown({ pointerId: 1, clientX: 100, clientY: 100, stopPropagation() {}, preventDefault() {} });
  svg.onpointerup();
  assert.equal(selectors['#graph-detail'].hidden, false, 'pointer-captured mouse click must open details');
  const before = lines[0].attributes.x2;
  target.onpointerdown({ pointerId: 1, clientX: 100, clientY: 100, stopPropagation() {}, preventDefault() {} });
  svg.onpointermove({ clientX: 150, clientY: 100 });
  svg.onpointerup();
  assert.notEqual(lines[0].attributes.x2, before);
  svg.onwheel({ deltaY: -1, clientX: 600, clientY: 300, preventDefault() {} });
  assert.ok(Number(svg.attributes.viewBox.split(' ')[2]) < 1200);
  selectors['#graph-reset'].onclick();
  assert.equal(svg.attributes.viewBox, '0 0 1200 620');
});

test('chain layout uses separated columns and readable row spacing', () => {
  const context = {};
  vm.runInNewContext(graphFunctions, context);
  const nodes = [{ id: 'me' }, ...Array.from({ length: 12 }, (_, index) => ({ id: `step-${index}` }))];
  const positions = context.layoutChainGraph(nodes, 1200, 620, 'me');
  assert.ok(Math.abs(positions.get('step-0').x - positions.get('step-1').x) > 300);
  assert.ok(Math.abs(positions.get('step-0').y - positions.get('step-2').y) > 80);
});

test('older real-server summary format retains failure and missing-phase status without inventing shell proof', () => {
  const context = {};
  vm.runInNewContext(legacyGraphFunction, context);
  const graph = context.legacyChainGraph({
    metadata: { mode: 'chain' },
    findings: [{ ruleId: 'KH-CHAIN-SUMMARY', description:
      'Maximum Access Achieved: INITIAL\n  1. [✓] assessment → Assessment (0s)\n  2. [✗] pod-creation → Create hostPID (1s)\n' }],
  });
  assert.ok(graph.nodes.some(node => node.phase === 'pod-creation' && node.status === 'failed'));
  assert.ok(graph.nodes.some(node => node.phase === 'control-plane' && node.status === 'skipped'));
  assert.ok(!graph.nodes.some(node => node.highValue));
});
