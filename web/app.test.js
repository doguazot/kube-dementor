const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'static', 'app.js'), 'utf8');
const code = source.slice(0, source.lastIndexOf('loadOverview();'));

function dashboard(fetch) {
  const messages = [];
  const draw = { clearRect() {}, fillText(message) { messages.push(message); } };
  const canvas = {
    getContext: () => draw,
    parentElement: { getBoundingClientRect: () => ({ width: 900, height: 600 }) },
  };
  const nodes = {
    'graph-canvas': canvas,
    'graph-legend': { innerHTML: '' },
    'scans-content': { innerHTML: '' },
    'chain-content': { innerHTML: '' },
  };
  const context = vm.createContext({
    fetch,
    document: { getElementById: id => nodes[id] },
    window: { removeEventListener() {}, addEventListener() {} },
  });
  vm.runInContext(code, context);
  vm.runInContext('runSimulation = () => {}; esc = s => String(s ?? "").replace(/</g, "&lt;");', context);
  return { context, messages, nodes };
}

test('graph includes prospective actions through a fixed endpoint', async () => {
  const requests = [];
  const { context } = dashboard(async url => {
    requests.push(url);
    return {
      ok: true,
      json: async () => [{
        source: 'operator', sname: 'alice', slabel: 'Identity',
        target: 'future-pod', tname: 'create pods', tlabel: 'Action', type: 'POD_CREATE',
      }],
    };
  });
  await context.initGraph();
  assert.deepEqual(requests, ['/api/v1/graph']);
  assert.equal(vm.runInContext('graphData.nodes.length', context), 2);
  assert.equal(vm.runInContext('graphData.edges[0].type', context), 'POD_CREATE');
});

test('failed graph reads never become a safety claim and can retry', async () => {
  const { context, messages } = dashboard(async () => ({
    ok: false, status: 503, json: async () => ({ error: 'graph unavailable' }),
  }));
  await context.initGraph();
  assert.match(messages[0], /Graph unavailable/);
  assert.equal(vm.runInContext('graphInited', context), false);
  assert.ok(messages.every(message => !message.includes('securely configured')));
});

test('empty graph is not a clean bill of health', async () => {
  const { context, messages } = dashboard(async () => ({ ok: true, json: async () => [] }));
  await context.initGraph();
  assert.match(messages[0], /not a safety guarantee/);
});

test('scan list preserves and escapes incomplete coverage warnings', () => {
  const { context } = dashboard();
  const html = context.renderScanList([{
    id: 'fixture', status: 'completed', incomplete: true, warnings: ['<synthetic missing resource>'],
  }]);
  assert.match(html, /Incomplete coverage/);
  assert.ok(!html.includes('<synthetic'));
});

test('identity picker works without arbitrary query permissions', async () => {
  const requests = [];
  const { context, nodes } = dashboard(async url => {
    requests.push(url);
    return { ok: true, json: async () => [{ uid: 'sa-uid', name: 'runner', namespace: 'team' }] };
  });
  await context.loadChainView();
  assert.deepEqual(requests, ['/api/v1/nodes?type=Identity']);
  assert.match(nodes['chain-content'].innerHTML, /value="sa-uid"/);
});
