const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, 'assets', 'app.js'), 'utf8');
const identityFunctions = source.slice(
  source.indexOf('function identityNodeID('),
  source.indexOf('function renderThreatIntelStatus('),
);
const graphRenderer = source.slice(
  source.indexOf('function renderAttackGraph()'),
  source.indexOf('// refreshPathsHeaderChip writes'),
);

function element() {
  return {
    children: [],
    dataset: {},
    hidden: false,
    classList: { add() {}, contains() { return false; } },
    appendChild(child) { this.children.push(child); },
    append(...children) { this.children.push(...children); },
    addEventListener() {},
    set innerHTML(value) { this.children = []; },
  };
}

function contextFor(finding, identity) {
  const table = element();
  const elements = {
    '#paths-card': element(),
    '#paths-table tbody': table,
    '#paths-empty': element(),
    '#p-onlyme': { checked: true },
    '#p-onlyhv': { checked: true },
  };
  const context = {
    STATE: { findings: finding ? [finding] : [], accepted: [], identity, graph: { me: '' }, metadata: {} },
    $: selector => elements[selector] || null,
    document: {
      getElementById: () => null,
      createElement: () => element(),
    },
    refreshPathsHeaderChip() {},
    parsePathEvidence() { throw new Error('structured paths must not parse textual evidence'); },
  };
  vm.runInNewContext(identityFunctions + '\n' + graphRenderer, context);
  return { context, table };
}

test('service-account and high-value action paths survive default filters', () => {
  const id = { username: 'system:serviceaccount:team:runner', groups: [] };
  const finding = {
    ruleId: 'KH-PATH-001',
    severity: 'HIGH',
    evidence: 'misleading display text',
    attackPath: {
      nodes: [
        { id: 'ServiceAccount/team/runner', kind: 'ServiceAccount', namespace: 'team', name: 'runner' },
        { id: 'Action/team/create', kind: 'Action', namespace: 'team', name: 'create pods', highValue: true },
      ],
      edges: [],
    },
  };
  const { context, table } = contextFor(finding, id);
  context.renderAttackGraph();
  assert.equal(table.children.length, 1);
});

test('identity matching is exact and scoped impersonation is not universal', () => {
  const { context } = contextFor(null, { username: 'ann' });
  assert.equal(context.isFromMeLabel('User/ann', { username: 'ann' }), true);
  assert.equal(context.isFromMeLabel('User/joann', { username: 'ann' }), false);
  assert.equal(context.isFromMeLabel('User/admin', { impersonatableServiceAccounts: ['*'] }), false);
  assert.equal(context.isFromMeLabel('ServiceAccount/team/runner', { tokenRequestSAs: ['team/*'] }), true);
  assert.equal(context.isFromMeLabel('ServiceAccount/team-other/runner', { tokenRequestSAs: ['team/*'] }), false);
});

test('endpoint names cannot invent high-value status', () => {
  const finding = {
    ruleId: 'KH-PATH-001', severity: 'HIGH',
    attackPath: {
      nodes: [
        { id: 'User/ann', kind: 'User', name: 'ann' },
        { id: 'Action/readme', kind: 'Action', name: 'admin documentation', highValue: false },
      ],
      edges: [],
    },
  };
  const { context, table } = contextFor(finding, { username: 'ann' });
  context.renderAttackGraph();
  assert.equal(table.children.length, 0);
});
