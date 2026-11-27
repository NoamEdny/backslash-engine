import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadGraph, InputError } from '../dist/index.js';
const real = readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8');
const load = (input, policy) =>
  loadGraph(JSON.stringify(input), { version: 'test', missingNodePolicy: policy });
const n = (name, extra = {}) => ({ name, kind: 'service', ...extra });

test('real dataset: topology and diagnostics', () => {
  const g = loadGraph(real, { version: 'v1' });
  assert.equal(g.nodeCount, 47);
  assert.equal(g.edgeCount, 98);
  const missing = g.findNode('assurance-service');
  assert.equal(g.node(missing).unresolved, true);
  assert.equal([...g.incoming(missing)].length, 2);
  const gateway = g.findNode('gateway-service');
  assert.equal(g.node(gateway).properties.publicExposed, true);
  assert.deepEqual([...g.outgoing(gateway)], []);
  assert.deepEqual([...g.incoming(gateway)], []);
  assert.equal(g.diagnostics.filter((d) => d.code === 'UNRESOLVED_NODE').length, 1);
  assert.equal(g.diagnostics.filter((d) => d.code === 'NORMALIZED_TARGET').length, 1);
  for (let i = 0; i < g.edgeCount; i++) {
    const e = g.edge(i);
    assert.ok([...g.outgoing(e.source)].includes(i));
    assert.ok([...g.incoming(e.target)].includes(i));
  }
});
test('resolution policies', () => {
  const input = { nodes: [n('a')], edges: [{ from: 'a', to: 'b' }] };
  assert.equal(load(input, 'placeholder').nodeCount, 2);
  const dropped = load(input, 'drop');
  assert.equal(dropped.edgeCount, 0);
  assert.equal(dropped.nodeCount, 1);
  assert.throws(() => load(input, 'reject'), InputError);
});
test('reject malformed input and duplicate identities', () => {
  assert.throws(() => loadGraph('{', { version: 'v1' }), InputError);
  assert.throws(() => load({ nodes: [n('a'), n('a')], edges: [] }), InputError);
  assert.throws(() => load({ nodes: [n('a', { vulnerabilities: null })], edges: [] }), InputError);
  assert.throws(() => load({ nodes: [n('a')], edges: [{ from: 'a', to: [1] }] }), InputError);
  assert.throws(() => load({ nodes: [n('a', { publicExposed: 'true' })], edges: [] }), InputError);
});
test('preserve unknown fields, loops and distinct parallel edges; deduplicate identical edges', () => {
  const g = load({
    nodes: [n('a', { extra: { x: 1 } }), n('b')],
    edges: [
      { from: 'a', to: 'b', protocol: 'x' },
      { from: 'a', to: ['b'], protocol: 'x' },
      { from: 'a', to: 'b', protocol: 'y' },
      { from: 'b', to: 'b' },
    ],
  });
  assert.equal(g.edgeCount, 3);
  assert.equal(g.node(g.findNode('a')).properties.extra.x, 1);
  assert.deepEqual(g.node(g.findNode('b')).properties.vulnerabilities, []);
  assert.equal(g.diagnostics.filter((d) => d.code === 'DUPLICATE_EDGE').length, 1);
  assert.throws(() => {
    g.node(0).properties.extra.x = 2;
  }, TypeError);
});
test('canonical IDs and traversal order do not depend on input ordering', () => {
  const nodes = [n('b'), n('a'), n('c')];
  const edges = [
    { from: 'a', to: ['c', 'b'] },
    { from: 'c', to: 'a' },
  ];
  const a = load({ nodes, edges });
  const b = load({ nodes: [...nodes].reverse(), edges: [...edges].reverse() });
  for (let i = 0; i < a.nodeCount; i++) {
    assert.deepEqual(a.node(i), b.node(i));
    assert.deepEqual([...a.outgoing(i)], [...b.outgoing(i)]);
  }
  for (let i = 0; i < a.edgeCount; i++) assert.deepEqual(a.edge(i), b.edge(i));
});
