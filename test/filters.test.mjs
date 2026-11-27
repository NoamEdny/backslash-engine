import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadGraph, compileQuery, createDefaultRegistry, QueryError } from '../dist/index.js';
const real = loadGraph(
  readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8'),
  { version: 'v1' },
);
const q = (filters = [], extra = {}) => ({ operator: 'AND', filters, ...extra });
const named = (type) => ({ type });
const f = (scope, field, op, value) => ({
  scope,
  predicate: { field, op, ...(value === undefined ? {} : { value }) },
});
const ids = (g, mask) => Array.from(mask).flatMap((v, i) => (v ? [g.node(i).id] : []));
const fixture = () =>
  loadGraph(
    JSON.stringify({
      nodes: [
        { name: 'a', kind: 'service', publicExposed: true, language: 'java' },
        { name: 'b', kind: 'service', language: 'python', vulnerabilities: [{ severity: 'high' }] },
        { name: 'c', kind: 'rds' },
        { name: 'd', kind: 'service', language: 'java' },
      ],
      edges: [
        { from: 'a', to: 'b', protocol: 'tcp' },
        { from: 'b', to: 'c', protocol: 'udp' },
        { from: 'a', to: 'a', protocol: 'tcp' },
      ],
    }),
    { version: 'test' },
  );
test('real data: compile built-in filters and preserve isolated public gateway', () => {
  const c = compileQuery(real, q(['public', 'sink', 'vulnerability'].map(named)));
  assert.deepEqual(ids(real, c.starts), ['frontend', 'gateway-service']);
  assert.deepEqual(ids(real, c.ends), ['prod-postgresdb']);
  assert.deepEqual(ids(real, c.nodeMasks), ['auth-service', 'order-service']);
  assert.equal(c.requiredMask, 1);
  assert.equal(c.maxDepth, undefined);
});
test('empty filters permit all nodes, excluding self-loops from traversable edges', () => {
  const g = fixture(),
    c = compileQuery(g, q());
  assert.deepEqual([...c.starts], [1, 1, 1, 1]);
  assert.deepEqual([...c.ends], [1, 1, 1, 1]);
  assert.equal(c.requiredMask, 0);
  assert.equal(
    c.allowedEdges.reduce((a, b) => a + b, 0),
    2,
  );
});
test('AND scopes and independent ANY bits', () => {
  const g = fixture();
  const c = compileQuery(
    g,
    q(
      [
        named('vulnerability'),
        f('ANY_NODE', 'language', 'eq', 'java'),
        f('ALL_NODES', 'kind', 'eq', 'service'),
        named('public'),
        f('ALL_EDGES', 'protocol', 'eq', 'tcp'),
      ],
      { maxDepth: 0 },
    ),
  );
  assert.deepEqual([...c.nodeMasks], [2, 1, 0, 2]);
  assert.equal(c.requiredMask, 3);
  assert.deepEqual(ids(g, c.starts), ['a']);
  assert.deepEqual(ids(g, c.ends), ['a', 'b', 'd']);
  assert.equal(
    c.allowedEdges.reduce((a, b) => a + b, 0),
    1,
  );
  assert.equal(c.maxDepth, 0);
});
test('generic registry extension requires no compiler changes', () => {
  const g = fixture(),
    r = createDefaultRegistry().register({
      id: 'java',
      description: 'Java',
      filter: f('ANY_NODE', 'language', 'eq', 'java'),
    });
  assert.deepEqual(ids(g, compileQuery(g, q([named('java')]), r).nodeMasks), ['a', 'd']);
  assert.equal(r.list().length, 4);
  assert.throws(() => r.register(r.list()[0]), QueryError);
  const copy = r.list();
  copy[0].filter.predicate.value = false;
  assert.deepEqual(ids(g, compileQuery(g, q([named('public')]), r).starts), ['a']);
});
test('strict predicate semantics: missing fields, equality, type checks and own properties', () => {
  const g = fixture();
  for (const [field, op, value, expected] of [
    ['language', 'exists', undefined, ['a', 'b', 'd']],
    ['language', 'eq', null, []],
    ['vulnerabilities', 'eq', [], ['a', 'c', 'd']],
    ['vulnerabilities', 'notEmpty', undefined, ['b']],
    ['language', 'gt', 0, []],
    ['toString', 'exists', undefined, []],
  ]) {
    assert.deepEqual(ids(g, compileQuery(g, q([f('START', field, op, value)])).starts), expected);
  }
});
test('invalid queries and unsupported limits fail explicitly', () => {
  const g = fixture();
  for (const bad of [
    null,
    { operator: 'OR', filters: [] },
    q([named('missing')]),
    q([f('ANY_EDGE', 'protocol', 'eq', 'tcp')]),
    q([f('START', 'kind', 'in', 'rds')]),
    q([f('START', 'kind', 'gt', '1')]),
    q([f('START', 'kind', 'eq')]),
    q(Array(6).fill(named('vulnerability'))),
    q([], { maxDepth: -1 }),
    q([], { maxDepth: 1.5 }),
    q([], { extra: true }),
  ])
    assert.throws(() => compileQuery(g, bad), QueryError);
});
