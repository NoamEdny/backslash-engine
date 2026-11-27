import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  loadGraph,
  compileQuery,
  buildProductRegion,
  productRegionSteps,
  QueryError,
} from '../dist/index.js';
const q = (filters = [], extra = {}) => ({
  operator: 'AND',
  filters: filters.map((x) => (typeof x === 'string' ? { type: x } : x)),
  ...extra,
});
const fixture = (names, edges) =>
  loadGraph(
    JSON.stringify({
      nodes: names.map((name) => ({
        name,
        kind: name === 't' ? 'rds' : 'service',
        publicExposed: name === 's',
        vulnerabilities: name === 'x' ? [{}] : [],
        language: name === 'a' ? 'java' : 'python',
      })),
      edges: edges.map(([from, to]) => ({ from, to })),
    }),
    { version: 'test' },
  );
const nodeIds = (g, r) => Array.from(r.nodes).flatMap((x, i) => (x ? [g.node(i).id] : []));
const edgeIds = (g, r) =>
  Array.from(r.edges).flatMap((x, i) =>
    x ? [`${g.node(g.edge(i).source).id}->${g.node(g.edge(i).target).id}`] : [],
  );
const all = q(['public', 'sink', 'vulnerability']);
test('diamond: ANY-aware projection excludes nonmatching branch', () => {
  const g = fixture(
    ['s', 'x', 'a', 't'],
    [
      ['s', 'x'],
      ['s', 'a'],
      ['x', 't'],
      ['a', 't'],
    ],
  );
  const r = buildProductRegion(g, compileQuery(g, all));
  assert.equal(r.acyclic, true);
  assert.deepEqual(nodeIds(g, r), ['s', 't', 'x']);
  assert.deepEqual(edgeIds(g, r), ['s->x', 'x->t']);
  assert.equal(r.backward[g.findNode('a') * 2], -1);
  assert.equal(r.backward[g.findNode('a') * 2 + 1], 1);
});
test('cyclic counterexample is an upper bound, never labeled acyclic', () => {
  const g = fixture(
    ['s', 'a', 'x', 't'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['x', 'a'],
      ['a', 't'],
    ],
  );
  const r = buildProductRegion(g, compileQuery(g, all));
  assert.equal(r.acyclic, false);
  assert.equal(r.edgeCount, 4);
});
test('cycles outside candidate region do not disable exact fast path', () => {
  const g = fixture(
    ['s', 'x', 't', 'a', 'b'],
    [
      ['s', 'x'],
      ['x', 't'],
      ['s', 'a'],
      ['a', 'b'],
      ['b', 'a'],
    ],
  );
  const r = buildProductRegion(g, compileQuery(g, all));
  assert.equal(r.acyclic, true);
  assert.equal(r.edgeCount, 2);
});
test('depth constraints and zero-length paths', () => {
  const g = fixture(
    ['s', 'x', 't'],
    [
      ['s', 'x'],
      ['x', 't'],
    ],
  );
  for (const [depth, count] of [
    [0, 0],
    [1, 0],
    [2, 3],
  ])
    assert.equal(
      buildProductRegion(g, compileQuery(g, { ...all, maxDepth: depth })).nodeCount,
      count,
    );
  const r = buildProductRegion(g, compileQuery(g, q(['public'], { maxDepth: 0 })));
  assert.deepEqual(nodeIds(g, r), ['s']);
  assert.equal(r.edgeCount, 0);
});
test('real dataset: public and sink empty; isolated gateway preserved', () => {
  const g = loadGraph(readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8'), {
    version: 'real',
  });
  const r = buildProductRegion(g, compileQuery(g, all));
  assert.equal(r.nodeCount, 0);
  assert.equal(r.acyclic, true);
  assert.ok(
    nodeIds(g, buildProductRegion(g, compileQuery(g, q(['public'])))).includes('gateway-service'),
  );
});
function reference(g, c) {
  const nodes = new Uint8Array(g.nodeCount),
    edges = new Uint8Array(g.edgeCount);
  function dfs(u, m, path, es) {
    if (c.ends[u] && m === c.requiredMask) {
      for (const v of path) nodes[v] = 1;
      for (const e of es) edges[e] = 1;
    }
    if (es.length >= (c.maxDepth ?? Infinity)) return;
    for (const id of g.outgoing(u)) {
      const v = g.edge(id).target;
      if (c.allowedEdges[id] && !path.includes(v))
        dfs(v, m | c.nodeMasks[v], [...path, v], [...es, id]);
    }
  }
  for (let u = 0; u < g.nodeCount; u++) if (c.starts[u]) dfs(u, c.nodeMasks[u], [u], []);
  return { nodes, edges };
}
test('differential random graphs: safe upper bound and exact acyclic projection', () => {
  let seed = 12345;
  const random = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32;
  const names = ['s', 'a', 'x', 'b', 't'];
  for (let i = 0; i < 150; i++) {
    const es = [];
    for (let u = 0; u < 5; u++)
      for (let v = 0; v < 5; v++)
        if ((i % 2 || u < v) && random() < 0.3) es.push([names[u], names[v]]);
    const g = fixture(names, es);
    for (const filters of [
      [],
      ['public'],
      ['sink', 'vulnerability'],
      [
        'public',
        'sink',
        'vulnerability',
        { scope: 'ANY_NODE', predicate: { field: 'language', op: 'eq', value: 'java' } },
      ],
    ]) {
      const c = compileQuery(g, q(filters, i % 3 === 0 ? { maxDepth: i % 5 } : {})),
        r = buildProductRegion(g, c),
        expected = reference(g, c);
      for (const key of ['nodes', 'edges']) {
        for (let j = 0; j < r[key].length; j++) assert.ok(r[key][j] >= expected[key][j]);
        if (r.acyclic) assert.deepEqual(r[key], expected[key]);
      }
    }
  }
});
test('memory cap and cooperative work batches', () => {
  const g = fixture(
      ['s', 'x', 't'],
      [
        ['s', 'x'],
        ['x', 't'],
      ],
    ),
    c = compileQuery(g, all);
  assert.throws(() => buildProductRegion(g, c, { maxStateBytes: 1 }), QueryError);
  const it = productRegionSteps(g, c);
  let step = it.next(),
    ops = 0;
  while (!step.done) {
    assert.ok(step.value > 0 && step.value <= 4096);
    ops += step.value;
    step = it.next();
  }
  assert.ok(ops > 0);
  assert.equal(step.value.edgeCount, 2);
});
