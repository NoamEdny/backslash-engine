import test from 'node:test';
import assert from 'node:assert/strict';
import {
  loadGraph,
  compileQuery,
  buildProductRegion,
  executeDfs,
  ExecutionBudget,
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
const all = q(['public', 'sink', 'vulnerability']);
function reference(g, c) {
  const nodes = new Uint8Array(g.nodeCount),
    edges = new Uint8Array(g.edgeCount);
  function visit(u, m, path, es) {
    if (c.ends[u] && m === c.requiredMask) {
      for (const v of path) nodes[v] = 1;
      for (const e of es) edges[e] = 1;
    }
    if (es.length >= (c.maxDepth ?? Infinity)) return;
    for (const id of g.outgoing(u)) {
      const v = g.edge(id).target;
      if (c.allowedEdges[id] && !path.includes(v))
        visit(v, m | c.nodeMasks[v], [...path, v], [...es, id]);
    }
  }
  for (let u = 0; u < g.nodeCount; u++) if (c.starts[u]) visit(u, c.nodeMasks[u], [u], []);
  return { nodes, edges };
}
const budget = () =>
  new ExecutionBudget({ maxOperations: 1000000, timeBudgetMs: 30000, yieldEvery: 1000000 });
async function run(g, input, b = budget()) {
  const c = compileQuery(g, input),
    r = buildProductRegion(g, c);
  return executeDfs(g, c, r, b);
}
test('cyclic vulnerability counterexample has no valid simple path', async () => {
  const g = fixture(
    ['s', 'a', 'x', 't'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['x', 'a'],
      ['a', 't'],
    ],
  );
  const r = await run(g, all);
  assert.equal(r.completeness, 'exact');
  assert.equal(r.nodeCount, 0);
  assert.equal(r.edgeCount, 0);
});
test('START only excludes a reachable back edge', async () => {
  const g = fixture(
    ['s', 'a', 'x'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['x', 'a'],
    ],
  );
  const r = await run(g, q(['public']));
  assert.equal(r.completeness, 'exact');
  assert.equal(r.nodeCount, 3);
  assert.equal(r.edgeCount, 2);
  for (let i = 0; i < g.edgeCount; i++)
    if (g.node(g.edge(i).source).id === 'x') assert.equal(r.edges[i], 0);
});
test('zero length, depth, multiple endpoints and shared prefixes', async () => {
  const g = fixture(
    ['s', 'a', 'x', 't'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['a', 't'],
      ['x', 't'],
      ['x', 'a'],
    ],
  );
  for (const input of [
    q(['public']),
    q(['public'], { maxDepth: 0 }),
    { ...all, maxDepth: 2 },
    { ...all, maxDepth: 3 },
  ]) {
    const r = await run(g, input),
      ref = reference(g, compileQuery(g, input));
    assert.equal(r.completeness, 'exact');
    assert.deepEqual(r.nodes, ref.nodes);
    assert.deepEqual(r.edges, ref.edges);
  }
});
test('operation budget gives deterministic lower bounds with valid edge endpoints', async () => {
  const g = fixture(
    ['s', 'a', 'x', 't'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['x', 'a'],
      ['a', 't'],
      ['x', 't'],
    ],
  );
  const c = compileQuery(g, all),
    region = buildProductRegion(g, c),
    ref = reference(g, c);
  for (let limit = 0; limit < 40; limit++) {
    const b = () => new ExecutionBudget({ maxOperations: limit, timeBudgetMs: 30000 });
    const r = await executeDfs(g, c, region, b()),
      again = await executeDfs(g, c, region, b());
    assert.deepEqual(r, again);
    assert.ok(r.operations <= limit);
    for (const key of ['nodes', 'edges'])
      for (let i = 0; i < r[key].length; i++) assert.ok(r[key][i] <= ref[key][i]);
    for (let i = 0; i < g.edgeCount; i++)
      if (r.edges[i]) {
        assert.ok(r.nodes[g.edge(i).source]);
        assert.ok(r.nodes[g.edge(i).target]);
      }
    if (r.completeness === 'exact') {
      assert.deepEqual(r.nodes, ref.nodes);
      assert.deepEqual(r.edges, ref.edges);
    } else assert.equal(r.stopReason, 'OPERATION_BUDGET');
  }
});
test('cooperative cancellation and time budget', async () => {
  const g = fixture(
    ['s', 'a', 'x', 't'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['x', 'a'],
      ['a', 't'],
    ],
  );
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 0);
  const r = await run(
    g,
    all,
    new ExecutionBudget({ signal: controller.signal, yieldEvery: 1, timeBudgetMs: 30000 }),
  );
  assert.equal(r.stopReason, 'CANCELLED');
  assert.equal(r.completeness, 'lowerBound');
  const timed = await run(g, all, new ExecutionBudget({ timeBudgetMs: 0 }));
  assert.equal(timed.stopReason, 'TIME_BUDGET');
});
test('differential DFS on random graphs, with independent ANY masks', async () => {
  let seed = 54321;
  const random = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 2 ** 32;
  const names = ['s', 'a', 'x', 'b', 't'];
  for (let i = 0; i < 150; i++) {
    const es = [];
    for (const u of names) for (const v of names) if (random() < 0.35) es.push([u, v]);
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
      const input = q(filters, i % 3 === 0 ? { maxDepth: i % 5 } : {}),
        c = compileQuery(g, input),
        r = await run(g, input),
        ref = reference(g, c);
      assert.equal(r.completeness, 'exact');
      assert.deepEqual(r.nodes, ref.nodes);
      assert.deepEqual(r.edges, ref.edges);
    }
  }
});
test('early completion confirms all candidate items', async () => {
  const g = fixture(
    ['s', 'a', 'x', 't'],
    [
      ['s', 'a'],
      ['a', 'x'],
      ['x', 'a'],
      ['x', 't'],
    ],
  );
  const r = await run(g, q());
  assert.equal(r.completeness, 'exact');
  assert.equal(r.edgeCount, 4);
  assert.equal(r.unverifiedEdges, 0);
});
