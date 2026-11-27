import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  loadGraph,
  compileQuery,
  buildProductRegion,
  executeDfs,
  executeQuery,
  QueryEngine,
  QueryError,
  ExecutionBudget,
} from '../dist/index.js';
const q = (...filters) => ({ operator: 'AND', filters: filters.map((type) => ({ type })) });
const fixture = (edges) =>
  loadGraph(
    JSON.stringify({
      nodes: ['s', 'a', 'x', 't'].map((name) => ({
        name,
        kind: name === 't' ? 'rds' : 'service',
        publicExposed: name === 's',
        vulnerabilities: name === 'x' ? [{}] : [],
      })),
      edges: edges.map(([from, to]) => ({ from, to })),
    }),
    { version: 'test' },
  );
const all = q('public', 'sink', 'vulnerability');
const opts = { maxOperations: 1000000, timeBudgetMs: 30000, yieldEvery: 1000000 };
test('engine selects exact fast path and excludes irrelevant branches', async () => {
  const g = fixture([
    ['s', 'a'],
    ['a', 't'],
    ['s', 'x'],
    ['x', 't'],
  ]);
  const r = await executeQuery(g, all, opts);
  assert.equal(r.algorithm, 'product-bfs');
  assert.equal(r.completeness, 'exact');
  assert.equal(r.stage, 'complete');
  assert.equal(r.nodeCount, 3);
  assert.equal(r.edgeCount, 2);
  assert.equal(r.nodes[g.findNode('a')], 0);
});
test('engine verifies cyclic region instead of returning false positives', async () => {
  const g = fixture([
    ['s', 'a'],
    ['a', 'x'],
    ['x', 'a'],
    ['a', 't'],
  ]);
  const r = await executeQuery(g, all, opts);
  assert.equal(r.algorithm, 'pruned-dfs');
  assert.equal(r.completeness, 'exact');
  assert.equal(r.nodeCount, 0);
});
test('shared budget covers compile, reachability and DFS; partial results remain sound', async () => {
  const g = fixture([
    ['s', 'a'],
    ['a', 'x'],
    ['x', 'a'],
    ['a', 't'],
    ['x', 't'],
  ]);
  const full = await executeQuery(g, all, opts);
  const stages = new Set();
  for (let maxOperations = 0; maxOperations <= full.operations + 1; maxOperations++) {
    const r = await executeQuery(g, all, { ...opts, maxOperations });
    assert.ok(r.operations <= maxOperations);
    stages.add(r.stage);
    for (const key of ['nodes', 'edges'])
      for (let i = 0; i < r[key].length; i++) assert.ok(r[key][i] <= full[key][i]);
    if (r.completeness === 'exact') {
      assert.deepEqual(r.nodes, full.nodes);
      assert.deepEqual(r.edges, full.edges);
    } else {
      assert.equal(r.stopReason, 'OPERATION_BUDGET');
      if (r.algorithm === 'none') assert.equal(r.unverifiedNodes, null);
    }
  }
  for (const s of ['compile', 'reachability', 'dfs', 'complete']) assert.ok(stages.has(s), s);
});
test('cancellation during compilation and reachability yields no unverified results', async () => {
  const g = fixture([
    ['s', 'a'],
    ['a', 'x'],
    ['x', 't'],
  ]);
  const controller = new AbortController();
  controller.abort();
  const r = await executeQuery(g, all, { signal: controller.signal });
  assert.equal(r.stopReason, 'CANCELLED');
  assert.equal(r.nodeCount, 0);
  const later = new AbortController();
  setTimeout(() => later.abort(), 0);
  const result = await executeQuery(g, all, { ...opts, signal: later.signal, yieldEvery: 1 });
  assert.equal(result.stopReason, 'CANCELLED');
  assert.equal(result.completeness, 'lowerBound');
});
test('invalid requests and memory caps fail explicitly', async () => {
  const g = fixture([]);
  await assert.rejects(
    executeQuery(g, { operator: 'OR', filters: [] }, { maxOperations: 0 }),
    QueryError,
  );
  await assert.rejects(executeQuery(g, all, { ...opts, maxStateBytes: 1 }), QueryError);
});
test('repository snapshot captured once per query and real input works', async () => {
  const g = loadGraph(readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8'), {
    version: 'real',
  });
  let captures = 0;
  const engine = new QueryEngine({
    snapshot() {
      captures++;
      return g;
    },
  });
  const r = await engine.execute(q('public'), opts);
  assert.equal(captures, 1);
  assert.equal(r.graphVersion, 'real');
  assert.equal(r.completeness, 'exact');
  assert.equal(r.nodes[g.findNode('gateway-service')], 1);
  const empty = await engine.execute(all, opts);
  assert.equal(empty.nodeCount, 0);
  assert.equal(empty.completeness, 'exact');
  assert.equal(captures, 2);
});
