import test from 'node:test';
import assert from 'node:assert/strict';
import { loadGraph, executePaths, StaticGraphRepository } from '../dist/index.js';
import { createGraphService } from '../dist/api/service.js';

const query = {
  operator: 'AND',
  filters: [{ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }],
};
const graph = loadGraph(
  JSON.stringify({
    nodes: [
      { name: 'P', kind: 'service', publicExposed: true },
      { name: 'Q', kind: 'service', publicExposed: true },
      { name: 'V', kind: 'service', vulnerabilities: [{}] },
      { name: 'W', kind: 'service', vulnerabilities: [{}] },
      { name: 'A', kind: 'service' },
      { name: 'S', kind: 'rds' },
      { name: 'S2', kind: 'rds' },
    ],
    edges: [
      { from: 'P', to: 'V' },
      { from: 'V', to: 'A' },
      { from: 'A', to: ['S', 'W'] },
      { from: 'Q', to: 'A' },
      { from: 'W', to: 'S2' },
    ],
  }),
  { version: 'paths' },
);

test('explicit paths distinguish valid routes from paths implied by the union', async () => {
  const result = await executePaths(graph, query, 10);
  assert.equal(result.completeness, 'exact');
  assert.deepEqual(result.paths.map((path) => path.nodes.join('->')).sort(), [
    'P->V->A->S',
    'P->V->A->W->S2',
    'Q->A->W->S2',
  ]);
  for (const path of result.paths) {
    assert.equal(path.edges.length, path.nodes.length - 1);
    for (let i = 0; i < path.edges.length; i++) {
      const edge = graph.edge(Number(path.edges[i].slice(1)));
      assert.equal(graph.node(edge.source).id, path.nodes[i]);
      assert.equal(graph.node(edge.target).id, path.nodes[i + 1]);
    }
  }
});

test('path count limit distinguishes truncation from an exact boundary', async () => {
  const result = await executePaths(graph, query, 1);
  assert.equal(result.paths.length, 1);
  assert.equal(result.completeness, 'lowerBound');
  assert.equal(result.stopReason, 'PATH_LIMIT');
  assert.equal((await executePaths(graph, query, 3)).completeness, 'exact');
});

test('paths handle cycles, zero-length paths, and depth limits', async () => {
  const cycle = loadGraph(
    JSON.stringify({
      nodes: [
        { name: 'a', kind: 'service' },
        { name: 'b', kind: 'service' },
      ],
      edges: [
        { from: 'a', to: 'b' },
        { from: 'b', to: 'a' },
      ],
    }),
    { version: 'cycle' },
  );
  const all = { operator: 'AND', filters: [] };
  const result = await executePaths(cycle, all, 10);
  assert.equal(result.completeness, 'exact');
  assert.deepEqual(result.paths.map((path) => path.nodes.join('->')).sort(), [
    'a',
    'a->b',
    'b',
    'b->a',
  ]);
  assert.equal((await executePaths(cycle, { ...all, maxDepth: 0 }, 10)).paths.length, 2);
});

test('path budget never publishes an incomplete path and invalid limit is rejected', async () => {
  const result = await executePaths(graph, query, 10, { maxOperations: 0 });
  assert.equal(result.completeness, 'lowerBound');
  assert.equal(result.stopReason, 'OPERATION_BUDGET');
  assert.deepEqual(result.paths, []);
  await assert.rejects(executePaths(graph, query, 101), { name: 'QueryError' });
});

test('path service and resource-limit status', async () => {
  const repository = new StaticGraphRepository(graph);
  const service = createGraphService(repository);
  assert.equal((await service.paths({ query, limit: 3 })).paths.length, 3);
  await assert.rejects(service.paths({ query, limit: 0 }), { statusCode: 400 });
  const limited = createGraphService(repository, { executionOptions: { maxWorkingBytes: 1 } });
  await assert.rejects(limited.paths({ query }), { statusCode: 422 });
  await assert.rejects(limited.query({ query }), { statusCode: 422 });
});
