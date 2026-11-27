import test from 'node:test';
import assert from 'node:assert/strict';
import { loadGraph, StaticGraphRepository, executeQuery, QueryError } from '../dist/index.js';
import { createGraphService } from '../dist/api/service.js';
const graph = loadGraph(
  JSON.stringify({
    nodes: [
      { name: 'a', kind: 'service' },
      { name: 'b', kind: 'service' },
      { name: 'c', kind: 'service' },
    ],
    edges: [
      { from: 'a', to: 'b' },
      { from: 'b', to: 'c' },
    ],
  }),
  { version: 'v1' },
);
const query = { operator: 'AND', filters: [] };
const repo = new StaticGraphRepository(graph);
test('working-array limit rejects before compile even with zero operation budget', async () => {
  await assert.rejects(
    executeQuery(graph, query, { maxWorkingBytes: 1, maxOperations: 0 }),
    QueryError,
  );
  await assert.rejects(executeQuery(graph, query, { maxWorkingBytes: NaN }), QueryError);
  assert.equal((await executeQuery(graph, query, { maxWorkingBytes: 84 })).completeness, 'exact'); // 26*3+3*2
});
test('query result size cap checked before ID conversion', async () => {
  const service = createGraphService(repo, { maxStoredBytes: 1 });
  await assert.rejects(service.query({ query }), { statusCode: 503, code: 'RESULT_TOO_LARGE' });
});
test('single-page queries do not evict an existing paginated result', async () => {
  const service = createGraphService(repo, { maxResults: 1 });
  const first = service.graph(1);
  assert.ok(first.meta.nextCursor);
  const single = await service.query({ query: { operator: 'AND', filters: [{ type: 'public' }] } });
  assert.equal(single.meta.nextCursor, null);
  assert.ok(service.next(first.meta.nextCursor).nodes.length);
});
test('ingestion rejects blank identifiers and preserves extra schema properties', () => {
  assert.throws(
    () => loadGraph('{"nodes":[{"name":" ","kind":"service"}],"edges":[]}', { version: 'test' }),
    { name: 'InputError' },
  );
  const g = loadGraph(
    '{"nodes":[{"name":"a","kind":"service","extra":{"x":1}}],"edges":[{"from":"a","to":[],"tag":"keep"}]}',
    { version: 'test' },
  );
  assert.equal(g.node(0).properties.extra.x, 1);
  assert.equal(g.edgeCount, 0);
});
