import test from 'node:test';
import assert from 'node:assert/strict';
import { ExecutionBudget, loadGraph, StaticGraphRepository } from '../dist/index.js';
import { createGraphService } from '../dist/api/service.js';
const g = loadGraph(JSON.stringify({ nodes: [{ name: 'a', kind: 'service' }], edges: [] }), {
  version: 'test',
});
const repo = new StaticGraphRepository(g);
test('default budget accommodates measured million-edge scenario', () => {
  const b = new ExecutionBudget();
  assert.equal(b.remainingOperations, 25_000_000);
  b.charge(10_149_439);
  assert.equal(b.stopReason, undefined);
});
test('invalid cache and concurrency settings fail at startup', () => {
  for (const key of ['ttlMs', 'maxResults', 'maxStoredBytes', 'maxActive'])
    for (const value of [0, -1, NaN, Infinity, 1.5])
      assert.throws(() => createGraphService(repo, { [key]: value }), RangeError);
});
test('graph request validates page size before allocation and enforces cache limit', () => {
  const s = createGraphService(repo, { maxStoredBytes: 1 });
  assert.throws(() => s.graph(0), { statusCode: 400 });
  assert.throws(() => s.graph(1), { statusCode: 503 });
});
