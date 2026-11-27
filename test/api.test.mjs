import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadGraph, StaticGraphRepository } from '../dist/index.js';
import { createGraphService } from '../dist/api/service.js';
const graph = loadGraph(
  readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8'),
  { version: 'v1' },
);
const make = (options) => createGraphService(new StaticGraphRepository(graph), options);
test('API service: graph pagination preserves endpoints and isolated nodes', () => {
  const s = make();
  let p = s.graph(3);
  const ns = new Set(),
    es = new Set();
  while (true) {
    const local = new Set(p.nodes.map((n) => n.id));
    for (const n of local) ns.add(n);
    for (const e of p.edges) {
      assert(local.has(e.source) && local.has(e.target));
      assert(!es.has(e.id));
      es.add(e.id);
    }
    if (!p.meta.nextCursor) break;
    p = s.next(p.meta.nextCursor);
  }
  assert.equal(ns.size, 47);
  assert.equal(es.size, 98);
  assert(ns.has('gateway-service'));
});
test('API service: exact empty and public isolated results', async () => {
  const s = make();
  let p = await s.query({
    query: { operator: 'AND', filters: [{ type: 'public' }, { type: 'sink' }] },
  });
  assert.equal(p.meta.completeness, 'exact');
  assert.equal(p.nodes.length, 0);
  p = await s.query({ query: { operator: 'AND', filters: [{ type: 'public' }] } });
  assert(p.nodes.some((n) => n.id === 'gateway-service'));
});
test('API service: metadata, projection and errors', async () => {
  const s = make();
  assert.equal(s.meta().nodeCount, 47);
  assert.equal(s.filters().filters.length, 3);
  assert(s.details('auth-service').properties.vulnerabilities.length);
  assert(!Object.hasOwn(s.graph().nodes[0], 'properties'));
  assert.throws(() => s.details('bad'), { statusCode: 404 });
  await assert.rejects(s.query({ query: { operator: 'OR', filters: [] } }), { statusCode: 400 });
  assert.throws(() => s.graph(0), { statusCode: 400 });
});
test('API service: stable cursors, eviction and snapshot changes', () => {
  let g = graph;
  const s = createGraphService({ snapshot: () => g }, { maxResults: 1 });
  const p = s.graph(1),
    c = p.meta.nextCursor;
  assert.deepEqual(s.next(c), s.next(c));
  s.graph(1);
  assert.throws(() => s.next(c), { statusCode: 410 });
  const c2 = s.graph(1).meta.nextCursor;
  g = loadGraph('{"nodes":[],"edges":[]}', { version: 'v2' });
  assert.throws(() => s.next(c2), { statusCode: 410 });
});
test('API service: budget partial result stays labeled and concurrency limited', async () => {
  const s = make({ maxActive: 1, executionOptions: { maxOperations: 0 } });
  const a = s.query({ query: { operator: 'AND', filters: [] } });
  await assert.rejects(s.query({ query: { operator: 'AND', filters: [] } }), { statusCode: 503 });
  const p = await a;
  assert.equal(p.meta.completeness, 'lowerBound');
  assert.equal(p.nodes.length, 0);
});
