import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemorySnapshot } from '../dist/graph/snapshot.js';
import { compileQuery } from '../dist/query/compiler.js';
import { createDefaultRegistry } from '../dist/query/registry.js';
import { executeQuery } from '../dist/query/engine.js';
import { QueryError } from '../dist/query/model.js';

function fixture() {
  const nodes = [
    { id: 'public', kind: 'service', unresolved: false, properties: { publicExposed: true } },
    { id: 'risk', kind: 'service', unresolved: false, properties: { severity: 'high', score: 9 } },
    { id: 'sink', kind: 'rds', unresolved: false, properties: {} },
  ];
  const edges = [
    { source: 0, target: 1, properties: { encrypted: true } },
    { source: 1, target: 2, properties: { encrypted: true } },
    { source: 0, target: 2, properties: { encrypted: false } },
  ];
  return new InMemorySnapshot('fixture', nodes, edges, []);
}

function registry() {
  return createDefaultRegistry()
    .registerCustom({
      id: 'highRisk',
      description: 'Node has high severity and a numeric risk score above 8',
      scope: 'ANY_NODE',
      match: (entity) => entity.properties.severity === 'high' && entity.properties.score > 8,
    })
    .registerCustom({
      id: 'encrypted',
      description: 'Every edge is encrypted',
      scope: 'ALL_EDGES',
      match: (entity) => entity.properties.encrypted === true,
    });
}

const query = (...ids) => ({ operator: 'AND', filters: ids.map((type) => ({ type })) });

test('custom filters compose with built-ins and work through the full engine', async () => {
  const graph = fixture();
  const filters = registry();
  const input = query('public', 'sink', 'highRisk', 'encrypted');
  const compiled = compileQuery(graph, input, filters);
  assert.deepEqual([...compiled.nodeMasks], [0, 1, 0]);
  assert.deepEqual([...compiled.allowedEdges], [1, 1, 0]);
  const result = await executeQuery(graph, input, {}, filters);
  assert.equal(result.completeness, 'exact');
  assert.deepEqual([...result.nodes], [1, 1, 1]);
  assert.deepEqual([...result.edges], [1, 1, 0]);
});

test('registry exposes metadata, rejects duplicate IDs across filter types', () => {
  const filters = registry();
  const metadata = filters.list().find((item) => item.id === 'highRisk');
  assert.deepEqual(metadata, {
    id: 'highRisk',
    description: 'Node has high severity and a numeric risk score above 8',
    scope: 'ANY_NODE',
  });
  assert.throws(
    () => filters.registerCustom({ ...metadata, id: 'public', match: () => true }),
    QueryError,
  );
  assert.throws(
    () => filters.register({ id: 'highRisk', description: '', filter: filters.resolve('public') }),
    QueryError,
  );
});

test('untrusted queries cannot supply executable predicates', () => {
  const graph = fixture();
  const filters = registry();
  for (const filter of [
    { scope: 'ANY_NODE', match: () => true },
    { type: 'highRisk', match: () => true },
    { scope: 'START', match: 'return true' },
  ]) {
    assert.throws(
      () => compileQuery(graph, { operator: 'AND', filters: [filter] }, filters),
      QueryError,
    );
  }
});
