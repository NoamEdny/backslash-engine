import test from 'node:test';
import assert from 'node:assert/strict';
import { matches } from '../dist/query/predicates.js';
import { validateQuery } from '../dist/query/validation.js';
import { createDefaultRegistry } from '../dist/query/registry.js';

const node = {
  id: 'service',
  kind: 'service',
  unresolved: false,
  properties: {
    vulnerabilities: [
      { severity: 'low', score: 2 },
      { severity: 'high', score: 9 },
    ],
    cloud: { provider: 'AWS', tags: ['prod', 'web'] },
    empty: [],
    nested: [[{ value: null }]],
    'literal.key': 'literal',
  },
};

test('nested filters traverse arrays with existential semantics and preserve terminal arrays', () => {
  assert.equal(matches(node, { field: 'vulnerabilities.severity', op: 'eq', value: 'high' }), true);
  assert.equal(
    matches(node, { field: 'vulnerabilities.severity', op: 'eq', value: 'critical' }),
    false,
  );
  assert.equal(matches(node, { field: 'vulnerabilities.score', op: 'gt', value: 8 }), true);
  assert.equal(matches(node, { field: 'cloud.provider', op: 'in', value: ['AWS', 'GCP'] }), true);
  assert.equal(matches(node, { field: 'cloud.tags', op: 'eq', value: ['prod', 'web'] }), true);
  assert.equal(matches(node, { field: 'cloud.tags', op: 'eq', value: 'prod' }), false);
  assert.equal(matches(node, { field: 'nested.value', op: 'eq', value: null }), true);
  assert.equal(matches(node, { field: 'literal.key', op: 'eq', value: 'literal' }), true);
});

test('missing nested fields, empty arrays and inherited properties do not match', () => {
  for (const field of ['empty.value', 'cloud.missing', 'cloud.toString', 'cloud.__proto__']) {
    assert.equal(matches(node, { field, op: 'exists' }), false);
  }
  assert.equal(matches(node, { field: 'empty', op: 'exists' }), true);
  assert.equal(matches(node, { field: 'empty', op: 'notEmpty' }), false);
});

test('invalid dotted paths are rejected during query validation', () => {
  for (const field of ['cloud..provider', '.cloud', 'cloud.', Array(33).fill('a').join('.')]) {
    assert.throws(() =>
      validateQuery(
        { operator: 'AND', filters: [{ scope: 'START', predicate: { field, op: 'exists' } }] },
        createDefaultRegistry(),
      ),
    );
  }
});
