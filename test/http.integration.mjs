import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadGraph, StaticGraphRepository } from '../dist/index.js';
import { buildApp } from '../dist/api/app.js';
test('Fastify integration: query, validation, pagination, OpenAPI', async () => {
  const graph = loadGraph(
    readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8'),
    { version: 'v1' },
  );
  const app = await buildApp(new StaticGraphRepository(graph));
  try {
    await app.ready();
    const q = await app.inject({
      method: 'POST',
      url: '/api/v1/routes/query',
      payload: { query: { operator: 'AND', filters: [{ type: 'public' }] }, pageSize: 1 },
    });
    assert.equal(q.statusCode, 200, q.body);
    assert.equal(q.json().meta.completeness, 'exact');
    const next = await app.inject({ url: '/api/v1/results/' + q.json().meta.nextCursor });
    assert.equal(next.statusCode, 200);
    const invalid = await app.inject({
      method: 'POST',
      url: '/api/v1/routes/query',
      payload: { query: { operator: 'OR', filters: [] } },
    });
    assert.equal(invalid.statusCode, 400);
    assert.equal((await app.inject({ url: '/docs/json' })).statusCode, 200);
  } finally {
    await app.close();
  }
});

test('Fastify paths endpoint and documented response schemas', async () => {
  const graph = loadGraph(
    readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8'),
    { version: 'paths-http' },
  );
  const app = await buildApp(new StaticGraphRepository(graph));
  try {
    const response = await app.inject({
      method: 'POST',
      url: '/api/v1/routes/paths',
      payload: { query: { operator: 'AND', filters: [{ type: 'public' }] }, limit: 1 },
    });
    assert.equal(response.statusCode, 200, response.body);
    assert.equal(response.json().paths.length, 1);
    assert.equal(response.json().stopReason, 'PATH_LIMIT');
    const doc = (await app.inject({ url: '/docs/json' })).json();
    assert.ok(doc.paths['/api/v1/routes/paths'].post.responses['200'].content);
    assert.ok(doc.paths['/api/v1/routes/query'].post.responses['200'].content);
  } finally {
    await app.close();
  }
});
