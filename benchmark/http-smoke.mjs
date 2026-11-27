// Manual smoke test over a real socket: responsiveness during a heavy query,
// the concurrency limit, client abort, and error responses.
import { loadGraph, StaticGraphRepository } from '../dist/index.js';
import { buildApp } from '../dist/api/app.js';
import { denseCoreWithFalseDetour } from './fixtures.mjs';
const heavy = loadGraph(JSON.stringify(denseCoreWithFalseDetour(14)), { version: 'h' });
const app = await buildApp(new StaticGraphRepository(heavy));
await app.listen({ port: 0, host: '127.0.0.1' });
const base = `http://127.0.0.1:${app.server.address().port}`;
const body = JSON.stringify({
  query: {
    operator: 'AND',
    filters: [{ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }],
  },
});
// 1. responsiveness while heavy query runs
const t0 = performance.now();
const heavyP = fetch(base + '/api/v1/routes/query', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body,
}).then(async (r) => ({ s: r.status, ms: performance.now() - t0, meta: (await r.json()).meta }));
await new Promise((r) => setTimeout(r, 100));
const lat = [];
for (let i = 0; i < 5; i++) {
  const t = performance.now();
  await fetch(base + '/health');
  lat.push((performance.now() - t).toFixed(1));
}
console.log('health latency during heavy query (ms):', lat.join(','));
const h = await heavyP;
console.log(
  'heavy:',
  h.s,
  h.ms.toFixed(0),
  'ms',
  h.meta.completeness,
  h.meta.stopReason,
  h.meta.unverifiedEdges,
);
// 2. concurrency limit
const ps = [1, 2, 3].map(() =>
  fetch(base + '/api/v1/routes/query', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  }).then((r) => r.status),
);
console.log('3 concurrent statuses:', await Promise.all(ps));
// 3. client abort frees slot
const ac = new AbortController();
const t1 = performance.now();
const ab = fetch(base + '/api/v1/routes/query', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body,
  signal: ac.signal,
}).catch((e) => e.name);
await new Promise((r) => setTimeout(r, 150));
ac.abort();
console.log('abort ->', await ab);
const t2 = performance.now();
const after = await Promise.all(
  [1, 2].map(() =>
    fetch(base + '/api/v1/routes/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: { operator: 'AND', filters: [] } }),
    }).then((r) => r.status),
  ),
);
console.log('two queries right after abort:', after, (performance.now() - t2).toFixed(0), 'ms');
// 4. error cases
const cases = [
  [
    'bad json',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      headers: { 'content-type': 'application/json' },
      body: '{bad',
    },
  ],
  [
    'text/plain',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      headers: { 'content-type': 'text/plain' },
      body: 'x',
    },
  ],
  [
    'unknown filter',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: { query: { operator: 'AND', filters: [{ type: 'nope' }] } },
    },
  ],
  [
    'filter extra key',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: { query: { operator: 'AND', filters: [{ type: 'public', x: 1 }] } },
    },
  ],
  [
    'maxDepth float',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: { query: { operator: 'AND', filters: [], maxDepth: 1.5 } },
    },
  ],
  [
    'maxDepth string',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: { query: { operator: 'AND', filters: [], maxDepth: '2' } },
    },
  ],
  [
    'pageSize 0',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: { query: { operator: 'AND', filters: [] }, pageSize: 0 },
    },
  ],
  [
    'OR',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: { query: { operator: 'OR', filters: [] } },
    },
  ],
  ['tampered cursor', { url: '/api/v1/results/abc.10.xyz' }],
  ['unknown route', { url: '/nope' }],
  ['node 404', { url: '/api/v1/graph/nodes/nope' }],
  ['graph pageSize=abc', { url: '/api/v1/graph?pageSize=abc' }],
  [
    '6 ANY filters',
    {
      method: 'POST',
      url: '/api/v1/routes/query',
      json: {
        query: {
          operator: 'AND',
          filters: Array(6).fill({ scope: 'ANY_NODE', predicate: { field: 'a', op: 'exists' } }),
        },
      },
    },
  ],
];
for (const [name, c] of cases) {
  const r = await fetch(base + c.url, {
    method: c.method ?? 'GET',
    headers: c.json ? { 'content-type': 'application/json' } : c.headers,
    body: c.json ? JSON.stringify(c.json) : c.body,
  });
  console.log(
    name.padEnd(18),
    r.status,
    r.headers.get('content-type'),
    (await r.text()).slice(0, 140),
  );
}
await app.close();
