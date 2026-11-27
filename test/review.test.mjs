// Independent review tests. Tests marked `todo` document known failures /
// limitations found during review: they run and report, but do not fail CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadGraph, executeQuery, StaticGraphRepository } from '../dist/index.js';
import { buildApp } from '../dist/api/app.js';

const realText = readFileSync(new URL('../data/train-ticket.json', import.meta.url), 'utf8');
const real = loadGraph(realText, { version: 'review' });
const AND = (...filters) => ({ operator: 'AND', filters });

function nodeNames(graph, result) {
  return [...result.nodes].flatMap((on, i) => (on ? [graph.node(i).id] : [])).sort();
}
function edgeNames(graph, result) {
  return [...result.edges]
    .flatMap((on, i) => {
      if (!on) return [];
      const e = graph.edge(i);
      return [`${graph.node(e.source).id}->${graph.node(e.target).id}`];
    })
    .sort();
}
function build(nodes, edges) {
  return loadGraph(JSON.stringify({ nodes, edges }), { version: 't' });
}
function completeDigraph(n) {
  const nodes = Array.from({ length: n }, (_, i) => ({
    name: `n${String(i).padStart(3, '0')}`,
    kind: i === n - 1 ? 'rds' : 'service',
    publicExposed: i === 0,
    vulnerabilities: i === Math.floor(n / 2) ? [{}] : [],
  }));
  const edges = nodes.map((a, i) => ({
    from: a.name,
    to: nodes.filter((_, j) => j !== i).map((b) => b.name),
  }));
  return build(nodes, edges);
}

// ---------------------------------------------------------------------------
// Independent brute-force reference (no shared code with the engine).
function bruteForce(nodes, edges, query) {
  const byName = new Map(nodes.map((n) => [n.name, n]));
  const value = (n, field) => (field === 'kind' ? n.kind : n[field]);
  const ok = (n, { predicate: p }) => {
    const v = value(n, p.field);
    if (p.op === 'eq') return v === p.value;
    if (p.op === 'in') return p.value.includes(v);
    if (p.op === 'notEmpty') return Array.isArray(v) && v.length > 0;
    throw new Error(`unsupported op ${p.op}`);
  };
  const of = (scope) => query.filters.filter((f) => f.scope === scope);
  const allowed = (n) => of('ALL_NODES').every((f) => ok(n, f));
  const adj = new Map(nodes.map((n) => [n.name, []]));
  for (const { from, to } of edges) if (from !== to) adj.get(from).push(to);
  const maxDepth = query.maxDepth ?? Infinity;
  const N = new Set(),
    E = new Set();
  const visit = (path) => {
    const first = byName.get(path[0]),
      last = byName.get(path.at(-1));
    const matches =
      of('START').every((f) => ok(first, f)) &&
      of('END').every((f) => ok(last, f)) &&
      of('ANY_NODE').every((f) => path.some((x) => ok(byName.get(x), f)));
    if (matches) {
      path.forEach((x) => N.add(x));
      for (let i = 1; i < path.length; i++) E.add(`${path[i - 1]}->${path[i]}`);
    }
    if (path.length - 1 >= maxDepth) return;
    for (const t of new Set(adj.get(path.at(-1)))) {
      if (!path.includes(t) && allowed(byName.get(t))) visit([...path, t]);
    }
  };
  for (const n of nodes) if (allowed(n)) visit([n.name]);
  return { nodes: [...N].sort(), edges: [...E].sort() };
}

test('review: full-pipeline differential vs independent brute force (random cyclic graphs)', async () => {
  let seed = 424242;
  const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const pool = [
    { scope: 'START', predicate: { field: 'publicExposed', op: 'eq', value: true } },
    { scope: 'END', predicate: { field: 'kind', op: 'in', value: ['rds'] } },
    { scope: 'ANY_NODE', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
    { scope: 'ANY_NODE', predicate: { field: 'tag', op: 'eq', value: 'a' } },
    { scope: 'ALL_NODES', predicate: { field: 'tag', op: 'in', value: ['a', 'b'] } },
    { scope: 'END', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
  ];
  let cyclicRuns = 0;
  for (let it = 0; it < 1500; it++) {
    const n = 2 + Math.floor(rnd() * 8);
    const nodes = Array.from({ length: n }, (_, i) => ({
      name: `n${i}`,
      kind: pick(['service', 'rds', 'sqs']),
      publicExposed: rnd() < 0.3,
      vulnerabilities: rnd() < 0.25 ? [{}] : [],
      tag: pick(['a', 'b', 'c']),
    }));
    const density = rnd() * 0.5;
    const edges = [];
    for (let i = 0; i < n; i++)
      for (let j = 0; j < n; j++) if (rnd() < density) edges.push({ from: `n${i}`, to: [`n${j}`] });
    const query = AND(...pool.filter(() => rnd() < 0.3));
    if (rnd() < 0.3) query.maxDepth = Math.floor(rnd() * 4);
    const graph = build(nodes, edges);
    const result = await executeQuery(graph, query);
    if (result.algorithm === 'pruned-dfs') cyclicRuns++;
    assert.equal(result.completeness, 'exact');
    const flat = edges.map((e) => ({ from: e.from, to: e.to[0] }));
    const expected = bruteForce(nodes, flat, query);
    assert.deepEqual(
      nodeNames(graph, result),
      expected.nodes,
      JSON.stringify({ query, nodes, edges }),
    );
    assert.deepEqual(
      edgeNames(graph, result),
      expected.edges,
      JSON.stringify({ query, nodes, edges }),
    );
  }
  assert.ok(cyclicRuns > 100, `cyclic coverage too low: ${cyclicRuns}`);
});

// ---------------------------------------------------------------------------
// Real dataset: expected answers derived independently.
test('review: real dataset answers match independent brute force for every filter combination', async () => {
  const raw = JSON.parse(realText);
  const declared = new Set(raw.nodes.map((n) => n.name));
  const nodes = [...raw.nodes];
  const edges = raw.edges.flatMap((e) => [].concat(e.to).map((to) => ({ from: e.from, to })));
  for (const { to } of edges)
    if (!declared.has(to)) {
      declared.add(to);
      nodes.push({ name: to, kind: 'unknown' });
    }
  const filters = {
    public: { scope: 'START', predicate: { field: 'publicExposed', op: 'eq', value: true } },
    sink: { scope: 'END', predicate: { field: 'kind', op: 'in', value: ['rds', 'sql'] } },
    vulnerability: { scope: 'ANY_NODE', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
  };
  const names = Object.keys(filters);
  for (let mask = 0; mask < 8; mask++) {
    const chosen = names.filter((_, i) => mask & (1 << i));
    const result = await executeQuery(real, AND(...chosen.map((type) => ({ type }))));
    const expected = bruteForce(nodes, edges, AND(...chosen.map((c) => filters[c])));
    assert.equal(result.completeness, 'exact', chosen.join('+'));
    assert.deepEqual(nodeNames(real, result), expected.nodes, chosen.join('+'));
    assert.deepEqual(edgeNames(real, result), expected.edges, chosen.join('+'));
  }
});

test('review: real dataset key facts (public region, gateway, all-three empty)', async () => {
  const pub = await executeQuery(real, AND({ type: 'public' }));
  assert.deepEqual(nodeNames(real, pub), [
    'admin-basic-info-service',
    'config-service',
    'contacts-service',
    'frontend',
    'gateway-service',
    'price-service',
    'station-service',
    'train-service',
  ]);
  const all = await executeQuery(
    real,
    AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
  );
  assert.equal(all.nodeCount, 0);
  assert.equal(all.completeness, 'exact');
  // Every non-trivial path into postgres passes auth-service or order-service (both vulnerable).
  const sink = await executeQuery(real, AND({ type: 'sink' }));
  const sinkVuln = await executeQuery(real, AND({ type: 'sink' }, { type: 'vulnerability' }));
  assert.deepEqual(edgeNames(real, sink), edgeNames(real, sinkVuln));
});

// ---------------------------------------------------------------------------
// Ingestion edge cases.
test('review: ingestion edge cases', () => {
  const svc = (name, extra = {}) => ({ name, kind: 'service', ...extra });
  assert.equal(build([svc('a')], [{ from: 'a', to: [] }]).edgeCount, 0);
  const unknownSource = build([svc('a')], [{ from: 'zz', to: ['a'] }]);
  assert.equal(unknownSource.node(unknownSource.findNode('zz')).unresolved, true);
  const proto = build([svc('__proto__'), svc('a')], [{ from: '__proto__', to: 'a' }]);
  assert.equal(proto.nodeCount, 2);
  assert.equal(proto.edgeCount, 1);
  assert.equal(build([svc('a'), svc('b')], [{ from: 'a', to: ['b', 'b'] }]).edgeCount, 1);
  assert.equal(
    build(
      [svc('a'), svc('b'), svc('c')],
      [
        { from: 'a', to: ['b'] },
        { from: 'a', to: ['c'] },
      ],
    ).edgeCount,
    2,
  );
  assert.throws(() => build([svc('a', { publicExposed: 'true' })], []), /boolean/);
  assert.throws(() => loadGraph('{"nodes":[]}', { version: 'v' }), /edges/);
});

// ---------------------------------------------------------------------------
// Resource protection under adversarial cyclic input.
test('review: exponential cyclic input stops within budget and stays honestly labeled', async () => {
  const graph = completeDigraph(30);
  const started = performance.now();
  const result = await executeQuery(
    graph,
    AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
  );
  assert.ok(performance.now() - started < 6000);
  assert.equal(result.completeness, 'lowerBound');
  assert.ok(result.stopReason);
  assert.ok(result.unverifiedEdges > 0);
});

test('review: event loop stays responsive during a heavy query', async () => {
  const app = await buildApp(new StaticGraphRepository(completeDigraph(14)));
  try {
    await app.ready();
    const heavy = app.inject({
      method: 'POST',
      url: '/api/v1/routes/query',
      payload: { query: AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }) },
    });
    await new Promise((r) => setTimeout(r, 100));
    const t = performance.now();
    assert.equal((await app.inject({ url: '/health' })).statusCode, 200);
    assert.ok(performance.now() - t < 100, 'health check blocked by query');
    assert.equal((await heavy).statusCode, 200);
  } finally {
    await app.close();
  }
});

// ---------------------------------------------------------------------------
// HTTP negative tests.
test('review: HTTP rejects malformed requests with problem+json', async () => {
  const app = await buildApp(new StaticGraphRepository(real));
  try {
    await app.ready();
    const post = (payload) => app.inject({ method: 'POST', url: '/api/v1/routes/query', payload });
    const cases = [
      await app.inject({
        method: 'POST',
        url: '/api/v1/routes/query',
        headers: { 'content-type': 'application/json' },
        payload: '{bad',
      }),
      await post({ query: AND({ type: 'nope' }) }),
      await post({ query: AND({ type: 'public', extra: 1 }) }),
      await post({ query: { ...AND(), maxDepth: 1.5 } }),
      await post({ query: AND(), pageSize: 0 }),
      await post({
        query: AND(
          ...Array(6).fill({ scope: 'ANY_NODE', predicate: { field: 'a', op: 'exists' } }),
        ),
      }),
    ];
    for (const r of cases) {
      assert.equal(r.statusCode, 400, r.body);
      assert.match(r.headers['content-type'], /problem\+json/);
    }
    const tampered = await app.inject({ url: '/api/v1/results/abc.10.xyz' });
    assert.equal(tampered.statusCode, 410);
  } finally {
    await app.close();
  }
});

// ---------------------------------------------------------------------------
// Known failures / limitations (todo: reported, not CI-failing).
test('review: unknown routes use the same error format', async () => {
  const app = await buildApp(new StaticGraphRepository(real));
  try {
    await app.ready();
    const r = await app.inject({ url: '/nope' });
    assert.match(r.headers['content-type'], /problem\+json/);
  } finally {
    await app.close();
  }
});

test('review: filters on nested properties (e.g. vulnerability severity)', async () => {
  const graph = build(
    [
      {
        name: 'a',
        kind: 'service',
        publicExposed: true,
        vulnerabilities: [{ severity: 'high' }],
      },
      { name: 'b', kind: 'rds' },
    ],
    [{ from: 'a', to: 'b' }],
  );
  const r = await executeQuery(
    graph,
    AND({
      scope: 'ANY_NODE',
      predicate: { field: 'vulnerabilities.severity', op: 'eq', value: 'high' },
    }),
  );
  assert.ok(r.nodeCount > 0);
});

test(
  'review KNOWN LIMITATION: union subgraph renders routes that do not match',
  {
    todo: 'response is a union of nodes/edges, without paths; client cannot distinguish matching routes',
  },
  async () => {
    const svc = (name, extra = {}) => ({ name, kind: 'service', ...extra });
    const graph = build(
      [
        svc('P', { publicExposed: true }),
        svc('Q', { publicExposed: true }),
        svc('V', { vulnerabilities: [{}] }),
        svc('W', { vulnerabilities: [{}] }),
        svc('A'),
        { name: 'S', kind: 'rds' },
        { name: 'S2', kind: 'rds' },
      ],
      [
        { from: 'P', to: ['V'] },
        { from: 'V', to: ['A'] },
        { from: 'A', to: ['S', 'W'] },
        { from: 'Q', to: ['A'] },
        { from: 'W', to: ['S2'] },
      ],
    );
    const r = await executeQuery(
      graph,
      AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
    );
    const edges = edgeNames(graph, r);
    // Q->A->S is public->sink with no vulnerability, yet fully drawn.
    assert.ok(!(edges.includes('Q->A') && edges.includes('A->S')));
  },
);

test(
  'review KNOWN LIMITATION: small dense cyclic graph (12 nodes) answered exactly',
  { todo: 'DFS exhausts the default 25M-operation budget; no targeted witness search' },
  async () => {
    const r = await executeQuery(
      completeDigraph(12),
      AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
    );
    assert.equal(r.completeness, 'exact');
  },
);
