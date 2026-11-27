// Independent review tests, including differential checks against a brute-force
// oracle that shares no code with the engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  loadGraph,
  executeQuery,
  executePaths,
  compileQuery,
  buildProductRegion,
  StaticGraphRepository,
} from '../dist/index.js';
import { findWitness, isMatchingSimplePath } from '../dist/query/witness.js';
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
test('review: complete digraphs are answered exactly under the default budget', async () => {
  for (const n of [12, 30]) {
    const graph = completeDigraph(n);
    const result = await executeQuery(
      graph,
      AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
    );
    assert.equal(result.completeness, 'exact', `K${n}`);
    assert.equal(result.nodeCount, n);
    // Every edge except those into the start, out of the sink, and start->sink
    // (which cannot contain the vulnerable middle node).
    const start = graph.node(0).id,
      sink = graph.node(n - 1).id;
    const expected = [];
    for (let i = 0; i < n; i++)
      for (let j = 0; j < n; j++) {
        const [a, b] = [graph.node(i).id, graph.node(j).id];
        if (i !== j && b !== start && a !== sink && !(a === start && b === sink))
          expected.push(`${a}->${b}`);
      }
    assert.deepEqual(edgeNames(graph, result), expected.sort(), `K${n}`);
  }
});

/** Dense core with two starts and two sinks (so no boundary pruning applies) and a
 * detour s1 -> x -> s1 that exists only as a walk. Witnesses cannot confirm it and
 * only an exhaustive DFS could exclude it, which is exponential in the core size. */
function denseCoreWithFalseDetour(core) {
  const svc = (name, extra = {}) => ({ name, kind: 'service', ...extra });
  const names = Array.from({ length: core }, (_, i) => `c${String(i).padStart(2, '0')}`);
  const nodes = [
    svc('s1', { publicExposed: true }),
    svc('s2', { publicExposed: true }),
    svc('x'),
    ...names.map((name, i) => svc(name, i === 0 ? { vulnerabilities: [{}] } : {})),
    { name: 't1', kind: 'rds' },
    { name: 't2', kind: 'rds' },
  ];
  const edges = [
    { from: 's1', to: [...names, 'x'] },
    { from: 's2', to: [...names, 's1'] },
    { from: 'x', to: ['s1'] },
    ...names.map((a) => ({ from: a, to: [...names.filter((b) => b !== a), 't1', 't2'] })),
  ];
  return { nodes, edges };
}

test('review: hard cyclic input stays a sound lower bound within the operation budget', async () => {
  const { nodes, edges } = denseCoreWithFalseDetour(14);
  const graph = build(nodes, edges);
  const query = AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' });
  const maxOperations = 2_000_000;
  const started = performance.now();
  const result = await executeQuery(graph, query, { maxOperations });
  assert.ok(performance.now() - started < 6000);
  assert.equal(result.completeness, 'lowerBound');
  assert.equal(result.stopReason, 'OPERATION_BUDGET');
  assert.ok(result.operations <= maxOperations);
  // Sound: the two detour edges and x are never confirmed. Everything else is.
  const confirmed = edgeNames(graph, result);
  assert.ok(!confirmed.includes('s1->x') && !confirmed.includes('x->s1'));
  assert.ok(!nodeNames(graph, result).includes('x'));
  assert.equal(result.unverifiedEdges, 2);
  assert.equal(result.unverifiedNodes, 1);
  // The same instance at a size the oracle can enumerate is exact and matches it.
  const small = denseCoreWithFalseDetour(4);
  const smallGraph = build(small.nodes, small.edges);
  const smallResult = await executeQuery(smallGraph, query);
  assert.equal(smallResult.completeness, 'exact');
  const flat = small.edges.flatMap((e) => e.to.map((to) => ({ from: e.from, to })));
  // The oracle takes explicit predicates equivalent to the named filters.
  const explicit = AND(
    { scope: 'START', predicate: { field: 'publicExposed', op: 'eq', value: true } },
    { scope: 'END', predicate: { field: 'kind', op: 'in', value: ['rds', 'sql'] } },
    { scope: 'ANY_NODE', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
  );
  const expected = bruteForce(small.nodes, flat, explicit);
  assert.deepEqual(nodeNames(smallGraph, smallResult), expected.nodes);
  assert.deepEqual(edgeNames(smallGraph, smallResult), expected.edges);
});

test('review: event loop stays responsive during a heavy query', async () => {
  const { nodes, edges } = denseCoreWithFalseDetour(14);
  const app = await buildApp(new StaticGraphRepository(build(nodes, edges)));
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
    const response = await heavy;
    assert.equal(response.statusCode, 200);
    // The query must still have been running when /health answered.
    assert.equal(response.json().meta.completeness, 'lowerBound');
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

test('review: union items lie on matching paths, may imply nonmatching routes, paths stay exact', async () => {
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
  const query = AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' });
  const union = await executeQuery(graph, query);
  const paths = await executePaths(graph, query, 100);
  assert.equal(union.completeness, 'exact');
  assert.equal(paths.completeness, 'exact');
  const routes = paths.paths.map((p) => p.nodes.join('->')).sort();
  assert.deepEqual(routes, ['P->V->A->S', 'P->V->A->W->S2', 'Q->A->W->S2']);
  // 1. Every union item participates in at least one actual matching path.
  const edgeName = (id) => {
    const e = graph.edge(Number(id.slice(1)));
    return `${graph.node(e.source).id}->${graph.node(e.target).id}`;
  };
  assert.deepEqual(
    nodeNames(graph, union),
    [...new Set(paths.paths.flatMap((p) => p.nodes))].sort(),
  );
  assert.deepEqual(
    edgeNames(graph, union),
    [...new Set(paths.paths.flatMap((p) => p.edges.map(edgeName)))].sort(),
  );
  // 2. Combining valid union edges implies Q->A->S, which has no vulnerability.
  const unionEdges = edgeNames(graph, union);
  assert.ok(unionEdges.includes('Q->A') && unionEdges.includes('A->S'));
  assert.ok(!routes.includes('Q->A->S'));
  // 3. Explicit paths are actual matching paths, with edges matching consecutive nodes.
  for (const p of paths.paths) {
    assert.deepEqual(
      p.edges.map(edgeName),
      p.nodes.slice(1).map((node, i) => `${p.nodes[i]}->${node}`),
    );
  }
});

// ---------------------------------------------------------------------------
// Boundary pruning and targeted witnesses.
const svcNode = (name, extra = {}) => ({ name, kind: 'service', ...extra });
const PS = AND({ type: 'public' }, { type: 'sink' });

test('pruning: edges into a unique start or out of a unique end are excluded', async () => {
  const graph = build(
    [svcNode('s', { publicExposed: true }), svcNode('a'), { name: 't', kind: 'rds' }],
    [
      { from: 's', to: 'a' },
      { from: 'a', to: ['s', 't'] },
      { from: 't', to: 'a' },
    ],
  );
  const result = await executeQuery(graph, PS);
  // Without pruning, a->s and t->a make the candidate region cyclic.
  assert.equal(result.algorithm, 'product-bfs');
  assert.equal(result.completeness, 'exact');
  assert.deepEqual(edgeNames(graph, result), ['a->t', 's->a']);
});

test('pruning: not applied when there are two starts or two ends', async () => {
  const graph = build(
    [
      svcNode('s1', { publicExposed: true }),
      svcNode('s2', { publicExposed: true }),
      { name: 't1', kind: 'rds' },
      { name: 't2', kind: 'rds' },
    ],
    [
      { from: 's1', to: 's2' },
      { from: 's2', to: 't1' },
      { from: 't1', to: 't2' },
    ],
  );
  const result = await executeQuery(graph, PS);
  // s1->s2 enters a start and t1->t2 leaves an end; both are on s1->s2->t1->t2.
  assert.deepEqual(edgeNames(graph, result), ['s1->s2', 's2->t1', 't1->t2']);
});

test('pruning: a node that is the only start and only end keeps its zero-length path', async () => {
  const graph = build(
    [{ name: 'p', kind: 'rds', publicExposed: true }, svcNode('a')],
    [
      { from: 'p', to: 'a' },
      { from: 'a', to: 'p' },
    ],
  );
  const result = await executeQuery(graph, PS);
  assert.equal(result.completeness, 'exact');
  assert.deepEqual(nodeNames(graph, result), ['p']);
  assert.deepEqual(edgeNames(graph, result), []);
});

test('witness: never confirms an edge through a repeated node', async () => {
  // The only way to collect the vulnerability is a->w->a, so nothing matches.
  const graph = build(
    [
      svcNode('s', { publicExposed: true }),
      svcNode('a'),
      svcNode('w', { vulnerabilities: [{}] }),
      { name: 't', kind: 'rds' },
    ],
    [
      { from: 's', to: 'a' },
      { from: 'a', to: ['w', 't'] },
      { from: 'w', to: 'a' },
    ],
  );
  const query = AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' });
  const compiled = compileQuery(graph, query);
  const region = buildProductRegion(graph, compiled);
  assert.equal(region.acyclic, false);
  const used = new Uint8Array(graph.nodeCount);
  for (let edgeId = 0; edgeId < graph.edgeCount; edgeId++) {
    if (!region.edges[edgeId]) continue;
    const steps = findWitness(graph, compiled, region, edgeId, used);
    let step = steps.next();
    while (!step.done) step = steps.next();
    assert.equal(step.value, undefined);
    assert.ok(
      used.every((v) => v === 0),
      'scratch array restored',
    );
  }
  const result = await executeQuery(graph, query);
  assert.equal(result.completeness, 'exact');
  assert.equal(result.nodeCount, 0);
});

test('witness: the independent path check rejects invalid candidates', () => {
  const graph = build(
    [
      svcNode('s', { publicExposed: true }),
      svcNode('v', { vulnerabilities: [{}] }),
      { name: 't', kind: 'rds' },
    ],
    [
      { from: 's', to: ['v', 't'] },
      { from: 'v', to: ['s', 't'] },
    ],
  );
  const id = (name) => graph.findNode(name);
  const edge = (a, b) => {
    for (const e of graph.outgoing(id(a))) if (graph.edge(e).target === id(b)) return e;
  };
  const query = compileQuery(
    graph,
    AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
  );
  const path = (...names) => ({
    nodes: names.map(id),
    edges: names.slice(1).map((name, i) => edge(names[i], name)),
  });
  assert.equal(isMatchingSimplePath(graph, query, path('s', 'v', 't')), true);
  assert.equal(isMatchingSimplePath(graph, query, path('s', 't')), false); // no vulnerability
  assert.equal(isMatchingSimplePath(graph, query, path('s', 'v', 's', 't')), false); // repeated
  assert.equal(isMatchingSimplePath(graph, query, path('v', 't')), false); // not a start
  const shallow = compileQuery(graph, {
    ...AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }),
    maxDepth: 1,
  });
  assert.equal(isMatchingSimplePath(graph, shallow, path('s', 'v', 't')), false); // too long
});

test('witness and pruning: dense random graphs match the brute-force oracle exactly', async () => {
  let seed = 20261127;
  const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const pool = [
    { scope: 'START', predicate: { field: 'publicExposed', op: 'eq', value: true } },
    { scope: 'END', predicate: { field: 'kind', op: 'in', value: ['rds'] } },
    { scope: 'ANY_NODE', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
    { scope: 'ANY_NODE', predicate: { field: 'tag', op: 'eq', value: 'a' } },
    { scope: 'ALL_NODES', predicate: { field: 'tag', op: 'in', value: ['a', 'b'] } },
  ];
  let cyclic = 0,
    singleStart = 0;
  for (let it = 0; it < 600; it++) {
    const n = 3 + Math.floor(rnd() * 6);
    const nodes = Array.from({ length: n }, (_, i) => ({
      name: `n${i}`,
      kind: i === n - 1 || rnd() < 0.15 ? 'rds' : 'service',
      publicExposed: i === 0 || rnd() < 0.15,
      vulnerabilities: rnd() < 0.3 ? [{}] : [],
      tag: pick(['a', 'b', 'c']),
    }));
    const density = 0.6 + rnd() * 0.4;
    const edges = [];
    for (let i = 0; i < n; i++)
      for (let j = 0; j < n; j++)
        if (i !== j && rnd() < density) edges.push({ from: `n${i}`, to: [`n${j}`] });
    const query = AND(pool[0], pool[1], ...pool.slice(2).filter(() => rnd() < 0.5));
    if (rnd() < 0.3) query.maxDepth = 1 + Math.floor(rnd() * 4);
    if (nodes.filter((x) => x.publicExposed).length === 1) singleStart++;
    const graph = build(nodes, edges);
    const result = await executeQuery(graph, query);
    if (result.algorithm === 'pruned-dfs') cyclic++;
    const context = JSON.stringify({ query, nodes, edges });
    assert.equal(result.completeness, 'exact', context);
    const expected = bruteForce(
      nodes,
      edges.map((e) => ({ from: e.from, to: e.to[0] })),
      query,
    );
    assert.deepEqual(nodeNames(graph, result), expected.nodes, context);
    assert.deepEqual(edgeNames(graph, result), expected.edges, context);
  }
  assert.ok(cyclic > 150, `cyclic coverage too low: ${cyclic}`);
  assert.ok(singleStart > 150, `single-start coverage too low: ${singleStart}`);
});

test('witness: every operation budget gives a sound, consistent partial result', async () => {
  const graph = completeDigraph(6);
  const query = AND({ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' });
  const full = await executeQuery(graph, query);
  assert.equal(full.completeness, 'exact');
  for (let maxOperations = 0; maxOperations <= full.operations; maxOperations += 7) {
    const r = await executeQuery(graph, query, { maxOperations });
    assert.ok(r.operations <= maxOperations);
    for (let i = 0; i < graph.edgeCount; i++) {
      if (!r.edges[i]) continue;
      assert.ok(full.edges[i], 'confirmed edge must be in the exact answer');
      assert.ok(r.nodes[graph.edge(i).source] && r.nodes[graph.edge(i).target]);
    }
    for (let i = 0; i < graph.nodeCount; i++) if (r.nodes[i]) assert.ok(full.nodes[i]);
    if (r.completeness === 'exact') assert.deepEqual(edgeNames(graph, r), edgeNames(graph, full));
    else assert.equal(r.stopReason, 'OPERATION_BUDGET');
  }
});

test('witness: failed attempts cannot starve the exhaustive DFS of its budget', async () => {
  // A chain with long back edges. Every back-edge witness walks back half the chain
  // before failing; only the DFS can prove these edges are on no simple path.
  const n = 4000,
    backEdges = 200;
  const id = (i) => `n${String(i).padStart(5, '0')}`;
  const nodes = Array.from({ length: n }, (_, i) => ({
    name: id(i),
    kind: i === n - 1 ? 'rds' : 'service',
    publicExposed: i === 0,
  }));
  const edges = [];
  for (let i = 0; i < n - 1; i++) edges.push({ from: id(i), to: id(i + 1) });
  for (let j = 1; j <= backEdges; j++) {
    const a = Math.floor((j * n) / (2 * (backEdges + 1)));
    edges.push({ from: id(a + n / 2), to: id(a) });
  }
  const graph = build(nodes, edges);
  // Without the cap the witness pass alone needs more than this budget.
  const result = await executeQuery(graph, AND({ type: 'public' }, { type: 'sink' }), {
    maxOperations: 400_000,
  });
  assert.equal(result.completeness, 'exact', result.stopReason);
  assert.equal(result.edgeCount, n - 1);
});
