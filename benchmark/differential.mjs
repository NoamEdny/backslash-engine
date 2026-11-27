// Differential check: 3,000 random graphs (many cyclic) against an independent
// brute-force enumeration of matching simple paths. Exits non-zero on any
// mismatch or any result that is not exact.
import { loadGraph, executeQuery } from '../dist/index.js';
let seed = 987654321;
const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
const pick = (a) => a[Math.floor(rnd() * a.length)];
function brute(nodes, edges, q) {
  // nodes: [{name,kind,pub,vul,tag}], edges [[s,t]]
  const ok = (n, f) => {
    const p = f.predicate;
    const v = p.field === 'kind' ? n.kind : n.props[p.field];
    if (p.op === 'eq') return v === p.value;
    if (p.op === 'notEmpty') return Array.isArray(v) && v.length > 0;
    if (p.op === 'in') return p.value.includes(v);
    throw 0;
  };
  const by = (s) => q.filters.filter((f) => f.scope === s);
  const N = new Set(),
    E = new Set();
  const max = q.maxDepth ?? Infinity;
  const adj = new Map(nodes.map((n) => [n.name, []]));
  edges.forEach(([s, t], i) => {
    if (s !== t) adj.get(s).push([t, i]);
  });
  const nodeOk = (n) => by('ALL_NODES').every((f) => ok(n, f));
  const byName = new Map(nodes.map((n) => [n.name, n]));
  function dfs(path, eids) {
    const first = byName.get(path[0]),
      last = byName.get(path.at(-1));
    if (
      by('START').every((f) => ok(first, f)) &&
      by('END').every((f) => ok(last, f)) &&
      by('ANY_NODE').every((f) => path.some((x) => ok(byName.get(x), f)))
    ) {
      path.forEach((x) => N.add(x));
      eids.forEach((e) => E.add(e));
    }
    if (eids.length >= max) return;
    for (const [t, i] of adj.get(path.at(-1)))
      if (!path.includes(t) && nodeOk(byName.get(t))) dfs([...path, t], [...eids, i]);
  }
  for (const n of nodes) if (nodeOk(n)) dfs([n.name], []);
  return { N, E };
}
let mismatches = 0,
  runs = 0,
  cyclic = 0,
  lower = 0;
for (let it = 0; it < 3000; it++) {
  const n = 2 + Math.floor(rnd() * 8);
  const nodes = Array.from({ length: n }, (_, i) => ({
    name: 'n' + i,
    kind: pick(['service', 'rds', 'sqs']),
    props: {
      publicExposed: rnd() < 0.3,
      vulnerabilities: rnd() < 0.25 ? [{ s: 1 }] : [],
      tag: pick(['a', 'b', 'c']),
    },
  }));
  const edges = [];
  const p = rnd() * 0.5;
  for (let i = 0; i < n; i++)
    for (let j = 0; j < n; j++) if (rnd() < p) edges.push(['n' + i, 'n' + j]);
  const pool = [
    { scope: 'START', predicate: { field: 'publicExposed', op: 'eq', value: true } },
    { scope: 'END', predicate: { field: 'kind', op: 'in', value: ['rds'] } },
    { scope: 'ANY_NODE', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
    { scope: 'ANY_NODE', predicate: { field: 'tag', op: 'eq', value: 'a' } },
    { scope: 'ANY_NODE', predicate: { field: 'tag', op: 'eq', value: 'b' } },
    { scope: 'ALL_NODES', predicate: { field: 'tag', op: 'in', value: ['a', 'b'] } },
    { scope: 'START', predicate: { field: 'tag', op: 'eq', value: 'c' } },
    { scope: 'END', predicate: { field: 'vulnerabilities', op: 'notEmpty' } },
  ];
  const filters = pool.filter(() => rnd() < 0.3);
  const q = { operator: 'AND', filters };
  if (rnd() < 0.3) q.maxDepth = Math.floor(rnd() * 4);
  const json = {
    nodes: nodes.map((x) => ({ name: x.name, kind: x.kind, ...x.props })),
    edges: edges.map(([f, t]) => ({ from: f, to: [t] })),
  };
  const g = loadGraph(JSON.stringify(json), { version: 'x' });
  // map edge indices: engine sorts + dedups; compare by "s->t" keys
  const r = await executeQuery(g, q);
  runs++;
  if (r.algorithm === 'pruned-dfs') cyclic++;
  if (r.completeness !== 'exact') {
    lower++;
    continue;
  }
  const b = brute(nodes, edges, q);
  const en = new Set([...r.nodes].map((v, i) => (v ? g.node(i).id : null)).filter(Boolean));
  const ee = new Set(
    [...r.edges]
      .map((v, i) => {
        if (!v) return null;
        const e = g.edge(i);
        return g.node(e.source).id + '>' + g.node(e.target).id;
      })
      .filter(Boolean),
  );
  const be = new Set([...b.E].map((i) => edges[i].join('>')));
  const same = (a, c) => a.size === c.size && [...a].every((x) => c.has(x));
  if (!same(en, b.N) || !same(ee, be)) {
    mismatches++;
    if (mismatches < 4)
      console.log(
        'MISMATCH',
        JSON.stringify(q),
        JSON.stringify(json),
        [...en],
        [...b.N],
        [...ee],
        [...be],
      );
  }
}
console.log({ runs, cyclic, lower, mismatches });
if (mismatches || lower) process.exitCode = 1;
