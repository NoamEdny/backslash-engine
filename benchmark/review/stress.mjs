import { loadGraph, executeQuery } from '../../dist/index.js';
function complete(n, vulnIdx) {
  // complete digraph -> exponential simple paths
  const nodes = Array.from({ length: n }, (_, i) => ({
    name: 'n' + String(i).padStart(3, '0'),
    kind: i === n - 1 ? 'rds' : 'service',
    publicExposed: i === 0,
    vulnerabilities: i === vulnIdx ? [{}] : [],
  }));
  const edges = nodes.map((a, i) => ({
    from: a.name,
    to: nodes.filter((_, j) => j !== i).map((b) => b.name),
  }));
  return loadGraph(JSON.stringify({ nodes, edges }), { version: 'c' });
}
for (const n of [12, 30, 200]) {
  const g = complete(n, Math.floor(n / 2));
  let t = performance.now();
  const r = await executeQuery(g, {
    operator: 'AND',
    filters: [{ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }],
  });
  console.log(
    'complete',
    n,
    'edges',
    g.edgeCount,
    r.completeness,
    r.algorithm,
    r.stopReason,
    'ms',
    (performance.now() - t).toFixed(0),
    'ops',
    r.operations,
    'found',
    r.nodeCount,
    r.edgeCount,
    'unverified',
    r.unverifiedNodes,
    r.unverifiedEdges,
  );
}
// Adversarial: a hard-to-confirm edge requires exhausting search. ladder of cycles with a dead-end trap
function trap(k) {
  // chain of k "diamond-cycles" then edge that only valid if...; s -> (a_i <-> b_i) ... -> t ; plus back edge t2->s
  const nodes = [{ name: 's', kind: 'service', publicExposed: true }],
    edges = [];
  let prev = 's';
  for (let i = 0; i < k; i++) {
    const a = 'a' + i,
      b = 'b' + i;
    nodes.push({ name: a, kind: 'service' }, { name: b, kind: 'service' });
    edges.push({ from: prev, to: [a, b] }, { from: a, to: [b] }, { from: b, to: [a] });
    prev = 'j' + i;
    nodes.push({ name: prev, kind: 'service' });
    edges.push({ from: a, to: [prev] }, { from: b, to: [prev] });
  }
  nodes.push({ name: 't', kind: 'rds' });
  edges.push({ from: prev, to: ['t'] });
  // an edge that is in the upper bound but never on a simple path: x->s where x reachable only from s
  nodes.push({ name: 'x', kind: 'service', vulnerabilities: [{}] });
  edges.push({ from: 's', to: ['x'] }, { from: 'x', to: ['s'] });
  return loadGraph(JSON.stringify({ nodes, edges }), { version: 't' });
}
for (const k of [10, 20, 40]) {
  const g = trap(k);
  let t = performance.now();
  const r = await executeQuery(g, {
    operator: 'AND',
    filters: [{ type: 'public' }, { type: 'sink' }],
  });
  console.log(
    'trap',
    k,
    r.completeness,
    r.algorithm,
    r.stopReason,
    'ms',
    (performance.now() - t).toFixed(0),
    'ops',
    r.operations,
    'found',
    r.nodeCount,
    r.edgeCount,
    'unverified',
    r.unverifiedNodes,
    r.unverifiedEdges,
  );
}
