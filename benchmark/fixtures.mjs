// Synthetic graph inputs shared by the stress and HTTP smoke scripts.
// Each function returns loader input: { nodes, edges }.

const service = (name, extra = {}) => ({ name, kind: 'service', ...extra });

/** Complete digraph: n0 is the only public start, the last node the only sink,
 * the middle node vulnerable. Exponentially many simple paths. */
export function completeDigraph(n) {
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
  return { nodes, edges };
}

/** A chain of k two-node cycles (a_i <-> b_i) from s to t, plus s <-> x. */
export function cycleLadder(k) {
  const nodes = [service('s', { publicExposed: true })];
  const edges = [];
  let previous = 's';
  for (let i = 0; i < k; i++) {
    const [a, b, join] = [`a${i}`, `b${i}`, `j${i}`];
    nodes.push(service(a), service(b), service(join));
    edges.push(
      { from: previous, to: [a, b] },
      { from: a, to: [b, join] },
      { from: b, to: [a, join] },
    );
    previous = join;
  }
  nodes.push({ name: 't', kind: 'rds' }, service('x', { vulnerabilities: [{}] }));
  edges.push({ from: previous, to: ['t'] }, { from: 's', to: ['x'] }, { from: 'x', to: ['s'] });
  return { nodes, edges };
}

/** Dense core with two starts and two sinks, so no boundary pruning applies, and a
 * detour s1 -> x -> s1 that exists only as a walk. Proving that the detour is on
 * no matching path requires exhausting all simple paths through the core. */
export function denseCoreWithFalseDetour(core) {
  const names = Array.from({ length: core }, (_, i) => `c${String(i).padStart(2, '0')}`);
  const nodes = [
    service('s1', { publicExposed: true }),
    service('s2', { publicExposed: true }),
    service('x'),
    ...names.map((name, i) => service(name, i === 0 ? { vulnerabilities: [{}] } : {})),
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
