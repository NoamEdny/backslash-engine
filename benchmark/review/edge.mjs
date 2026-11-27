import { loadGraph, executeQuery } from '../../dist/index.js';
const L = (o, p) => {
  try {
    const g = loadGraph(JSON.stringify(o), {
      version: 'v',
      ...(p ? { missingNodePolicy: p } : {}),
    });
    return `ok nodes=${g.nodeCount} edges=${g.edgeCount} diag=${g.diagnostics.map((d) => d.code)}`;
  } catch (e) {
    return 'ERR ' + e.message;
  }
};
const n = (name, x = {}) => ({ name, kind: 'service', ...x });
console.log('empty to[]        ', L({ nodes: [n('a')], edges: [{ from: 'a', to: [] }] }));
console.log('unknown source    ', L({ nodes: [n('a')], edges: [{ from: 'zz', to: ['a'] }] }));
console.log(
  '__proto__ node    ',
  L({ nodes: [n('__proto__'), n('a')], edges: [{ from: '__proto__', to: 'a' }] }),
);
console.log('vulns null        ', L({ nodes: [n('a', { vulnerabilities: null })], edges: [] }));
console.log('publicExposed str ', L({ nodes: [n('a', { publicExposed: 'true' })], edges: [] }));
console.log(
  'dup target in list',
  L({ nodes: [n('a'), n('b')], edges: [{ from: 'a', to: ['b', 'b'] }] }),
);
console.log(
  'two entries same from',
  L({
    nodes: [n('a'), n('b'), n('c')],
    edges: [
      { from: 'a', to: ['b'] },
      { from: 'a', to: ['c'] },
    ],
  }),
);
console.log(
  'drop policy       ',
  L({ nodes: [n('a')], edges: [{ from: 'a', to: ['x'] }] }, 'drop'),
);
console.log(
  'reject policy     ',
  L({ nodes: [n('a')], edges: [{ from: 'a', to: ['x'] }] }, 'reject'),
);
console.log('edges missing     ', L({ nodes: [n('a')] }));
// Genericity: nested field / severity filter
const g = loadGraph(
  JSON.stringify({
    nodes: [
      n('a', { publicExposed: true, vulnerabilities: [{ severity: 'high' }] }),
      n('b', { vulnerabilities: [{ severity: 'low' }] }),
    ],
    edges: [{ from: 'a', to: 'b' }],
  }),
  { version: 'v' },
);
for (const f of ['vulnerabilities.severity', 'vulnerabilities[].severity', 'metadata.cloud']) {
  try {
    const r = await executeQuery(g, {
      operator: 'AND',
      filters: [{ scope: 'ANY_NODE', predicate: { field: f, op: 'eq', value: 'high' } }],
    });
    console.log('field', f, '-> nodes', r.nodeCount, '(0 = cannot express)');
  } catch (e) {
    console.log('field', f, 'ERR', e.message);
  }
}
// Union lossiness: Q->A->S appears in rendered subgraph though no vuln on it
const u = loadGraph(
  JSON.stringify({
    nodes: [
      n('P', { publicExposed: true }),
      n('Q', { publicExposed: true }),
      n('V', { vulnerabilities: [{}] }),
      n('W', { vulnerabilities: [{}] }),
      n('A'),
      { name: 'S', kind: 'rds' },
      { name: 'S2', kind: 'rds' },
    ],
    edges: [
      { from: 'P', to: ['V'] },
      { from: 'V', to: ['A'] },
      { from: 'A', to: ['S', 'W'] },
      { from: 'Q', to: ['A'] },
      { from: 'W', to: ['S2'] },
    ],
  }),
  { version: 'u' },
);
const r = await executeQuery(u, {
  operator: 'AND',
  filters: [{ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }],
});
const es = [...r.edges]
  .map((v, i) => (v ? `${u.node(u.edge(i).source).id}->${u.node(u.edge(i).target).id}` : null))
  .filter(Boolean);
console.log(
  'union edges:',
  es.join(' '),
  ' => contains Q->A->S (public->sink, NO vulnerability):',
  es.includes('Q->A') && es.includes('A->S'),
);
