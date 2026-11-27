import { readFileSync } from 'node:fs';
import { loadGraph, executeQuery } from '../../dist/index.js';
const text = readFileSync(new URL('../../data/train-ticket.json', import.meta.url), 'utf8');
const g = loadGraph(text, { version: 'v' });
const names = (r) => [...r.nodes].map((b, i) => (b ? g.node(i).id : null)).filter(Boolean);
for (const fs of [
  [{ type: 'public' }],
  [{ type: 'sink' }],
  [{ type: 'vulnerability' }],
  [{ type: 'sink' }, { type: 'vulnerability' }],
  [{ type: 'public' }, { type: 'vulnerability' }],
  [],
]) {
  const r = await executeQuery(g, { operator: 'AND', filters: fs });
  console.log(
    JSON.stringify(fs.map((f) => f.type)),
    r.completeness,
    r.algorithm,
    'nodes',
    r.nodeCount,
    'edges',
    r.edgeCount,
    fs.length && r.nodeCount < 15 ? names(r).join(',') : '',
  );
}
console.log(g.diagnostics);
console.log(g.node(g.findNode('prod-postgresdb')).properties);
