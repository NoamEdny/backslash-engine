// Dense and adversarial cyclic graphs under the production default execution
// settings (25M operations, 5 s). Prints one JSON line per scenario.
import { loadGraph, executeQuery } from '../dist/index.js';
import { completeDigraph, cycleLadder, denseCoreWithFalseDetour } from './fixtures.mjs';

const scenarios = [
  ...[12, 30, 200].map((n) => ['complete', n, completeDigraph(n), true]),
  ...[10, 20, 40].map((k) => ['cycle-ladder', k, cycleLadder(k), false]),
  ...[14, 30].map((k) => ['dense-core-false-detour', k, denseCoreWithFalseDetour(k), true]),
];
for (const [scenario, size, input, withVulnerability] of scenarios) {
  const graph = loadGraph(JSON.stringify(input), { version: scenario });
  const filters = [{ type: 'public' }, { type: 'sink' }];
  if (withVulnerability) filters.push({ type: 'vulnerability' });
  const start = performance.now();
  const r = await executeQuery(graph, { operator: 'AND', filters });
  console.log(
    JSON.stringify({
      scenario,
      size,
      nodes: graph.nodeCount,
      edges: graph.edgeCount,
      completeness: r.completeness,
      algorithm: r.algorithm,
      stopReason: r.stopReason ?? null,
      ms: Math.round(performance.now() - start),
      operations: r.operations,
      confirmedNodes: r.nodeCount,
      confirmedEdges: r.edgeCount,
      unverifiedNodes: r.unverifiedNodes,
      unverifiedEdges: r.unverifiedEdges,
    }),
  );
}
