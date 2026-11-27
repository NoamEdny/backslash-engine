import type { GraphSnapshot, GraphNode, GraphEdge } from '../graph/model.js';
import type { CompiledQuery } from './model.js';
import { matches } from './predicates.js';
import { createDefaultRegistry, type FilterRegistry, type ResolvedFilter } from './registry.js';
import { validateQuery } from './validation.js';

function matchesFilter(entity: GraphNode | GraphEdge, filter: ResolvedFilter): boolean {
  // Custom callbacks are trusted, synchronous and must be pure.
  return 'match' in filter ? filter.match(entity) === true : matches(entity, filter.predicate);
}

/** Compile once per query; traversal only reads numeric masks. */
export function compileQuery(
  graph: GraphSnapshot,
  input: unknown,
  registry: FilterRegistry = createDefaultRegistry(),
): CompiledQuery {
  const steps = compileValidatedQuerySteps(graph, validateQuery(input, registry));
  let step = steps.next();
  while (!step.done) step = steps.next();
  return step.value;
}

/** Each yielded count represents completed node/edge evaluations. */
export function* compileValidatedQuerySteps(
  graph: GraphSnapshot,
  { filters, maxDepth }: ReturnType<typeof validateQuery>,
  initialBatch = 4096,
): Generator<number, CompiledQuery, number | void> {
  let batch = initialBatch,
    work = 0;
  function* tick(): Generator<number, void, number | void> {
    if (++work >= batch) {
      batch = (yield work) ?? 4096;
      work = 0;
    }
  }
  const startFilters = filters.filter((filter) => filter.scope === 'START');
  const endFilters = filters.filter((filter) => filter.scope === 'END');
  const allNodeFilters = filters.filter((filter) => filter.scope === 'ALL_NODES');
  const allEdgeFilters = filters.filter((filter) => filter.scope === 'ALL_EDGES');
  const anyNodeFilters = filters.filter((filter) => filter.scope === 'ANY_NODE');
  const starts = new Uint8Array(graph.nodeCount),
    ends = new Uint8Array(graph.nodeCount);
  const allowedNodes = new Uint8Array(graph.nodeCount),
    allowedEdges = new Uint8Array(graph.edgeCount);
  const nodeMasks = new Uint32Array(graph.nodeCount);
  for (let id = 0; id < graph.nodeCount; id++) {
    const node = graph.node(id);
    if (!allNodeFilters.every((filter) => matchesFilter(node, filter))) {
      yield* tick();
      continue;
    }
    allowedNodes[id] = 1;
    if (startFilters.every((filter) => matchesFilter(node, filter))) starts[id] = 1;
    if (endFilters.every((filter) => matchesFilter(node, filter))) ends[id] = 1;
    let mask = 0;
    for (let bit = 0; bit < anyNodeFilters.length; bit++) {
      if (matchesFilter(node, anyNodeFilters[bit]!)) mask |= 1 << bit;
    }
    nodeMasks[id] = mask;
    yield* tick();
  }
  for (let id = 0; id < graph.edgeCount; id++) {
    const edge = graph.edge(id);
    if (
      edge.source !== edge.target &&
      allowedNodes[edge.source] &&
      allowedNodes[edge.target] &&
      allEdgeFilters.every((filter) => matchesFilter(edge, filter))
    )
      allowedEdges[id] = 1;
    yield* tick();
  }
  if (work) yield work;
  return {
    starts,
    ends,
    allowedNodes,
    allowedEdges,
    nodeMasks,
    requiredMask: (1 << anyNodeFilters.length) - 1,
    anyCount: anyNodeFilters.length,
    maxDepth,
  };
}
