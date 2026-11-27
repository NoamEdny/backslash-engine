import type { GraphSnapshot } from '../graph/model.js';
import type { CompiledQuery } from './model.js';
import { QueryLimitError } from './model.js';

export interface ProductRegion {
  readonly stateCount: number;
  /** Flat state index: node * stateCount + mask. -1 means unreachable. */
  readonly forward: Int32Array;
  readonly backward: Int32Array;
  readonly nodes: Uint8Array;
  readonly edges: Uint8Array;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly acyclic: boolean;
}
export interface ReachabilityOptions {
  readonly maxStateBytes?: number;
}
const DEFAULT_MAX_BYTES = 128 * 1024 * 1024;

/** Work is yielded in bounded batches so the eventual orchestrator can enforce
 * cancellation and budgets without duplicating the traversal. */
export function* productRegionSteps(
  graph: GraphSnapshot,
  query: CompiledQuery,
  options: ReachabilityOptions = {},
  initialBatch = 4096,
): Generator<number, ProductRegion, number | void> {
  const totalNodes = graph.nodeCount;
  const totalEdges = graph.edgeCount;
  const maskCount = 2 ** query.anyCount;
  const totalStates = totalNodes * maskCount;
  const memoryLimit = options.maxStateBytes ?? DEFAULT_MAX_BYTES;
  // Two distance arrays, one reusable queue, candidate masks and indegrees.
  if (
    !Number.isSafeInteger(memoryLimit) ||
    memoryLimit < 0 ||
    totalStates >= 0x7fffffff ||
    12 * totalStates + 5 * totalNodes + totalEdges > memoryLimit
  ) {
    throw new QueryLimitError('$.filters', 'Product reachability exceeds working-memory limit');
  }
  const forward = new Int32Array(totalStates);
  const backward = new Int32Array(totalStates);
  const queue = new Uint32Array(totalStates);
  const nodes = new Uint8Array(totalNodes);
  const edges = new Uint8Array(totalEdges);
  const indegree = new Uint32Array(totalNodes);
  let work = 0;
  let batch = initialBatch;
  // Count work at the inner-loop level, not just per visited node.
  function* tick(): Generator<number, void, number | void> {
    if (++work >= batch) {
      batch = (yield work) ?? 4096;
      work = 0;
    }
  }
  for (let stateIndex = 0; stateIndex < totalStates; stateIndex++) {
    forward[stateIndex] = -1;
    backward[stateIndex] = -1;
    yield* tick();
  }
  let head = 0;
  let tail = 0;
  const depthLimit = query.maxDepth ?? Infinity;
  // Forward BFS starts with the bits contributed by each allowed start.
  for (let sourceNode = 0; sourceNode < totalNodes; sourceNode++) {
    if (query.starts[sourceNode]) {
      const stateIndex = sourceNode * maskCount + query.nodeMasks[sourceNode]!;
      forward[stateIndex] = 0;
      queue[tail++] = stateIndex;
    }
    yield* tick();
  }
  while (head < tail) {
    const stateIndex = queue[head++]!;
    const sourceNode = Math.floor(stateIndex / maskCount);
    const mask = stateIndex % maskCount;
    const distance = forward[stateIndex]!;
    yield* tick();
    if (distance >= depthLimit) continue;
    for (const edgeId of graph.outgoing(sourceNode)) {
      yield* tick();
      if (!query.allowedEdges[edgeId]) continue;
      const targetNode = graph.edge(edgeId).target;
      const nextStateIndex = targetNode * maskCount + (mask | query.nodeMasks[targetNode]!);
      if (forward[nextStateIndex] === -1) {
        forward[nextStateIndex] = distance + 1;
        queue[tail++] = nextStateIndex;
      }
    }
  }
  // Precompute inverse OR transitions. Across all target masks, each
  // predecessor mask occurs exactly once for a fixed node mask.
  const inverseMasks: number[][][] = Array.from({ length: maskCount }, (_, bits) => {
    const lists: number[][] = Array.from({ length: maskCount }, () => []);
    for (let mask = 0; mask < maskCount; mask++) lists[mask | bits]!.push(mask);
    return lists;
  });
  // Reverse BFS starts from accepting states with all required bits set.
  head = 0;
  tail = 0;
  for (let targetNode = 0; targetNode < totalNodes; targetNode++) {
    if (query.ends[targetNode]) {
      const stateIndex = targetNode * maskCount + query.requiredMask;
      backward[stateIndex] = 0;
      queue[tail++] = stateIndex;
    }
    yield* tick();
  }
  while (head < tail) {
    const stateIndex = queue[head++]!;
    const targetNode = Math.floor(stateIndex / maskCount);
    const mask = stateIndex % maskCount;
    const distance = backward[stateIndex]!;
    yield* tick();
    if (distance >= depthLimit) continue;
    const masks = inverseMasks[query.nodeMasks[targetNode]!]![mask]!;
    for (const edgeId of graph.incoming(targetNode)) {
      yield* tick();
      if (!query.allowedEdges[edgeId]) continue;
      const sourceNode = graph.edge(edgeId).source;
      const sourceBits = query.nodeMasks[sourceNode]!;
      for (const previousMask of masks) {
        yield* tick();
        if ((previousMask & sourceBits) !== sourceBits) continue;
        const nextStateIndex = sourceNode * maskCount + previousMask;
        if (backward[nextStateIndex] === -1) {
          backward[nextStateIndex] = distance + 1;
          queue[tail++] = nextStateIndex;
        }
      }
    }
  }
  // Intersect forward and backward states to project the accepting walks.
  let nodeCount = 0;
  let edgeCount = 0;
  for (let sourceNode = 0; sourceNode < totalNodes; sourceNode++) {
    for (let mask = 0; mask < maskCount; mask++) {
      yield* tick();
      const distanceFromStart = forward[sourceNode * maskCount + mask]!;
      const distanceToEnd = backward[sourceNode * maskCount + mask]!;
      if (
        distanceFromStart >= 0 &&
        distanceToEnd >= 0 &&
        distanceFromStart + distanceToEnd <= depthLimit
      ) {
        nodes[sourceNode] = 1;
        nodeCount++;
        break;
      }
    }
  }
  // Test each transition, not just its endpoints: the masks must be compatible.
  for (let edgeId = 0; edgeId < totalEdges; edgeId++) {
    yield* tick();
    if (!query.allowedEdges[edgeId]) continue;
    const { source: sourceNode, target: targetNode } = graph.edge(edgeId);
    if (!nodes[sourceNode] || !nodes[targetNode]) continue;
    for (let mask = 0; mask < maskCount; mask++) {
      yield* tick();
      const distanceFromStart = forward[sourceNode * maskCount + mask]!;
      const nextMask = mask | query.nodeMasks[targetNode]!;
      const distanceToEnd = backward[targetNode * maskCount + nextMask]!;
      if (
        distanceFromStart >= 0 &&
        distanceToEnd >= 0 &&
        distanceFromStart + 1 + distanceToEnd <= depthLimit
      ) {
        edges[edgeId] = 1;
        edgeCount++;
        indegree[targetNode] = indegree[targetNode]! + 1;
        break;
      }
    }
  }
  // Kahn on the projected candidate graph, not on the original topology.
  head = 0;
  tail = 0;
  for (let sourceNode = 0; sourceNode < totalNodes; sourceNode++) {
    if (nodes[sourceNode] && indegree[sourceNode] === 0) queue[tail++] = sourceNode;
    yield* tick();
  }
  let processedNodes = 0;
  while (head < tail) {
    const sourceNode = queue[head++]!;
    processedNodes++;
    yield* tick();
    for (const edgeId of graph.outgoing(sourceNode)) {
      yield* tick();
      if (!edges[edgeId]) continue;
      const targetNode = graph.edge(edgeId).target;
      indegree[targetNode] = indegree[targetNode]! - 1;
      if (indegree[targetNode] === 0) queue[tail++] = targetNode;
    }
  }
  if (work) yield work;
  return {
    stateCount: maskCount,
    forward,
    backward,
    nodes,
    edges,
    nodeCount,
    edgeCount,
    acyclic: processedNodes === nodeCount,
  };
}

/** Synchronous convenience for tests and offline use. HTTP will drive the
 * step iterator cooperatively instead of blocking the event loop. */
export function buildProductRegion(
  graph: GraphSnapshot,
  query: CompiledQuery,
  options: ReachabilityOptions = {},
): ProductRegion {
  const steps = productRegionSteps(graph, query, options);
  let step = steps.next();
  while (!step.done) step = steps.next();
  return step.value;
}
