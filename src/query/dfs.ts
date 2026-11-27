import type { GraphSnapshot } from '../graph/model.js';
import type { CompiledQuery } from './model.js';
import type { ProductRegion } from './reachability.js';
import { ExecutionBudget, type StopReason } from './budget.js';
import { findWitness } from './witness.js';

export interface DfsResult {
  readonly nodes: Uint8Array;
  readonly edges: Uint8Array;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly completeness: 'exact' | 'lowerBound';
  readonly stopReason: StopReason | undefined;
  readonly operations: number;
  readonly unverifiedNodes: number;
  readonly unverifiedEdges: number;
}
interface Frame {
  node: number;
  mask: number;
  incoming: number | undefined;
  neighbors: Iterator<number>;
  evaluated: boolean;
  committed: boolean;
}

/** Confirm the union of matching simple paths, restricted to a completed
 * product-region upper bound from the same graph and compiled query. */
export async function executeDfs(
  graph: GraphSnapshot,
  query: CompiledQuery,
  region: ProductRegion,
  budget = new ExecutionBudget(),
): Promise<DfsResult> {
  const nodes = new Uint8Array(graph.nodeCount);
  const edges = new Uint8Array(graph.edgeCount);
  const visited = new Uint8Array(graph.nodeCount);
  const stack: Frame[] = [];
  let nodeCount = 0;
  let edgeCount = 0;
  const limit = query.maxDepth ?? Infinity;
  const initialOperations = budget.operations;
  const complete = () => nodeCount === region.nodeCount && edgeCount === region.edgeCount;
  function markNode(id: number) {
    if (!nodes[id]) {
      nodes[id] = 1;
      nodeCount++;
    }
  }
  function markEdge(id: number) {
    if (!edges[id]) {
      edges[id] = 1;
      edgeCount++;
    }
  }
  function enter(node: number, mask: number, incoming?: number) {
    visited[node] = 1;
    stack.push({
      node,
      mask,
      incoming,
      neighbors: graph.outgoing(node)[Symbol.iterator](),
      evaluated: false,
      committed: false,
    });
  }
  // Every yielded step performs bounded work. A matching path is a witness
  // for each of its items. Even interrupted commits preserve edge endpoints.
  function* steps(): Generator<void, void, void> {
    // First try one targeted witness per unconfirmed edge. This confirms most
    // items of dense cyclic regions cheaply; the DFS below handles the rest and
    // is still the only way to prove that an item is on no matching path.
    // The DFS stack is empty here, so `visited` is free to use as scratch.
    // Failed attempts can be expensive on long paths, so witnesses may use at most
    // half of the remaining operations; the exhaustive DFS always keeps the rest.
    const witnessStart = budget.operations;
    const witnessShare = Math.floor(budget.remainingOperations / 2);
    for (
      let edgeId = 0;
      edgeId < graph.edgeCount && !complete() && budget.operations - witnessStart < witnessShare;
      edgeId++
    ) {
      yield;
      if (!region.edges[edgeId] || edges[edgeId]) continue;
      const attempt = findWitness(graph, query, region, edgeId, visited);
      let step = attempt.next();
      while (!step.done && budget.operations - witnessStart < witnessShare) {
        yield;
        step = attempt.next();
      }
      if (!step.done) {
        // An interrupted witness may leave scratch marks. Clear them before DFS.
        attempt.return(undefined);
        visited.fill(0);
        break;
      }
      const witness = step.value;
      if (!witness) continue;
      for (const node of witness.nodes) markNode(node);
      for (const id of witness.edges) markEdge(id);
    }
    if (complete()) return;
    for (let start = 0; start < graph.nodeCount; start++) {
      yield;
      if (!query.starts[start] || !region.nodes[start]) continue;
      const mask = query.nodeMasks[start]!;
      const remaining = region.backward[start * region.stateCount + mask]!;
      if (remaining < 0 || remaining > limit) continue;
      enter(start, mask);
      while (stack.length && !complete()) {
        yield;
        const frame = stack[stack.length - 1]!;
        if (!frame.evaluated) {
          frame.evaluated = true;
          if (query.ends[frame.node] && frame.mask === query.requiredMask) {
            // Only uncommitted frames since the last matching prefix.
            for (let i = stack.length - 1; i >= 0 && !stack[i]!.committed; i--) {
              yield;
              const item = stack[i]!;
              markNode(item.node);
              if (item.incoming !== undefined) {
                markNode(stack[i - 1]!.node);
                markEdge(item.incoming);
              }
              item.committed = true;
            }
          }
          if (complete()) return;
        }
        const depth = stack.length - 1;
        const next = depth >= limit ? { done: true as const } : frame.neighbors.next();
        // Backtracking clears only the current path, not global reachability.
        if (next.done) {
          visited[frame.node] = 0;
          stack.pop();
          continue;
        }
        const edgeId = next.value;
        if (!region.edges[edgeId] || !query.allowedEdges[edgeId]) continue;
        const targetNode = graph.edge(edgeId).target;
        if (visited[targetNode]) continue;
        const nextMask = frame.mask | query.nodeMasks[targetNode]!;
        // A reverse distance is a lower bound on the remaining simple-path length.
        const distance = region.backward[targetNode * region.stateCount + nextMask]!;
        if (distance < 0 || depth + 1 + distance > limit) continue;
        enter(targetNode, nextMask, edgeId);
      }
      if (complete()) return;
    }
  }
  const iterator = steps();
  let exhausted = false;
  while (!complete()) {
    if (budget.stopReason) break;
    if (budget.shouldYield) {
      await budget.yieldControl();
      if (budget.stopReason) break;
    }
    // The generator yields before each unit; a final next() may only finish.
    budget.charge();
    if (iterator.next().done) {
      exhausted = true;
      break;
    }
  }
  iterator.return();
  const exact = exhausted || complete();
  return {
    nodes,
    edges,
    nodeCount,
    edgeCount,
    completeness: exact ? 'exact' : 'lowerBound',
    stopReason: exact ? undefined : budget.stopReason,
    operations: budget.operations - initialOperations,
    unverifiedNodes: exact ? 0 : region.nodeCount - nodeCount,
    unverifiedEdges: exact ? 0 : region.edgeCount - edgeCount,
  };
}
