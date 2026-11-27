import type { GraphSnapshot } from '../graph/model.js';
import type { CompiledQuery } from './model.js';
import type { ProductRegion } from './reachability.js';
import type { ExecutionBudget, StopReason } from './budget.js';

export interface MatchingPath {
  readonly nodes: string[];
  readonly edges: string[];
}
export interface PathsResult {
  readonly paths: MatchingPath[];
  readonly graphVersion: string;
  readonly completeness: 'exact' | 'lowerBound';
  readonly stopReason: StopReason | 'PATH_LIMIT' | 'OUTPUT_LIMIT' | undefined;
  readonly operations: number;
}
interface Frame {
  node: number;
  mask: number;
  incoming?: number;
  neighbors: Iterator<number>;
  evaluated: boolean;
}

/** Enumerate actual simple paths, not combinations of the projected edges.
 * The output item cap bounds the total number of returned node and edge IDs. */
export async function enumeratePaths(
  graph: GraphSnapshot,
  query: CompiledQuery,
  region: ProductRegion,
  budget: ExecutionBudget,
  limit: number,
  itemLimit = 100_000,
): Promise<PathsResult> {
  const paths: MatchingPath[] = [];
  const visited = new Uint8Array(graph.nodeCount);
  const stack: Frame[] = [];
  const maxDepth = query.maxDepth ?? Infinity;
  let items = 0;
  let outputStop: 'PATH_LIMIT' | 'OUTPUT_LIMIT' | undefined;
  function enter(node: number, mask: number, incoming?: number) {
    visited[node] = 1;
    stack.push({
      node,
      mask,
      ...(incoming === undefined ? {} : { incoming }),
      neighbors: graph.outgoing(node)[Symbol.iterator](),
      evaluated: false,
    });
  }
  function* walk(): Generator<void, void, void> {
    for (let start = 0; start < graph.nodeCount; start++) {
      yield;
      if (!query.starts[start] || !region.nodes[start]) continue;
      const mask = query.nodeMasks[start]!;
      const distance = region.backward[start * region.stateCount + mask]!;
      if (distance < 0 || distance > maxDepth) continue;
      enter(start, mask);
      while (stack.length) {
        yield;
        const frame = stack[stack.length - 1]!;
        if (!frame.evaluated) {
          frame.evaluated = true;
          if (query.ends[frame.node] && frame.mask === query.requiredMask) {
            // Look for one additional match before declaring truncation.
            if (paths.length === limit) {
              outputStop = 'PATH_LIMIT';
              return;
            }
            if (items + 2 * stack.length - 1 > itemLimit) {
              outputStop = 'OUTPUT_LIMIT';
              return;
            }
            const path: MatchingPath = { nodes: [], edges: [] };
            for (const entry of stack) {
              yield;
              path.nodes.push(graph.node(entry.node).id);
              if (entry.incoming !== undefined) path.edges.push(`e${entry.incoming}`);
            }
            paths.push(path);
            items += path.nodes.length + path.edges.length;
          }
        }
        const depth = stack.length - 1;
        const next = depth >= maxDepth ? { done: true as const } : frame.neighbors.next();
        if (next.done) {
          visited[frame.node] = 0;
          stack.pop();
          continue;
        }
        const edgeId = next.value;
        if (!region.edges[edgeId] || !query.allowedEdges[edgeId]) continue;
        const target = graph.edge(edgeId).target;
        if (visited[target]) continue;
        const nextMask = frame.mask | query.nodeMasks[target]!;
        const remaining = region.backward[target * region.stateCount + nextMask]!;
        if (remaining < 0 || depth + 1 + remaining > maxDepth) continue;
        enter(target, nextMask, edgeId);
      }
    }
  }
  const iterator = walk();
  let exhausted = false;
  try {
    while (!budget.stopReason) {
      if (budget.shouldYield) {
        await budget.yieldControl();
        if (budget.stopReason) break;
      }
      budget.charge();
      if (iterator.next().done) {
        exhausted = true;
        break;
      }
    }
  } finally {
    iterator.return();
  }
  const exact = exhausted && !outputStop;
  return {
    paths,
    graphVersion: graph.version,
    completeness: exact ? 'exact' : 'lowerBound',
    stopReason: exact ? undefined : (outputStop ?? budget.stopReason),
    operations: budget.operations,
  };
}
