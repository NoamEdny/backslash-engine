import type { GraphSnapshot } from '../graph/model.js';
import type { CompiledQuery } from './model.js';
import type { ProductRegion } from './reachability.js';

export interface Witness {
  readonly nodes: number[];
  readonly edges: number[];
}

/** Try to build one matching simple path through `edgeId`.
 *
 * The prefix is walked back from the edge source along decreasing forward BFS
 * distances, and the suffix forward from the edge target along decreasing
 * backward distances. Nodes already on the path are skipped, so the result is
 * simple. This is a heuristic: returning undefined does not prove that the edge
 * is on no matching path (the DFS still decides that). A returned path is
 * checked independently before the caller may mark anything.
 *
 * `used` must be all zero on entry and is all zero again on return. */
export function* findWitness(
  graph: GraphSnapshot,
  query: CompiledQuery,
  region: ProductRegion,
  edgeId: number,
  used: Uint8Array,
): Generator<void, Witness | undefined, void> {
  const states = region.stateCount;
  const limit = query.maxDepth ?? Infinity;
  const { source, target } = graph.edge(edgeId);
  for (let mask = 0; mask < states; mask++) {
    yield;
    const targetMask = mask | query.nodeMasks[target]!;
    const before = region.forward[source * states + mask]!;
    const after = region.backward[target * states + targetMask]!;
    if (before < 0 || after < 0 || before + 1 + after > limit) continue;
    used[source] = 1;
    used[target] = 1;
    const prefix = yield* walkBack(source, mask, before);
    const suffix = prefix ? yield* walkForward(target, targetMask, after) : undefined;
    // A failed walk clears its own marks; clear everything else here.
    for (const node of [...(prefix?.nodes ?? []), ...(suffix?.nodes ?? []), source, target])
      used[node] = 0;
    if (prefix && suffix) {
      // The prefix ends at the edge source and the suffix starts at its target.
      const witness = {
        nodes: [...prefix.nodes, ...suffix.nodes],
        edges: [...prefix.edges, edgeId, ...suffix.edges],
      };
      if (isMatchingSimplePath(graph, query, witness)) return witness;
    }
  }
  return undefined;

  // From a start state to (node, mask); returns nodes in path order, ending at node.
  function* walkBack(node: number, mask: number, distance: number) {
    const nodes = [node];
    const edges: number[] = [];
    while (distance > 0) {
      let found = false;
      for (const incoming of graph.incoming(node)) {
        yield;
        if (!region.edges[incoming]) continue;
        const previous = graph.edge(incoming).source;
        if (used[previous]) continue;
        for (let previousMask = 0; previousMask < states && !found; previousMask++) {
          yield;
          if ((previousMask | query.nodeMasks[node]!) !== mask) continue;
          if (region.forward[previous * states + previousMask] !== distance - 1) continue;
          found = true;
          mask = previousMask;
        }
        if (!found) continue;
        used[previous] = 1;
        nodes.push(previous);
        edges.push(incoming);
        node = previous;
        distance--;
        break;
      }
      if (!found) {
        for (const visited of nodes.slice(1)) used[visited] = 0;
        return undefined;
      }
    }
    return { nodes: nodes.reverse(), edges: edges.reverse() };
  }

  // From (node, mask) to an accepting end state; returns nodes starting at node.
  function* walkForward(node: number, mask: number, distance: number) {
    const nodes = [node];
    const edges: number[] = [];
    while (distance > 0) {
      let found = false;
      for (const outgoing of graph.outgoing(node)) {
        yield;
        if (!region.edges[outgoing]) continue;
        const next = graph.edge(outgoing).target;
        if (used[next]) continue;
        const nextMask = mask | query.nodeMasks[next]!;
        if (region.backward[next * states + nextMask] !== distance - 1) continue;
        found = true;
        used[next] = 1;
        nodes.push(next);
        edges.push(outgoing);
        node = next;
        mask = nextMask;
        distance--;
        break;
      }
      if (!found) {
        for (const visited of nodes.slice(1)) used[visited] = 0;
        return undefined;
      }
    }
    return { nodes, edges };
  }
}

/** Independent check of a candidate path against the compiled query. */
export function isMatchingSimplePath(
  graph: GraphSnapshot,
  query: CompiledQuery,
  { nodes, edges }: Witness,
): boolean {
  if (nodes.length === 0 || edges.length !== nodes.length - 1) return false;
  if (edges.length > (query.maxDepth ?? Infinity)) return false;
  if (!query.starts[nodes[0]!] || !query.ends[nodes.at(-1)!]) return false;
  if (new Set(nodes).size !== nodes.length) return false;
  let mask = 0;
  for (const node of nodes) {
    if (!query.allowedNodes[node]) return false;
    mask |= query.nodeMasks[node]!;
  }
  return (
    mask === query.requiredMask &&
    edges.every((edgeId, i) => {
      const edge = graph.edge(edgeId);
      return (
        query.allowedEdges[edgeId] === 1 && edge.source === nodes[i] && edge.target === nodes[i + 1]
      );
    })
  );
}
