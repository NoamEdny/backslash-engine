import type { GraphEdge, EdgeId, NodeId } from './model.js';

/** CSR stores canonical edge IDs, not duplicate edge objects. */
export class Csr {
  readonly #offsets: Uint32Array;
  readonly #edgeIds: Uint32Array;

  constructor(nodeCount: number, edges: readonly GraphEdge[], reverse: boolean) {
    if (nodeCount >= 0xffffffff || edges.length >= 0xffffffff) {
      throw new RangeError('Graph exceeds 32-bit CSR capacity');
    }
    const offsets = new Uint32Array(nodeCount + 1);
    for (const edge of edges) {
      const node = reverse ? edge.target : edge.source;
      offsets[node + 1] = offsets[node + 1]! + 1;
    }
    for (let i = 1; i < offsets.length; i++) {
      offsets[i] = offsets[i]! + offsets[i - 1]!;
    }
    const positions = offsets.slice();
    const ids = new Uint32Array(edges.length);
    // Input edges already have deterministic canonical order.
    edges.forEach((edge, id) => {
      const node = reverse ? edge.target : edge.source;
      const position = positions[node]!;
      ids[position] = id;
      positions[node] = position + 1;
    });
    this.#offsets = offsets;
    this.#edgeIds = ids;
  }

  *edgesOf(node: NodeId): IterableIterator<EdgeId> {
    if (!Number.isInteger(node) || node < 0 || node >= this.#offsets.length - 1) {
      throw new RangeError(`Invalid node ID: ${node}`);
    }
    const end = this.#offsets[node + 1]!;
    for (let i = this.#offsets[node]!; i < end; i++) yield this.#edgeIds[i]!;
  }
}
