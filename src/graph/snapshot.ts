import { Csr } from './csr.js';
import type { Diagnostic, GraphEdge, GraphNode, GraphRepository, GraphSnapshot } from './model.js';

export class InMemorySnapshot implements GraphSnapshot {
  readonly #nodes: readonly GraphNode[];
  readonly #edges: readonly GraphEdge[];
  readonly #ids: ReadonlyMap<string, number>;
  readonly #forward: Csr;
  readonly #reverse: Csr;
  readonly version: string;
  readonly diagnostics: readonly Diagnostic[];

  constructor(
    version: string,
    nodes: readonly GraphNode[],
    edges: readonly GraphEdge[],
    diagnostics: readonly Diagnostic[],
  ) {
    this.version = version;
    this.#nodes = Object.freeze([...nodes]);
    this.#edges = Object.freeze([...edges]);
    this.#ids = new Map(nodes.map((node, id) => [node.id, id]));
    this.#forward = new Csr(nodes.length, edges, false);
    this.#reverse = new Csr(nodes.length, edges, true);
    this.diagnostics = Object.freeze(diagnostics.map((d) => Object.freeze({ ...d })));
    Object.freeze(this);
  }
  get nodeCount() {
    return this.#nodes.length;
  }
  get edgeCount() {
    return this.#edges.length;
  }
  node(id: number): GraphNode {
    const node = this.#nodes[id];
    if (!node) throw new RangeError(`Invalid node ID: ${id}`);
    return node;
  }
  edge(id: number): GraphEdge {
    const edge = this.#edges[id];
    if (!edge) throw new RangeError(`Invalid edge ID: ${id}`);
    return edge;
  }
  findNode(id: string) {
    return this.#ids.get(id);
  }
  outgoing(id: number) {
    return this.#forward.edgesOf(id);
  }
  incoming(id: number) {
    return this.#reverse.edgesOf(id);
  }
}

export class StaticGraphRepository implements GraphRepository {
  constructor(private readonly graph: GraphSnapshot) {}
  snapshot(): GraphSnapshot {
    return this.graph;
  }
}
