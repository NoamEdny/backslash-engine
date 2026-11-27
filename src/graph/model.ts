export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject {
  readonly [key: string]: JsonValue;
}
export type NodeId = number;
export type EdgeId = number;

export interface GraphNode {
  readonly id: string;
  readonly kind: string;
  readonly unresolved: boolean;
  readonly properties: JsonObject;
}
export interface GraphEdge {
  readonly source: NodeId;
  readonly target: NodeId;
  readonly properties: JsonObject;
}
export interface Diagnostic {
  readonly code: 'UNRESOLVED_NODE' | 'DROPPED_EDGE' | 'DUPLICATE_EDGE' | 'NORMALIZED_TARGET';
  readonly path: string;
  readonly message: string;
}
export interface GraphSnapshot {
  readonly version: string;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly diagnostics: readonly Diagnostic[];
  node(id: NodeId): GraphNode;
  edge(id: EdgeId): GraphEdge;
  findNode(externalId: string): NodeId | undefined;
  // Both directions return the same canonical edge IDs.
  outgoing(id: NodeId): Iterable<EdgeId>;
  incoming(id: NodeId): Iterable<EdgeId>;
}
export interface GraphRepository {
  snapshot(): GraphSnapshot;
}
