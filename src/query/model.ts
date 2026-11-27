import type { JsonValue } from '../graph/model.js';
export type Scope = 'START' | 'END' | 'ANY_NODE' | 'ALL_NODES' | 'ALL_EDGES';
export type Predicate =
  | { readonly field: string; readonly op: 'eq'; readonly value: JsonValue }
  | { readonly field: string; readonly op: 'in'; readonly value: readonly JsonValue[] }
  | { readonly field: string; readonly op: 'exists' | 'notEmpty' }
  | { readonly field: string; readonly op: 'gt' | 'lt'; readonly value: number };
export interface Filter {
  readonly scope: Scope;
  readonly predicate: Predicate;
}
export type FilterInput = Filter | { readonly type: string };
export interface Query {
  readonly operator: 'AND';
  readonly filters: readonly FilterInput[];
  readonly maxDepth?: number;
}
export interface CompiledQuery {
  readonly starts: Uint8Array;
  readonly ends: Uint8Array;
  readonly allowedNodes: Uint8Array;
  readonly allowedEdges: Uint8Array;
  readonly nodeMasks: Uint32Array;
  readonly requiredMask: number;
  readonly anyCount: number;
  readonly maxDepth: number | undefined;
}
export class QueryError extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(`${path}: ${message}`);
    this.name = 'QueryError';
  }
}

/** Valid query that exceeds a configured resource limit. */
export class QueryLimitError extends QueryError {
  constructor(path: string, message: string) {
    super(path, message);
    this.name = 'QueryLimitError';
  }
}
