import type { GraphRepository, GraphSnapshot } from '../graph/model.js';
import { ExecutionBudget, type BudgetOptions, type StopReason } from './budget.js';
import { compileValidatedQuerySteps } from './compiler.js';
import { executeDfs } from './dfs.js';
import { productRegionSteps, type ReachabilityOptions } from './reachability.js';
import { createDefaultRegistry, type FilterRegistry } from './registry.js';
import { validateQuery } from './validation.js';
import { QueryError, QueryLimitError } from './model.js';
import { enumeratePaths, type PathsResult } from './paths.js';

export interface QueryExecutionOptions extends BudgetOptions, ReachabilityOptions {
  /** Conservative cap on typed-array allocations across compile, BFS and DFS.
   * Does not include graph storage, JS object/iterator overhead or API cache. */
  readonly maxWorkingBytes?: number;
}
const DEFAULT_WORKING_BYTES = 128 * 1024 * 1024;

export interface QueryResult {
  readonly nodes: Uint8Array;
  readonly edges: Uint8Array;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly graphVersion: string;
  readonly completeness: 'exact' | 'lowerBound';
  readonly algorithm: 'none' | 'product-bfs' | 'pruned-dfs';
  readonly stage: 'compile' | 'reachability' | 'dfs' | 'complete';
  readonly operations: number;
  readonly stopReason: StopReason | undefined;
  /** Unknown until a complete upper bound exists. */
  readonly unverifiedNodes: number | null;
  readonly unverifiedEdges: number | null;
}

/** Drive batched computations using one budget. The next batch never exceeds
 * the remaining operation allowance. No incomplete product region is used. */
async function drive<T>(
  make: (batch: number) => Generator<number, T, number | void>,
  budget: ExecutionBudget,
): Promise<T | undefined> {
  if (budget.stopReason) return undefined;
  if (budget.shouldYield) {
    await budget.yieldControl();
    if (budget.stopReason) return undefined;
  }
  const batch = () => Math.min(4096, budget.remainingOperations, budget.operationsUntilYield);
  const iterator = make(batch());
  try {
    let step = iterator.next();
    while (!step.done) {
      budget.charge(step.value);
      if (budget.stopReason) return undefined;
      if (budget.shouldYield) {
        await budget.yieldControl();
        if (budget.stopReason) return undefined;
      }
      step = iterator.next(batch());
    }
    return step.value;
  } finally {
    iterator.return(undefined as T);
  }
}

function validateExecution(
  graph: GraphSnapshot,
  input: unknown,
  options: QueryExecutionOptions,
  registry: FilterRegistry,
) {
  // Reject invalid requests even if the execution allowance is zero.
  const validated = validateQuery(input, registry);
  // Compiler: 7V+E; product region including temporary arrays: 12VM+5V+E;
  // DFS result and visited arrays: 2V+E. Conservatively sum all phases.
  const width = 2 ** validated.filters.filter((f) => f.scope === 'ANY_NODE').length;
  const n = graph.nodeCount,
    e = graph.edgeCount;
  const bytes = 12 * n * width + 14 * n + 3 * e;
  const cap = options.maxWorkingBytes ?? DEFAULT_WORKING_BYTES;
  if (!Number.isSafeInteger(cap) || cap < 0 || !Number.isSafeInteger(bytes) || bytes > cap) {
    throw new QueryLimitError('$.filters', 'Query exceeds typed-array working-memory limit');
  }
  return validated;
}

export class QueryEngine {
  constructor(
    private readonly repository: GraphRepository,
    private readonly registry: FilterRegistry = createDefaultRegistry(),
  ) {}
  async execute(input: unknown, options: QueryExecutionOptions = {}): Promise<QueryResult> {
    const graph = this.repository.snapshot();
    return executeQuery(graph, input, options, this.registry);
  }
}

/** Execute against one captured snapshot; HTTP and serialization are separate. */
export async function executeQuery(
  graph: GraphSnapshot,
  input: unknown,
  options: QueryExecutionOptions = {},
  registry: FilterRegistry = createDefaultRegistry(),
): Promise<QueryResult> {
  const budget = new ExecutionBudget(options);
  const validated = validateExecution(graph, input, options, registry);
  const interrupted = (stage: 'compile' | 'reachability'): QueryResult => ({
    nodes: new Uint8Array(graph.nodeCount),
    edges: new Uint8Array(graph.edgeCount),
    nodeCount: 0,
    edgeCount: 0,
    graphVersion: graph.version,
    completeness: 'lowerBound',
    algorithm: 'none',
    stage,
    operations: budget.operations,
    stopReason: budget.stopReason,
    unverifiedNodes: null,
    unverifiedEdges: null,
  });
  const compiled = await drive(
    (batch) => compileValidatedQuerySteps(graph, validated, batch),
    budget,
  );
  if (!compiled) return interrupted('compile');
  const region = await drive(
    (batch) => productRegionSteps(graph, compiled, options, batch),
    budget,
  );
  if (!region) return interrupted('reachability');
  if (region.acyclic)
    return {
      nodes: region.nodes,
      edges: region.edges,
      nodeCount: region.nodeCount,
      edgeCount: region.edgeCount,
      graphVersion: graph.version,
      completeness: 'exact',
      algorithm: 'product-bfs',
      stage: 'complete',
      operations: budget.operations,
      stopReason: undefined,
      unverifiedNodes: 0,
      unverifiedEdges: 0,
    };
  const result = await executeDfs(graph, compiled, region, budget);
  return {
    ...result,
    graphVersion: graph.version,
    algorithm: 'pruned-dfs',
    stage: result.completeness === 'exact' ? 'complete' : 'dfs',
    operations: budget.operations,
  };
}

/** Bounded path enumeration uses the same compilation and backward pruning as the union query. */
export async function executePaths(
  graph: GraphSnapshot,
  input: unknown,
  limit = 20,
  options: QueryExecutionOptions = {},
  registry: FilterRegistry = createDefaultRegistry(),
): Promise<PathsResult> {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new QueryError('$.limit', 'Expected integer between 1 and 100');
  }
  const budget = new ExecutionBudget(options);
  const validated = validateExecution(graph, input, options, registry);
  const interrupted = (): PathsResult => ({
    paths: [],
    graphVersion: graph.version,
    completeness: 'lowerBound',
    stopReason: budget.stopReason,
    operations: budget.operations,
  });
  const compiled = await drive(
    (batch) => compileValidatedQuerySteps(graph, validated, batch),
    budget,
  );
  if (!compiled) return interrupted();
  const region = await drive(
    (batch) => productRegionSteps(graph, compiled, options, batch),
    budget,
  );
  if (!region) return interrupted();
  if (region.nodeCount === 0)
    return {
      paths: [],
      graphVersion: graph.version,
      completeness: 'exact',
      stopReason: undefined,
      operations: budget.operations,
    };
  return enumeratePaths(graph, compiled, region, budget, limit);
}
