import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import {
  executeQuery,
  executePaths,
  createDefaultRegistry,
  QueryError,
  QueryLimitError,
} from '../index.js';
import type {
  GraphRepository,
  GraphSnapshot,
  QueryExecutionOptions,
  QueryResult,
  FilterRegistry,
} from '../index.js';

export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}
function integer(value: unknown, fallback: number, max: number, name: string): number {
  if (value === undefined) return fallback;
  if (typeof value === 'string' && /^\d+$/.test(value)) value = Number(value);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new HttpError(400, 'INVALID_PARAMETER', `${name} must be between 1 and ${max}`);
  }
  return value;
}
const token = () => randomBytes(24).toString('base64url');
function summary(g: GraphSnapshot, i: number) {
  const n = g.node(i);
  const vulnerabilities = n.properties.vulnerabilities;
  return {
    id: n.id,
    kind: n.kind,
    unresolved: n.unresolved,
    publicExposed:
      typeof n.properties.publicExposed === 'boolean' ? n.properties.publicExposed : null,
    vulnerabilityCount: Array.isArray(vulnerabilities) ? vulnerabilities.length : 0,
  };
}
function edge(g: GraphSnapshot, i: number) {
  const e = g.edge(i);
  return { id: `e${i}`, source: g.node(e.source).id, target: g.node(e.target).id };
}

type ResultMetadata = Pick<
  QueryResult,
  'graphVersion' | 'nodeCount' | 'edgeCount' | 'completeness'
> &
  Partial<
    Omit<
      QueryResult,
      'nodes' | 'edges' | 'graphVersion' | 'nodeCount' | 'edgeCount' | 'completeness'
    >
  >;
interface StoredResult {
  g: GraphSnapshot;
  nodes: Uint32Array;
  edges: Uint32Array;
  meta: ResultMetadata;
  pageSize: number;
  bytes: number;
  expires: number;
}
export interface ServiceOptions {
  ttlMs?: number;
  maxResults?: number;
  maxStoredBytes?: number;
  maxActive?: number;
  executionOptions?: QueryExecutionOptions;
  registry?: FilterRegistry;
}

/** Bounded, expiring, single-process result store. Cursors are signed positions. */
export function createGraphService(
  repository: GraphRepository,
  {
    ttlMs = 120_000,
    maxResults = 16,
    maxStoredBytes = 32 * 1024 * 1024,
    maxActive = 2,
    executionOptions = {},
    registry = createDefaultRegistry(),
  }: ServiceOptions = {},
) {
  for (const [name, value] of Object.entries({ ttlMs, maxResults, maxStoredBytes, maxActive })) {
    if (!Number.isSafeInteger(value) || value < 1)
      throw new RangeError(`Invalid service option: ${name}`);
  }
  const results = new Map<string, StoredResult>();
  let storedBytes = 0,
    active = 0;
  const secret = randomBytes(32);
  function sign(value: string) {
    return createHmac('sha256', secret).update(value).digest('base64url');
  }
  function encode(id: string, offset: number) {
    const value = `${id}.${offset}`;
    return `${value}.${sign(value)}`;
  }
  function decode(cursor: unknown) {
    if (typeof cursor !== 'string' || cursor.length > 128) return null;
    const [id, offset, signature, extra] = cursor.split('.');
    if (!id || !offset || !signature || extra !== undefined) return null;
    const expected = Buffer.from(sign(`${id}.${offset}`)),
      actual = Buffer.from(signature);
    if (
      expected.length !== actual.length ||
      !timingSafeEqual(expected, actual) ||
      !/^\d+$/.test(offset)
    )
      return null;
    const n = Number(offset);
    return Number.isSafeInteger(n) ? { id, offset: n } : null;
  }
  function remove(id: string) {
    const r = results.get(id);
    if (!r) return;
    storedBytes -= r.bytes;
    results.delete(id);
  }
  function sweep() {
    for (const [id, r] of results) if (r.expires <= Date.now()) remove(id);
  }
  function checkResultSize(nodeCount: number, edgeCount: number) {
    if (4 * (nodeCount + edgeCount) > maxStoredBytes) {
      throw new HttpError(503, 'RESULT_TOO_LARGE', 'Result exceeds server storage limit');
    }
  }
  function save(
    g: GraphSnapshot,
    nodes: Uint32Array,
    edges: Uint32Array,
    meta: ResultMetadata,
    pageSize: number,
  ) {
    sweep();
    checkResultSize(nodes.length, edges.length);
    const bytes = nodes.byteLength + edges.byteLength;
    const id = token();
    const r = { g, nodes, edges, meta, pageSize, bytes, expires: Date.now() + ttlMs };
    // A single-page result needs no retained cursor or cache entry.
    const first = page(id, r, 0);
    if (first.meta.hasMorePages) {
      while (results.size >= maxResults || storedBytes + bytes > maxStoredBytes) {
        const oldest = results.keys().next();
        if (oldest.done) throw new Error('Inconsistent result store accounting');
        remove(oldest.value);
      }
      results.set(id, r);
      storedBytes += bytes;
    }
    return first;
  }
  function page(id: string, r: StoredResult, offset: number) {
    const total = r.nodes.length + r.edges.length,
      end = Math.min(total, offset + r.pageSize);
    const ns = new Set<number>(),
      es: ReturnType<typeof edge>[] = [];
    for (let i = offset; i < end; i++) {
      if (i < r.nodes.length) ns.add(r.nodes[i]!);
      else {
        const eid = r.edges[i - r.nodes.length]!;
        const e = r.g.edge(eid);
        ns.add(e.source);
        ns.add(e.target);
        es.push(edge(r.g, eid));
      }
    }
    const nextCursor = end < total ? encode(id, end) : null;
    return {
      nodes: [...ns].map((i) => summary(r.g, i)),
      edges: es,
      meta: { ...r.meta, pageSize: r.pageSize, hasMorePages: nextCursor !== null, nextCursor },
    };
  }
  function ids(mask: Uint8Array, count: number) {
    const out = new Uint32Array(count);
    let j = 0;
    for (let i = 0; i < mask.length; i++) if (mask[i]) out[j++] = i;
    if (j !== count) throw new Error('Result count mismatch');
    return out;
  }
  return {
    filters: () => ({ filters: registry.list(), operator: 'AND' as const }),
    meta: () => {
      const g = repository.snapshot();
      return {
        graphVersion: g.version,
        nodeCount: g.nodeCount,
        edgeCount: g.edgeCount,
        diagnostics: g.diagnostics,
      };
    },
    details(id: string) {
      const g = repository.snapshot(),
        i = g.findNode(id);
      if (i === undefined) throw new HttpError(404, 'NODE_NOT_FOUND', 'Unknown node');
      return { ...summary(g, i), properties: g.node(i).properties, graphVersion: g.version };
    },
    graph(pageSize?: unknown) {
      const size = integer(pageSize, 500, 2000, 'pageSize'),
        g = repository.snapshot();
      checkResultSize(g.nodeCount, g.edgeCount);
      return save(
        g,
        Uint32Array.from({ length: g.nodeCount }, (_, i) => i),
        Uint32Array.from({ length: g.edgeCount }, (_, i) => i),
        {
          graphVersion: g.version,
          nodeCount: g.nodeCount,
          edgeCount: g.edgeCount,
          completeness: 'exact',
        },
        size,
      );
    },
    async query(body: unknown, signal?: AbortSignal) {
      if (
        !body ||
        typeof body !== 'object' ||
        Array.isArray(body) ||
        Object.keys(body).some((k) => !['query', 'pageSize'].includes(k)) ||
        !Object.hasOwn(body, 'query')
      ) {
        throw new HttpError(400, 'INVALID_QUERY', 'Expected query and optional pageSize');
      }
      const request = body as { query: unknown; pageSize?: unknown };
      const size = integer(request.pageSize, 500, 2000, 'pageSize');
      if (active >= maxActive) throw new HttpError(503, 'BUSY', 'Too many active queries');
      active++;
      try {
        const g = repository.snapshot();
        let r: QueryResult;
        try {
          r = await executeQuery(
            g,
            request.query,
            { ...executionOptions, ...(signal ? { signal } : {}) },
            registry,
          );
        } catch (e) {
          if (e instanceof QueryLimitError) throw new HttpError(422, 'QUERY_LIMIT', e.message);
          if (e instanceof QueryError) throw new HttpError(400, 'INVALID_QUERY', e.message);
          if (e instanceof RangeError) throw new HttpError(422, 'QUERY_LIMIT', e.message);
          throw e;
        }
        if (signal?.aborted) throw new HttpError(499, 'CANCELLED', 'Request cancelled');
        checkResultSize(r.nodeCount, r.edgeCount);
        const { nodes, edges, ...meta } = r;
        return save(g, ids(nodes, r.nodeCount), ids(edges, r.edgeCount), meta, size);
      } finally {
        active--;
      }
    },
    async paths(body: unknown, signal?: AbortSignal) {
      if (
        !body ||
        typeof body !== 'object' ||
        Array.isArray(body) ||
        Object.keys(body).some((key) => !['query', 'limit'].includes(key)) ||
        !Object.hasOwn(body, 'query')
      ) {
        throw new HttpError(400, 'INVALID_QUERY', 'Expected query and optional limit');
      }
      const request = body as { query: unknown; limit?: unknown };
      if (request.limit !== undefined && typeof request.limit !== 'number') {
        throw new HttpError(400, 'INVALID_PARAMETER', 'limit must be an integer');
      }
      const limit = integer(request.limit, 20, 100, 'limit');
      if (active >= maxActive) throw new HttpError(503, 'BUSY', 'Too many active queries');
      active++;
      try {
        const result = await executePaths(
          repository.snapshot(),
          request.query,
          limit,
          { ...executionOptions, ...(signal ? { signal } : {}) },
          registry,
        );
        if (signal?.aborted) throw new HttpError(499, 'CANCELLED', 'Request cancelled');
        return result;
      } catch (error) {
        if (error instanceof QueryLimitError || error instanceof RangeError) {
          throw new HttpError(422, 'QUERY_LIMIT', error.message);
        }
        if (error instanceof QueryError) throw new HttpError(400, 'INVALID_QUERY', error.message);
        throw error;
      } finally {
        active--;
      }
    },
    next(cursor: unknown) {
      sweep();
      const c = decode(cursor);
      const r = c ? results.get(c.id) : undefined;
      if (!c || !r) throw new HttpError(410, 'CURSOR_EXPIRED', 'Unknown or expired cursor');
      if (repository.snapshot() !== r.g) {
        remove(c.id);
        throw new HttpError(410, 'SNAPSHOT_CHANGED', 'Graph snapshot changed');
      }
      return page(c.id, r, c.offset);
    },
  };
}
