import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { gzipSync } from 'node:zlib';
import { cpus, platform, arch } from 'node:os';
import { loadGraph, executeQuery, StaticGraphRepository } from '../dist/index.js';
import { createGraphService } from '../dist/api/service.js';
// Usage: node --expose-gc benchmark/run.mjs [nodeCount] [--defaults]
//   (no flag)   extended budget: 100M operations, 30 s, yield every 16,384
//   --defaults  the production defaults used by the HTTP service
const args = process.argv.slice(2);
const defaults = args.includes('--defaults');
const unknown = args.filter((arg) => arg.startsWith('--') && arg !== '--defaults');
if (unknown.length) throw new Error(`Unknown option: ${unknown.join(', ')}`);
const n = Number(args.find((arg) => !arg.startsWith('--')) ?? 100000);
if (!Number.isSafeInteger(n) || n < 10 || n > 100000)
  throw new Error('Node count must be 10..100000');
const query = {
  operator: 'AND',
  filters: [{ type: 'public' }, { type: 'sink' }, { type: 'vulnerability' }],
};
const mb = (bytes) => Math.round((bytes / 1e6) * 100) / 100;
const ms = (start) => Math.round((performance.now() - start) * 100) / 100;
const options = defaults
  ? {}
  : { maxOperations: 100_000_000, timeBudgetMs: 30_000, yieldEvery: 16384 };
function fixture(kind) {
  const id = (i) => `n${String(i).padStart(6, '0')}`;
  const nodes = Array.from({ length: n }, (_, i) => ({
    name: id(i),
    kind: i === n - 1 ? 'rds' : 'service',
    publicExposed: i === 0,
    vulnerabilities: i === Math.floor(n / 2) ? [{}] : [],
  }));
  const edges = [];
  for (let i = 0; i < n - 1; i++) {
    const width = kind === 'dense-dag' ? 10 : kind === 'branching-dag' ? 2 : 1;
    edges.push({
      from: id(i),
      to: Array.from({ length: Math.min(width, n - 1 - i) }, (_, j) => id(i + j + 1)),
    });
  }
  // `cyclic`: the back edge leaves the only sink, so boundary pruning removes it.
  // `interior-cycle`: a back edge in the middle that only the DFS can rule out.
  if (kind === 'cyclic') edges.push({ from: id(n - 1), to: id(n - 2) });
  const middle = Math.floor(n / 2);
  if (kind === 'interior-cycle') edges.push({ from: id(middle + 1), to: id(middle) });
  return JSON.stringify({ nodes, edges });
}
async function run(kind) {
  global.gc?.();
  const baseline = process.memoryUsage();
  let raw = fixture(kind);
  const inputBytes = Buffer.byteLength(raw);
  let start = performance.now();
  const graph = loadGraph(raw, { version: kind });
  const loadMs = ms(start);
  raw = null;
  global.gc?.();
  const loaded = process.memoryUsage();
  start = performance.now();
  const result = await executeQuery(graph, query, options);
  const queryMs = ms(start);
  // The extended budget must complete every scenario; the defaults are reported as measured.
  if (!defaults) assert.equal(result.completeness, 'exact', `${kind}: ${result.stopReason}`);
  if (result.completeness === 'exact') {
    assert.equal(result.nodeCount, n);
    if (kind === 'cyclic' || kind === 'interior-cycle') assert.equal(result.edgeCount, n - 1);
  }
  const service = createGraphService(new StaticGraphRepository(graph), {
    executionOptions: options,
  });
  start = performance.now();
  let page = await service.query({ query, pageSize: 2000 });
  const firstPageMs = ms(start);
  let bytes = 0,
    gzipBytes = 0,
    pages = 0,
    serializeMs = 0,
    compressMs = 0;
  do {
    let t = performance.now();
    const wire = JSON.stringify(page);
    serializeMs += performance.now() - t;
    t = performance.now();
    gzipBytes += gzipSync(wire).length;
    compressMs += performance.now() - t;
    bytes += Buffer.byteLength(wire);
    pages++;
    if (!page.meta.nextCursor) break;
    page = service.next(page.meta.nextCursor);
  } while (true);
  console.log(
    JSON.stringify({
      scenario: kind,
      mode: defaults ? 'defaults' : 'extended',
      nodes: graph.nodeCount,
      edges: graph.edgeCount,
      inputMB: mb(inputBytes),
      loadMs,
      retainedHeapDeltaMB: mb(loaded.heapUsed - baseline.heapUsed),
      retainedArrayBufferDeltaMB: mb(loaded.arrayBuffers - baseline.arrayBuffers),
      queryMs,
      algorithm: result.algorithm,
      completeness: result.completeness,
      stopReason: result.stopReason ?? null,
      operations: result.operations,
      matchedNodes: result.nodeCount,
      matchedEdges: result.edgeCount,
      firstPageMs,
      pages,
      jsonMB: mb(bytes),
      gzipMB: mb(gzipBytes),
      serializeMs: Math.round(serializeMs),
      compressMs: Math.round(compressMs),
    }),
  );
  if (kind === 'cyclic' && result.completeness === 'exact') {
    const limited = await executeQuery(graph, query, {
      ...options,
      maxOperations: Math.floor(result.operations * 0.8),
    });
    assert.ok(limited.completeness === 'lowerBound');
    console.log(
      JSON.stringify({
        scenario: 'cyclic-budget',
        completeness: limited.completeness,
        stopReason: limited.stopReason,
        operations: limited.operations,
        matchedNodes: limited.nodeCount,
        matchedEdges: limited.edgeCount,
        unverifiedNodes: limited.unverifiedNodes,
        unverifiedEdges: limited.unverifiedEdges,
      }),
    );
  }
}
console.log(
  JSON.stringify({
    node: process.version,
    platform: platform(),
    arch: arch(),
    cpu: cpus()[0]?.model,
    mode: defaults ? 'defaults' : 'extended',
    options: defaults ? 'production defaults (25M operations, 5 s, yield every 4,096)' : options,
    gc: typeof global.gc === 'function',
  }),
);
for (const kind of ['chain', 'branching-dag', 'cyclic', 'interior-cycle', 'dense-dag'])
  await run(kind);
