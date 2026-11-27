# Backslash Graph Query Engine

A TypeScript REST backend for filtering directed property graphs by matching simple paths. It returns a compact graph for visualization and can also enumerate a bounded list of actual matching paths. The supplied Train Ticket dataset is included.

## Quick start

Requires Node.js 22+.

```sh
npm ci
npm run build
npm start
```

Open [Swagger UI](http://localhost:3000/docs). The default bind address is `127.0.0.1:3000`. Configure `HOST`, `PORT`, `GRAPH_FILE` or `MISSING_NODE_POLICY` through environment variables.

```sh
curl -X POST http://localhost:3000/api/v1/routes/query \
  -H 'Content-Type: application/json' \
  -d '{"query":{"operator":"AND","filters":[{"type":"public"},{"type":"sink"},{"type":"vulnerability"}]}}'
```

For this dataset all three filters together have no matching path. A response to that query has the following shape (illustrative metadata):

```json
{
  "nodes": [],
  "edges": [],
  "meta": {
    "graphVersion": "<snapshot version>",
    "nodeCount": 0,
    "edgeCount": 0,
    "completeness": "exact",
    "algorithm": "product-bfs",
    "stage": "complete",
    "operations": 123,
    "unverifiedNodes": 0,
    "unverifiedEdges": 0,
    "pageSize": 500,
    "hasMorePages": false,
    "nextCursor": null
  }
}
```

Try the `public` filter alone to see the reachable frontend region and isolated public gateway.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/api/v1/graph` | Original graph, paginated |
| GET | `/api/v1/graph/meta` | Snapshot counts and ingestion diagnostics |
| GET | `/api/v1/graph/nodes/:id` | Full node properties |
| GET | `/api/v1/filters` | Registered filters |
| POST | `/api/v1/routes/query` | Union of matching nodes and edges |
| POST | `/api/v1/routes/paths` | Bounded explicit matching paths |
| GET | `/api/v1/results/:cursor` | Next page of a stored graph result |
| GET | `/docs` | Interactive OpenAPI documentation |

The graph endpoint returns node summaries and canonical edge IDs with source and target IDs. Each page includes its edge endpoints. Merge pages by IDs within the same graph version; repeated endpoints are expected. `pageSize` defaults to 500, maximum 2000 primary entries. Follow `meta.nextCursor` until null. Gzip is negotiated through `Accept-Encoding`.

**The union is not a list of matching paths.** Edges from different valid paths may combine into a route that fails a filter. To identify valid individual routes, use the explicit paths endpoint:

```sh
curl -X POST http://localhost:3000/api/v1/routes/paths \
  -H 'Content-Type: application/json' \
  -d '{"query":{"operator":"AND","filters":[{"type":"public"}]},"limit":20}'
```

Each path has ordered `nodes` (external IDs) and `edges` (canonical IDs). Zero-edge paths have one node and no edges. `limit` defaults to 20, maximum 100; total output is capped at 100,000 node/edge ID entries. This endpoint does not page or resume enumeration. `exact` means enumeration exhausted; `lowerBound` means the returned paths are valid but more may exist. `PATH_LIMIT`, `OUTPUT_LIMIT` or an execution stop reason identifies truncation.

For graph queries, `exact` means the complete union is available across pages; `lowerBound` includes only confirmed items. Missing items in a lower bound cannot be considered nonmatching. Pagination is independent of computation completeness; it does not resume interrupted computation. Unverified candidate counts may be null if preprocessing did not complete.

## Filters and extensibility

The built-in filters select paths that start at `publicExposed: true`, end at `rds` or `sql`, or contain a nonempty vulnerabilities array. They can be combined with AND. Generic predicates support `START`, `END`, `ANY_NODE`, `ALL_NODES`, `ALL_EDGES` and operators `eq`, `in`, `exists`, `notEmpty`, `gt`, `lt`. Up to 32 filters, including at most five ANY filters. `maxDepth` optionally limits edges; no implicit depth cutoff.

For example, select paths containing a high-severity vulnerability:

```json
{
  "operator": "AND",
  "filters": [{
    "scope": "ANY_NODE",
    "predicate": {"field": "vulnerabilities.severity", "op": "eq", "value": "high"}
  }]
}
```

Dotted paths traverse intermediate arrays existentially; terminal arrays remain intact. Only own properties are read. A literal property matching the complete field name takes precedence. To require multiple conditions on the same array element, use a trusted server-side custom predicate:

```typescript
const registry = createDefaultRegistry().registerCustom({
  id: 'high-public',
  description: 'Contains a public node with a high-severity vulnerability',
  scope: 'ANY_NODE',
  match: (entity) => entity.properties.publicExposed === true &&
    Array.isArray(entity.properties.vulnerabilities) &&
    entity.properties.vulnerabilities.some((item) =>
      item !== null && typeof item === 'object' &&
      'severity' in item && item.severity === 'high'),
});
// Supply registry through buildApp(repository, { service: { registry } }).
```

Clients refer to the registered filter by `{ "type": "high-public" }`. Functions are never accepted from request JSON. Custom callbacks are trusted, synchronous and should be pure and bounded. Named declarative filters can also be added with `registry.register`.

## Input assumptions

- Normalize string and array edge targets. Reject malformed structure and duplicate node identities. Preserve unknown properties, distinct parallel edges, and stored self-loops; deduplicate identical edges.
- The undeclared `assurance-service` becomes an unresolved placeholder by default; alternatively drop affected edges or reject the input. Default normalization: 47 nodes, 98 edges (46 declared nodes).
- Missing vulnerabilities mean none. Missing public exposure does not satisfy the public filter and remains unknown in the node summary.
- Paths are directed and simple (no repeated vertex); include valid subpaths, endpoints in ANY predicates, and zero-edge paths including isolated nodes. Self-loops are not traversed.

## Design and complexity

`src/ingestion` validates and normalizes; `src/graph` stores an immutable snapshot with numeric IDs and forward/reverse CSR adjacency; `src/query` compiles and executes filters independently of HTTP; `src/api` exposes the service and paginated responses. The repository captures one snapshot per query. A future dynamic graph can publish new snapshots without changing traversal.

Compilation creates start/end sets, allowed node/edge masks and one bit per ANY predicate. Forward and reverse BFS on implicit `(node, mask)` states find accepting walks, with distances supporting `maxDepth`. A transition ORs in the destination's bits; reverse traversal uses inverse OR mappings. Project only compatible reachable states and transitions onto the original graph. Kahn's cycle check on this projection proves exactness when acyclic: any repeated vertex in an accepting walk would create a directed cycle. For cyclic candidates, iterative DFS tracks path-local visits, prunes using backward distances, and confirms only witnessed items. It can stop once every upper-bound item is confirmed. Explicit enumeration uses the same compilation and backward pruning but emits complete paths rather than union masks.

For V vertices, E edges and M = 2^k masks (k ANY predicates), product traversal and projection take O((V+E)M) time and O(VM+V+E) auxiliary space, plus O(M²) inverse tables. Compilation adds predicate evaluation costs; nested property traversal and custom predicates need not be constant time. Ingestion sorts identifiers and edges, then builds CSR in linear time (excluding property processing). DFS and explicit enumeration can take exponential or factorial time; explicit output also costs the total length of returned paths. No general latency or completeness guarantee is claimed for arbitrary cyclic graphs.

## Resource limits and trade-offs

Default operation budget: 25 million; cooperative deadline: five seconds. Compilation and traversal share these limits and yield to the event loop. Cancellation is wired to HTTP disconnect. The estimated typed-array allocation cap is 128 MiB, not a total-process memory limit. Request bodies are limited to 64 KiB and at most two queries are active. Graph cursors use a bounded single-process result store (16 entries, 32 MiB of ID arrays, two-minute TTL, FIFO eviction). Cursors are signed and expire on eviction, restart or snapshot replacement. Clients may evict each other's results; single-page results are not cached. Production authentication, network rate limiting and distributed storage are outside scope.

Dense cyclic graphs can exhaust the budget even at small sizes; an exact answer may require exploring many paths. The union is kept as the default because enumerating all paths is unsuitable for large graphs. OR, dynamic update endpoints and distributed execution are not implemented.

## Verification and benchmarks

```sh
npm test
npm run test:api
npm run format:check
npm audit
node --expose-gc benchmark/run.mjs 100000
node benchmark/review/stress.mjs
node benchmark/review/diff.mjs
node benchmark/review/http.mjs
```

Tests include independent differential comparisons against brute force, real-data filter combinations, cyclic counterexamples, malformed requests, budgets and pagination. The review suite retains explicit TODO tests documenting limitations of union representation and dense cyclic search. The paths tests separately verify actual route identity. The benchmark reports load/query time, operations, completeness, retained memory deltas, and JSON/gzip sizes over all pages; compression measurements exclude real network latency. Synthetic shapes include 100,000 nodes and approximately one million edges. Stress fixtures exercise dense cyclic graphs and a cyclic trap. Run on the target machine for current timings; no universal SLA is implied.

## Docker and CI

```sh
docker build -t backslash-engine .
docker run --rm -p 127.0.0.1:3000:3000 backslash-engine
```

The multi-stage Dockerfile runs as a non-root user. GitHub Actions is configured to build, test and audit on Node.js 22 and 24. Container execution and hosted CI have not yet been verified in the current environment.
