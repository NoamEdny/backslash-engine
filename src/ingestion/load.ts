import type {
  Diagnostic,
  GraphEdge,
  GraphNode,
  GraphSnapshot,
  JsonObject,
  JsonValue,
} from '../graph/model.js';
import { InMemorySnapshot } from '../graph/snapshot.js';
import { InputError, parseAndValidate } from './validation.js';

export type MissingNodePolicy = 'placeholder' | 'drop' | 'reject';
export interface LoadOptions {
  readonly version: string;
  readonly missingNodePolicy?: MissingNodePolicy;
}
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function freezeJson(value: JsonValue): JsonValue {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}
function properties(
  data: JsonObject,
  excluded: readonly string[],
  defaults: JsonObject = {},
): JsonObject {
  const result = Object.fromEntries(
    Object.entries(data).filter(([key]) => !excluded.includes(key)),
  );
  return freezeJson({ ...defaults, ...result }) as JsonObject;
}
/** Stable serialization for semantic duplicate detection, including nested properties. */
function canonical(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const obj = value as JsonObject;
  return `{${Object.keys(obj)
    .sort(compare)
    .map((k) => `${JSON.stringify(k)}:${canonical(obj[k]!)}`)
    .join(',')}}`;
}

export function loadGraph(text: string, options: LoadOptions): GraphSnapshot {
  const policy = options.missingNodePolicy ?? 'placeholder';
  if (!['placeholder', 'drop', 'reject'].includes(policy))
    throw new InputError('$options.missingNodePolicy', 'Unknown policy');
  if (typeof options.version !== 'string' || !options.version.trim())
    throw new InputError('$options.version', 'Version required');
  const raw = parseAndValidate(text);
  const diagnostics: Diagnostic[] = [];
  const nodes = new Map<string, GraphNode>();
  const pending: { source: string; target: string; properties: JsonObject; key: string }[] = [];
  const seen = new Set<string>();

  raw.nodes.forEach((n, i) => {
    if (nodes.has(n.name)) throw new InputError(`$.nodes[${i}].name`, `Duplicate node: ${n.name}`);
    nodes.set(
      n.name,
      Object.freeze({
        id: n.name,
        kind: n.kind,
        unresolved: false,
        properties: properties(n.data, ['name', 'kind'], { vulnerabilities: [] }),
      }),
    );
  });

  function resolve(id: string, path: string): boolean {
    if (nodes.has(id)) return true;
    if (policy === 'reject') throw new InputError(path, `Unknown node: ${id}`);
    if (policy === 'drop') return false;
    nodes.set(
      id,
      Object.freeze({
        id,
        kind: 'unknown',
        unresolved: true,
        properties: properties({}, [], { vulnerabilities: [] }),
      }),
    );
    diagnostics.push({ code: 'UNRESOLVED_NODE', path, message: `Created placeholder for ${id}` });
    return true;
  }
  raw.edges.forEach((e, i) => {
    const path = `$.edges[${i}]`;
    if (e.wasString)
      diagnostics.push({
        code: 'NORMALIZED_TARGET',
        path: `${path}.to`,
        message: 'Normalized string target to array',
      });
    const props = properties(e.data, ['from', 'to']);
    const signature = canonical(props);
    e.to.forEach((target, j) => {
      const targetPath = e.wasString ? `${path}.to` : `${path}.to[${j}]`;
      const sourceExists = resolve(e.from, `${path}.from`);
      const targetExists = resolve(target, targetPath);
      if (!sourceExists || !targetExists) {
        diagnostics.push({
          code: 'DROPPED_EDGE',
          path: targetPath,
          message: `Dropped ${e.from} -> ${target}`,
        });
        return;
      }
      const key = JSON.stringify([e.from, target, signature]);
      if (seen.has(key)) {
        diagnostics.push({
          code: 'DUPLICATE_EDGE',
          path: targetPath,
          message: `Duplicate ${e.from} -> ${target}`,
        });
        return;
      }
      seen.add(key);
      pending.push({ source: e.from, target, properties: props, key });
    });
  });
  const orderedNodes = [...nodes.values()].sort((a, b) => compare(a.id, b.id));
  const ids = new Map(orderedNodes.map((node, id) => [node.id, id]));
  const edges: GraphEdge[] = pending
    .sort(
      (a, b) => compare(a.source, b.source) || compare(a.target, b.target) || compare(a.key, b.key),
    )
    .map((e) =>
      Object.freeze({
        source: ids.get(e.source)!,
        target: ids.get(e.target)!,
        properties: e.properties,
      }),
    );
  return new InMemorySnapshot(options.version, orderedNodes, edges, diagnostics);
}
