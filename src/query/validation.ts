import { QueryError } from './model.js';
import type { Predicate, Scope } from './model.js';
import type { JsonValue } from '../graph/model.js';
import type { FilterRegistry, ResolvedFilter } from './registry.js';
export const MAX_ANY = 5;
const scopes = new Set<string>(['START', 'END', 'ANY_NODE', 'ALL_NODES', 'ALL_EDGES']);
function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new QueryError(path, 'Expected object');
  return value as Record<string, unknown>;
}
function keys(obj: Record<string, unknown>, allowed: string[], path: string) {
  for (const key of Object.keys(obj))
    if (!allowed.includes(key)) throw new QueryError(`${path}.${key}`, 'Unknown field');
}
function json(value: unknown, path: string, depth = 0): JsonValue {
  if (depth > 32) throw new QueryError(path, 'Value nesting exceeds limit');
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  )
    return value as JsonValue;
  if (Array.isArray(value)) return Array.from(value, (v, i) => json(v, `${path}[${i}]`, depth + 1));
  if (
    typeof value === 'object' &&
    value !== null &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, json(v, `${path}.${k}`, depth + 1)]),
    );
  }
  throw new QueryError(path, 'Expected JSON value');
}
function predicate(value: unknown, path: string): Predicate {
  const p = record(value, path);
  const { field, op } = p;
  if (
    typeof field !== 'string' ||
    !field.trim() ||
    field.split('.').some((part) => !part.trim()) ||
    field.split('.').length > 32
  )
    throw new QueryError(`${path}.field`, 'Expected a non-empty field path of at most 32 segments');
  if (op === 'exists' || op === 'notEmpty') {
    keys(p, ['field', 'op'], path);
    return { field, op };
  }
  keys(p, ['field', 'op', 'value'], path);
  if (op === 'eq') return { field, op, value: json(p.value, `${path}.value`) };
  if (op === 'in') {
    if (!Array.isArray(p.value)) throw new QueryError(`${path}.value`, 'Expected array');
    return { field, op, value: Array.from(p.value, (v, i) => json(v, `${path}.value[${i}]`)) };
  }
  if (op === 'gt' || op === 'lt') {
    if (typeof p.value !== 'number' || !Number.isFinite(p.value))
      throw new QueryError(`${path}.value`, 'Expected finite number');
    return { field, op, value: p.value };
  }
  throw new QueryError(`${path}.op`, 'Unsupported predicate operator');
}
function filter(value: unknown, path: string, registry: FilterRegistry): ResolvedFilter {
  let f = record(value, path);
  if (Object.hasOwn(f, 'type')) {
    keys(f, ['type'], path);
    if (typeof f.type !== 'string') throw new QueryError(`${path}.type`, 'Expected filter ID');
    const resolved = registry.resolve(f.type);
    if (!resolved) throw new QueryError(`${path}.type`, 'Unknown filter ID');
    if ('match' in resolved) return resolved;
    f = record(resolved, path);
  }
  keys(f, ['scope', 'predicate'], path);
  if (typeof f.scope !== 'string' || !scopes.has(f.scope))
    throw new QueryError(`${path}.scope`, 'Unsupported scope');
  return { scope: f.scope as Scope, predicate: predicate(f.predicate, `${path}.predicate`) };
}
export function validateQuery(
  value: unknown,
  registry: FilterRegistry,
): { filters: ResolvedFilter[]; maxDepth: number | undefined } {
  const q = record(value, '$');
  keys(q, ['operator', 'filters', 'maxDepth'], '$');
  if (q.operator !== 'AND') throw new QueryError('$.operator', 'Only AND is supported');
  if (!Array.isArray(q.filters) || q.filters.length > 32)
    throw new QueryError('$.filters', 'Expected array of at most 32 filters');
  const filters = Array.from(q.filters, (f, i) => filter(f, `$.filters[${i}]`, registry));
  if (filters.filter((f) => f.scope === 'ANY_NODE').length > MAX_ANY)
    throw new QueryError('$.filters', `At most ${MAX_ANY} ANY filters are supported`);
  const depth = q.maxDepth;
  if (
    depth !== undefined &&
    (typeof depth !== 'number' || !Number.isSafeInteger(depth) || depth < 0)
  )
    throw new QueryError('$.maxDepth', 'Expected nonnegative safe integer');
  return { filters, maxDepth: depth as number | undefined };
}
