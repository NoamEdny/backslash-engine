import type { GraphNode, GraphEdge, JsonValue } from '../graph/model.js';
import type { Predicate } from './model.js';

const own = (object: object, key: string) => Object.hasOwn(object, key);
export function readField(entity: GraphNode | GraphEdge, field: string): JsonValue | undefined {
  // Canonical fields take precedence over arbitrary input properties.
  if ('id' in entity) {
    if (field === 'id') return entity.id;
    if (field === 'kind') return entity.kind;
    if (field === 'unresolved') return entity.unresolved;
  }
  return own(entity.properties, field) ? entity.properties[field] : undefined;
}
function equal(a: JsonValue | undefined, b: JsonValue): boolean {
  if (a === b) return true;
  if (a === undefined || a === null || b === null || typeof a !== 'object' || typeof b !== 'object')
    return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((v, i) => equal(v, b[i]!))
    );
  }
  const left = a as Record<string, JsonValue>,
    right = b as Record<string, JsonValue>;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((k) => own(right, k) && equal(left[k], right[k]!))
  );
}
/** A dotted path traverses arrays existentially; terminal arrays stay intact.
 * Only own properties are considered, including inside nested objects. */
function* fieldValues(entity: GraphNode | GraphEdge, field: string): Generator<JsonValue> {
  const segments = field.split('.');
  if (segments.length === 1) return;
  const root = readField(entity, segments[0]!);
  if (root === undefined) return;
  function* visit(value: JsonValue, index: number): Generator<JsonValue> {
    if (index === segments.length) {
      yield value;
    } else if (Array.isArray(value)) {
      for (const item of value) yield* visit(item, index);
    } else if (value !== null && typeof value === 'object') {
      const object = value as Record<string, JsonValue>;
      const key = segments[index]!;
      if (own(object, key)) yield* visit(object[key]!, index + 1);
    }
  }
  yield* visit(root, 1);
}

export function matches(entity: GraphNode | GraphEdge, predicate: Predicate): boolean {
  // Keep the common top-level case free of iterator allocations.
  const direct = readField(entity, predicate.field);
  if (direct !== undefined) return matchesValue(direct, predicate);
  if (!predicate.field.includes('.')) return false;
  for (const value of fieldValues(entity, predicate.field)) {
    if (matchesValue(value, predicate)) return true;
  }
  return false;
}

function matchesValue(value: JsonValue, predicate: Predicate): boolean {
  switch (predicate.op) {
    case 'eq':
      return equal(value, predicate.value);
    case 'in':
      return predicate.value.some((v) => equal(value, v));
    case 'exists':
      return true;
    case 'notEmpty':
      return (typeof value === 'string' || Array.isArray(value)) && value.length > 0;
    case 'gt':
      return typeof value === 'number' && value > predicate.value;
    case 'lt':
      return typeof value === 'number' && value < predicate.value;
  }
}
