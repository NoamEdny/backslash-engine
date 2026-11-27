import { Ajv } from 'ajv';
import type { JsonObject } from '../graph/model.js';

export class InputError extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(`${path}: ${message}`);
    this.name = 'InputError';
  }
}
export interface RawNode {
  readonly name: string;
  readonly kind: string;
  readonly data: JsonObject;
}
export interface RawEdge {
  readonly from: string;
  readonly to: readonly string[];
  readonly wasString: boolean;
  readonly data: JsonObject;
}
export interface RawGraph {
  readonly nodes: readonly RawNode[];
  readonly edges: readonly RawEdge[];
}

type NodeData = JsonObject & { readonly name: string; readonly kind: string };
type EdgeData = JsonObject & { readonly from: string; readonly to: string | readonly string[] };
interface GraphData {
  readonly nodes: readonly NodeData[];
  readonly edges: readonly EdgeData[];
}
const nonBlank = { type: 'string', pattern: '\\S' };
const schema = {
  type: 'object',
  required: ['nodes', 'edges'],
  additionalProperties: true,
  properties: {
    nodes: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'kind'],
        additionalProperties: true,
        properties: {
          name: nonBlank,
          kind: nonBlank,
          publicExposed: { type: 'boolean' },
          vulnerabilities: { type: 'array', items: { type: 'object', additionalProperties: true } },
        },
      },
    },
    edges: {
      type: 'array',
      items: {
        type: 'object',
        required: ['from', 'to'],
        additionalProperties: true,
        properties: {
          from: nonBlank,
          to: { anyOf: [nonBlank, { type: 'array', items: nonBlank }] },
        },
      },
    },
  },
};
const ajv = new Ajv({
  strict: true,
  allErrors: false,
  coerceTypes: false,
  removeAdditional: false,
  useDefaults: false,
  ownProperties: true,
});
const validate = ajv.compile<GraphData>(schema);

/** Parse JSON, validate structure, and normalize string edge targets. */
export function parseAndValidate(text: string): RawGraph {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new InputError('$', 'Invalid JSON');
  }
  if (!validate(parsed)) {
    const error = validate.errors?.[0];
    throw new InputError(
      `$${error?.instancePath ?? ''}`,
      error?.message ?? 'Invalid graph structure',
    );
  }
  return {
    nodes: parsed.nodes.map((data) => ({ name: data.name, kind: data.kind, data })),
    edges: parsed.edges.map((data) => ({
      from: data.from,
      to: typeof data.to === 'string' ? [data.to] : data.to,
      wasString: typeof data.to === 'string',
      data,
    })),
  };
}
