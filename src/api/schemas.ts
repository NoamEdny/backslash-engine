/** Transport schemas describe the JSON envelope; semantic filter validation
 * is owned by query/validation.ts and shared with direct engine callers. */
const string = { type: 'string' };
const integer = { type: 'integer', minimum: 0 };
const nullableString = { anyOf: [string, { type: 'null' }] };
const completeness = { type: 'string', enum: ['exact', 'lowerBound'] };
export const querySchema = {
  type: 'object',
  description: 'AND query with named or scoped property filters; optional maxDepth in edges.',
  properties: {
    operator: { type: 'string', const: 'AND' },
    filters: { type: 'array', items: { type: 'object', additionalProperties: true } },
    maxDepth: integer,
  },
  additionalProperties: true,
};
const node = {
  type: 'object',
  required: ['id', 'kind', 'unresolved', 'publicExposed', 'vulnerabilityCount'],
  properties: {
    id: string,
    kind: string,
    unresolved: { type: 'boolean' },
    publicExposed: { anyOf: [{ type: 'boolean' }, { type: 'null' }] },
    vulnerabilityCount: integer,
  },
};
const edge = {
  type: 'object',
  required: ['id', 'source', 'target'],
  properties: { id: string, source: string, target: string },
};
export const graphPageSchema = {
  type: 'object',
  required: ['nodes', 'edges', 'meta'],
  properties: {
    nodes: { type: 'array', items: node },
    edges: { type: 'array', items: edge },
    meta: {
      type: 'object',
      additionalProperties: true,
      required: [
        'graphVersion',
        'nodeCount',
        'edgeCount',
        'completeness',
        'pageSize',
        'hasMorePages',
        'nextCursor',
      ],
      properties: {
        graphVersion: string,
        nodeCount: integer,
        edgeCount: integer,
        completeness,
        pageSize: integer,
        hasMorePages: { type: 'boolean' },
        nextCursor: nullableString,
        algorithm: string,
        stage: string,
        operations: integer,
        stopReason: nullableString,
        unverifiedNodes: { anyOf: [integer, { type: 'null' }] },
        unverifiedEdges: { anyOf: [integer, { type: 'null' }] },
      },
    },
  },
};
export const pathsSchema = {
  type: 'object',
  required: ['paths', 'graphVersion', 'completeness', 'operations'],
  properties: {
    paths: {
      type: 'array',
      items: {
        type: 'object',
        required: ['nodes', 'edges'],
        properties: {
          nodes: { type: 'array', items: string },
          edges: { type: 'array', items: string },
        },
      },
    },
    graphVersion: string,
    completeness,
    operations: integer,
    stopReason: nullableString,
  },
};
