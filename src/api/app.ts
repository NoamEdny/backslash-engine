import Fastify from 'fastify';
import { STATUS_CODES } from 'node:http';
import { graphPageSchema, pathsSchema, querySchema } from './schemas.js';
import compress from '@fastify/compress';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import type { GraphRepository } from '../graph/model.js';
import { createGraphService, HttpError, type ServiceOptions } from './service.js';

export interface AppOptions {
  logger?: boolean;
  service?: ServiceOptions;
}
export async function buildApp(repository: GraphRepository, options: AppOptions = {}) {
  const app = Fastify({
    logger: options.logger ?? false,
    bodyLimit: 65536,
    ajv: { customOptions: { removeAdditional: false, coerceTypes: false } },
  });
  const service = createGraphService(repository, options.service);
  await app.register(compress, { global: true, threshold: 1024 });
  await app.register(swagger, {
    openapi: { info: { title: 'Backslash Graph API', version: '1.0.0' } },
  });
  await app.register(swaggerUi, { routePrefix: '/docs' });
  app.setErrorHandler((error, req, reply) => {
    const err = error as Error & { statusCode?: number; validation?: unknown };
    const code = err.statusCode;
    const status = typeof code === 'number' && code >= 400 && code < 600 ? code : 500;
    if (status >= 500) req.log.error(err);
    return reply
      .code(status)
      .type('application/problem+json')
      .send({
        type: 'about:blank',
        title: STATUS_CODES[status] ?? 'Request failed',
        detail: status >= 500 ? 'Service error' : err.message,
        status,
        code:
          err instanceof HttpError ? err.code : err.validation ? 'INVALID_REQUEST' : 'HTTP_ERROR',
      });
  });
  app.setNotFoundHandler((_request, reply) =>
    reply.code(404).type('application/problem+json').send({
      type: 'about:blank',
      title: 'Not Found',
      status: 404,
      code: 'HTTP_ERROR',
    }),
  );
  const pageQuery = {
    type: 'object',
    additionalProperties: false,
    properties: { pageSize: { type: 'string', pattern: '^[0-9]+$' } },
  };
  app.get('/health', { schema: { description: 'Service health' } }, () => ({ status: 'ok' }));
  app.get(
    '/api/v1/graph/meta',
    { schema: { description: 'Graph metadata and ingestion warnings' } },
    () => service.meta(),
  );
  app.get('/api/v1/filters', { schema: { description: 'Available registered filters' } }, () =>
    service.filters(),
  );
  app.get<{ Querystring: { pageSize?: string } }>(
    '/api/v1/graph',
    {
      schema: {
        description: 'Page through original graph',
        querystring: pageQuery,
        response: { 200: graphPageSchema },
      },
    },
    (req) => service.graph(req.query.pageSize),
  );
  app.get<{ Params: { id: string } }>(
    '/api/v1/graph/nodes/:id',
    {
      schema: {
        description: 'Full node properties',
        params: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } },
      },
    },
    (req) => service.details(req.params.id),
  );
  app.get<{ Params: { cursor: string } }>(
    '/api/v1/results/:cursor',
    {
      schema: {
        description: 'Next page of a stored result',
        response: { 200: graphPageSchema },
        params: {
          type: 'object',
          required: ['cursor'],
          properties: { cursor: { type: 'string', maxLength: 128 } },
        },
      },
    },
    (req) => service.next(req.params.cursor),
  );
  app.post(
    '/api/v1/routes/query',
    {
      schema: {
        description: 'Compute union of matching simple paths',
        response: { 200: graphPageSchema },
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['query'],
          properties: {
            query: querySchema,
            pageSize: { type: 'integer', minimum: 1, maximum: 2000 },
          },
        },
      },
    },
    async (req, reply) => {
      const controller = new AbortController();
      const close = () => {
        if (!reply.raw.writableEnded) controller.abort();
      };
      reply.raw.once('close', close);
      try {
        return await service.query(req.body, controller.signal);
      } finally {
        reply.raw.off('close', close);
      }
    },
  );
  app.post(
    '/api/v1/routes/paths',
    {
      schema: {
        description: 'Enumerate a bounded list of matching simple paths',
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['query'],
          properties: { query: querySchema, limit: { type: 'integer', minimum: 1, maximum: 100 } },
        },
        response: { 200: pathsSchema },
      },
    },
    async (req, reply) => {
      const controller = new AbortController();
      const close = () => {
        if (!reply.raw.writableEnded) controller.abort();
      };
      reply.raw.once('close', close);
      try {
        return await service.paths(req.body, controller.signal);
      } finally {
        reply.raw.off('close', close);
      }
    },
  );
  return app;
}
