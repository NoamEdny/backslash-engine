import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { loadGraph, StaticGraphRepository } from '../index.js';
import type { MissingNodePolicy } from '../index.js';
import { buildApp } from './app.js';

const text = await readFile(
  process.env.GRAPH_FILE ?? new URL('../../data/train-ticket.json', import.meta.url),
  'utf8',
);
const policy = process.env.MISSING_NODE_POLICY ?? 'placeholder';
if (policy !== 'placeholder' && policy !== 'drop' && policy !== 'reject') {
  throw new Error('MISSING_NODE_POLICY must be placeholder, drop or reject');
}
const port = Number(process.env.PORT ?? 3000);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
  throw new Error('PORT must be 1..65535');
const graph = loadGraph(text, {
  version: createHash('sha256')
    .update(policy + '\0' + text)
    .digest('hex'),
  missingNodePolicy: policy satisfies MissingNodePolicy,
});
const app = await buildApp(new StaticGraphRepository(graph), { logger: true });
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => {
    void app.close().catch((error) => {
      app.log.error(error);
      process.exitCode = 1;
    });
  });
}
await app.listen({ port, host: process.env.HOST ?? '127.0.0.1' });
