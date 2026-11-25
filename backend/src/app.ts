import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import type { Pool } from 'pg';
import type { SecurityConfig } from './config.js';
import { registerSecurity } from './security.js';
import type { VerificationMailer } from './mail.js';
import { randomUUID } from 'node:crypto';
import type { DiagnosticSink } from './safe-diagnostics.js';
import { createServingReadiness } from './serving-readiness.js';

export type Dependencies = { checkDatabase: () => Promise<void>; safeDiagnostic?: DiagnosticSink; security?: { pool: Pool; config: SecurityConfig; mailer?: VerificationMailer | null } };

export async function createApp(dependencies: Dependencies) {
  const app = Fastify({
    logger: false,
    // Never trust a caller-supplied correlation identifier.
    requestIdHeader: false,
    genReqId: () => randomUUID(),
    // Trust an exact configured proxy address only; never arbitrary forwarded headers.
    trustProxy: dependencies.security?.config.TRUSTED_PROXY_IP ? [dependencies.security.config.TRUSTED_PROXY_IP] : false,
    bodyLimit: 16 * 1024,
    requestTimeout: 5_000,
  });
  await app.register(helmet, {
    // This API serves JSON only. Frontend CSP will be configured at the reverse proxy later.
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    crossOriginEmbedderPolicy: false,
  });
  app.addHook('onSend', async (request, reply, payload) => {
    // All API responses may contain personal data, including errors and schedules.
    if (request.url.startsWith('/api/')) { reply.header('Cache-Control', 'no-store'); reply.header('X-Request-Id', request.id); }
    return payload;
  });
  app.addHook('onResponse', async (request, reply) => {
    if (request.url.startsWith('/api/') && dependencies.safeDiagnostic) {
      try {
        dependencies.safeDiagnostic({requestId: request.id, method: request.method, url: request.url, status: reply.statusCode, durationMs: reply.elapsedTime});
      } catch { /* diagnostics must not affect request handling */ }
    }
  });
  // Do not knowingly serve API traffic against a schema this release rejects.
  // Coalesce concurrent checks, but cache no successful result between requests.
  // This is not atomic with the subsequent handler or a replacement for draining
  // the instance before a migration.
  const checkServingReadiness = createServingReadiness(dependencies.checkDatabase);
  app.addHook('preHandler', async (request, reply) => {
    if (!request.url.startsWith('/api/')) return;
    try { await checkServingReadiness(); }
    catch { return reply.code(503).send({ error: 'UNAVAILABLE' }); }
  });
  app.get('/health', async (_request, reply) => reply.header('Cache-Control', 'no-store').send({ status: 'ok' }));
  app.get('/ready', async (_request, reply) => {
    try {
      await checkServingReadiness();
      return reply.header('Cache-Control', 'no-store').send({ status: 'ok' });
    } catch {
      // No SQL, credentials, internal topology, or personal data in responses.
      return reply.header('Cache-Control', 'no-store').code(503).send({ status: 'unavailable' });
    }
  });
  if (dependencies.security) await registerSecurity(app, dependencies.security.pool, dependencies.security.config, dependencies.security.mailer ?? null);
  app.setNotFoundHandler((_request, reply) => reply.code(404).send({ error: 'NOT_FOUND' }));
  app.setErrorHandler((error, _request, reply) => {
    const status = typeof error === 'object' && error !== null && 'statusCode' in error && typeof error.statusCode === 'number' ? error.statusCode : 500;
    if (status === 429) return reply.code(429).send({ error: 'RATE_LIMITED' });
    if (status >= 400 && status < 500) return reply.code(400).send({ error: 'INVALID_REQUEST' });
    return reply.code(500).send({ error: 'INTERNAL_ERROR' });
  });
  return app;
}
