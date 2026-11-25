import { readConfig, readSecurityConfig } from './config.js';
import { createPool } from './db.js';
import { createApp } from './app.js';
import { createMailer } from './mail.js';
import { fileURLToPath } from 'node:url';
import { readMigrations } from './migration-lib.js';
import { createSchemaReadiness } from './schema-readiness.js';
import { createSafeDiagnostics } from './safe-diagnostics.js';

async function main() {
  // Unlike command-line migration tools, the network-facing API must never
  // silently fall back to development security settings.
  if (!process.env.NODE_ENV) throw new Error('NODE_ENV must be explicit');
  const config = readConfig(process.env);
  const securityConfig = readSecurityConfig(process.env, config.NODE_ENV);
  const mailer = createMailer(process.env);
  const migrations = await readMigrations(fileURLToPath(new URL('../migrations/', import.meta.url)));
  const pool = createPool(config);
  let app;
  try {
    const checkDatabase = createSchemaReadiness(pool, migrations);
    // Fail closed on startup; /ready also rechecks after startup. /health is
    // liveness only and must not be used to route traffic to this service.
    await checkDatabase();
    app = await createApp({ checkDatabase, ...(config.SAFE_DIAGNOSTICS === 'true' ? { safeDiagnostic: createSafeDiagnostics(line => console.log(line)) } : {}), security: { pool, config: securityConfig, mailer } });
    app.addHook('onClose', async () => { await pool.end(); });
    await app.listen({ host: config.HOST, port: config.PORT });
  } catch (error) {
    if (app) await app.close(); else await pool.end();
    throw error;
  }
  const shutdown = async () => { try { await app.close(); } finally { process.exit(0); } };
  process.once('SIGTERM', () => { void shutdown(); });
  process.once('SIGINT', () => { void shutdown(); });
  console.log('API started');
}
main().catch(() => { console.error('API startup failed; check configuration and service availability.'); process.exitCode = 1; });
