import { join } from 'node:path';
import { readConfig } from './config.js';
import { createPool } from './db.js';
import { readMigrations, applyMigrations } from './migration-lib.js';

async function main() {
  const config = readConfig(process.env);
  const migrations = await readMigrations(join(process.cwd(), 'migrations'));
  const pool = createPool(config);
  try {
    const client = await pool.connect();
    try { await applyMigrations(client, migrations); } finally { client.release(); }
    console.log('Database migrations complete');
  } finally { await pool.end(); }
}
main().catch(() => { console.error('Migration failed; no further migrations applied. Verify configuration and migration history.'); process.exitCode = 1; });
