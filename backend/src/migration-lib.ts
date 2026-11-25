import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type pg from 'pg';

export type Migration = { name: string; sql: string; checksum: string };
export async function readMigrations(directory: string): Promise<Migration[]> {
  const files = (await readdir(directory)).filter(f => f.endsWith('.sql')).sort();
  if (!files.length || files.some(f => !/^\d{4}_[a-z0-9_]+\.sql$/.test(f))) throw new Error('Invalid migration filenames');
  if (new Set(files.map(f => f.slice(0, 4))).size !== files.length) throw new Error('Duplicate migration version');
  return Promise.all(files.map(async name => {
    const sql = await readFile(join(directory, name), 'utf8');
    return { name, sql, checksum: createHash('sha256').update(sql).digest('hex') };
  }));
}
// One session-level lock prevents concurrent migrators from interleaving.
// Each file and its ledger entry commit atomically.
export async function applyMigrations(client: pg.PoolClient, migrations: Migration[]): Promise<void> {
  await client.query('SELECT pg_advisory_lock($1)', [741930211]);
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      checksum text NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);
    const result = await client.query<{ name: string; checksum: string }>('SELECT name, checksum FROM schema_migrations ORDER BY name');
    const byName = new Map(migrations.map(m => [m.name, m]));
    const applied = new Set<string>();
    for (const [index, row] of result.rows.entries()) {
      const expected = byName.get(row.name);
      if (!expected || expected.checksum !== row.checksum || migrations[index]?.name !== row.name) throw new Error('Migration history differs from release');
      applied.add(row.name);
    }
    for (const migration of migrations) {
      if (applied.has(migration.name)) continue;
      await client.query('BEGIN');
      try {
        await client.query(migration.sql);
        await client.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [migration.name, migration.checksum]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [741930211]);
  }
}
