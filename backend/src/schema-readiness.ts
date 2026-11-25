import type { Pool } from 'pg';

export type MigrationFingerprint = { name: string; checksum: string };

// Both missing and newer or edited migrations are incompatible. This check
// intentionally makes no promise about object integrity or data correctness.
export function assertReleaseSchema(expected: readonly MigrationFingerprint[], actual: readonly MigrationFingerprint[]): void {
  if (!expected.length || actual.length !== expected.length ||
      expected.some((item, index) => item.name !== actual[index]?.name || item.checksum !== actual[index]?.checksum)) {
    throw new Error('Database schema does not match release');
  }
}

export function createSchemaReadiness(pool: Pool, expected: readonly MigrationFingerprint[]): () => Promise<void> {
  // Copy once so callers cannot mutate the fingerprint after startup.
  const release = expected.map(({name, checksum}) => ({name, checksum}));
  return async () => {
    const result = await pool.query<MigrationFingerprint>('SELECT name, checksum FROM public.runtime_schema_state()');
    assertReleaseSchema(release, result.rows);
  };
}
