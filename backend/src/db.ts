import pg from 'pg';
import type { AppConfig } from './config.js';

// PostgreSQL DATE is a calendar day, not an instant. Keep it as YYYY-MM-DD.
// TIMESTAMPTZ retains pg's default Date parser.
pg.types.setTypeParser(1082, (value: string) => value);

export function createPool(config: AppConfig): pg.Pool {
  const pool = new pg.Pool({
    host: config.DB_HOST,
    port: config.DB_PORT,
    database: config.DB_NAME,
    user: config.DB_USER,
    password: config.DB_PASSWORD,
    max: 5,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 2_000,
    statement_timeout: 3_000,
    application_name: 'sobralis_api',
  });
  // Idle pg clients emit errors when the database disconnects. Handle them
  // without dumping the client object (which may contain credentials).
  pool.on('error', () => { console.error('Database connection interrupted'); });
  return pool;
}
