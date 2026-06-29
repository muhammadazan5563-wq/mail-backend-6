/**
 * Database connection pool and query helper.
 * Uses PostgreSQL via the 'pg' package.
 * IMPORTANT: Server must start even if DATABASE_URL is not set.
 */
import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

let pool: pg.Pool | null = null;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
    max: 30,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
    statement_timeout: 60000,
  });

  pool.on('error', (err) => {
    console.error('Unexpected PostgreSQL pool error:', err);
  });
} else {
  console.warn('WARNING: DATABASE_URL is not set. Database features will be unavailable.');
}

export async function query(text: string, params?: any[]) {
  if (!pool) {
    throw new Error('Database not configured. Set DATABASE_URL environment variable.');
  }
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

export async function getClient() {
  if (!pool) {
    throw new Error('Database not configured. Set DATABASE_URL environment variable.');
  }
  return pool.connect();
}

export default pool;
