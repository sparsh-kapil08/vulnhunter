import pkg from 'pg';
const { Pool } = pkg;

export async function connectDB() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.log('[Database] No DATABASE_URL set. Running in stateless mode.');
    return null;
  }

  try {
    const pool = new Pool({ connectionString: dbUrl });
    const res = await pool.query('SELECT NOW()');
    console.log('[Database] Connected to PostgreSQL at:', res.rows[0].now);
    return pool;
  } catch (error) {
    console.error('[Database] PostgreSQL connection error:', error.message);
    return null;
  }
}
