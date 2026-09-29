import pkg from 'pg';
const { Pool } = pkg;

export async function connectDB() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    if (process.env.SUPABASE_URL && process.env.SUPABASE_KEY) {
      console.log('[Database] Supabase REST persistence configured.');
    } else {
      console.log('[Database] No DATABASE_URL or Supabase credentials set. Running without persistence.');
    }
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
