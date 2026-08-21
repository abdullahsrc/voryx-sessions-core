import type pg from "pg";

export async function withPostgresSchemaLock<T>(
  pool: pg.Pool,
  scope: string,
  work: () => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock(hashtext($1))", [scope]);
    return await work();
  } finally {
    try {
      await client.query("SELECT pg_advisory_unlock(hashtext($1))", [scope]);
    } catch {
    }
    client.release();
  }
}
