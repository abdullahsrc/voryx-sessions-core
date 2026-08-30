import pg from "pg";
import { withPostgresSchemaLock } from "./postgres-schema-lock";

export type RequestNonceStoreEntry = {
  keyId: string;
  method: string;
  path: string;
  bodyHash: string;
  expiresAt: number;
  createdAt: number;
};

export interface RequestNonceStore {
  readonly provider: "memory" | "postgres";
  consume(scopeKey: string, globalKey: string, entry: RequestNonceStoreEntry): Promise<boolean>;
}

type RequestNonceStoreOptions = {
  cacheMax: number;
  log?: (message: string, source?: string) => void;
};

class MemoryRequestNonceStore implements RequestNonceStore {
  readonly provider = "memory" as const;
  private readonly used = new Map<string, RequestNonceStoreEntry>();

  async consume(scopeKey: string, globalKey: string, entry: RequestNonceStoreEntry): Promise<boolean> {
    this.cleanup(entry.createdAt);
    if (this.used.has(scopeKey) || this.used.has(globalKey)) return false;
    this.used.set(scopeKey, entry);
    this.used.set(globalKey, entry);
    this.trim();
    return true;
  }

  private cleanup(now = Date.now()) {
    for (const [key, entry] of this.used.entries()) {
      if (entry.expiresAt <= now) this.used.delete(key);
    }
  }

  private trim() {
    if (this.used.size <= this.cacheMax) return;
    const target = Math.floor(this.cacheMax * 0.95);
    for (const key of this.used.keys()) {
      this.used.delete(key);
      if (this.used.size <= target) break;
    }
  }

  constructor(private readonly cacheMax: number) {}
}

class PostgresRequestNonceStore implements RequestNonceStore {
  readonly provider = "postgres" as const;
  private readonly pool: pg.Pool;
  private ready: Promise<void> | null = null;
  private cleanupCounter = 0;

  constructor(connectionString: string) {
    this.pool = new pg.Pool({
      connectionString,
      max: Number(process.env.VORYX_REQUEST_NONCE_PG_POOL_MAX || 4),
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 3_000,
    });
  }

  async consume(scopeKey: string, globalKey: string, entry: RequestNonceStoreEntry): Promise<boolean> {
    await this.ensureReady();
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      if (this.cleanupCounter++ % 1000 === 0) {
        await client.query("DELETE FROM voryx_request_nonces WHERE expires_at <= $1", [entry.createdAt]);
      }
      const result = await client.query(
        `
          INSERT INTO voryx_request_nonces (nonce_key, key_id, method, path, body_hash, expires_at, created_at)
          VALUES
            ($1, $3, $4, $5, $6, $7, $8),
            ($2, $3, $4, $5, $6, $7, $8)
          ON CONFLICT (nonce_key) DO NOTHING
        `,
        [
          scopeKey,
          globalKey,
          entry.keyId,
          entry.method,
          entry.path,
          entry.bodyHash,
          entry.expiresAt,
          entry.createdAt,
        ],
      );
      if (result.rowCount !== 2) {
        await client.query("ROLLBACK");
        return false;
      }
      await client.query("COMMIT");
      return true;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {
      }
      throw error;
    } finally {
      client.release();
    }
  }

  private ensureReady(): Promise<void> {
    if (!this.ready) {
      this.ready = withPostgresSchemaLock(this.pool, "voryx_request_nonces_schema", async () => {
        await this.pool.query(`
          CREATE TABLE IF NOT EXISTS voryx_request_nonces (
            nonce_key TEXT PRIMARY KEY,
            key_id TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            body_hash TEXT NOT NULL,
            expires_at BIGINT NOT NULL,
            created_at BIGINT NOT NULL
          )
        `);
        await this.pool.query("CREATE INDEX IF NOT EXISTS voryx_request_nonces_expires_at_idx ON voryx_request_nonces (expires_at)");
        await this.pool.query("DELETE FROM voryx_request_nonces WHERE expires_at <= $1", [Date.now()]);
      });
    }
    return this.ready;
  }
}

export function createRequestNonceStore(options: RequestNonceStoreOptions): RequestNonceStore {
  const provider = String(process.env.VORYX_REQUEST_NONCE_STORE || "memory").trim().toLowerCase();
  if (provider === "postgres" || provider === "pg") {
    const connectionString = String(process.env.DATABASE_URL || "").trim();
    if (!connectionString) {
      throw new Error("VORYX_REQUEST_NONCE_STORE=postgres requires DATABASE_URL");
    }
    options.log?.("request nonce store: postgres", "runtime");
    return new PostgresRequestNonceStore(connectionString);
  }
  if (provider && provider !== "memory") {
    throw new Error(`Unsupported VORYX_REQUEST_NONCE_STORE provider: ${provider}`);
  }
  options.log?.("request nonce store: memory", "runtime");
  return new MemoryRequestNonceStore(options.cacheMax);
}
