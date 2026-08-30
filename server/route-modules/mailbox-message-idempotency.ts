import pg from "pg";
import { withPostgresSchemaLock } from "../postgres-schema-lock";

export type MailboxMessageIdempotencyEntry = {
  message: any;
  expiresAt: number;
};

export interface MailboxMessageIdempotencyStore {
  readonly provider: "memory" | "postgres";
  get(key: string, now?: number): Promise<MailboxMessageIdempotencyEntry | null>;
  set(key: string, entry: MailboxMessageIdempotencyEntry, now?: number): Promise<void>;
  cleanup(now?: number): Promise<void>;
}

type MailboxMessageIdempotencyStoreOptions = {
  maxEntries: number;
};

const normalizeKey = (key: unknown) => String(key || "").trim();
const cloneEntry = (entry: MailboxMessageIdempotencyEntry): MailboxMessageIdempotencyEntry => ({
  expiresAt: Number(entry.expiresAt || 0),
  message: entry.message && typeof entry.message === "object" ? { ...entry.message } : entry.message,
});

class MemoryMailboxMessageIdempotencyStore implements MailboxMessageIdempotencyStore {
  readonly provider = "memory" as const;
  private readonly rows = new Map<string, MailboxMessageIdempotencyEntry>();

  constructor(private readonly options: MailboxMessageIdempotencyStoreOptions) {}

  async get(key: string, now = Date.now()) {
    await this.cleanup(now);
    const row = this.rows.get(normalizeKey(key));
    if (!row || row.expiresAt <= now) return null;
    return cloneEntry(row);
  }

  async set(key: string, entry: MailboxMessageIdempotencyEntry, now = Date.now()) {
    await this.cleanup(now);
    this.rows.set(normalizeKey(key), cloneEntry(entry));
    this.trim();
  }

  async cleanup(now = Date.now()) {
    for (const [key, entry] of this.rows) {
      if (entry.expiresAt <= now) this.rows.delete(key);
    }
  }

  private trim() {
    if (this.rows.size <= this.options.maxEntries) return;
    const target = Math.floor(this.options.maxEntries * 0.95);
    for (const key of this.rows.keys()) {
      this.rows.delete(key);
      if (this.rows.size <= target) break;
    }
  }
}

class PostgresMailboxMessageIdempotencyStore implements MailboxMessageIdempotencyStore {
  readonly provider = "postgres" as const;
  private readonly pool: pg.Pool;
  private ready: Promise<void> | null = null;
  private cleanupCounter = 0;

  constructor(connectionString: string) {
    this.pool = new pg.Pool({
      connectionString,
      max: Number(process.env.VORYX_MESSAGE_IDEMPOTENCY_PG_POOL_MAX || 4),
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 3_000,
    });
  }

  async get(key: string, now = Date.now()) {
    await this.ensureReady();
    const result = await this.pool.query(
      `
        SELECT message, expires_at
        FROM voryx_message_idempotency
        WHERE idempotency_key = $1 AND expires_at > $2
      `,
      [normalizeKey(key), now],
    );
    const row = result.rows[0];
    if (!row) return null;
    return cloneEntry({ message: row.message, expiresAt: Number(row.expires_at || 0) });
  }

  async set(key: string, entry: MailboxMessageIdempotencyEntry, now = Date.now()) {
    await this.ensureReady();
    await this.cleanupOccasionally(now);
    const normalized = cloneEntry(entry);
    await this.pool.query(
      `
        INSERT INTO voryx_message_idempotency (idempotency_key, message, expires_at, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (idempotency_key) DO UPDATE SET
          message = EXCLUDED.message,
          expires_at = EXCLUDED.expires_at
      `,
      [normalizeKey(key), normalized.message, normalized.expiresAt, now],
    );
  }

  async cleanup(now = Date.now()) {
    await this.ensureReady();
    await this.pool.query("DELETE FROM voryx_message_idempotency WHERE expires_at <= $1", [now]);
  }

  private cleanupOccasionally(now = Date.now()) {
    if (this.cleanupCounter++ % 1000 !== 0) return Promise.resolve();
    return this.cleanup(now);
  }

  private ensureReady(): Promise<void> {
    if (!this.ready) {
      this.ready = withPostgresSchemaLock(this.pool, "voryx_message_idempotency_schema", async () => {
        await this.pool.query(`
          CREATE TABLE IF NOT EXISTS voryx_message_idempotency (
            idempotency_key TEXT PRIMARY KEY,
            message JSONB NOT NULL,
            expires_at BIGINT NOT NULL,
            created_at BIGINT NOT NULL
          )
        `);
        await this.pool.query("CREATE INDEX IF NOT EXISTS voryx_message_idempotency_expires_at_idx ON voryx_message_idempotency (expires_at)");
        await this.pool.query("DELETE FROM voryx_message_idempotency WHERE expires_at <= $1", [Date.now()]);
      });
    }
    return this.ready;
  }
}

export function createMailboxMessageIdempotencyStore(options: MailboxMessageIdempotencyStoreOptions): MailboxMessageIdempotencyStore {
  const provider = String(process.env.VORYX_MESSAGE_IDEMPOTENCY_STORE || "memory").trim().toLowerCase();
  if (provider === "postgres" || provider === "pg") {
    const connectionString = String(process.env.DATABASE_URL || "").trim();
    if (!connectionString) {
      throw new Error("VORYX_MESSAGE_IDEMPOTENCY_STORE=postgres requires DATABASE_URL");
    }
    return new PostgresMailboxMessageIdempotencyStore(connectionString);
  }
  if (provider && provider !== "memory") {
    throw new Error(`Unsupported VORYX_MESSAGE_IDEMPOTENCY_STORE provider: ${provider}`);
  }
  return new MemoryMailboxMessageIdempotencyStore(options);
}
