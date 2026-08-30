import pg from "pg";
import { withPostgresSchemaLock } from "./postgres-schema-lock";
import { randomBytes } from "crypto";
import { deriveOpaqueIndex } from "./crypto-primitives";

export type MailboxBucketPlane = "control";
export type MailboxTokenPlane = "message" | "control";

export type MailboxPlaneTokenRow = {
  token: string;
  plane: MailboxTokenPlane;
  sessionId: string;
  routeToken: string;
  keyId: string;
  publicKey: string;
  controlBucketKey?: string;
  issuedAt: number;
  expiresAt: number;
};

export interface MailboxPlaneStore {
  readonly provider: "memory" | "postgres";
  resolveBucketCapability(input: {
    sessionId: string;
    publicKey: string;
    plane: MailboxBucketPlane;
    ttlMs: number;
  }): Promise<string>;
  issueToken(input: Omit<MailboxPlaneTokenRow, "token" | "routeToken" | "issuedAt" | "expiresAt"> & {
    tokenPrefix: string;
    routeTokenPrefix: string;
    ttlMs: number;
  }): Promise<MailboxPlaneTokenRow>;
  getToken(token: string, plane: MailboxTokenPlane): Promise<MailboxPlaneTokenRow | null>;
  deleteToken(token: string): Promise<void>;
}

function bucketCompositeHash(sessionId: string, publicKey: string, plane: MailboxBucketPlane) {
  return deriveOpaqueIndex(plane, String(sessionId || "").trim(), String(publicKey || "").trim());
}

function randomToken(prefix: string) {
  return `${prefix}_${randomBytes(24).toString("hex")}`;
}

class MemoryMailboxPlaneStore implements MailboxPlaneStore {
  readonly provider = "memory" as const;
  private readonly buckets = new Map<string, {
    bucketKey: string;
    plane: MailboxBucketPlane;
    compositeHash: string;
    expiresAt: number;
    lastSeenAt: number;
  }>();
  private readonly bucketByCompositeHash = new Map<string, string>();
  private readonly tokens = new Map<string, MailboxPlaneTokenRow>();

  async resolveBucketCapability(input: {
    sessionId: string;
    publicKey: string;
    plane: MailboxBucketPlane;
    ttlMs: number;
  }): Promise<string> {
    const now = Date.now();
    this.cleanup(now);
    const compositeHash = bucketCompositeHash(input.sessionId, input.publicKey, input.plane);
    const existingBucketKey = this.bucketByCompositeHash.get(compositeHash);
    if (existingBucketKey) {
      const existing = this.buckets.get(existingBucketKey);
      if (existing && existing.expiresAt > now) {
        existing.lastSeenAt = now;
        return existing.bucketKey;
      }
      this.bucketByCompositeHash.delete(compositeHash);
      if (existing) this.buckets.delete(existingBucketKey);
    }
    const bucketKey = randomToken("mbb1");
    this.buckets.set(bucketKey, {
      bucketKey,
      plane: input.plane,
      compositeHash,
      expiresAt: now + input.ttlMs,
      lastSeenAt: now,
    });
    this.bucketByCompositeHash.set(compositeHash, bucketKey);
    return bucketKey;
  }

  async issueToken(input: Omit<MailboxPlaneTokenRow, "token" | "routeToken" | "issuedAt" | "expiresAt"> & {
    tokenPrefix: string;
    routeTokenPrefix: string;
    ttlMs: number;
  }): Promise<MailboxPlaneTokenRow> {
    const issuedAt = Date.now();
    this.cleanup(issuedAt);
    const row: MailboxPlaneTokenRow = {
      token: randomToken(input.tokenPrefix),
      plane: input.plane,
      sessionId: input.sessionId,
      routeToken: randomToken(input.routeTokenPrefix),
      keyId: input.keyId,
      publicKey: input.publicKey,
      controlBucketKey: input.controlBucketKey,
      issuedAt,
      expiresAt: issuedAt + input.ttlMs,
    };
    this.tokens.set(row.token, row);
    return row;
  }

  async getToken(token: string, plane: MailboxTokenPlane): Promise<MailboxPlaneTokenRow | null> {
    const now = Date.now();
    this.cleanup(now);
    const row = this.tokens.get(String(token || "").trim());
    if (!row || row.plane !== plane || row.expiresAt <= now) return null;
    return row;
  }

  async deleteToken(token: string): Promise<void> {
    this.tokens.delete(String(token || "").trim());
  }

  private cleanup(now = Date.now()) {
    for (const [token, row] of this.tokens.entries()) {
      if (row.expiresAt <= now) this.tokens.delete(token);
    }
    for (const [bucketKey, row] of this.buckets.entries()) {
      if (row.expiresAt > now) continue;
      this.buckets.delete(bucketKey);
      if (this.bucketByCompositeHash.get(row.compositeHash) === bucketKey) {
        this.bucketByCompositeHash.delete(row.compositeHash);
      }
    }
  }
}

class PostgresMailboxPlaneStore implements MailboxPlaneStore {
  readonly provider = "postgres" as const;
  private readonly pool: pg.Pool;
  private ready: Promise<void> | null = null;
  private cleanupCounter = 0;

  constructor(connectionString: string) {
    this.pool = new pg.Pool({
      connectionString,
      max: Number(process.env.VORYX_MAILBOX_PLANE_PG_POOL_MAX || 4),
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 3_000,
    });
  }

  async resolveBucketCapability(input: {
    sessionId: string;
    publicKey: string;
    plane: MailboxBucketPlane;
    ttlMs: number;
  }): Promise<string> {
    await this.ensureReady();
    const now = Date.now();
    await this.cleanupOccasionally(now);
    const compositeHash = bucketCompositeHash(input.sessionId, input.publicKey, input.plane);
    const nextBucketKey = randomToken("mbb1");
    const result = await this.pool.query(
      `
        INSERT INTO voryx_mailbox_bucket_capabilities
          (bucket_key, plane, composite_hash, expires_at, last_seen_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $5)
        ON CONFLICT (composite_hash) DO UPDATE SET
          bucket_key = CASE
            WHEN voryx_mailbox_bucket_capabilities.expires_at <= $5 THEN EXCLUDED.bucket_key
            ELSE voryx_mailbox_bucket_capabilities.bucket_key
          END,
          plane = EXCLUDED.plane,
          expires_at = CASE
            WHEN voryx_mailbox_bucket_capabilities.expires_at <= $5 THEN EXCLUDED.expires_at
            ELSE voryx_mailbox_bucket_capabilities.expires_at
          END,
          last_seen_at = $5
        RETURNING bucket_key
      `,
      [nextBucketKey, input.plane, compositeHash, now + input.ttlMs, now],
    );
    return String(result.rows[0]?.bucket_key || nextBucketKey);
  }

  async issueToken(input: Omit<MailboxPlaneTokenRow, "token" | "routeToken" | "issuedAt" | "expiresAt"> & {
    tokenPrefix: string;
    routeTokenPrefix: string;
    ttlMs: number;
  }): Promise<MailboxPlaneTokenRow> {
    await this.ensureReady();
    const issuedAt = Date.now();
    await this.cleanupOccasionally(issuedAt);
    const row: MailboxPlaneTokenRow = {
      token: randomToken(input.tokenPrefix),
      plane: input.plane,
      sessionId: input.sessionId,
      routeToken: randomToken(input.routeTokenPrefix),
      keyId: input.keyId,
      publicKey: input.publicKey,
      controlBucketKey: input.controlBucketKey,
      issuedAt,
      expiresAt: issuedAt + input.ttlMs,
    };
    await this.pool.query(
      `
        INSERT INTO voryx_mailbox_plane_tokens
          (token, plane, session_id, route_token, key_id, public_key, control_bucket_key, issued_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `,
      [
        row.token,
        row.plane,
        row.sessionId,
        row.routeToken,
        row.keyId,
        row.publicKey,
        row.controlBucketKey || null,
        row.issuedAt,
        row.expiresAt,
      ],
    );
    return row;
  }

  async getToken(token: string, plane: MailboxTokenPlane): Promise<MailboxPlaneTokenRow | null> {
    await this.ensureReady();
    const normalized = String(token || "").trim();
    if (!normalized) return null;
    const now = Date.now();
    const result = await this.pool.query(
      `
        SELECT token, plane, session_id, route_token, key_id, public_key, control_bucket_key, issued_at, expires_at
        FROM voryx_mailbox_plane_tokens
        WHERE token = $1 AND plane = $2 AND expires_at > $3
      `,
      [normalized, plane, now],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      token: String(row.token || ""),
      plane: String(row.plane || "message") as MailboxTokenPlane,
      sessionId: String(row.session_id || ""),
      routeToken: String(row.route_token || ""),
      keyId: String(row.key_id || ""),
      publicKey: String(row.public_key || ""),
      controlBucketKey: row.control_bucket_key ? String(row.control_bucket_key) : undefined,
      issuedAt: Number(row.issued_at || 0),
      expiresAt: Number(row.expires_at || 0),
    };
  }

  async deleteToken(token: string): Promise<void> {
    await this.ensureReady();
    await this.pool.query("DELETE FROM voryx_mailbox_plane_tokens WHERE token = $1", [String(token || "").trim()]);
  }

  private cleanupOccasionally(now = Date.now()) {
    if (this.cleanupCounter++ % 1000 !== 0) return Promise.resolve();
    return Promise.all([
      this.pool.query("DELETE FROM voryx_mailbox_plane_tokens WHERE expires_at <= $1", [now]),
      this.pool.query("DELETE FROM voryx_mailbox_bucket_capabilities WHERE expires_at <= $1", [now]),
    ]).then(() => undefined);
  }

  private ensureReady(): Promise<void> {
    if (!this.ready) {
      this.ready = withPostgresSchemaLock(this.pool, "voryx_mailbox_plane_schema", async () => {
        await this.pool.query(`
          CREATE TABLE IF NOT EXISTS voryx_mailbox_bucket_capabilities (
            bucket_key TEXT PRIMARY KEY,
            plane TEXT NOT NULL,
            composite_hash TEXT UNIQUE NOT NULL,
            expires_at BIGINT NOT NULL,
            last_seen_at BIGINT NOT NULL,
            created_at BIGINT NOT NULL
          )
        `);
        await this.pool.query(`
          CREATE TABLE IF NOT EXISTS voryx_mailbox_plane_tokens (
            token TEXT PRIMARY KEY,
            plane TEXT NOT NULL,
            session_id TEXT NOT NULL,
            route_token TEXT NOT NULL,
            key_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            control_bucket_key TEXT,
            issued_at BIGINT NOT NULL,
            expires_at BIGINT NOT NULL
          )
        `);
        await this.pool.query("CREATE INDEX IF NOT EXISTS voryx_mailbox_plane_tokens_route_idx ON voryx_mailbox_plane_tokens (route_token)");
        await this.pool.query("CREATE INDEX IF NOT EXISTS voryx_mailbox_plane_tokens_expires_at_idx ON voryx_mailbox_plane_tokens (expires_at)");
        await this.pool.query("CREATE INDEX IF NOT EXISTS voryx_mailbox_bucket_capabilities_expires_at_idx ON voryx_mailbox_bucket_capabilities (expires_at)");
        await this.cleanupOccasionally(Date.now());
      });
    }
    return this.ready;
  }
}

export function createMailboxPlaneStore(options: { log?: (message: string, source?: string) => void } = {}): MailboxPlaneStore {
  const provider = String(process.env.VORYX_MAILBOX_PLANE_STORE || "memory").trim().toLowerCase();
  if (provider === "postgres" || provider === "pg") {
    const connectionString = String(process.env.DATABASE_URL || "").trim();
    if (!connectionString) {
      throw new Error("VORYX_MAILBOX_PLANE_STORE=postgres requires DATABASE_URL");
    }
    options.log?.("mailbox plane store: postgres", "runtime");
    return new PostgresMailboxPlaneStore(connectionString);
  }
  if (provider && provider !== "memory") {
    throw new Error(`Unsupported VORYX_MAILBOX_PLANE_STORE provider: ${provider}`);
  }
  options.log?.("mailbox plane store: memory", "runtime");
  return new MemoryMailboxPlaneStore();
}
