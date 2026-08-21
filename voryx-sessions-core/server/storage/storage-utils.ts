import { randomBytes } from "crypto";
import type { ChatMessage } from "@shared/schema";
import { computeSessionSenderScopeId } from "@shared/sender-scope";
import { deriveOpaqueIndex } from "../crypto-primitives";
import { buildOpaqueKeyReputationIndexScoped } from "./key-reputation-policy";

export const VALID_DISAPPEAR_AFTER_READ_SECONDS = new Set<number>([15, 30, 60, 120, 300, 600, 900, 1800, 3600]);
export const VALID_DISAPPEAR_AFTER_SEND_SECONDS = new Set<number>([15, 30, 60, 120, 300, 600, 900, 1800, 3600]);

export function hexToBytes(hex: string): Uint8Array {
  const clean = String(hex || "").trim();
  if (!clean || clean.length % 2 !== 0) return new Uint8Array();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function generateSignatureToken(): string {
  return `prf_${randomBytes(24).toString("hex")}`;
}

export function generateInviteCode(): string {
  return `VORYX-${randomBytes(5).toString("hex").toUpperCase()}`;
}

export function sanitizeMessageContent(content: string): string {
  return content
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

export function sanitizeTransportMessage(message: ChatMessage): ChatMessage {
  // Fail-closed: never expose legacy duplicated encryptedContent side-channel.
  const {
    encryptedContent: _legacyEncryptedContent,
    attachmentArtifactId: _attachmentArtifactId,
    attachmentArtifactIds: _attachmentArtifactIds,
    senderSessionCryptoPublicKey: _senderSessionCryptoPublicKey,
    senderSessionCryptoKeyId: _senderSessionCryptoKeyId,
    ...rest
  } = message as ChatMessage & { encryptedContent?: string; attachmentArtifactId?: string; attachmentArtifactIds?: string[] };
  const senderPublicKey = String(rest.senderPublicKey || "").trim();
  if (!senderPublicKey || senderPublicKey === "system") {
    return {
      ...(rest as ChatMessage),
      senderScopeId: "system",
      senderPublicKey: "system",
      senderSessionCryptoPublicKey: undefined,
      senderSessionCryptoKeyId: undefined,
    } as ChatMessage;
  }
  const senderScopeId = computeSessionSenderScopeId(rest.sessionId, senderPublicKey);
  return {
    ...(rest as ChatMessage),
    senderScopeId,
    senderPublicKey: senderScopeId,
    senderSessionCryptoPublicKey: undefined,
    senderSessionCryptoKeyId: undefined,
    senderLabel: undefined,
  } as ChatMessage;
}

export function collectMessageArtifactIds(message: unknown): string[] {
  const msg = message as { attachmentArtifactId?: unknown; attachmentArtifactIds?: unknown };
  const ids = new Set<string>();
  const legacy = String(msg?.attachmentArtifactId || "").trim();
  if (legacy) ids.add(legacy);
  if (Array.isArray(msg?.attachmentArtifactIds)) {
    msg.attachmentArtifactIds.forEach((value) => {
      const id = String(value || "").trim();
      if (id) ids.add(id);
    });
  }
  return Array.from(ids).slice(0, 24);
}

export const STRICT_CRYPTO_MODE = true;
export const STRICT_PQ_MODE = String(process.env.VORYX_STRICT_PQ_MODE || "false").toLowerCase() === "true";
export const MINIMIZE_SERVER_METADATA = String(process.env.VORYX_MINIMIZE_SERVER_METADATA || "true").toLowerCase() !== "false";
export const EVENT_LOGGING_ENABLED =
  String(process.env.VORYX_EVENT_LOGGING || (MINIMIZE_SERVER_METADATA ? "false" : "true")).toLowerCase() === "true";
export const EVENT_DATA_REDACT =
  String(process.env.VORYX_EVENT_DATA_REDACT || (MINIMIZE_SERVER_METADATA ? "true" : "false")).toLowerCase() !== "false";
export const ALLOW_NON_EXPIRING = String(process.env.VORYX_ALLOW_NON_EXPIRING || "false").toLowerCase() === "true";
export const SNAPSHOT_REDACT_AUDIT = String(process.env.VORYX_SNAPSHOT_REDACT_AUDIT || "true").toLowerCase() !== "false";
export const SNAPSHOT_INCLUDE_MESSAGE_HISTORY =
  String(process.env.VORYX_SNAPSHOT_INCLUDE_MESSAGE_HISTORY || "false").toLowerCase() === "true";
export const SNAPSHOT_INCLUDE_TASK_HISTORY =
  String(process.env.VORYX_SNAPSHOT_INCLUDE_TASK_HISTORY || "false").toLowerCase() === "true";
export const STRICT_NO_PERSISTENT_IDENTITY =
  String(process.env.VORYX_STRICT_NO_PERSISTENT_IDENTITY || "true").toLowerCase() !== "false";
export const CREATOR_ONLY_STRICT_PASSPHRASE =
  String(process.env.VORYX_CREATOR_ONLY_STRICT_PASSPHRASE || "false").toLowerCase() === "true";
export const SESSION_EPHEMERAL_IDENTITIES_ENABLED =
  String(process.env.VORYX_SESSION_EPHEMERAL_IDENTITIES || "true").toLowerCase() !== "false";
export const REQUIRE_ARGON2ID_PASSPHRASE_HASH =
  String(process.env.VORYX_REQUIRE_ARGON2ID_PASSPHRASE_HASH || (STRICT_PQ_MODE ? "true" : "false")).toLowerCase() !== "false";
export const MAX_ENCRYPTED_PAYLOAD_SIZE = 256 * 1024; // 256KB
export const MAX_VOICE_NOTE_PAYLOAD_CHARS = (() => {
  // Default raised for long voice notes (2h+), still configurable by env.
  const raw = Number(process.env.VORYX_MAX_VOICE_NOTE_PAYLOAD_CHARS || 256 * 1024 * 1024);
  if (!Number.isFinite(raw)) return 256 * 1024 * 1024;
  return Math.max(256 * 1024, Math.floor(raw));
})();
export const MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024; // 8GB
export const MIN_REPUTATION_SCORE_TO_JOIN = -5;
export const MIN_REPUTATION_TOTAL_FOR_ENFORCEMENT = 5;
export const MAX_REPORT_RATE_TO_JOIN = 80;
export const SPAM_STRIKES_BAN_THRESHOLD = 3;
export const INACTIVE_KEY_CLEANUP_ENABLED =
  String(process.env.VORYX_INACTIVE_KEY_CLEANUP_ENABLED || "false").toLowerCase() === "true";
export const INACTIVE_KEY_MAX_IDLE_MS = Math.max(
  8_000,
  Math.min(24 * 60 * 60 * 1000, Number(process.env.VORYX_INACTIVE_KEY_MAX_IDLE_MS || 120_000)),
);
export const DELETION_RECONCILE_INTERVAL_MS = Math.max(
  5_000,
  Math.min(10 * 60 * 1000, Number(process.env.VORYX_DELETION_RECONCILE_INTERVAL_MS || 30_000)),
);
export const SECURITY_AUDIT_ACTIONS = new Set<string>([
  "key.created",
  "key.extended",
  "key.killed",
  "key.expired",
  "session.created",
  "session.joined",
  "session.join_request_created",
  "session.left",
  "session.terminated",
  "audit.session.remove_participant",
  "audit.session.block_write",
  "audit.session.delete_my_data",
  "audit.session.passphrase_set",
  "audit.session.passphrase_grant",
  "audit.session.join_request_created",
  "audit.session.join_request_responded",
  "audit.kill_all",
]);

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => stableJson(v)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`).join(",")}}`;
}

export function buildOpaqueRuntimeIndexKey(scope: string, ...parts: Array<string | undefined>): string {
  const normalizedScope = String(scope || "").trim() || "runtime";
  const normalizedParts = parts.map((part) => String(part || "").trim());
  return deriveOpaqueIndex(
    normalizedScope,
    normalizedParts[0] || "",
    normalizedParts[1],
    normalizedParts[2],
    normalizedParts[3],
  );
}

export const SESSION_PASSPHRASE_GRANT_INDEX_PREFIX = "spg1_";
export const SESSION_WRITE_BLOCK_INDEX_PREFIX = "swb1_";
export const SESSION_REENTRY_BLOCK_INDEX_PREFIX = "srb1_";
export const SESSION_MEMBERSHIP_INDEX_PREFIX = "smi1_";

export function buildOpaqueSessionParticipantIndexKey(
  prefix: string,
  sessionIdRaw: string,
  publicKeyRaw: string,
): string {
  const sessionId = String(sessionIdRaw || "").trim();
  const publicKey = String(publicKeyRaw || "").trim();
  if (!prefix || !sessionId || !publicKey) return "";
  return `${prefix}${deriveOpaqueIndex(prefix, sessionId, publicKey)}`;
}

export function matchesOpaqueKeyIndex(indexValue: string | undefined, publicKey: string): boolean {
  const expected = buildOpaqueKeyReputationIndexScoped(String(publicKey || "").trim());
  if (!expected) return false;
  const current = String(indexValue || "").trim();
  return current ? current === expected : false;
}

export function isStrictEncryptedEnvelope(payload: string): boolean {
  return isWellFormedStrictEncryptedEnvelope(payload, STRICT_PQ_MODE);
}

function decodeBase64Length(value: string): number {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.length > 1024 * 1024) return -1;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized) || normalized.length % 4 === 1) return -1;
  try {
    return Buffer.from(normalized, "base64").length;
  } catch {
    return -1;
  }
}

export function isWellFormedStrictEncryptedEnvelope(payload: string, strictPqMode = STRICT_PQ_MODE): boolean {
  const value = String(payload || "").trim();
  const parts = value.split(":");
  const kind = parts[0];
  if (strictPqMode && kind !== "v9pq") return false;
  if (kind !== "v8r" && kind !== "v9pq") return false;
  if ((kind === "v8r" && parts.length !== 4) || (kind === "v9pq" && parts.length !== 5)) return false;

  const counter = Number(parts[1]);
  if (!Number.isSafeInteger(counter) || counter < 0) return false;

  if (kind === "v8r") {
    const ivLen = decodeBase64Length(parts[2]);
    const ctLen = decodeBase64Length(parts[3]);
    return ivLen === 12 && ctLen >= 16;
  }

  const pqNonceLen = decodeBase64Length(parts[2]);
  const ivLen = decodeBase64Length(parts[3]);
  const ctLen = decodeBase64Length(parts[4]);
  return pqNonceLen >= 16 && pqNonceLen <= 64 && ivLen === 12 && ctLen >= 16;
}

export function stableIndexFromSeed(seed: string, length: number): number {
  if (length <= 1) return 0;
  const digestHex = deriveOpaqueIndex("stable-index", seed);
  return (Number.parseInt(digestHex.slice(0, 8), 16) >>> 0) % length;
}

export function sanitizeStoredFeedbackReactionActor(actor: string): string {
  const normalized = String(actor || "").trim();
  if (!normalized) return "";
  if (normalized.startsWith("pfr1_")) return normalized;
  return `pfr1_${deriveOpaqueIndex("public-feedback-reaction", normalized)}`;
}
