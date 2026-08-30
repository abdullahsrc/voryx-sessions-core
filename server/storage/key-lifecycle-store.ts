import { randomUUID } from "crypto";
import type { ChatMessage, EphemeralKey, KeyPermission, Session, Task } from "@shared/schema";
import { buildExpiredKeySessionLifecycleEventScoped } from "./session-lifecycle-store";
import type { KeyPurgeLifecyclePayload } from "./storage-types";

type CreateKeyParams = {
  ttlMinutes: number;
  permissions: KeyPermission[];
  label?: string;
  domain?: string;
  provided?: { publicKey?: string; kxPublicKey?: string };
  ownerTag?: string;
  allowNonExpiring: boolean;
};

type CreateKeyContext = {
  keys: Map<string, EphemeralKey>;
  keyOwners: Map<string, string>;
  keyLastSeenAt: Map<string, number>;
  isLabelReservedByExistingKey: (label?: string, excludeKeyId?: string) => boolean;
  pickNodeBySeed: (type: "session" | "bootstrap" | "relay" | "proof" | "policy", seed: string) => { id: string } | undefined;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
};

type ExtendKeyContext = {
  keys: Map<string, EphemeralKey>;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
};

type KillKeyContext = {
  keys: Map<string, EphemeralKey>;
  keyOwners: Map<string, string>;
  keyLastSeenAt: Map<string, number>;
  purgePublicKeyData: (publicKey: string, keyIds?: Set<string>, reason?: KeyPurgeLifecyclePayload["reason"]) => void;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
};

type DeleteExpiredKeyContext = {
  sessions: Map<string, Session>;
  keys: Map<string, EphemeralKey>;
  keyOwners: Map<string, string>;
  keyLastSeenAt: Map<string, number>;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  getSessionCreatorPublicKey: (session: Session) => string | undefined;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  purgePublicKeyData: (publicKey: string, keyIds?: Set<string>, reason?: KeyPurgeLifecyclePayload["reason"]) => void;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
};

export function getKeysSorted(keys: Map<string, EphemeralKey>): EphemeralKey[] {
  return Array.from(keys.values()).sort((a, b) => b.createdAt - a.createdAt);
}

export function normalizeKeyLabelScoped(label?: string): string {
  return (label || "").trim().toLowerCase();
}

export function isLabelReservedByExistingKeyScoped(params: {
  keys: Map<string, EphemeralKey>;
  label?: string;
  excludeKeyId?: string;
  now?: number;
}): boolean {
  const normalized = normalizeKeyLabelScoped(params.label);
  if (!normalized) return false;
  const now = params.now ?? Date.now();
  for (const key of params.keys.values()) {
    if (params.excludeKeyId && key.id === params.excludeKeyId) continue;
    // Username is reserved only by active, non-expired keys.
    if (!key.isActive) continue;
    if (Number(key.expiresAt || 0) <= now) continue;
    if (normalizeKeyLabelScoped(key.label) === normalized) {
      return true;
    }
  }
  return false;
}

export function expireAllKeysScoped(keys: Map<string, EphemeralKey>): void {
  keys.forEach((key) => {
    key.isActive = false;
    key.expiresAt = Date.now();
  });
}

export function getActiveKeyByPublicKeyScoped(
  keys: Map<string, EphemeralKey>,
  publicKey: string,
): EphemeralKey | undefined {
  for (const key of keys.values()) {
    if (key.isActive && key.publicKey === publicKey) {
      return { ...key };
    }
  }
  return undefined;
}

export function findActiveKeyByPublicKeyScoped(
  keys: Iterable<EphemeralKey>,
  publicKey: string,
): EphemeralKey | undefined {
  for (const key of keys) {
    if (key.isActive && key.publicKey === publicKey) return key;
  }
  return undefined;
}

export function findAnyKeyByPublicKeyScoped(
  keys: Iterable<EphemeralKey>,
  publicKey: string,
): EphemeralKey | undefined {
  for (const key of keys) {
    if (key.publicKey === publicKey) return key;
  }
  return undefined;
}

export function createAnyKeyIdByPublicKeyResolverScoped(params: {
  keys: Map<string, EphemeralKey>;
}): (publicKey: string) => string | undefined {
  return (publicKey) => findAnyKeyByPublicKeyScoped(params.keys.values(), publicKey)?.id;
}

export function isKeyCurrentlyActiveByPublicKeyScoped(params: {
  keys: Iterable<EphemeralKey>;
  publicKey: string;
  now?: number;
}): boolean {
  const now = params.now ?? Date.now();
  for (const key of params.keys) {
    if (key.publicKey !== params.publicKey) continue;
    if (key.isActive && key.expiresAt > now) return true;
  }
  return false;
}

export function createPublicKeyActivityResolverScoped(params: {
  keys: Map<string, EphemeralKey>;
}): (publicKey: string) => boolean {
  return (publicKey) =>
    isKeyCurrentlyActiveByPublicKeyScoped({
      keys: params.keys.values(),
      publicKey,
    });
}

export function getActivePublicKeyForKeyIdOrThrowScoped(params: {
  keys: Map<string, EphemeralKey>;
  keyIdRaw: string;
  normalizePublicKey: (value: string) => string;
}): string {
  const keyId = String(params.keyIdRaw || "").trim();
  const key = keyId ? params.keys.get(keyId) : undefined;
  const publicKey = params.normalizePublicKey(String(key?.publicKey || ""));
  if (!key || !key.isActive || !publicKey) throw new Error("Invalid or inactive key");
  return publicKey;
}

export function createActivePublicKeyForKeyIdResolverScoped(params: {
  keys: Map<string, EphemeralKey>;
  normalizePublicKey: (value: string) => string;
}): (keyIdRaw: string) => string {
  return (keyIdRaw) =>
    getActivePublicKeyForKeyIdOrThrowScoped({
      keys: params.keys,
      keyIdRaw,
      normalizePublicKey: params.normalizePublicKey,
    });
}

export function touchKeyActivityScoped(params: {
  keys: Map<string, EphemeralKey>;
  keyLastSeenAt: Map<string, number>;
  keyId: string;
  now?: number;
}): void {
  const normalized = String(params.keyId || "").trim();
  if (!normalized) return;
  const key = params.keys.get(normalized);
  if (!key || !key.isActive) return;
  params.keyLastSeenAt.set(normalized, params.now ?? Date.now());
}

export function getKeysByOwnerScoped(
  keys: Map<string, EphemeralKey>,
  keyOwners: Map<string, string>,
  ownerTag: string,
): EphemeralKey[] {
  const normalizedOwner = String(ownerTag || "").trim();
  if (!normalizedOwner) return [];
  const scoped = Array.from(keys.values())
    .filter((key) => keyOwners.get(key.id) === normalizedOwner)
    .sort((a, b) => b.createdAt - a.createdAt);
  if (scoped.length > 0) return scoped;
  const key = keys.get(normalizedOwner);
  return key ? [key] : [];
}

export function getKeyOwnerScoped(
  keys: Map<string, EphemeralKey>,
  keyOwners: Map<string, string>,
  id: string,
): string | undefined {
  const normalized = String(id || "").trim();
  if (!normalized) return undefined;
  return keyOwners.get(normalized) || (keys.has(normalized) ? normalized : undefined);
}

export function getOwnerKeyIdsScoped(keyOwners: Map<string, string>, ownerTag: string): string[] {
  const normalizedOwner = String(ownerTag || "").trim();
  if (!normalizedOwner) return [];
  return Array.from(keyOwners.entries())
    .filter(([, tag]) => String(tag || "").trim() === normalizedOwner)
    .map(([keyId]) => keyId);
}

export function groupKeyIdsByPublicKeyScoped(
  keys: Map<string, EphemeralKey>,
  keyIds: string[],
): { publicKeys: Set<string>; keyIdsByPublicKey: Map<string, Set<string>> } {
  const publicKeys = new Set<string>();
  const keyIdsByPublicKey = new Map<string, Set<string>>();
  for (const keyId of keyIds) {
    const key = keys.get(keyId);
    if (!key) continue;
    publicKeys.add(key.publicKey);
    if (!keyIdsByPublicKey.has(key.publicKey)) keyIdsByPublicKey.set(key.publicKey, new Set());
    keyIdsByPublicKey.get(key.publicKey)!.add(keyId);
  }
  return { publicKeys, keyIdsByPublicKey };
}

export function deleteKeyRuntimeMetadataScoped(params: {
  keys: Map<string, EphemeralKey>;
  keyOwners: Map<string, string>;
  keyLastSeenAt: Map<string, number>;
  keyIds: Iterable<string>;
}): void {
  for (const keyId of params.keyIds) {
    params.keys.delete(keyId);
    params.keyOwners.delete(keyId);
    params.keyLastSeenAt.delete(keyId);
  }
}

export function purgePublicKeyLinkedStoresScoped(params: {
  publicKey: string;
  normalizedPublicKey: string;
  keyIds: Set<string>;
  normalizePublicKey: (value: string) => string;
  purgeTasks: (publicKey: string, normalizePublicKey: (value: string) => string) => unknown;
  purgeReputation: (publicKey: string) => void;
  purgeKeyFeedback: (publicKey: string) => void;
  purgeKeyTrust: (publicKey: string) => void;
  purgeJoinRequests: (publicKey: string, keyIds: Set<string>) => void;
  deletePassphraseGrants: (publicKey: string) => void;
  purgeSessionModeration: (publicKey: string) => void;
  purgeMatchRequestKeyIds: (keyIds: Set<string>) => void;
}): void {
  params.purgeTasks(params.normalizedPublicKey, params.normalizePublicKey);

  params.purgeReputation(params.publicKey);
  params.purgeKeyFeedback(params.publicKey);
  params.purgeKeyTrust(params.publicKey);

  params.purgeJoinRequests(params.publicKey, params.keyIds);
  params.deletePassphraseGrants(params.publicKey);
  params.purgeSessionModeration(params.publicKey);

  params.purgeMatchRequestKeyIds(params.keyIds);
}

export function shouldKeepEventAfterPublicKeyPurgeScoped(params: {
  event: { data?: Record<string, unknown> } | undefined;
  publicKey: string;
  keyIds: Set<string>;
  creatorSessionIds: Set<string>;
  matchesSanitizedAuditValue: (value: unknown, raw: string) => boolean;
}): boolean {
  const data = params.event?.data || {};
  const eventKeyId = String((data as any).keyId || "").trim();
  const eventPublicKey = (data as any).publicKey;
  const eventSessionId = String((data as any).sessionId || "").trim();
  if (params.matchesSanitizedAuditValue(eventPublicKey, params.publicKey)) return false;
  if (eventKeyId && params.keyIds.has(eventKeyId)) return false;
  if (eventSessionId && params.creatorSessionIds.has(eventSessionId)) return false;
  return true;
}

export function collectInactiveKeyIdsScoped(params: {
  keys: Map<string, EphemeralKey>;
  keyLastSeenAt: Map<string, number>;
  now: number;
  maxIdleMs: number;
}): string[] {
  const staleIds: string[] = [];
  for (const [keyId, key] of params.keys.entries()) {
    if (!key.isActive) continue;
    const lastSeen = Number(params.keyLastSeenAt.get(keyId) || key.createdAt || params.now);
    if (params.now - lastSeen > params.maxIdleMs) {
      staleIds.push(keyId);
    }
  }
  return staleIds;
}

export function collectExpiredKeyIdsScoped(keys: Map<string, EphemeralKey>, now: number): string[] {
  const expiredIds: string[] = [];
  for (const [keyId, key] of keys.entries()) {
    if (key.expiresAt <= now) {
      expiredIds.push(keyId);
    }
  }
  return expiredIds;
}

export function buildKeyExpiredEventPayloadScoped(keyId: string) {
  return { keyId };
}

export function buildKeyKilledDeleteMyDataEventPayloadScoped() {
  return { reason: "delete_my_data" };
}

export function deleteExpiredKeyCompletelyScoped(ctx: DeleteExpiredKeyContext, keyId: string, publicKey: string): void {
  const normalizedPublicKey = String(publicKey || "").trim();
  if (!normalizedPublicKey) return;
  const keyIds = new Set<string>([String(keyId || "").trim()].filter(Boolean));
  for (const session of Array.from(ctx.sessions.values())) {
    const isCreator = ctx.getSessionCreatorPublicKey(session) === normalizedPublicKey;
    if (!ctx.hasSessionParticipant(session, normalizedPublicKey) && !isCreator) continue;
    const event = buildExpiredKeySessionLifecycleEventScoped({
      session,
      keyId,
      isCreator,
      peerId: isCreator ? undefined : ctx.getParticipantPeerId(session.id, normalizedPublicKey),
    });
    ctx.addEvent(event.type, event.nodeId, event.data);
  }
  ctx.purgePublicKeyData(normalizedPublicKey, keyIds, "expired");
  deleteKeyRuntimeMetadataScoped({
    keys: ctx.keys,
    keyOwners: ctx.keyOwners,
    keyLastSeenAt: ctx.keyLastSeenAt,
    keyIds,
  });
}

export function cleanupExpiredKeysScoped(ctx: DeleteExpiredKeyContext, now: number): void {
  collectExpiredKeyIdsScoped(ctx.keys, now).forEach((id) => {
    const key = ctx.keys.get(id);
    if (!key) return;
    key.isActive = false;
    ctx.addEvent("key.expired", key.nodeId || "system", buildKeyExpiredEventPayloadScoped(id));
    deleteExpiredKeyCompletelyScoped(ctx, id, key.publicKey);
  });
}

export function cleanupInactiveKeysScoped(params: {
  keys: Map<string, EphemeralKey>;
  keyLastSeenAt: Map<string, number>;
  now: number;
  maxIdleMs: number;
  killKey: (keyId: string) => Promise<unknown>;
}): void {
  collectInactiveKeyIdsScoped({
    keys: params.keys,
    keyLastSeenAt: params.keyLastSeenAt,
    now: params.now,
    maxIdleMs: params.maxIdleMs,
  }).forEach((keyId) => {
    void params.killKey(keyId);
  });
}

export function buildKeyPurgeLifecyclePayloadScoped(params: {
  publicKey: string;
  keyIds: Set<string>;
  reason?: KeyPurgeLifecyclePayload["reason"];
  creatorSessionIds: Set<string>;
  participantSessionIds: Set<string>;
  removedMessageIdsBySession: Map<string, Set<string>>;
}): KeyPurgeLifecyclePayload {
  const removedMessagesRecord: Record<string, string[]> = {};
  params.removedMessageIdsBySession.forEach((removedIds, sessionId) => {
    removedMessagesRecord[sessionId] = Array.from(removedIds);
  });
  return {
    publicKey: params.publicKey,
    keyIds: Array.from(params.keyIds).map((id) => String(id || "").trim()).filter(Boolean),
    reason: params.reason || "removed",
    creatorSessionIds: Array.from(params.creatorSessionIds),
    participantSessionIds: Array.from(params.participantSessionIds).filter((sid) => !params.creatorSessionIds.has(sid)),
    removedMessageIdsBySession: removedMessagesRecord,
  };
}

export function countUserArtifactsScoped(params: {
  publicKey: string;
  keys: Iterable<EphemeralKey>;
  sessions: Iterable<Session>;
  messages: Iterable<ChatMessage[]>;
  tasks: Iterable<Task>;
  normalizePublicKey: (value: string) => string;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  countFeedbackReferences: (publicKey: string) => number;
}): number {
  const normalized = params.normalizePublicKey(params.publicKey);
  if (!normalized) return 0;
  let count = 0;
  for (const key of params.keys) {
    if (params.normalizePublicKey(key.publicKey) === normalized) count += 1;
  }
  for (const session of params.sessions) {
    if (params.hasSessionParticipant(session, normalized)) count += 1;
  }
  for (const msgs of params.messages) {
    for (const message of msgs) {
      if (params.normalizePublicKey(message.senderPublicKey) === normalized) count += 1;
    }
  }
  for (const task of params.tasks) {
    if (
      params.normalizePublicKey(task.createdByPublicKey) === normalized ||
      params.normalizePublicKey(String(task.assignedToPublicKey || "")) === normalized
    ) {
      count += 1;
    }
  }
  return count + params.countFeedbackReferences(normalized);
}

export function countOwnerArtifactsScoped(params: {
  keyOwners: Map<string, string>;
  ownerTag: string;
}): number {
  const normalizedOwner = String(params.ownerTag || "").trim();
  if (!normalizedOwner) return 0;
  return getOwnerKeyIdsScoped(params.keyOwners, normalizedOwner).length;
}

export async function createKeyScoped(ctx: CreateKeyContext, params: CreateKeyParams): Promise<{ key: EphemeralKey }> {
  const trimmedLabel = params.label?.trim();
  if (trimmedLabel && ctx.isLabelReservedByExistingKey(trimmedLabel)) {
    throw new Error("Username is already used by an existing key");
  }

  const providedPublicKey = String(params.provided?.publicKey || "").trim().toLowerCase();
  const providedKxPublicKey = String(params.provided?.kxPublicKey || "").trim().toLowerCase();
  if (!providedPublicKey || !providedKxPublicKey) {
    throw new Error("Client key material required");
  }
  const publicKey = providedPublicKey;
  const kxPublicKey = providedKxPublicKey;
  const normalizedTtlMinutes = Math.max(0, Math.floor(Number(params.ttlMinutes) || 0));
  if (!params.allowNonExpiring && normalizedTtlMinutes <= 0) {
    throw new Error("Non-expiring keys are disabled by security policy");
  }
  const now = Date.now();
  const ttlMs = normalizedTtlMinutes <= 0 ? Number.MAX_SAFE_INTEGER - now : normalizedTtlMinutes * 60 * 1000;
  const assignedNode = ctx.pickNodeBySeed("session", publicKey);

  const key: EphemeralKey = {
    id: randomUUID(),
    publicKey,
    kxPublicKey,
    permissions: params.permissions,
    ttl: normalizedTtlMinutes * 60,
    createdAt: now,
    expiresAt: now + ttlMs,
    isActive: true,
    nodeId: assignedNode?.id,
    label: trimmedLabel,
    domain: String(params.domain || "").trim() || undefined,
  };

  const normalizedOwnerTag = String(params.ownerTag || "").trim() || key.id;
  ctx.keys.set(key.id, key);
  ctx.keyOwners.set(key.id, normalizedOwnerTag);
  ctx.keyLastSeenAt.set(key.id, now);
  await ctx.addEvent("key.created", assignedNode?.id || "system", { keyId: key.id });
  return { key };
}

export async function extendKeyScoped(ctx: ExtendKeyContext, id: string): Promise<EphemeralKey | undefined> {
  const key = ctx.keys.get(id);
  if (!key || !key.isActive) return undefined;
  const extension = (key.ttl * 1000) * 0.5;
  key.expiresAt += extension;
  await ctx.addEvent("key.extended", key.nodeId || "system", { keyId: id, extension });
  return key;
}

export async function killKeyScoped(ctx: KillKeyContext, id: string): Promise<boolean> {
  const key = ctx.keys.get(id);
  if (!key) return false;

  ctx.purgePublicKeyData(key.publicKey, new Set([id]), "removed");
  ctx.keys.delete(id);
  ctx.keyOwners.delete(id);
  ctx.keyLastSeenAt.delete(id);
  await ctx.addEvent("key.killed", key.nodeId || "system", { keyId: id, publicKey: key.publicKey });
  return true;
}
