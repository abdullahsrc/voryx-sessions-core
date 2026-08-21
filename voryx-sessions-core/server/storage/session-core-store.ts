import { randomBytes, randomUUID } from "crypto";
import type { EphemeralKey, Participant, Session } from "@shared/schema";
import { deriveCommitment } from "../crypto-primitives";

export type CreateSessionRecordInput = {
  key: EphemeralKey;
  keyId: string;
  creatorKeyExpiresAt: number;
  now: number;
  selectedNodes: string[];
  opts?: {
    name?: string;
    domain?: string;
    description?: string;
    maxParticipants?: number;
    isPrivate?: boolean;
  };
  sessionIdentityMode: Session["sessionIdentityMode"];
};

export function buildSessionCreatorParticipantScoped(
  key: EphemeralKey,
  keyId: string,
  now: number,
): Participant {
  return {
    publicKey: key.publicKey,
    sessionCryptoPublicKey: undefined,
    sessionCryptoKeyId: undefined,
    peerId: undefined,
    label: key.label || "Creator",
    role: "creator",
    joinedAt: now,
    isOnline: true,
    keyId,
    voiceEnabled: false,
  };
}

export function createSessionRecordScoped(input: CreateSessionRecordInput): Session {
  const { key, keyId, creatorKeyExpiresAt, now, selectedNodes, opts, sessionIdentityMode } = input;
  const sessionDurationSeconds = Math.max(1, Math.ceil((creatorKeyExpiresAt - now) / 1000));
  const resolvedMaxParticipants =
    typeof opts?.maxParticipants === "number" && Number.isFinite(opts.maxParticipants) && opts.maxParticipants > 0
      ? Math.floor(opts.maxParticipants)
      : Number.MAX_SAFE_INTEGER;

  return {
    id: randomUUID(),
    participants: [key.publicKey],
    participantPeerIds: [],
    sessionIdentityMode,
    creatorPeerId: undefined,
    participantCount: 1,
    participantDetails: [buildSessionCreatorParticipantScoped(key, keyId, now)],
    status: "active",
    startTime: now,
    duration: sessionDurationSeconds,
    expiresAt: creatorKeyExpiresAt,
    nodeIds: selectedNodes,
    name: String(opts?.name || "").trim() || undefined,
    domain: opts?.domain,
    description: opts?.description,
    maxParticipants: resolvedMaxParticipants,
    isPrivate: Boolean(opts?.isPrivate ?? false),
    encryptionPublicKey: deriveCommitment("session-encryption-public", randomBytes(32).toString("hex")),
    voiceChannelActive: false,
  };
}

export function assertCreateSessionCreatorKeyAllowedScoped(params: {
  key: EphemeralKey | undefined;
  getKeySessionAccessDecision: (publicKey: string) => { blocked: boolean; reason?: string };
  now: number;
}): { key: EphemeralKey; creatorKeyExpiresAt: number } {
  const { key } = params;
  if (!key || !key.isActive) throw new Error("Invalid or inactive key");
  const access = params.getKeySessionAccessDecision(key.publicKey);
  if (access.blocked) throw new Error(access.reason || "Key is blocked from session access");

  const creatorKeyExpiresAt = Number(key.expiresAt || 0);
  if (!Number.isFinite(creatorKeyExpiresAt) || creatorKeyExpiresAt <= params.now) {
    throw new Error("Creator key has expired");
  }
  return { key, creatorKeyExpiresAt };
}

export function initializeCreatedSessionCreatorIdentityScoped(params: {
  session: Session;
  creatorPublicKey: string;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
}): void {
  const creatorParticipant = params.session.participantDetails?.[0];
  if (creatorParticipant) {
    creatorParticipant.peerId = params.getParticipantPeerId(params.session.id, params.creatorPublicKey);
  }
  params.ensureSessionPeerIndex(params.session);
}

export type BuildJoinParticipantInput = {
  key: EphemeralKey;
  keyId: string;
  role: string;
  participantCount: number;
  peerId?: string;
  now: number;
};

export function buildSessionJoinParticipantScoped(input: BuildJoinParticipantInput): Participant {
  const { key, keyId, role, participantCount, peerId, now } = input;
  return {
    publicKey: key.publicKey,
    sessionCryptoPublicKey: undefined,
    sessionCryptoKeyId: undefined,
    peerId,
    label: key.label || `Participant ${participantCount + 1}`,
    role: role as Participant["role"],
    joinedAt: now,
    isOnline: true,
    keyId,
    voiceEnabled: false,
  };
}

export function addSessionParticipantScoped(session: Session, participant: Participant): void {
  if (!session.participantDetails) session.participantDetails = [];
  session.participantDetails.push(participant);
}

export function buildSessionStartedSystemMessageScoped(session: Session) {
  return {
    sessionId: session.id,
    senderPublicKey: "system",
    senderLabel: "System",
    type: "system" as const,
    content: `Session started. Visibility: ${session.isPrivate ? "Private" : "Public"}. E2E encrypted.`,
    edited: false,
  };
}

export function buildSessionParticipantJoinedSystemMessageScoped(sessionId: string) {
  return {
    sessionId,
    senderPublicKey: "system",
    senderLabel: "System",
    type: "system" as const,
    content: "A participant joined the session.",
    edited: false,
  };
}

export async function joinSessionForStorageScoped(params: {
  sessionId: string;
  keyId: string;
  role: string;
  session: Session | undefined;
  key: EphemeralKey | undefined;
  getKeySessionAccessDecision: (publicKey: string) => { blocked: boolean; reason?: string };
  ensureReentryAllowed: (sessionId: string, publicKey: string) => void;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  getSessionParticipantCount: (session: Session) => number;
  getSessionParticipantPublicKeys: (session: Session) => string[];
  ensureNoBlockConflict: (publicKey: string, sessionPublicKeys: string[]) => void;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string;
  addSessionParticipant: (session: Session, participant: Participant) => void;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
  addMessage: (message: ReturnType<typeof buildSessionParticipantJoinedSystemMessageScoped>) => Promise<unknown>;
  now?: number;
}): Promise<Session | undefined> {
  const { session, key } = params;
  if (!session || !key || !key.isActive) return undefined;
  const access = params.getKeySessionAccessDecision(key.publicKey);
  if (access.blocked) throw new Error(access.reason || "Key is blocked from session access");
  if (session.status !== "active" && session.status !== "expiring_soon") return undefined;
  params.ensureReentryAllowed(params.sessionId, key.publicKey);
  if (params.hasSessionParticipant(session, key.publicKey)) return session;
  if (params.getSessionParticipantCount(session) >= session.maxParticipants) return undefined;
  params.ensureNoBlockConflict(key.publicKey, params.getSessionParticipantPublicKeys(session));

  const participant = buildSessionJoinParticipantScoped({
    key,
    keyId: params.keyId,
    role: params.role,
    participantCount: params.getSessionParticipantCount(session),
    peerId: params.getParticipantPeerId(params.sessionId, key.publicKey),
    now: params.now ?? Date.now(),
  });

  params.addSessionParticipant(session, participant);
  params.ensureSessionPeerIndex(session);

  await params.addEvent("session.joined", session.nodeIds[0] || "system", buildSessionJoinedEventPayloadScoped({
    sessionId: params.sessionId,
    peerId: params.getParticipantPeerId(params.sessionId, key.publicKey),
  }));

  await params.addMessage(buildSessionParticipantJoinedSystemMessageScoped(params.sessionId));

  return session;
}

export function buildSessionCreatedEventPayloadScoped(session: Session) {
  return {
    sessionId: session.id,
    visibility: session.isPrivate ? "private" : "public",
  };
}

export async function finalizeCreatedSessionForStorageScoped(params: {
  session: Session;
  sessions: Map<string, Session>;
  selectedNodes: string[];
  ensureMessageSession: (sessionId: string) => void;
  incrementNodeActiveSessions: (nodeId: string) => void;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
  addMessage: (message: ReturnType<typeof buildSessionStartedSystemMessageScoped>) => Promise<unknown>;
}): Promise<void> {
  params.sessions.set(params.session.id, params.session);
  params.ensureMessageSession(params.session.id);

  params.selectedNodes.forEach((nodeId) => {
    params.incrementNodeActiveSessions(nodeId);
  });

  await params.addEvent(
    "session.created",
    params.selectedNodes[0] || "system",
    buildSessionCreatedEventPayloadScoped(params.session),
  );

  await params.addMessage(buildSessionStartedSystemMessageScoped(params.session));
}

export function buildSessionJoinedEventPayloadScoped(params: {
  sessionId: string;
  peerId?: string;
}) {
  return {
    sessionId: params.sessionId,
    peerId: params.peerId,
  };
}

export function buildSessionLeftEventPayloadScoped(params: {
  sessionId: string;
  peerId?: string;
}) {
  return {
    sessionId: params.sessionId,
    peerId: params.peerId,
  };
}

export async function leaveSessionForStorageScoped(params: {
  sessionId: string;
  publicKey?: string;
  session: Session | undefined;
  blockReentry: (sessionId: string, publicKey: string) => void;
  removeSessionParticipant: (session: Session, publicKey: string) => void;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
  clearWriteBlocked: (sessionId: string, publicKey: string) => void;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
}): Promise<Session | undefined> {
  const { session } = params;
  if (!session) return undefined;

  if (params.publicKey) {
    params.blockReentry(params.sessionId, params.publicKey);
    params.removeSessionParticipant(session, params.publicKey);
    params.ensureSessionPeerIndex(session);
    params.clearWriteBlocked(params.sessionId, params.publicKey);
  }

  await params.addEvent("session.left", session.nodeIds[0] || "system", buildSessionLeftEventPayloadScoped({
    sessionId: params.sessionId,
    peerId: params.publicKey ? params.getParticipantPeerId(params.sessionId, params.publicKey) : undefined,
  }));
  return session;
}

export function deleteSessionsCreatedByPublicKeyScoped(params: {
  sessions: Map<string, Session>;
  publicKey: string;
  getSessionCreatorPublicKey: (session: Session) => string | undefined;
  deleteSessionCompletely: (sessionId: string) => void;
}): Set<string> {
  const createdSessionIds = Array.from(params.sessions.values())
    .filter((session) => params.getSessionCreatorPublicKey(session) === params.publicKey)
    .map((session) => session.id);

  createdSessionIds.forEach((sessionId) => params.deleteSessionCompletely(sessionId));
  return new Set(createdSessionIds);
}

export function removeSessionParticipantScoped(
  session: Session,
  publicKeyRaw: string,
  normalizePublicKey: (value: string) => string,
): void {
  const publicKey = normalizePublicKey(publicKeyRaw);
  if (!publicKey) return;
  if (session.participantDetails) {
    session.participantDetails = session.participantDetails.filter((participant) =>
      normalizePublicKey(String(participant?.publicKey || "")) !== publicKey,
    );
  }
  session.participants = session.participants.filter((participantPublicKey) =>
    normalizePublicKey(participantPublicKey) !== publicKey,
  );
}

export function removePublicKeyFromSessionsScoped(params: {
  sessions: Map<string, Session>;
  publicKey: string;
  normalizePublicKey: (value: string) => string;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
  getSessionParticipantCount: (session: Session) => number;
}): Set<string> {
  const participantSessionIds = new Set<string>();
  params.sessions.forEach((session) => {
    const wasParticipant = params.hasSessionParticipant(session, params.publicKey);
    removeSessionParticipantScoped(session, params.publicKey, params.normalizePublicKey);
    if (wasParticipant) participantSessionIds.add(session.id);
    params.ensureSessionPeerIndex(session);
    if (params.getSessionParticipantCount(session) === 0) {
      session.status = "terminated";
    }
  });
  return participantSessionIds;
}
