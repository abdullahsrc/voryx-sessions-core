import type {
  ChatMessage,
  DashboardStats,
  EphemeralKey,
  KeyPermission,
  MatchRequest,
  Node,
  Session,
  SystemEvent,
  Task,
} from "@shared/schema";
import type { CreateSessionTaskInput } from "./session-task-store";
import type { PublicFeedbackView } from "./public-feedback-store";
import type {
  BlockEnforcementResult,
  KeyFeedbackEntry,
  KeyFeedbackSummary,
  KeyFeedbackVote,
  PublicFeedbackReaction,
  SecurityAuditRecord,
  SessionJoinRequest,
  SessionMessageMeta,
  SessionParticipantIdentity,
} from "./storage-types";

export interface IStorage {
  getKeys(): Promise<EphemeralKey[]>;
  getKeysByOwner(ownerTag: string): Promise<EphemeralKey[]>;
  getKey(id: string): Promise<EphemeralKey | undefined>;
  getActiveKeyByPublicKey(publicKey: string): Promise<EphemeralKey | undefined>;
  getKeySessionAccessState(publicKey: string): Promise<{
    blocked: boolean;
    reason?: string;
    score: number;
    reportRate: number;
    total: number;
    spamStrikes: number;
  }>;
  noteKeySpam(publicKey: string, amount?: number): Promise<{
    blocked: boolean;
    reason?: string;
    score: number;
    reportRate: number;
    total: number;
    spamStrikes: number;
  }>;
  createKey(
    ttlMinutes: number,
    permissions: KeyPermission[],
    label?: string,
    domain?: string,
    provided?: { publicKey?: string; kxPublicKey?: string },
    ownerTag?: string,
  ): Promise<{ key: EphemeralKey }>;
  extendKey(id: string): Promise<EphemeralKey | undefined>;
  killKey(id: string): Promise<boolean>;
  getKeyOwner(id: string): Promise<string | undefined>;
  getBlockedTargets(blockerPublicKey: string): Promise<string[]>;
  setKeyBlock(blockerPublicKey: string, targetPublicKey: string, blocked: boolean): Promise<boolean>;
  setKeyBlockByPeerId(
    blockerKeyId: string,
    sessionId: string,
    targetPeerId: string,
    blocked: boolean,
  ): Promise<{
    targetPeerId: string;
    blocked: boolean;
    blockedPublicKeys: string[];
    enforcement: BlockEnforcementResult[];
  }>;
  enforceBlockRelationship(blockerPublicKey: string, targetPublicKey: string): Promise<BlockEnforcementResult[]>;
  isKeyBlocked(blockerPublicKey: string, targetPublicKey: string): Promise<boolean>;
  isKeyBlockedEitherDirection(leftPublicKey: string, rightPublicKey: string): Promise<boolean>;
  getKeyRiskState(publicKey: string): Promise<{
    blocked: boolean;
    reason?: string;
    score: number;
    reportRate: number;
    total: number;
    spamStrikes: number;
    lowScoreWarning: boolean;
    criticalDeactivation: boolean;
  }>;
  removePublicKeyFromAllSessions(publicKey: string): Promise<string[]>;

  getSessions(): Promise<Session[]>;
  getSessionSummary(id: string): Promise<Session | undefined>;
  getSessionsSummary(): Promise<Session[]>;
  getSessionsForOwnerSummary(ownerTag: string): Promise<Session[]>;
  getSessionsForKeySummary(keyId: string): Promise<Session[]>;
  getSessionsForOwner(ownerTag: string): Promise<Session[]>;
  getSessionsForKey(keyId: string): Promise<Session[]>;
  getSession(id: string): Promise<Session | undefined>;
  listSessionParticipantIdentities(sessionId: string): Promise<SessionParticipantIdentity[]>;
  resolveSessionParticipantIdentity(sessionId: string, peerId: string): Promise<SessionParticipantIdentity | undefined>;
  resolveSessionParticipantPublicKey(sessionId: string, peerId: string): Promise<string | undefined>;
  getSessionParticipantPeerId(sessionId: string, publicKey: string): Promise<string | undefined>;
  collectKeyLinkedSessionIds(publicKey: string): Promise<{ creatorSessionIds: string[]; participantSessionIds: string[] }>;
  collectKeyLinkedSessionIdsForKeyId(keyId: string): Promise<{ creatorSessionIds: string[]; participantSessionIds: string[] }>;
  collectPublicKeyMessageIds(publicKey: string): Promise<Record<string, string[]>>;
  getSessionTraceHead(sessionId: string): Promise<{ head: string; messageCount: number }>;
  createSession(
    keyId: string,
    durationMinutes?: number,
    opts?: {
      name?: string;
      domain?: string;
      description?: string;
      maxParticipants?: number;
      isPrivate?: boolean;
    }
  ): Promise<Session>;
  joinSession(sessionId: string, keyId: string, role?: string): Promise<Session | undefined>;
  leaveSession(id: string, publicKey?: string): Promise<Session | undefined>;
  destroySession(id: string): Promise<boolean>;
  deleteSessionDataForParticipant(sessionId: string, publicKey: string): Promise<{
    removedMessages: number;
    removedMessageIds: string[];
    removedTasks: number;
    leftSession: boolean;
  }>;
  terminateSession(id: string): Promise<boolean>;
  removeSessionParticipant(sessionId: string, creatorPublicKey: string, targetPublicKey: string): Promise<{
    session?: Session;
    removedMessageIds: string[];
    removedTasks: number;
  } | undefined>;
  removeSessionParticipantByPeerId(sessionId: string, creatorKeyId: string, targetPeerId: string): Promise<{
    session?: Session;
    targetPeerId: string;
    removedMessageIds: string[];
    removedTasks: number;
  } | undefined>;
  setParticipantWriteBlocked(
    sessionId: string,
    creatorPublicKey: string,
    targetPublicKey: string,
    blocked: boolean,
  ): Promise<boolean>;
  setParticipantWriteBlockedByPeerId(
    sessionId: string,
    creatorKeyId: string,
    targetPeerId: string,
    blocked: boolean,
  ): Promise<{ targetPeerId: string; blocked: boolean; writeBlockedPeerIds: string[] } | undefined>;
  isParticipantWriteBlocked(sessionId: string, publicKey: string): Promise<boolean>;
  getSessionWriteBlockedMap(sessionId: string): Promise<Record<string, boolean>>;
  setSessionPassphrase(
    sessionId: string,
    creatorPublicKey: string,
    payload: { passphraseHash: string; grantedPayload: string }
  ): Promise<boolean>;
  createSessionJoinRequest(sessionId: string, keyId: string): Promise<SessionJoinRequest>;
  listSessionJoinRequests(sessionId: string, creatorPublicKey: string): Promise<SessionJoinRequest[]>;
  respondSessionJoinRequest(
    sessionId: string,
    requestId: string,
    creatorPublicKey: string,
    decision: "approve" | "reject"
  ): Promise<SessionJoinRequest | undefined>;
  getSessionPassphraseState(
    sessionId: string,
    publicKey: string,
  ): Promise<{ hasPassphrase: boolean; hasGrant: boolean; passphrase?: string }>;
  verifySessionPassphraseHash(
    sessionId: string,
    requesterPublicKey: string,
    passphraseHash: string,
  ): Promise<{ hasPassphrase: boolean; verified: boolean }>;
  grantSessionPassphrase(
    sessionId: string,
    creatorPublicKey: string,
    targetPublicKey: string,
    grantedPayload: string
  ): Promise<boolean>;
  grantSessionPassphraseByPeerId(
    sessionId: string,
    creatorKeyId: string,
    targetPeerId: string,
    grantedPayload: string
  ): Promise<{ granted: boolean; targetPeerId: string }>;
  getSessionParticipantKeyExchangeByPeerId(
    sessionId: string,
    requesterKeyId: string,
    targetPeerId: string,
  ): Promise<{ peerId: string; kxPublicKey: string; label: string } | undefined>;
  consumeSessionPassphrase(sessionId: string, publicKey: string): Promise<string | undefined>;
  generateSessionInviteCode(sessionId: string, creatorPublicKey: string): Promise<{ code: string; createdAt: number }>;
  revokeSessionInviteCode(sessionId: string, creatorPublicKey: string): Promise<boolean>;
  joinSessionByInviteCode(sessionId: string, keyId: string, inviteCode: string): Promise<Session | undefined>;

  getMessages(sessionId: string, limit?: number): Promise<ChatMessage[]>;
  getMessageById(messageId: string): Promise<ChatMessage | undefined>;
  addMessage(msg: Omit<ChatMessage, "id" | "timestamp" | "signature">): Promise<ChatMessage>;
  markMessagesRead(
    sessionId: string,
    readerPublicKey: string,
    messageIds: string[],
  ): Promise<Array<{ sessionId: string; messageId: string; deleteAt: number }>>;
  registerMessageDeleteAt(messageId: string, deleteAt: number): boolean;
  deleteMessageBySystem(messageId: string): Promise<ChatMessage | undefined>;
  updateMessage(messageId: string, senderPublicKey: string, content: string): Promise<ChatMessage | undefined>;
  deleteMessage(messageId: string, requesterPublicKey: string): Promise<ChatMessage | undefined>;
  getMessageDeleteEvents(
    sessionId: string,
    sinceTs: number,
    windowStart: number,
    windowEnd: number,
    limit: number,
  ): Promise<Array<{ id: string; ts: number }>>;
  getSessionMessageMeta(sessionId: string, requesterPublicKey?: string): Promise<SessionMessageMeta>;
  toggleMessageStar(messageId: string, requesterPublicKey: string): Promise<SessionMessageMeta>;
  toggleMessagePin(messageId: string, requesterPublicKey: string): Promise<SessionMessageMeta>;

  getTasks(sessionId: string): Promise<Task[]>;
  getTask(id: string): Promise<Task | undefined>;
  createTask(data: CreateSessionTaskInput): Promise<Task>;
  updateTask(id: string, updates: Partial<Task>): Promise<Task | undefined>;
  deleteTask(id: string): Promise<Task | undefined>;

  getNodes(): Promise<Node[]>;
  getNode(id: string): Promise<Node | undefined>;

  getEvents(limit?: number): Promise<SystemEvent[]>;
  addEvent(type: SystemEvent["type"], nodeId: string, data?: Record<string, unknown>): Promise<SystemEvent>;
  getSecurityAudit(limit?: number): Promise<SecurityAuditRecord[]>;
  verifySecurityAuditTrail(): Promise<{
    valid: boolean;
    head: string;
    count: number;
    brokenAtId?: string;
  }>;

  getMatchRequests(): Promise<MatchRequest[]>;
  createMatchRequest(keyId: string): Promise<MatchRequest>;
  cancelMatchRequest(id: string): Promise<boolean>;

  getStats(): Promise<DashboardStats>;
  getStatsForOwner(ownerTag: string): Promise<DashboardStats>;

  killAll(): Promise<void>;
  listFeedbackCandidates(raterPublicKey: string): Promise<Array<{
    candidateId: string;
    label?: string;
    sessions: Array<{ sessionId: string; domain?: string; targetPeerId: string }>;
    reputation: { score: number; approveRate: number; reportRate: number };
  }>>;
  submitKeyFeedback(data: {
    raterPublicKey: string;
    targetPublicKey: string;
    sessionId: string;
    vote: KeyFeedbackVote;
  }): Promise<KeyFeedbackEntry>;
  submitKeyFeedbackByPeerId(data: {
    raterKeyId: string;
    targetPeerId: string;
    sessionId: string;
    vote: KeyFeedbackVote;
  }): Promise<KeyFeedbackEntry>;
  getKeyFeedbackSummary(publicKey?: string): Promise<KeyFeedbackSummary[]>;
  listPublicFeedback(): Promise<PublicFeedbackView[]>;
  addPublicFeedback(message: string): Promise<PublicFeedbackView>;
  reactPublicFeedback(
    id: string,
    clientId: string,
    reaction: PublicFeedbackReaction,
  ): Promise<PublicFeedbackView | undefined>;
}

export interface StorageControlPlane {
  killOwnerData(ownerTag: string): Promise<unknown>;
  getDeletionCertificate(certificateId: string): unknown;
  getReputationScore(publicKey?: string): unknown;
  getReputationLedger(publicKey?: string): unknown;
  createReputationAttestation(data: {
    attesterPublicKey: string;
    subjectPublicKey: string;
    context: "session" | "task" | "manual";
    domain?: string;
    note?: string;
  }): unknown;
  respondReputationAttestation(
    id: string,
    responderPublicKey: string,
    decision: "approve" | "reject",
  ): unknown;
  createReputationTransfer(data: { fromPublicKey: string; toPublicKey: string; requestedByPublicKey: string }): unknown;
  respondReputationTransfer(id: string, responderPublicKey: string, decision: "approve" | "reject"): unknown;
  exportSnapshot(): unknown;
  exportRuntimeSnapshot(): unknown;
  importSnapshot(snapshot: unknown): void;
  importRuntimeSnapshot(snapshot: unknown): void;
}
