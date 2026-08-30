import type { ChatMessage, EphemeralKey, Node, Session, SystemEvent } from "@shared/schema";
import {
  clearPurgedMessageTraceHeadsScoped,
  isMessageLinkedToPurgedPublicKeyScoped,
} from "./message-lifecycle-store";
import {
  deleteSessionsCreatedByPublicKeyScoped,
  removePublicKeyFromSessionsScoped,
} from "./session-core-store";
import { deleteSessionLifecycleScoped } from "./session-lifecycle-store";
import {
  buildKeyKilledDeleteMyDataEventPayloadScoped,
  buildKeyPurgeLifecyclePayloadScoped,
  purgePublicKeyLinkedStoresScoped,
  shouldKeepEventAfterPublicKeyPurgeScoped,
} from "./key-lifecycle-store";
import type {
  DeletionCertificate,
  FileArtifactCleanupPayload,
  KeyPurgeLifecyclePayload,
} from "./storage-types";

type SessionDeleteStore = {
  deleteSession(sessionId: string): unknown;
};

type MessageOwnerPurgeStore = {
  purgeByOwner(predicate: (message: ChatMessage, sessionId: string) => boolean): {
    removedBySession: Map<string, Set<string>>;
    emptiedSessionIds: Set<string>;
  };
  purgeRequesterMeta?(publicKey: string): void;
};

type RuntimeAuditPurgeStore = {
  filterEvents(predicate: (event: SystemEvent) => boolean): void;
  resetSecurityAudit(): void;
};

export function purgeDeletedSessionStoresScoped(params: {
  sessionId: string;
  runFileArtifactCleanup: (payload: FileArtifactCleanupPayload) => void;
  messageStore: SessionDeleteStore;
  sessionTraceHeads: Map<string, string>;
  sessionPassphrases: SessionDeleteStore;
  joinRequests: SessionDeleteStore;
  sessionInvites: { delete(sessionId: string): unknown };
  sessionModeration: SessionDeleteStore;
  keyFeedback: { purgeSession(sessionId: string): unknown };
  tasks: SessionDeleteStore;
}): void {
  params.runFileArtifactCleanup({ sessionId: params.sessionId, reason: "session_deleted" });
  params.messageStore.deleteSession(params.sessionId);
  params.sessionTraceHeads.delete(params.sessionId);
  params.sessionPassphrases.deleteSession(params.sessionId);
  params.joinRequests.deleteSession(params.sessionId);
  params.sessionInvites.delete(params.sessionId);
  params.sessionModeration.deleteSession(params.sessionId);
  params.keyFeedback.purgeSession(params.sessionId);
  params.tasks.deleteSession(params.sessionId);
}

export function deleteSessionCompletelyForStorageScoped(params: {
  sessions: Map<string, Session>;
  nodes: Map<string, Node>;
  sessionId: string;
  purgeDeletedSessionStores: (sessionId: string) => void;
}): void {
  const session = deleteSessionLifecycleScoped(params.sessions, params.nodes, params.sessionId);
  if (!session) return;
  params.purgeDeletedSessionStores(params.sessionId);
}

export function createCompleteSessionDeletionRunnerScoped(params: {
  sessions: Map<string, Session>;
  nodes: Map<string, Node>;
  purgeDeletedSessionStores: (sessionId: string) => void;
}): (sessionId: string) => void {
  return (sessionId) =>
    deleteSessionCompletelyForStorageScoped({
      sessions: params.sessions,
      nodes: params.nodes,
      sessionId,
      purgeDeletedSessionStores: params.purgeDeletedSessionStores,
    });
}

export function purgeMessagesLinkedToPublicKeyScoped(params: {
  messageStore: MessageOwnerPurgeStore;
  sessionTraceHeads: Map<string, string>;
  publicKey: string;
  normalizePublicKey: (value: string) => string;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
}): {
  removedMessageIdsBySession: Map<string, Set<string>>;
  emptiedSessionIds: Set<string>;
} {
  const { removedBySession: removedMessageIdsBySession, emptiedSessionIds } = params.messageStore.purgeByOwner(
    (message, sid) => isMessageLinkedToPurgedPublicKeyScoped({
      message,
      sessionId: String(sid || "").trim(),
      publicKey: params.publicKey,
      normalizePublicKey: params.normalizePublicKey,
      getParticipantPeerId: params.getParticipantPeerId,
    }),
  );
  params.messageStore.purgeRequesterMeta?.(params.publicKey);
  clearPurgedMessageTraceHeadsScoped({
    sessionTraceHeads: params.sessionTraceHeads,
    removedMessageIdsBySession,
    emptiedSessionIds,
  });
  return { removedMessageIdsBySession, emptiedSessionIds };
}

export function purgePublicKeySessionMembershipScoped(params: {
  sessions: Map<string, Session>;
  publicKey: string;
  getSessionCreatorPublicKey: (session: Session) => string | undefined;
  deleteSessionCompletely: (sessionId: string) => void;
  runFileArtifactCleanup: (payload: FileArtifactCleanupPayload) => void;
  normalizePublicKey: (value: string) => string;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
  getSessionParticipantCount: (session: Session) => number;
}): {
  deletedCreatorSessionIds: Set<string>;
  participantSessionIds: Set<string>;
} {
  const deletedCreatorSessionIds = deleteSessionsCreatedByPublicKeyScoped({
    sessions: params.sessions,
    publicKey: params.publicKey,
    getSessionCreatorPublicKey: params.getSessionCreatorPublicKey,
    deleteSessionCompletely: params.deleteSessionCompletely,
  });
  params.runFileArtifactCleanup({ publicKey: params.publicKey, reason: "public_key_purged" });

  const participantSessionIds = removePublicKeyFromSessionsScoped({
    sessions: params.sessions,
    publicKey: params.publicKey,
    normalizePublicKey: params.normalizePublicKey,
    hasSessionParticipant: params.hasSessionParticipant,
    ensureSessionPeerIndex: params.ensureSessionPeerIndex,
    getSessionParticipantCount: params.getSessionParticipantCount,
  });

  return { deletedCreatorSessionIds, participantSessionIds };
}

export function purgePublicKeyRuntimeAuditResidueScoped(params: {
  runtimeAudit: RuntimeAuditPurgeStore;
  publicKey: string;
  keyIds: Set<string>;
  deletedCreatorSessionIds: Set<string>;
  matchesSanitizedAuditValue: (value: unknown, raw: string) => boolean;
}): void {
  params.runtimeAudit.filterEvents((event) => shouldKeepEventAfterPublicKeyPurgeScoped({
    event,
    publicKey: params.publicKey,
    keyIds: params.keyIds,
    creatorSessionIds: params.deletedCreatorSessionIds,
    matchesSanitizedAuditValue: params.matchesSanitizedAuditValue,
  }));

  // Audit rows are hash-chained and cannot be safely filtered per subject.
  // Fail closed: wipe the audit trail rather than preserve deletion residue.
  params.runtimeAudit.resetSecurityAudit();
}

export function purgePublicKeyDataScoped(params: {
  publicKey: string;
  keyIds: Set<string>;
  normalizePublicKey: (publicKey: string) => string;
  purgePublicKeySessionMembership: (publicKey: string) => {
    deletedCreatorSessionIds: Set<string>;
    participantSessionIds: Set<string>;
  };
  purgeMessagesLinkedToPublicKey: (publicKey: string) => {
    removedMessageIdsBySession: Map<string, Set<string>>;
  };
  runKeyPurgeLifecycle: (payload: KeyPurgeLifecyclePayload) => void;
  reason?: KeyPurgeLifecyclePayload["reason"];
  purgePublicKeyLinkedStores: (publicKey: string, normalizedPublicKey: string, keyIds: Set<string>) => void;
  purgePublicKeyRuntimeAuditResidue: (
    publicKey: string,
    keyIds: Set<string>,
    deletedCreatorSessionIds: Set<string>,
  ) => void;
}): void {
  const normalizedPublicKey = params.normalizePublicKey(params.publicKey);
  if (!normalizedPublicKey) return;
  // Purge messages before membership removal. Older/minimized messages may only
  // be linkable through the session peer index, which is lost after removal.
  const { removedMessageIdsBySession } = params.purgeMessagesLinkedToPublicKey(normalizedPublicKey);
  const { deletedCreatorSessionIds, participantSessionIds } =
    params.purgePublicKeySessionMembership(normalizedPublicKey);

  params.runKeyPurgeLifecycle(buildKeyPurgeLifecyclePayloadScoped({
    publicKey: normalizedPublicKey,
    keyIds: params.keyIds,
    reason: params.reason,
    creatorSessionIds: deletedCreatorSessionIds,
    participantSessionIds,
    removedMessageIdsBySession,
  }));

  params.purgePublicKeyLinkedStores(params.publicKey, normalizedPublicKey, params.keyIds);
  params.purgePublicKeyRuntimeAuditResidue(params.publicKey, params.keyIds, deletedCreatorSessionIds);
}

export function createPublicKeyDataPurgeRunnerScoped(params: {
  sessions: Map<string, Session>;
  messageStore: MessageOwnerPurgeStore;
  sessionTraceHeads: Map<string, string>;
  runtimeAudit: RuntimeAuditPurgeStore & {
    matchesSanitizedAuditValue(value: unknown, raw: string): boolean;
  };
  normalizePublicKey: (value: string) => string;
  getSessionCreatorPublicKey: (session: Session) => string | undefined;
  deleteSessionCompletely: (sessionId: string) => void;
  runFileArtifactCleanup: (payload: FileArtifactCleanupPayload) => void;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
  getSessionParticipantCount: (session: Session) => number;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  runKeyPurgeLifecycle: (payload: KeyPurgeLifecyclePayload) => void;
  purgeTasks: (publicKey: string, normalizePublicKey: (value: string) => string) => unknown;
  purgeReputation: (publicKey: string) => unknown;
  purgeKeyFeedback: (publicKey: string) => unknown;
  purgeKeyTrust: (publicKey: string) => unknown;
  purgeJoinRequests: (publicKey: string) => unknown;
  deletePassphraseGrants: (publicKey: string) => unknown;
  purgeSessionModeration: (publicKey: string) => unknown;
  purgeMatchRequestKeyIds: (keyIds: Set<string>) => unknown;
}): (publicKey: string, keyIds?: Set<string>, reason?: KeyPurgeLifecyclePayload["reason"]) => void {
  return (publicKey, keyIds: Set<string> = new Set(), reason: KeyPurgeLifecyclePayload["reason"] = "removed") =>
    purgePublicKeyDataScoped({
      publicKey,
      keyIds,
      reason,
      normalizePublicKey: params.normalizePublicKey,
      purgePublicKeySessionMembership: (normalizedPublicKey) => purgePublicKeySessionMembershipScoped({
        sessions: params.sessions,
        publicKey: normalizedPublicKey,
        getSessionCreatorPublicKey: params.getSessionCreatorPublicKey,
        deleteSessionCompletely: params.deleteSessionCompletely,
        runFileArtifactCleanup: params.runFileArtifactCleanup,
        normalizePublicKey: params.normalizePublicKey,
        hasSessionParticipant: params.hasSessionParticipant,
        ensureSessionPeerIndex: params.ensureSessionPeerIndex,
        getSessionParticipantCount: params.getSessionParticipantCount,
      }),
      purgeMessagesLinkedToPublicKey: (normalizedPublicKey) => purgeMessagesLinkedToPublicKeyScoped({
        messageStore: params.messageStore,
        sessionTraceHeads: params.sessionTraceHeads,
        publicKey: normalizedPublicKey,
        normalizePublicKey: params.normalizePublicKey,
        getParticipantPeerId: params.getParticipantPeerId,
      }),
      runKeyPurgeLifecycle: params.runKeyPurgeLifecycle,
      purgePublicKeyLinkedStores: (purgedPublicKey, normalizedPublicKey, purgedKeyIds) =>
        purgePublicKeyLinkedStoresScoped({
          publicKey: purgedPublicKey,
          normalizedPublicKey,
          keyIds: purgedKeyIds,
          normalizePublicKey: params.normalizePublicKey,
          purgeTasks: params.purgeTasks,
          purgeReputation: params.purgeReputation,
          purgeKeyFeedback: params.purgeKeyFeedback,
          purgeKeyTrust: params.purgeKeyTrust,
          purgeJoinRequests: params.purgeJoinRequests,
          deletePassphraseGrants: params.deletePassphraseGrants,
          purgeSessionModeration: params.purgeSessionModeration,
          purgeMatchRequestKeyIds: params.purgeMatchRequestKeyIds,
        }),
      purgePublicKeyRuntimeAuditResidue: (purgedPublicKey, purgedKeyIds, deletedCreatorSessionIds) =>
        purgePublicKeyRuntimeAuditResidueScoped({
          runtimeAudit: params.runtimeAudit,
          publicKey: purgedPublicKey,
          keyIds: purgedKeyIds,
          deletedCreatorSessionIds,
          matchesSanitizedAuditValue: params.runtimeAudit.matchesSanitizedAuditValue.bind(params.runtimeAudit),
        }),
    });
}

export function createDynamicDeletionRunnersForStorageScoped(params: {
  getSessions: () => Map<string, Session>;
  getNodes: () => Map<string, Node>;
  getSessionTraceHeads: () => Map<string, string>;
  runFileArtifactCleanup: (payload: FileArtifactCleanupPayload) => void;
  messageStore: SessionDeleteStore & MessageOwnerPurgeStore;
  sessionPassphrases: SessionDeleteStore & { deletePublicKeyGrants(publicKey: string, buildIndex: (sessionId: string, publicKey: string) => string): unknown };
  joinRequests: SessionDeleteStore & { purgeRequester(publicKey: string): unknown };
  sessionInvites: { delete(sessionId: string): unknown };
  sessionModeration: SessionDeleteStore & { purgePublicKey(publicKey: string, buildWriteBlockIndex: (sessionId: string, publicKey: string) => string, buildReentryBlockIndex: (sessionId: string, publicKey: string) => string): unknown };
  keyFeedback: { purgeSession(sessionId: string): unknown; purgePublicKey(publicKey: string): unknown };
  tasks: SessionDeleteStore & { purgePublicKey(publicKey: string, normalizePublicKey: (value: string) => string): unknown };
  runtimeAudit: RuntimeAuditPurgeStore & {
    matchesSanitizedAuditValue(value: unknown, raw: string): boolean;
  };
  normalizePublicKey: (value: string) => string;
  getSessionCreatorPublicKey: (session: Session) => string | undefined;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  ensureSessionPeerIndex: (session: Session) => Session | undefined;
  getSessionParticipantCount: (session: Session) => number;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  runKeyPurgeLifecycle: (payload: KeyPurgeLifecyclePayload) => void;
  purgeReputation: (publicKey: string) => unknown;
  purgeKeyTrust: (publicKey: string) => unknown;
  purgeMatchRequestKeyIds: (keyIds: Set<string>) => unknown;
  buildPassphraseGrantIndex: (sessionId: string, publicKey: string) => string;
  buildWriteBlockIndex: (sessionId: string, publicKey: string) => string;
  buildReentryBlockIndex: (sessionId: string, publicKey: string) => string;
}): {
  purgeDeletedSessionStores: (sessionId: string) => void;
  deleteSessionCompletely: (sessionId: string) => void;
  purgePublicKeyData: (publicKey: string, keyIds?: Set<string>, reason?: KeyPurgeLifecyclePayload["reason"]) => void;
} {
  const purgeDeletedSessionStores = (sessionId: string): void => {
    purgeDeletedSessionStoresScoped({
      sessionId,
      runFileArtifactCleanup: params.runFileArtifactCleanup,
      messageStore: params.messageStore,
      sessionTraceHeads: params.getSessionTraceHeads(),
      sessionPassphrases: params.sessionPassphrases,
      joinRequests: params.joinRequests,
      sessionInvites: params.sessionInvites,
      sessionModeration: params.sessionModeration,
      keyFeedback: params.keyFeedback,
      tasks: params.tasks,
    });
  };

  const deleteSessionCompletely = (sessionId: string): void => {
    deleteSessionCompletelyForStorageScoped({
      sessions: params.getSessions(),
      nodes: params.getNodes(),
      sessionId,
      purgeDeletedSessionStores,
    });
  };

  const purgePublicKeyData = (
    publicKey: string,
    keyIds: Set<string> = new Set(),
    reason: KeyPurgeLifecyclePayload["reason"] = "removed",
  ): void => {
    purgePublicKeyDataScoped({
      publicKey,
      keyIds,
      reason,
      normalizePublicKey: params.normalizePublicKey,
      purgePublicKeySessionMembership: (normalizedPublicKey) => ({
        deletedCreatorSessionIds: deleteSessionsCreatedByPublicKeyScoped({
          sessions: params.getSessions(),
          publicKey: normalizedPublicKey,
          getSessionCreatorPublicKey: params.getSessionCreatorPublicKey,
          deleteSessionCompletely,
        }),
        participantSessionIds: (() => {
          params.runFileArtifactCleanup({ publicKey: normalizedPublicKey, reason: "public_key_purged" });
          return removePublicKeyFromSessionsScoped({
            sessions: params.getSessions(),
            publicKey: normalizedPublicKey,
            normalizePublicKey: params.normalizePublicKey,
            hasSessionParticipant: params.hasSessionParticipant,
            ensureSessionPeerIndex: params.ensureSessionPeerIndex,
            getSessionParticipantCount: params.getSessionParticipantCount,
          });
        })(),
      }),
      purgeMessagesLinkedToPublicKey: (normalizedPublicKey) => purgeMessagesLinkedToPublicKeyScoped({
        messageStore: params.messageStore,
        sessionTraceHeads: params.getSessionTraceHeads(),
        publicKey: normalizedPublicKey,
        normalizePublicKey: params.normalizePublicKey,
        getParticipantPeerId: params.getParticipantPeerId,
      }),
      runKeyPurgeLifecycle: params.runKeyPurgeLifecycle,
      purgePublicKeyLinkedStores: (purgedPublicKey, normalizedPublicKey, purgedKeyIds) =>
        purgePublicKeyLinkedStoresScoped({
          publicKey: purgedPublicKey,
          normalizedPublicKey,
          keyIds: purgedKeyIds,
          normalizePublicKey: params.normalizePublicKey,
          purgeTasks: params.tasks.purgePublicKey.bind(params.tasks),
          purgeReputation: params.purgeReputation,
          purgeKeyFeedback: params.keyFeedback.purgePublicKey.bind(params.keyFeedback),
          purgeKeyTrust: params.purgeKeyTrust,
          purgeJoinRequests: params.joinRequests.purgeRequester.bind(params.joinRequests),
          deletePassphraseGrants: (grantPublicKey) => params.sessionPassphrases.deletePublicKeyGrants(
            grantPublicKey,
            params.buildPassphraseGrantIndex,
          ),
          purgeSessionModeration: (moderationPublicKey) => params.sessionModeration.purgePublicKey(
            moderationPublicKey,
            params.buildWriteBlockIndex,
            params.buildReentryBlockIndex,
          ),
          purgeMatchRequestKeyIds: params.purgeMatchRequestKeyIds,
        }),
      purgePublicKeyRuntimeAuditResidue: (purgedPublicKey, purgedKeyIds, deletedCreatorSessionIds) =>
        purgePublicKeyRuntimeAuditResidueScoped({
          runtimeAudit: params.runtimeAudit,
          publicKey: purgedPublicKey,
          keyIds: purgedKeyIds,
          deletedCreatorSessionIds,
          matchesSanitizedAuditValue: params.runtimeAudit.matchesSanitizedAuditValue.bind(params.runtimeAudit),
        }),
    });
  };

  return { purgeDeletedSessionStores, deleteSessionCompletely, purgePublicKeyData };
}

export function removePublicKeyFromAllSessionsForStorageScoped(params: {
  publicKey: string;
  sessions: Iterable<Session>;
  keys: Iterable<EphemeralKey>;
  normalizePublicKey: (value: string) => string;
  hasSessionParticipant: (session: Session, publicKey: string) => boolean;
  getSessionCreatorPublicKey: (session: Session) => string | undefined;
  purgePublicKeyData: (publicKey: string, keyIds?: Set<string>, reason?: KeyPurgeLifecyclePayload["reason"]) => void;
}): string[] {
  const normalized = params.normalizePublicKey(params.publicKey);
  if (!normalized) return [];
  const impacted = Array.from(params.sessions)
    .filter((session) =>
      params.hasSessionParticipant(session, normalized)
      || params.getSessionCreatorPublicKey(session) === normalized,
    )
    .map((session) => session.id);
  const keyIds = new Set(
    Array.from(params.keys)
      .filter((key) => params.normalizePublicKey(key.publicKey) === normalized)
      .map((key) => String(key.id || "").trim())
      .filter(Boolean),
  );
  params.purgePublicKeyData(normalized, keyIds);
  return impacted;
}

export function normalizeOwnerTagOrThrowScoped(ownerTag: string): string {
  const normalizedOwner = String(ownerTag || "").trim();
  if (!normalizedOwner) {
    throw new Error("ownerTag is required");
  }
  return normalizedOwner;
}

export async function issueOwnerDeletionCertificateThenKeyKilledEventScoped(params: {
  targetId: string;
  issueDeletionCertificate: (scope: string, targetId: string) => DeletionCertificate;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
}): Promise<DeletionCertificate> {
  const cert = params.issueDeletionCertificate("owner", params.targetId);
  await params.addEvent("key.killed", "system", buildKeyKilledDeleteMyDataEventPayloadScoped());
  return cert;
}

export async function issueKeyKilledEventThenUserDeletionCertificateScoped(params: {
  targetId: string;
  issueDeletionCertificate: (scope: string, targetId: string) => DeletionCertificate;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
}): Promise<DeletionCertificate> {
  await params.addEvent("key.killed", "system", buildKeyKilledDeleteMyDataEventPayloadScoped());
  return params.issueDeletionCertificate("user", params.targetId);
}

export async function killUserDataScoped(params: {
  publicKey: string;
  purgeUserKeyRuntimeData: (publicKey: string) => unknown;
  issueKeyKilledEventThenUserDeletionCertificate: (targetId: string) => Promise<DeletionCertificate>;
}): Promise<DeletionCertificate> {
  params.purgeUserKeyRuntimeData(params.publicKey);
  return params.issueKeyKilledEventThenUserDeletionCertificate(params.publicKey);
}

export async function killUserDataForStorageScoped(params: {
  publicKey: string;
  purgeUserKeyRuntimeData: (publicKey: string) => unknown;
  issueDeletionCertificate: (scope: string, targetId: string) => DeletionCertificate;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
}): Promise<DeletionCertificate> {
  return killUserDataScoped({
    publicKey: params.publicKey,
    purgeUserKeyRuntimeData: params.purgeUserKeyRuntimeData,
    issueKeyKilledEventThenUserDeletionCertificate: (targetId) =>
      issueKeyKilledEventThenUserDeletionCertificateScoped({
        targetId,
        issueDeletionCertificate: params.issueDeletionCertificate,
        addEvent: params.addEvent,
      }),
  });
}

export async function killOwnerDataScoped(params: {
  ownerTag: string;
  strictNoPersistentIdentity: boolean;
  keys: Map<string, EphemeralKey>;
  normalizeOwnerTagOrThrow: (ownerTag: string) => string;
  purgeOwnerKeyRuntimeData: (ownerTag: string) => boolean;
  issueOwnerDeletionCertificateThenKeyKilledEvent: (targetId: string) => Promise<DeletionCertificate>;
  killUserData: (publicKey: string) => Promise<DeletionCertificate>;
}): Promise<DeletionCertificate> {
  const normalizedOwner = params.normalizeOwnerTagOrThrow(params.ownerTag);
  if (params.strictNoPersistentIdentity) {
    if (params.purgeOwnerKeyRuntimeData(normalizedOwner)) {
      return params.issueOwnerDeletionCertificateThenKeyKilledEvent(normalizedOwner);
    }
    const fallbackKey = params.keys.get(normalizedOwner);
    if (!fallbackKey) {
      throw new Error("Owner key not found");
    }
    return params.killUserData(fallbackKey.publicKey);
  }

  params.purgeOwnerKeyRuntimeData(normalizedOwner);
  return params.issueOwnerDeletionCertificateThenKeyKilledEvent(normalizedOwner);
}

export async function killOwnerDataForStorageScoped(params: {
  ownerTag: string;
  strictNoPersistentIdentity: boolean;
  keys: Map<string, EphemeralKey>;
  purgeOwnerKeyRuntimeData: (ownerTag: string) => boolean;
  issueDeletionCertificate: (scope: string, targetId: string) => DeletionCertificate;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<any>;
  killUserData: (publicKey: string) => Promise<DeletionCertificate>;
}): Promise<DeletionCertificate> {
  return killOwnerDataScoped({
    ownerTag: params.ownerTag,
    strictNoPersistentIdentity: params.strictNoPersistentIdentity,
    keys: params.keys,
    normalizeOwnerTagOrThrow: normalizeOwnerTagOrThrowScoped,
    purgeOwnerKeyRuntimeData: params.purgeOwnerKeyRuntimeData,
    issueOwnerDeletionCertificateThenKeyKilledEvent: (targetId) =>
      issueOwnerDeletionCertificateThenKeyKilledEventScoped({
        targetId,
        issueDeletionCertificate: params.issueDeletionCertificate,
        addEvent: params.addEvent,
      }),
    killUserData: params.killUserData,
  });
}
