type SessionMessageMetaShape = {
  starredIds: string[];
  pinnedIds: string[];
};

export function findMessageSessionForRequesterScoped<TMessage, TSession>(params: {
  entries: Iterable<[string, TMessage[]]>;
  messageId: string;
  requesterPublicKey: string;
  getSession: (sessionId: string) => TSession | undefined;
  hasSessionParticipant: (session: TSession | undefined, publicKey: string) => boolean;
  canUseSessionMessages: (sessionId: string, publicKey: string) => boolean;
}): string {
  for (const [sessionId, messages] of params.entries) {
    const message = messages.find((item: any) => item?.id === params.messageId);
    if (!message) continue;
    const session = params.getSession(sessionId);
    if (!params.hasSessionParticipant(session, params.requesterPublicKey)) {
      throw new Error("Forbidden");
    }
    if (!params.canUseSessionMessages(sessionId, params.requesterPublicKey)) {
      throw new Error("PassphraseRequired");
    }
    return sessionId;
  }
  throw new Error("Message not found");
}

export function findMessageMutationTargetForRequesterScoped<TMessage, TSession>(params: {
  entries: Iterable<[string, TMessage[]]>;
  messageId: string;
  requesterPublicKey: string;
  getSession: (sessionId: string) => TSession | undefined;
  hasSessionParticipant: (session: TSession | undefined, publicKey: string) => boolean;
  canUseSessionMessages: (sessionId: string, publicKey: string) => boolean;
}): {
  sessionId: string;
  messages: TMessage[];
  index: number;
  message: TMessage;
} | undefined {
  for (const [sessionId, messages] of params.entries) {
    const index = messages.findIndex((item: any) => item?.id === params.messageId);
    if (index === -1) continue;
    const session = params.getSession(sessionId);
    if (!params.hasSessionParticipant(session, params.requesterPublicKey)) {
      throw new Error("Forbidden");
    }
    if (!params.canUseSessionMessages(sessionId, params.requesterPublicKey)) {
      throw new Error("PassphraseRequired");
    }
    return {
      sessionId,
      messages,
      index,
      message: messages[index],
    };
  }
  return undefined;
}

export function recordMessageDeletionScoped(
  messageDeleteEvents: Map<string, Array<{ id: string; ts: number }>>,
  sessionId: string,
  messageId: string,
): void {
  const sid = String(sessionId || "").trim();
  const mid = String(messageId || "").trim();
  if (!sid || !mid) return;
  const list = messageDeleteEvents.get(sid) || [];
  list.push({ id: mid, ts: Date.now() });
  const max = 1200;
  if (list.length > max) {
    list.splice(0, list.length - max);
  }
  messageDeleteEvents.set(sid, list);
}

export function recordRemovedMessageDeletesScoped(params: {
  sessionId: string;
  messageIds: string[];
  recordMessageDeletion: (sessionId: string, messageId: string) => void;
}): void {
  params.messageIds.forEach((messageId) => {
    params.recordMessageDeletion(params.sessionId, messageId);
  });
}

export function getSessionMessageMetaScoped(
  sessionMessageMeta: Map<string, SessionMessageMetaShape>,
  sessionId: string,
): SessionMessageMetaShape {
  const meta = sessionMessageMeta.get(sessionId);
  if (!meta) return { starredIds: [], pinnedIds: [] };
  return {
    starredIds: [...meta.starredIds],
    pinnedIds: [...meta.pinnedIds],
  };
}

export function toggleSessionMessageFlagScoped(
  sessionMessageMeta: Map<string, SessionMessageMetaShape>,
  sessionId: string,
  messageId: string,
  flag: "starredIds" | "pinnedIds",
): SessionMessageMetaShape {
  const existing = sessionMessageMeta.get(sessionId) || { starredIds: [], pinnedIds: [] };
  const set = new Set(existing[flag]);
  if (set.has(messageId)) {
    set.delete(messageId);
  } else {
    set.add(messageId);
  }
  const next: SessionMessageMetaShape = {
    starredIds: flag === "starredIds" ? Array.from(set) : existing.starredIds,
    pinnedIds: flag === "pinnedIds" ? Array.from(set) : existing.pinnedIds,
  };
  sessionMessageMeta.set(sessionId, next);
  return {
    starredIds: [...next.starredIds],
    pinnedIds: [...next.pinnedIds],
  };
}

export function registerMessageDeleteAtScoped(
  messageDeleteAt: Map<string, number>,
  messageId: string,
  deleteAt: number,
): boolean {
  const id = String(messageId || "").trim();
  if (!id) return false;
  const ts = Number(deleteAt || 0);
  if (!Number.isFinite(ts) || ts <= 0) return false;
  const existing = messageDeleteAt.get(id);
  if (existing && existing <= ts) return false;
  messageDeleteAt.set(id, ts);
  return true;
}

export function getMessageDeleteEventsScoped(
  messageDeleteEvents: Map<string, Array<{ id: string; ts: number }>>,
  sessionId: string,
  sinceTs: number,
  windowStart: number,
  windowEnd: number,
  limit: number,
): Array<{ id: string; ts: number }> {
  const sid = String(sessionId || "").trim();
  if (!sid) return [];
  const list = messageDeleteEvents.get(sid) || [];
  const safeLimit = Math.max(1, Math.min(1200, Math.floor(Number(limit) || 0) || 200));
  const filtered = list.filter((item) => {
    const ts = Number(item?.ts || 0);
    return ts > sinceTs && ts >= windowStart && ts <= windowEnd;
  });
  return filtered.slice(-safeLimit);
}

export function cleanupExpiredMessageDeletesScoped(
  expiredMessageIds: string[],
  deleteMessageBySystem: (messageId: string) => Promise<unknown>,
): void {
  for (const messageId of expiredMessageIds) {
    // Best-effort background cleanup in case scheduler callback was lost.
    void deleteMessageBySystem(messageId);
  }
}

export function isMessageLinkedToPurgedPublicKeyScoped(params: {
  message: any;
  sessionId: string;
  publicKey: string;
  normalizePublicKey: (publicKey: string) => string;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
}): boolean {
  const participantPeerId = params.getParticipantPeerId(
    String(params.sessionId || "").trim(),
    params.publicKey,
  );
  return (
    params.normalizePublicKey(String(params.message?.senderPublicKey || "")) === params.publicKey ||
    (!!participantPeerId && String(params.message?.senderScopeId || "").trim() === participantPeerId)
  );
}

export function isMessageSentByPublicKeyScoped(params: {
  message: any;
  publicKey: string;
  normalizePublicKey: (publicKey: string) => string;
}): boolean {
  return params.normalizePublicKey(String(params.message?.senderPublicKey || "")) ===
    params.normalizePublicKey(params.publicKey);
}

export function clearPurgedMessageTraceHeadsScoped(params: {
  sessionTraceHeads: Map<string, string>;
  removedMessageIdsBySession: Map<string, Set<string>>;
  emptiedSessionIds: Set<string>;
}): void {
  params.removedMessageIdsBySession.forEach((removedIds, sessionId) => {
    if (removedIds.size > 0) {
      params.sessionTraceHeads.delete(sessionId);
    }
  });
  params.emptiedSessionIds.forEach((sessionId) => {
    params.sessionTraceHeads.delete(sessionId);
  });
}
