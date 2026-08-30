import type { EphemeralKey, Node, Session } from "@shared/schema";

export function deleteSessionLifecycleScoped(
  sessions: Map<string, Session>,
  nodes: Map<string, Node>,
  sessionId: string,
): Session | undefined {
  const session = sessions.get(sessionId);
  if (!session) return undefined;
  session.nodeIds.forEach((nodeId) => {
    const node = nodes.get(nodeId);
    if (node && node.activeSessions > 0) node.activeSessions--;
  });
  sessions.delete(sessionId);
  return session;
}

export function markExpiredSessionsScoped(
  sessions: Map<string, Session>,
  now: number,
): Array<{ sessionId: string; nodeId: string }> {
  const expired: Array<{ sessionId: string; nodeId: string }> = [];
  sessions.forEach((session, sessionId) => {
    if (session.expiresAt <= now && session.status === "active") {
      session.status = "expired";
      expired.push({ sessionId, nodeId: session.nodeIds[0] || "system" });
    } else if (session.expiresAt - now < 60000 && session.status === "active") {
      session.status = "expiring_soon";
    }
  });
  return expired;
}

export function cleanupExpiredSessionsScoped(params: {
  sessions: Map<string, Session>;
  now: number;
  addEvent: (type: "session.expired", nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
}): void {
  markExpiredSessionsScoped(params.sessions, params.now).forEach(({ sessionId, nodeId }) => {
    params.addEvent("session.expired", nodeId, buildSessionExpiredEventPayloadScoped(sessionId));
  });
}

export function terminateSessionLifecycleScoped(
  sessions: Map<string, Session>,
  nodes: Map<string, Node>,
  sessionId: string,
): Session | undefined {
  const session = sessions.get(sessionId);
  if (!session) return undefined;
  session.status = "terminated";
  session.nodeIds.forEach((nodeId) => {
    const node = nodes.get(nodeId);
    if (node && node.activeSessions > 0) node.activeSessions--;
  });
  return session;
}

export function markAllSessionsTerminatedScoped(sessions: Map<string, Session>): void {
  sessions.forEach((session) => {
    session.status = "terminated";
  });
}

export function buildSessionExpiredEventPayloadScoped(sessionId: string) {
  return { sessionId };
}

export function buildSessionTerminatedEventPayloadScoped(params: {
  sessionId: string;
  reason?: string;
  keyId?: string;
}) {
  return {
    sessionId: params.sessionId,
    ...(params.reason ? { reason: params.reason } : {}),
    ...(params.keyId ? { keyId: params.keyId } : {}),
  };
}

export async function destroySessionForStorageScoped(params: {
  sessionId: string;
  session: { nodeIds?: string[] } | undefined;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
  deleteSessionCompletely: (sessionId: string) => void;
}): Promise<boolean> {
  if (!params.session) return false;
  await params.addEvent("session.terminated", params.session.nodeIds?.[0] || "system", buildSessionTerminatedEventPayloadScoped({
    sessionId: params.sessionId,
    reason: "destroy_session",
  }));
  params.deleteSessionCompletely(params.sessionId);
  return true;
}

export async function terminateSessionForStorageScoped(params: {
  sessions: Map<string, Session>;
  nodes: Map<string, Node>;
  sessionId: string;
  addEvent: (type: any, nodeId: string, data?: Record<string, unknown>) => Promise<unknown>;
}): Promise<boolean> {
  const session = terminateSessionLifecycleScoped(params.sessions, params.nodes, params.sessionId);
  if (!session) return false;
  await params.addEvent("session.terminated", session.nodeIds[0] || "system", buildSessionTerminatedEventPayloadScoped({
    sessionId: params.sessionId,
  }));
  return true;
}

export function buildSessionParticipantKeyExpiredLeftEventPayloadScoped(params: {
  sessionId: string;
  keyId: string;
  peerId?: string;
}) {
  return {
    sessionId: params.sessionId,
    reason: "participant_key_expired",
    keyId: params.keyId,
    peerId: params.peerId,
  };
}

export function buildExpiredKeySessionLifecycleEventScoped(params: {
  session: Session;
  keyId: string;
  isCreator: boolean;
  peerId?: string;
}): {
  type: "session.terminated" | "session.left";
  nodeId: string;
  data: Record<string, unknown>;
} {
  const nodeId = params.session.nodeIds[0] || "system";
  if (params.isCreator) {
    return {
      type: "session.terminated",
      nodeId,
      data: buildSessionTerminatedEventPayloadScoped({
        sessionId: params.session.id,
        reason: "creator_key_expired",
        keyId: params.keyId,
      }),
    };
  }
  return {
    type: "session.left",
    nodeId,
    data: buildSessionParticipantKeyExpiredLeftEventPayloadScoped({
      sessionId: params.session.id,
      keyId: params.keyId,
      peerId: params.peerId,
    }),
  };
}

export function clearKeySessionRuntimeMapsScoped(params: {
  keys: Map<string, EphemeralKey>;
  keyOwners: Map<string, string>;
  keyLastSeenAt: Map<string, number>;
  sessions: Map<string, Session>;
}): void {
  params.keys.clear();
  params.keyOwners.clear();
  params.keyLastSeenAt.clear();
  params.sessions.clear();
}
