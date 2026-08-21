import type { Request, Response } from "express";
import { createMailboxPlaneStore, type MailboxBucketPlane } from "../mailbox-plane-store";
import type { RequireSessionMessageAccess, RequireSessionParticipant, SendUniformAuthError } from "./route-context";

type CreateMailboxPlaneStateOptions = {
  mailboxMessagePlaneTokenTtlMs: number;
  mailboxControlPlaneTokenTtlMs: number;
  sendUniformAuthError: SendUniformAuthError;
  requireSessionMessageAccess: RequireSessionMessageAccess;
  requireSessionParticipant: RequireSessionParticipant;
  storage: {
    getKey: (keyId: string) => Promise<any | null | undefined>;
  };
};

export function createMailboxPlaneState(options: CreateMailboxPlaneStateOptions) {
  const store = createMailboxPlaneStore();
  const mailboxBucketCapabilityTtlMs = Math.max(
    options.mailboxMessagePlaneTokenTtlMs,
    options.mailboxControlPlaneTokenTtlMs,
    10 * 60_000,
  );
  const resolveMailboxBucketCapability = (sessionId: string, toPublicKey: string, plane: MailboxBucketPlane) =>
    store.resolveBucketCapability({
      sessionId,
      publicKey: toPublicKey,
      plane,
      ttlMs: mailboxBucketCapabilityTtlMs,
    });

  const issueMailboxMessagePlaneToken = async (
    auth: { keyId: string; publicKey: string; key: any },
    sessionId: string,
  ) => {
    return store.issueToken({
      plane: "message",
      sessionId: String(sessionId || "").trim(),
      keyId: String(auth.keyId || "").trim(),
      publicKey: String(auth.publicKey || "").trim(),
      controlBucketKey: await resolveMailboxBucketCapability(sessionId, auth.publicKey, "control"),
      tokenPrefix: "mbp1",
      routeTokenPrefix: "mbr1",
      ttlMs: options.mailboxMessagePlaneTokenTtlMs,
    });
  };

  const resolveMailboxMessagePlaneAuth = async (
    req: Request,
    res: Response,
    sessionId?: string,
    routeToken?: string,
  ): Promise<{ keyId: string; publicKey: string; key: any; sessionId: string; controlBucketKey: string } | null> => {
    const tokenFromBody = String(req.body?.mailboxPlaneToken || "").trim();
    const tokenFromHeader = String(req.headers["x-mailbox-plane-token"] || "").trim();
    const token = tokenFromBody || tokenFromHeader;
    if (!token) {
      await options.sendUniformAuthError(res, 401, "mailbox plane token required");
      return null;
    }
    const row = await store.getToken(token, "message");
    if (!row) {
      await options.sendUniformAuthError(res, 401, "invalid mailbox plane token");
      return null;
    }
    const normalizedSessionId = String(sessionId || "").trim();
    const normalizedRouteToken = String(routeToken || "").trim();
    if (normalizedSessionId && row.sessionId !== normalizedSessionId) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 403, "mailbox plane token/session mismatch");
      return null;
    }
    if (normalizedRouteToken && row.routeToken !== normalizedRouteToken) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 403, "mailbox plane token/route mismatch");
      return null;
    }
    if (row.expiresAt <= Date.now()) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 401, "mailbox plane token expired");
      return null;
    }
    const key = await options.storage.getKey(row.keyId);
    if (!key || !key.isActive || String(key.publicKey || "").trim() !== row.publicKey) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 401, "mailbox plane token is no longer valid");
      return null;
    }
    const sessionAccess = await options.requireSessionMessageAccess(req, res, row.sessionId, row.publicKey);
    if (!sessionAccess) {
      return null;
    }
    return {
      keyId: row.keyId,
      publicKey: row.publicKey,
      key,
      sessionId: row.sessionId,
      controlBucketKey: String(row.controlBucketKey || ""),
    };
  };

  const issueMailboxControlPlaneToken = async (
    auth: { keyId: string; publicKey: string; key: any },
    sessionId: string,
  ) => {
    return store.issueToken({
      plane: "control",
      sessionId: String(sessionId || "").trim(),
      keyId: String(auth.keyId || "").trim(),
      publicKey: String(auth.publicKey || "").trim(),
      tokenPrefix: "mbc1",
      routeTokenPrefix: "mbcr1",
      ttlMs: options.mailboxControlPlaneTokenTtlMs,
    });
  };

  const resolveMailboxControlPlaneAuth = async (
    req: Request,
    res: Response,
    sessionId?: string,
    routeToken?: string,
  ): Promise<{ keyId: string; publicKey: string; key: any; sessionId: string } | null> => {
    const tokenFromBody = String(req.body?.mailboxPlaneToken || "").trim();
    const tokenFromHeader = String(req.headers["x-mailbox-plane-token"] || "").trim();
    const token = tokenFromBody || tokenFromHeader;
    if (!token) {
      await options.sendUniformAuthError(res, 401, "mailbox control plane token required");
      return null;
    }
    const row = await store.getToken(token, "control");
    if (!row) {
      await options.sendUniformAuthError(res, 401, "invalid mailbox control plane token");
      return null;
    }
    const normalizedSessionId = String(sessionId || "").trim();
    const normalizedRouteToken = String(routeToken || "").trim();
    if (normalizedSessionId && row.sessionId !== normalizedSessionId) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 403, "mailbox control token/session mismatch");
      return null;
    }
    if (normalizedRouteToken && row.routeToken !== normalizedRouteToken) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 403, "mailbox control token/route mismatch");
      return null;
    }
    if (row.expiresAt <= Date.now()) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 401, "mailbox control plane token expired");
      return null;
    }
    const key = await options.storage.getKey(row.keyId);
    if (!key || !key.isActive || String(key.publicKey || "").trim() !== row.publicKey) {
      await store.deleteToken(token);
      await options.sendUniformAuthError(res, 401, "mailbox control plane token is no longer valid");
      return null;
    }
    const session = await options.requireSessionParticipant(req, res, row.sessionId, row.publicKey);
    if (!session) return null;
    return {
      keyId: row.keyId,
      publicKey: row.publicKey,
      key,
      sessionId: row.sessionId,
    };
  };

  return {
    resolveMailboxBucketCapability,
    issueMailboxMessagePlaneToken,
    resolveMailboxMessagePlaneAuth,
    issueMailboxControlPlaneToken,
    resolveMailboxControlPlaneAuth,
  };
}
