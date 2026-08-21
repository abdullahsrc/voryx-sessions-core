import type { Express, Request, Response } from "express";
import { createMailboxMessageIdempotencyStore } from "./mailbox-message-idempotency";

type RegisterMailboxMessageRoutesDeps = {
  requireVerifiedKey: (req: Request, res: Response) => Promise<{ keyId: string; publicKey: string; key: any } | null>;
  requireSessionMessageAccess: (req: Request, res: Response, sessionId: string, publicKey: string) => Promise<any>;
  resolveMailboxMessagePlaneAuth: (
    req: Request,
    res: Response,
    sessionId?: string,
    routeToken?: string,
  ) => Promise<{ keyId: string; publicKey: string; key: any; sessionId: string; controlBucketKey: string } | null>;
  resolveMailboxMessageBootstrapToken: (bootstrapToken: string) => Promise<{ sessionId: string } | null>;
  issueMailboxMessagePlaneToken: (auth: { keyId: string; publicKey: string; key: any }, sessionId: string) => Promise<{ token: string; routeToken: string; issuedAt: number; expiresAt: number }>;
  normalizeMailboxRequestPadding: (value: unknown) => string;
  METADATA_PUSH_BATCH_MAX: number;
  resolveCoverCount: (requestedRaw: unknown, fallback?: number) => number;
  clampMailboxWindowMs: (raw: number) => number;
  MAILBOX_PULL_WINDOW_DEFAULT_MS: number;
  clampTimestamp: (raw: unknown, fallback: number) => number;
  isStrictEncryptedEnvelope: (payload: string) => boolean;
  requireSessionPermission: (
    res: Response,
    key: { permissions?: string[] } | undefined,
    permission: string,
    errorMessage: string,
  ) => boolean;
  MESSAGE_LABEL_ALLOW_PLAINTEXT: boolean;
  storage: any;
  pubsub: any;
  scheduleDisappearingMessageDelete: (sessionId: string, messageId: string, deleteAt: number) => void;
  maybeMetadataJitter: () => Promise<void>;
  makeCoverToken: () => string;
  withFixedEnvelopePadding: <T extends Record<string, any>>(payload: T, targetBytes?: number) => T & { pad: string };
  METADATA_PULL_BATCH_DEFAULT: number;
  METADATA_PULL_BATCH_MAX: number;
  strictControlMailboxMode: boolean;
  pullMailboxControlEvents: (input: {
    bucketKey: string;
    sinceTs: number;
    windowStart: number;
    windowEnd: number;
    limit: number;
  }) => Promise<any[]>;
  shapeItemsWithCover: (
    items: Array<Record<string, unknown>>,
    targetCount: number,
    baseCoverCount: number,
  ) => { responseItems: Array<Record<string, unknown>>; cover: Array<Record<string, unknown>> };
  MAILBOX_PULL_TARGET_ITEMS: number;
  MAILBOX_HISTORY_TARGET_ITEMS: number;
  cancelDisappearingMessageDelete: (messageId: string) => void;
  strictBlindMetadataMode: boolean;
};

export function registerMailboxMessageRoutes(app: Express, deps: RegisterMailboxMessageRoutesDeps) {
  const MESSAGE_IDEMPOTENCY_TTL_MS = 5 * 60 * 1000;
  const MESSAGE_IDEMPOTENCY_MAX_ENTRIES = 5000;
  const messageIdempotency = createMailboxMessageIdempotencyStore({
    maxEntries: MESSAGE_IDEMPOTENCY_MAX_ENTRIES,
  });

  const withBlindMailboxResponse = <T extends Record<string, unknown>>(payload: T) =>
    deps.withFixedEnvelopePadding(
      deps.strictBlindMetadataMode
        ? payload
        : {
            ...payload,
            batchToken: deps.makeCoverToken(),
            serverTime: Date.now(),
          },
    );

  const resolveRouteToken = (req: Request) => String(req.params.routeToken || "").trim();
  const normalizeClientMessageId = (value: unknown) => {
    const normalized = String(value || "").trim();
    if (!normalized || normalized.length > 128) return "";
    return /^[A-Za-z0-9:_-]+$/.test(normalized) ? normalized : "";
  };
  app.post("/api/sessions/:id/mailbox/plane-token", async (req, res) => {
    try {
      const auth = await deps.requireVerifiedKey(req, res);
      if (!auth) return;
      const hasAccess = await deps.requireSessionMessageAccess(req, res, req.params.id, auth.publicKey);
      if (!hasAccess) return;
      deps.normalizeMailboxRequestPadding(req.body?.pad);
      const token = await deps.issueMailboxMessagePlaneToken(auth, req.params.id);
      await deps.maybeMetadataJitter();
      return res.json({
        success: true,
        data: withBlindMailboxResponse({
          token: token.token,
          routeBase: `/api/mailbox/${token.routeToken}`,
          expiresAt: token.expiresAt,
          cover: [{ kind: "cover", token: deps.makeCoverToken() }],
        }),
      });
    } catch {
      return res.status(400).json({ success: false, error: "Failed to issue mailbox plane token" });
    }
  });

  app.post("/api/mailbox-bootstrap/:bootstrapToken/plane-token", async (req, res) => {
    try {
      const auth = await deps.requireVerifiedKey(req, res);
      if (!auth) return;
      const bootstrap = await deps.resolveMailboxMessageBootstrapToken(req.params.bootstrapToken);
      if (!bootstrap?.sessionId) {
        return res.status(401).json({ success: false, error: "Invalid mailbox bootstrap token" });
      }
      const hasAccess = await deps.requireSessionMessageAccess(req, res, bootstrap.sessionId, auth.publicKey);
      if (!hasAccess) return;
      deps.normalizeMailboxRequestPadding(req.body?.pad);
      const token = await deps.issueMailboxMessagePlaneToken(auth, bootstrap.sessionId);
      await deps.maybeMetadataJitter();
      return res.json({
        success: true,
        data: withBlindMailboxResponse({
          token: token.token,
          routeBase: `/api/mailbox/${token.routeToken}`,
          expiresAt: token.expiresAt,
          cover: [{ kind: "cover", token: deps.makeCoverToken() }],
        }),
      });
    } catch {
      return res.status(400).json({ success: false, error: "Failed to issue mailbox plane token" });
    }
  });

  const pushHandler = async (req: Request, res: Response) => {
    try {
      const routeToken = resolveRouteToken(req);
      const auth = await deps.resolveMailboxMessagePlaneAuth(req, res, req.params.id, routeToken);
      if (!auth) return;

      deps.normalizeMailboxRequestPadding(req.body?.pad);
      const rawBatch = Array.isArray(req.body?.batch) ? req.body.batch : [];
      const batch = rawBatch.slice(0, deps.METADATA_PUSH_BATCH_MAX);
      const coverCount = deps.resolveCoverCount(req.body?.cover);
      const now = Date.now();
      const requestedWindowMs = deps.clampMailboxWindowMs(Number(req.body?.windowMs || deps.MAILBOX_PULL_WINDOW_DEFAULT_MS));
      const requestedWindowEnd = deps.clampTimestamp(req.body?.windowEnd, now);
      const requestedWindowStart = deps.clampTimestamp(req.body?.windowStart, Math.max(0, requestedWindowEnd - requestedWindowMs));

      const createdMessages: any[] = [];
      for (const item of batch) {
        if (!item || item.kind !== "message") continue;
        const payload = item.payload || {};
        const typeRaw = String(payload.type || "").trim();
        if (
          typeRaw !== "encrypted" &&
          typeRaw !== "file" &&
          typeRaw !== "voice_note"
        ) {
          continue;
        }
        const type: "encrypted" | "file" | "voice_note" = typeRaw;
        const content = String(payload.content || "");
        if (!type || !content) continue;
        if ((type === "encrypted" || type === "file" || type === "voice_note") && !deps.isStrictEncryptedEnvelope(content)) {
          continue;
        }
        if (type === "encrypted") {
          if (!deps.requireSessionPermission(res, auth.key, "session.write", "Key is not permitted to send messages")) return;
        } else if (type === "file") {
          if (!deps.requireSessionPermission(res, auth.key, "session.file", "Key is not permitted to share files")) return;
        } else if (type === "voice_note") {
          if (!deps.requireSessionPermission(res, auth.key, "session.voice", "Key is not permitted to send voice notes")) return;
        }
        const disappearAfterReadSecondsRaw = Number(payload.disappearAfterReadSeconds || 0);
        const disappearAfterReadSeconds = Number.isFinite(disappearAfterReadSecondsRaw) ? disappearAfterReadSecondsRaw : undefined;
        const disappearAfterSecondsRaw = Number(payload.disappearAfterSeconds || 0);
        const disappearAfterSeconds = Number.isFinite(disappearAfterSecondsRaw) ? disappearAfterSecondsRaw : undefined;
        const clientMessageId = normalizeClientMessageId(payload.clientMessageId);
        const idempotencyKey = clientMessageId
          ? `${auth.sessionId}:${auth.keyId}:${clientMessageId}`
          : "";
        if (idempotencyKey) {
          const existing = await messageIdempotency.get(idempotencyKey, now);
          if (existing && existing.expiresAt > now) {
            createdMessages.push(existing.message);
            continue;
          }
        }
        const message = await deps.storage.addMessage({
          sessionId: auth.sessionId,
          senderPublicKey: auth.publicKey,
          senderLabel: deps.MESSAGE_LABEL_ALLOW_PLAINTEXT
            ? String(payload.senderLabel || req.body?.senderLabel || "").trim()
            : "",
          type,
          content,
          disappearAfterReadSeconds,
          disappearAfterSeconds,
          replyToId: String(payload.replyToId || "").trim() || undefined,
          attachmentArtifactId: String(payload.attachmentArtifactId || "").trim() || undefined,
          attachmentArtifactIds: Array.isArray(payload.attachmentArtifactIds)
            ? payload.attachmentArtifactIds.map((value: unknown) => String(value || "").trim()).filter(Boolean).slice(0, 24)
            : undefined,
          edited: false,
        });
        if (idempotencyKey) {
          await messageIdempotency.set(idempotencyKey, {
            message,
            expiresAt: Date.now() + MESSAGE_IDEMPOTENCY_TTL_MS,
          });
        }
        createdMessages.push(message);
        deps.pubsub.broadcastSessionUpdate(auth.sessionId, "chat", { message });
      }

      await deps.maybeMetadataJitter();
      const cover = Array.from({ length: coverCount }, () => ({ kind: "cover", token: deps.makeCoverToken() }));
      res.json({
        success: true,
        data: withBlindMailboxResponse({
          accepted: createdMessages.length,
          acceptedCount: createdMessages.length,
          cover,
          messages: createdMessages,
        }),
      });
    } catch (error: any) {
      if (error?.message === "PassphraseRequired") {
        return res.status(423).json({ success: false, error: "Message access locked until passphrase grant" });
      }
      if (error?.message === "WriteBlocked") {
        return res.status(403).json({ success: false, error: "Writing is blocked by the session creator" });
      }
      if (error?.message === "EncryptionRequired") {
        return res.status(400).json({ success: false, error: "Encrypted content required" });
      }
      res.status(500).json({ success: false, error: "Failed to push mailbox batch" });
    }
  };
  app.post("/api/sessions/:id/mailbox/push", pushHandler);
  app.post("/api/mailbox/:routeToken/push", pushHandler);

  const pullHandler = async (req: Request, res: Response) => {
    try {
      const routeToken = resolveRouteToken(req);
      const auth = await deps.resolveMailboxMessagePlaneAuth(req, res, req.params.id, routeToken);
      if (!auth) return;

      deps.normalizeMailboxRequestPadding(req.body?.pad);
      const now = Date.now();
      const rawLimit = Number(req.body?.limit || deps.METADATA_PULL_BATCH_DEFAULT);
      const limit = Number.isFinite(rawLimit)
        ? Math.max(1, Math.min(deps.METADATA_PULL_BATCH_MAX, Math.floor(rawLimit)))
        : deps.METADATA_PULL_BATCH_DEFAULT;
      const windowMs = deps.clampMailboxWindowMs(Number(req.body?.windowMs || deps.MAILBOX_PULL_WINDOW_DEFAULT_MS));
      const windowEnd = deps.clampTimestamp(req.body?.windowEnd, now);
      const windowStart = deps.clampTimestamp(req.body?.windowStart, Math.max(0, windowEnd - windowMs));
      const sinceTs = deps.clampTimestamp(req.body?.sinceTs, 0);
      const coverCount = deps.resolveCoverCount(req.body?.cover);
      const history = await deps.storage.getMessages(auth.sessionId, Math.min(deps.METADATA_PULL_BATCH_MAX * 6, 720));
      const filteredMessages = history
        .filter((m: any) => {
          const timestamp = Number(m?.timestamp || 0);
          const editedAt = Number(m?.editedAt || 0);
          const eventTs = Math.max(timestamp, editedAt);
          return eventTs > sinceTs && eventTs >= windowStart && eventTs <= windowEnd;
        })
        .slice(-limit);
      const deleteEvents = await deps.storage.getMessageDeleteEvents(auth.sessionId, sinceTs, windowStart, windowEnd, limit);
      const deletedMessageIds = Array.from(new Set(deleteEvents.map((entry: any) => String(entry?.id || "").trim()).filter(Boolean)));
      const allDeleteEvents = await deps.storage.getMessageDeleteEvents(
        auth.sessionId,
        0,
        0,
        Number.MAX_SAFE_INTEGER,
        deps.METADATA_PULL_BATCH_MAX * 6,
      );
      const reconciledDeletedMessageIds = Array.from(
        new Set(
          allDeleteEvents
            .map((entry: any) => String(entry?.id || "").trim())
            .filter(Boolean),
        ),
      );
      const controlEvents = deps.strictControlMailboxMode
        ? await deps.pullMailboxControlEvents({
            bucketKey: String(auth.controlBucketKey || "").trim(),
            sinceTs,
            windowStart,
            windowEnd,
            limit,
          })
        : [];
      const items = [
        ...filteredMessages.map((message: any) => ({ kind: "message", payload: message })),
        ...deleteEvents.map((entry: any) => ({ kind: "message_deleted", payload: { messageId: entry.id } })),
        ...controlEvents.map((entry: any) => ({ kind: entry.kind, payload: entry.payload })),
      ];
      const { responseItems } = deps.shapeItemsWithCover(
        items,
        deps.MAILBOX_PULL_TARGET_ITEMS,
        coverCount,
      );
      await deps.maybeMetadataJitter();
      res.json({
        success: true,
        data: withBlindMailboxResponse({
          items: responseItems,
          deletedMessageIds,
          reconciledDeletedMessageIds,
        }),
      });
      } catch (error: any) {
        if (error?.message === "PassphraseRequired") {
          return res.status(423).json({
            success: false,
            error: "Message access locked until passphrase grant",
        });
      }

  console.error("mailbox_pull_failed", {
    message: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  });

  res.status(500).json({
    success: false,
    error: "Failed to pull mailbox batch",
  });
}

  };
  app.post("/api/sessions/:id/mailbox/pull", pullHandler);
  app.post("/api/mailbox/:routeToken/pull", pullHandler);

  const historyHandler = async (req: Request, res: Response) => {
    try {
      const routeToken = resolveRouteToken(req);
      const auth = await deps.resolveMailboxMessagePlaneAuth(req, res, req.params.id, routeToken);
      if (!auth) return;

      deps.normalizeMailboxRequestPadding(req.body?.pad);
      const now = Date.now();
      const rawLimit = Number(req.body?.limit || 180);
      const limit = Number.isFinite(rawLimit)
        ? Math.max(1, Math.min(deps.METADATA_PULL_BATCH_MAX * 6, Math.floor(rawLimit)))
        : deps.METADATA_PULL_BATCH_MAX;
      const beforeTs = deps.clampTimestamp(req.body?.beforeTs, now);
      const coverCount = deps.resolveCoverCount(req.body?.cover);

      const allDeleteEvents = await deps.storage.getMessageDeleteEvents(auth.sessionId, 0, 0, Number.MAX_SAFE_INTEGER, deps.METADATA_PULL_BATCH_MAX * 6);
      const deletedMessageIds = Array.from(new Set(allDeleteEvents.map((entry: any) => String(entry?.id || "").trim()).filter(Boolean)));
      const deletedMessageIdSet = new Set(deletedMessageIds);
      const history = await deps.storage.getMessages(auth.sessionId, Math.min(12_000, limit * 8));
      const messages = history
        .filter((m: any) => Number(m.timestamp || 0) <= beforeTs)
        .filter((m: any) => !deletedMessageIdSet.has(String(m?.id || "").trim()))
        .slice(-limit);
      const deleteEvents = allDeleteEvents
        .filter((entry: any) => Number(entry?.ts || 0) <= beforeTs)
        .slice(-limit);
      const items = [
        ...messages.map((message: any) => ({ kind: "message", payload: message })),
        ...deleteEvents.map((entry: any) => ({ kind: "message_deleted", payload: { messageId: entry.id } })),
      ];
      const oldestTs = messages.length > 0 ? Number(messages[0]?.timestamp || 0) : 0;
      const hasMore = messages.length >= limit;
      const { responseItems } = deps.shapeItemsWithCover(
        items,
        deps.MAILBOX_HISTORY_TARGET_ITEMS,
        coverCount,
      );
      await deps.maybeMetadataJitter();
      res.json({
        success: true,
        data: withBlindMailboxResponse({
          items: responseItems,
          deletedMessageIds,
          oldestTs,
          hasMore,
        }),
      });
    } catch (error: any) {
      if (error?.message === "PassphraseRequired") {
        return res.status(423).json({ success: false, error: "Message access locked until passphrase grant" });
      }
      res.status(500).json({ success: false, error: "Failed to fetch mailbox history" });
    }
  };
  app.post("/api/sessions/:id/mailbox/history", historyHandler);
  app.post("/api/mailbox/:routeToken/history", historyHandler);

  const actionHandler = async (req: Request, res: Response) => {
    try {
      const routeToken = resolveRouteToken(req);
      const auth = await deps.resolveMailboxMessagePlaneAuth(req, res, req.params.id, routeToken);
      if (!auth) return;
      deps.normalizeMailboxRequestPadding(req.body?.pad);
      const action = String(req.body?.action || "").trim().toLowerCase();
      const coverCount = deps.resolveCoverCount(req.body?.cover);
      let result: Record<string, unknown> = {};

      if (action === "mark_read") {
        const rawIds = Array.isArray(req.body?.messageIds) ? req.body.messageIds : [];
        const messageIds = rawIds.map((id: unknown) => String(id || "").trim()).filter(Boolean).slice(0, 500);
        const scheduled = await deps.storage.markMessagesRead(auth.sessionId, auth.publicKey, messageIds);
        scheduled.forEach((row: any) => deps.scheduleDisappearingMessageDelete(row.sessionId, row.messageId, row.deleteAt));
        result = { scheduledDeletes: scheduled.length };
      } else if (action === "edit") {
        if (!deps.requireSessionPermission(res, auth.key, "session.write", "Key is not permitted to edit messages")) return;
        const messageId = String(req.body?.messageId || "").trim();
        const content = String(req.body?.content || "");
        if (!messageId) return res.status(400).json({ success: false, error: "messageId is required" });
        const message = await deps.storage.getMessageById(messageId);
        if (!message || message.sessionId !== auth.sessionId) return res.status(404).json({ success: false, error: "Message not found" });
        if (!deps.isStrictEncryptedEnvelope(content)) return res.status(400).json({ success: false, error: "Encrypted content required" });
        const updated = await deps.storage.updateMessage(messageId, auth.publicKey, content);
        if (!updated) return res.status(404).json({ success: false, error: "Message not found" });
        deps.pubsub.broadcastSessionUpdate(updated.sessionId, "message_updated", { message: updated });
        result = { message: updated };
      } else if (action === "delete") {
        if (!deps.requireSessionPermission(res, auth.key, "session.write", "Key is not permitted to delete messages")) return;
        const messageId = String(req.body?.messageId || "").trim();
        if (!messageId) return res.status(400).json({ success: false, error: "messageId is required" });
        const message = await deps.storage.getMessageById(messageId);
        if (!message || message.sessionId !== auth.sessionId) return res.status(404).json({ success: false, error: "Message not found" });
        const deleted = await deps.storage.deleteMessage(messageId, auth.publicKey);
        if (!deleted) return res.status(404).json({ success: false, error: "Message not found" });
        deps.cancelDisappearingMessageDelete(deleted.id);
        deps.pubsub.broadcastSessionUpdate(deleted.sessionId, "message_deleted", { messageId: deleted.id });
        result = { id: deleted.id };
      } else if (action === "star") {
        const messageId = String(req.body?.messageId || "").trim();
        if (!messageId) return res.status(400).json({ success: false, error: "messageId is required" });
        const message = await deps.storage.getMessageById(messageId);
        if (!message || message.sessionId !== auth.sessionId) return res.status(404).json({ success: false, error: "Message not found" });
        const data = await deps.storage.toggleMessageStar(messageId, auth.publicKey);
        result = { messageMeta: data };
      } else if (action === "pin") {
        if (!deps.requireSessionPermission(res, auth.key, "session.write", "Key is not permitted to pin messages")) return;
        const messageId = String(req.body?.messageId || "").trim();
        if (!messageId) return res.status(400).json({ success: false, error: "messageId is required" });
        const message = await deps.storage.getMessageById(messageId);
        if (!message || message.sessionId !== auth.sessionId) return res.status(404).json({ success: false, error: "Message not found" });
        const data = await deps.storage.toggleMessagePin(messageId, auth.publicKey);
        deps.pubsub.broadcastSessionUpdate(message.sessionId, "message_meta_updated", { messageMeta: { pinnedIds: data.pinnedIds } });
        result = { messageMeta: data };
      } else if (action === "decrypt_ack") {
        const messageId = String(req.body?.messageId || "").trim();
        if (!messageId) return res.status(400).json({ success: false, error: "messageId is required" });
        const message = await deps.storage.getMessageById(messageId);
        if (!message || message.sessionId !== req.params.id) return res.status(404).json({ success: false, error: "Message not found" });
        const ttl = Number(message.disappearAfterSeconds || 0);
        if (ttl > 0) {
          const deleteAt = Date.now() + ttl * 1000;
          if (deps.storage.registerMessageDeleteAt(message.id, deleteAt)) {
            deps.scheduleDisappearingMessageDelete(auth.sessionId, message.id, deleteAt);
          }
        }
        result = { scheduled: ttl > 0, messageId };
      } else {
        return res.status(400).json({ success: false, error: "Unsupported action" });
      }

      await deps.maybeMetadataJitter();
      const cover = Array.from({ length: coverCount }, () => ({ kind: "cover", token: deps.makeCoverToken() }));
      return res.json({
        success: true,
        data: withBlindMailboxResponse({
          cover,
          ...result,
        }),
      });
    } catch (error: any) {
      if (error?.message === "PassphraseRequired") {
        return res.status(423).json({ success: false, error: "Message access locked until passphrase grant" });
      }
      if (error?.message === "Forbidden") {
        return res.status(403).json({ success: false, error: "Session access denied" });
      }
      return res.status(400).json({ success: false, error: error?.message || "Failed mailbox action" });
    }
  };
  app.post("/api/sessions/:id/mailbox/action", actionHandler);
  app.post("/api/mailbox/:routeToken/action", actionHandler);
}
