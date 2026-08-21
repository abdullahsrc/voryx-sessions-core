import type { Request, Response } from "express";
import { verifySignature } from "../signature-verification";
import { canonicalAuthPayloadV1 } from "../crypto-canonical";
import { sha256HexBytes } from "../crypto-primitives";
import { createRequestNonceStore } from "../request-nonce-store";

type RequestNonceEntry = {
  keyId: string;
  method: string;
  path: string;
  bodyHash: string;
  expiresAt: number;
  createdAt: number;
};

type CreateRequestAuthHelpersOptions = {
  requireRequestSignature: boolean;
  requestSignatureSkewMs: number;
  requestNonceTtlMs: number;
  requestNonceCacheMax: number;
  uniformAuthDelayMs: number;
  uniformAuthErrors: boolean;
  uniformAuthErrorStatus: number;
  uniformAuthErrorMessage: string;
};

export function createRequestAuthHelpers(options: CreateRequestAuthHelpersOptions) {
  const requestNonceStore = createRequestNonceStore({
    cacheMax: options.requestNonceCacheMax,
  });

  const delay = (ms: number) =>
    new Promise<void>((resolve) => {
      setTimeout(resolve, Math.max(0, ms));
    });

  const normalizeSignedPath = (value: string) => {
    const raw = String(value || "").trim();
    if (!raw) return "/";
    if (raw.startsWith("/")) return raw;
    try {
      const parsed = new URL(raw);
      return `${parsed.pathname}${parsed.search || ""}` || "/";
    } catch {
      return raw.startsWith("?") ? `/${raw}` : raw;
    }
  };

  const getRawBodyBuffer = (req: Request): Buffer => {
    const raw = (req as any).rawBody;
    if (Buffer.isBuffer(raw)) return raw;
    if (typeof raw === "string") return Buffer.from(raw, "utf8");
    return Buffer.alloc(0);
  };

  const verifyRequestSignature = async (
    req: Request,
    keyId: string,
    publicKey: string,
  ): Promise<{ ok: boolean; status: number; error: string }> => {
    if (!options.requireRequestSignature) return { ok: true, status: 200, error: "" };
    const signature = String(req.headers["x-auth-signature"] || "").trim();
    const tsRaw = String(req.headers["x-auth-ts"] || "").trim();
    const nonce = String(req.headers["x-auth-nonce"] || "").trim();
    const bodyHashHeader = String(req.headers["x-auth-body-sha256"] || "").trim().toLowerCase();
    if (!signature || !tsRaw || !nonce || !bodyHashHeader) {
      return { ok: false, status: 401, error: "Signed request headers are required" };
    }
    const ts = Number(tsRaw);
    if (!Number.isFinite(ts)) {
      return { ok: false, status: 401, error: "Invalid request timestamp" };
    }
    const now = Date.now();
    if (Math.abs(now - ts) > options.requestSignatureSkewMs) {
      return { ok: false, status: 401, error: "Stale signed request" };
    }
    const method = String(req.method || "GET").toUpperCase();
    const normalizedPath = normalizeSignedPath(req.originalUrl || req.url || "/");
    const nonceScopeKey = `${keyId}:${method}:${normalizedPath}:${nonce}`;
    const nonceGlobalKey = `${keyId}:*:${nonce}`;
    const bodyHash = sha256HexBytes(getRawBodyBuffer(req));
    if (bodyHash !== bodyHashHeader) {
      return { ok: false, status: 401, error: "Request body hash mismatch" };
    }
    const signedPayload = canonicalAuthPayloadV1({
      ts,
      nonce,
      method,
      path: normalizedPath,
      bodyHash,
      keyId,
      publicKey,
    });
    const valid = verifySignature(signedPayload, signature, publicKey);
    if (!valid) {
      return { ok: false, status: 401, error: "Request signature verification failed" };
    }
    const nonceEntry: RequestNonceEntry = {
      keyId,
      method,
      path: normalizedPath,
      bodyHash,
      expiresAt: now + options.requestNonceTtlMs,
      createdAt: now,
    };
    const consumed = await requestNonceStore.consume(nonceScopeKey, nonceGlobalKey, nonceEntry);
    if (!consumed) {
      return { ok: false, status: 401, error: "Replay detected" };
    }
    return { ok: true, status: 200, error: "" };
  };

  const sendUniformAuthError = async (res: Response, status: number, error: string, code?: string): Promise<Response> => {
    if (status === 401 || status === 403) {
      if (options.uniformAuthDelayMs > 0) {
        await delay(options.uniformAuthDelayMs);
      }
      if (options.uniformAuthErrors) {
        return res.status(options.uniformAuthErrorStatus).json({
          success: false,
          error: options.uniformAuthErrorMessage,
          ...(code ? { code } : {}),
        });
      }
    }
    return res.status(status).json({ success: false, error, ...(code ? { code } : {}) });
  };

  return {
    sendUniformAuthError,
    verifyRequestSignature,
  };
}
