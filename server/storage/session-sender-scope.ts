import { normalizeSenderPublicKey } from "@shared/sender-scope";
import { deriveOpaqueIndex } from "../crypto-primitives";

const SCOPE_PREFIX = "ss2_";
const SYSTEM_SENDER = "system";
const SCOPE_DOMAIN = "voryx:sender-scope:v2";

/**
 * Builds the session-local sender identifier used at server trust boundaries.
 *
 * This is intentionally native-backed: a collision-resistant, domain-separated
 * SHA-256 value prevents a public key from being exposed in transported metadata.
 */
export function computeSessionSenderScopeId(sessionId: string, senderPublicKey: string): string {
  const normalizedSession = String(sessionId || "").trim();
  const normalizedSender = normalizeSenderPublicKey(senderPublicKey);
  if (!normalizedSender || normalizedSender === SYSTEM_SENDER) return SYSTEM_SENDER;
  return `${SCOPE_PREFIX}${deriveOpaqueIndex(SCOPE_DOMAIN, normalizedSession, normalizedSender)}`;
}
