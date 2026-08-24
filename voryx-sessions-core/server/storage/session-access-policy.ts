import { timingSafeEqual } from "crypto";
import type { Session } from "@shared/schema";
import { deriveProofHash } from "../crypto-primitives";
import { computeSessionSenderScopeId } from "./session-sender-scope";

const BOX1_PUBLIC_KEY_BYTES = 32;
const BOX1_NONCE_BYTES = 24;

export type ParsedPassphraseHash = { algo: "pbkdf2" | "argon2id" | "legacy"; hex: string };

function hexToBytes(hex: string): Uint8Array {
  const clean = String(hex || "").trim();
  if (!clean || clean.length % 2 !== 0) return new Uint8Array();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function parsePassphraseHashValueScoped(hash: string): ParsedPassphraseHash | null {
  const raw = String(hash || "").trim().toLowerCase();
  if (!raw) return null;
  if (/^[a-f0-9]{64}$/i.test(raw)) {
    return { algo: "legacy", hex: raw };
  }
  const parts = raw.split(":");
  if (parts.length !== 2) return null;
  const [algo, hex] = parts;
  if (algo !== "pbkdf2" && algo !== "argon2id") return null;
  if (!/^[a-f0-9]{64}$/i.test(hex)) return null;
  return { algo, hex };
}

export function isValidPassphraseHashScoped(hash: string): boolean {
  return !!parsePassphraseHashValueScoped(hash);
}

export function isPassphraseHashAlgoAllowedScoped(hash: string, requireArgon2id: boolean): boolean {
  const parsed = parsePassphraseHashValueScoped(hash);
  if (!parsed) return false;
  if (!requireArgon2id) return true;
  return parsed.algo === "argon2id";
}

export function isTimingSafePassphraseHashMatchScoped(storedHash: string, candidateHash: string): boolean {
  const leftParsed = parsePassphraseHashValueScoped(storedHash);
  const rightParsed = parsePassphraseHashValueScoped(candidateHash);
  const leftHex = leftParsed?.hex || "0".repeat(64);
  const rightHex = rightParsed?.hex || "f".repeat(64);
  const leftBuf = Buffer.from(leftHex, "utf8");
  const rightBuf = Buffer.from(rightHex, "utf8");
  const equalHex = timingSafeEqual(leftBuf, rightBuf);
  if (!leftParsed || !rightParsed) return false;
  const leftAlgo = leftParsed.algo === "legacy" ? "pbkdf2" : leftParsed.algo;
  const rightAlgo = rightParsed.algo === "legacy" ? "pbkdf2" : rightParsed.algo;
  return equalHex && leftAlgo === rightAlgo;
}

export function isValidGrantPayloadScoped(payload: string): boolean {
  const raw = String(payload || "").trim();
  if (!raw.startsWith("box1:")) return false;
  const parts = raw.split(":");
  if (parts.length !== 4) return false;
  const [, ephPubHex, nonceHex, cipherHex] = parts;
  const ephPublic = hexToBytes(ephPubHex);
  const nonce = hexToBytes(nonceHex);
  const cipher = hexToBytes(cipherHex);
  return (
    ephPublic.length === BOX1_PUBLIC_KEY_BYTES &&
    nonce.length === BOX1_NONCE_BYTES &&
    cipher.length > 0
  );
}

export function getSessionCreatorPublicKeyScoped(session: Session): string | undefined {
  const explicitCreator = session.participantDetails?.find((p) => p.role === "creator")?.publicKey;
  if (explicitCreator) return explicitCreator;
  return session.participants[0];
}

export function getSessionCreatorPeerIdScoped(session: Session): string | undefined {
  const explicitCreator = session.participantDetails?.find((p) => p.role === "creator");
  if (explicitCreator?.peerId) return explicitCreator.peerId;
  const creatorPublicKey = getSessionCreatorPublicKeyScoped(session);
  const sessionId = String(session?.id || "").trim();
  if (!creatorPublicKey || !sessionId) return undefined;
  return computeSessionSenderScopeId(sessionId, String(creatorPublicKey || "").trim());
}

export function isSessionCreatorByPeerIdScoped(session: Session, peerId: string): boolean {
  const creatorPeerId = getSessionCreatorPeerIdScoped(session);
  const normalizedPeerId = String(peerId || "").trim();
  return !!creatorPeerId && !!normalizedPeerId && creatorPeerId === normalizedPeerId;
}

export function isSessionCreatorScoped(session: Session, publicKey: string): boolean {
  const creatorPublicKey = getSessionCreatorPublicKeyScoped(session);
  return !!creatorPublicKey && creatorPublicKey === publicKey;
}

export function isSessionCreatorForPublicKeyScoped(params: {
  session: Session;
  publicKey: string;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
}): boolean {
  const sessionId = String(params.session?.id || "").trim();
  const participantPeerId = sessionId
    ? params.getParticipantPeerId(sessionId, params.publicKey)
    : undefined;
  if (participantPeerId) {
    return isSessionCreatorByPeerIdScoped(params.session, participantPeerId);
  }
  return isSessionCreatorScoped(params.session, params.publicKey);
}

export function createSessionCreatorForPublicKeyResolverScoped(params: {
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
}) {
  return (session: Session, publicKey: string): boolean => isSessionCreatorForPublicKeyScoped({
    session,
    publicKey,
    getParticipantPeerId: params.getParticipantPeerId,
  });
}

export function canUseSessionMessagesScoped(params: {
  session: Session | undefined;
  sessionId: string;
  publicKey: string;
  hasSessionParticipant: (session: Session | undefined, publicKey: string) => boolean;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  creatorOnlyStrictPassphrase: boolean;
  hasPassphrase: (sessionId: string) => boolean;
  getGrant: (sessionId: string, publicKey: string) => string | undefined;
}): boolean {
  if (!params.session) return false;
  if (!params.hasSessionParticipant(params.session, params.publicKey)) return false;
  const participantPeerId = params.getParticipantPeerId(params.sessionId, params.publicKey);
  if (participantPeerId && isSessionCreatorByPeerIdScoped(params.session, participantPeerId)) return true;
  if (params.creatorOnlyStrictPassphrase) return false;
  if (!params.hasPassphrase(params.sessionId)) return false;
  return !!params.getGrant(params.sessionId, params.publicKey);
}

export function createCanUseSessionMessagesResolverScoped(params: {
  getSession: (sessionId: string) => Session | undefined;
  hasSessionParticipant: (session: Session | undefined, publicKey: string) => boolean;
  getParticipantPeerId: (sessionId: string, publicKey: string) => string | undefined;
  creatorOnlyStrictPassphrase: boolean;
  hasPassphrase: (sessionId: string) => boolean;
  getGrant: (sessionId: string, publicKey: string) => string | undefined;
}) {
  return (sessionId: string, publicKey: string): boolean => canUseSessionMessagesScoped({
    session: params.getSession(sessionId),
    sessionId,
    publicKey,
    hasSessionParticipant: params.hasSessionParticipant,
    getParticipantPeerId: params.getParticipantPeerId,
    creatorOnlyStrictPassphrase: params.creatorOnlyStrictPassphrase,
    hasPassphrase: params.hasPassphrase,
    getGrant: params.getGrant,
  });
}

export function isValidInviteCodeScoped(sessionId: string, inviteCode: string, expectedCodeHash: string): boolean {
  const incomingHash = deriveProofHash("session-invite-code", sessionId, inviteCode);
  const expected = String(expectedCodeHash || "");
  const sameLength = expected.length === incomingHash.length;
  if (!sameLength) return false;
  return timingSafeEqual(Buffer.from(incomingHash, "utf8"), Buffer.from(expected, "utf8"));
}
