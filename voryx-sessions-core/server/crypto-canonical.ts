import { nativeCanonicalAuthPayloadV1, nativeCanonicalWsSubscribePayloadV1 } from "./native/crypto-native";

function sanitizeField(value: string): string {
  return String(value || "").trim().replace(/\|/g, "");
}

export function canonicalAuthPayloadV1(input: {
  ts: number;
  nonce: string;
  method: string;
  path: string;
  bodyHash: string;
  keyId: string;
  publicKey: string;
}): string {
  const native = nativeCanonicalAuthPayloadV1({
    ts: Math.floor(input.ts),
    nonce: sanitizeField(input.nonce),
    method: sanitizeField(input.method).toUpperCase(),
    path: sanitizeField(input.path) || "/",
    bodyHash: sanitizeField(input.bodyHash),
    keyId: sanitizeField(input.keyId),
    publicKey: sanitizeField(input.publicKey),
  });
  if (!native) {
    throw new Error("Rust native canonical auth payload generation is required but unavailable");
  }
  return native;
}

export function canonicalWsSubscribePayloadV1(input: {
  ts: number;
  nonce: string;
  sessionId: string;
  keyId: string;
}): string {
  const native = nativeCanonicalWsSubscribePayloadV1({
    ts: Math.floor(input.ts),
    nonce: sanitizeField(input.nonce),
    sessionId: sanitizeField(input.sessionId),
    keyId: sanitizeField(input.keyId),
  });
  if (!native) {
    throw new Error("Rust native canonical websocket payload generation is required but unavailable");
  }
  return native;
}
