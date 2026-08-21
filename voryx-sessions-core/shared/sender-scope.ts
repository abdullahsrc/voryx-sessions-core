const SCOPE_PREFIX = "ss1_";
const SYSTEM_SENDER = "system";

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

function computePortableScopeDigest(input: string): Uint8Array {
  let h1 = 0x9e3779b9;
  let h2 = 0x85ebca6b;
  let h3 = 0xc2b2ae35;
  let h4 = 0x27d4eb2f;

  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ code, 0x85ebca6b);
    h2 = Math.imul(h2 ^ code, 0xc2b2ae35);
    h3 = Math.imul(h3 ^ code, 0x27d4eb2f);
    h4 = Math.imul(h4 ^ code, 0x165667b1);
  }

  h1 = Math.imul(h3 ^ (h1 >>> 18), 0x85ebca6b);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 0xc2b2ae35);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 0x27d4eb2f);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 0x165667b1);

  const out = new Uint8Array(16);
  const view = new DataView(out.buffer);
  view.setUint32(0, h1 >>> 0, false);
  view.setUint32(4, h2 >>> 0, false);
  view.setUint32(8, h3 >>> 0, false);
  view.setUint32(12, h4 >>> 0, false);
  return out;
}

export function isLikelyPublicKeyHex(value: string): boolean {
  return /^[a-f0-9]{64}$/i.test(String(value || "").trim());
}

export function normalizeSenderPublicKey(value: string): string {
  return String(value || "").trim().toLowerCase();
}

export function isSessionSenderScopeId(value: string): boolean {
  return String(value || "").trim().toLowerCase().startsWith(SCOPE_PREFIX);
}

export function computeSessionSenderScopeId(sessionId: string, senderPublicKey: string): string {
  const normalizedSession = String(sessionId || "").trim();
  const normalizedSender = normalizeSenderPublicKey(senderPublicKey);
  if (!normalizedSender || normalizedSender === SYSTEM_SENDER) return SYSTEM_SENDER;
  const payload = `voryx:sender-scope:v1:${normalizedSession}:${normalizedSender}`;
  return `${SCOPE_PREFIX}${bytesToHex(computePortableScopeDigest(payload))}`;
}
